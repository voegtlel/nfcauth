# NFC Auth protocol v3

All integers are unsigned big-endian. JSON is UTF-8. AES-GCM envelopes include
the protocol version, service/credential/profile identity, key epoch, 12-byte
random IV, and ciphertext/tag. Every application message is also inside the
authenticated NFC transport.

## Profiles and AIDs

| Profile | AID |
| --- | --- |
| possession | `F064652E696E666F726E617574696B01` |
| biometric | `F064652E696E666F726E617574696B02` |

The selected AID fixes the profile for the entire session. A credential ID,
credential key, and authentication signing key are scoped to that profile.

## 1. Provisional NFC session

The reader sends `D0 00` with:

```text
version(03) || session_id(16) || reader_ephemeral_P256_uncompressed(65)
```

The phone returns:

```text
version(03) || session_id(16) || phone_ephemeral_P256_uncompressed(65) ||
phone_challenge(32)
```

Both derive:

```text
provisional_root = HKDF-SHA256(ECDH, salt=session_id,
                               info="nfcauth-v3-provisional-session")
```

Only purpose `session-authentication` is permitted under this provisional
root.

## 2. Certificate-authenticated transcript

The reader sends `D0 06` containing the manifest, DER certificate chain,
signature algorithm, and signature. The service signs:

```text
"NFCAuth-v3-server-auth\0" || version ||
len(service_origin) || service_origin ||
len(service_id) || service_id ||
len(authentication_profile) || authentication_profile ||
len(manifest_hash) || unhex(manifest_hash) ||
len(session_id) || session_id ||
len(phone_challenge) || phone_challenge ||
len(reader_ephemeral_public_key) || reader_ephemeral_public_key ||
len(phone_ephemeral_public_key) || phone_ephemeral_public_key
```

Lengths are uint32. Supported signatures are ECDSA/SHA-256 and
RSA-PSS/SHA-256. The phone validates PKIX, DNS SAN, certificate time, digital
signature key usage, `serverAuth` EKU, profile, manifest, and signature.

Both then reset message counters and derive:

```text
authenticated_root = HKDF-SHA256(provisional_root, salt=session_id,
  info="nfcauth-v3-authenticated-session" || SHA256(signed_transcript))
```

The signing API client timeout is 2 seconds; the phone's challenge window is 5
seconds. The API accepts the typed fields above and returns only chain,
algorithm, and signature.

## 3. Registration

The authenticated manifest contains:

```text
service_origin, service_id, service_name, operator_name,
privacy_policy_url, privacy_notice_version, requested_fields, purposes,
data_deletion_url_or_contact, authentication_profile,
encryption_public_key, privacy_notice_material_change
```

The service creates an opaque `credential_id` before `D0 01` and sends it
with a fresh registration nonce and manifest hash. It may associate the ID with
an existing account. The phone never invents this ID.

After explicit consent, the phone returns exactly the approved fields. It
always includes the profile-specific public authentication key and includes an
alias only when requested. The payload is encrypted with a credential key
derived from phone-ephemeral/service-static P-256 ECDH:

```text
K0 = HKDF-SHA256(ECDH, salt=manifest_hash,
  info="nfcauth-v3-credential|service_id|credential_id|profile")
```

The service persists the credential only after validating the response, then
sends `D0 04` registration ACK encrypted under `K0`. The phone commits its
pending registration only after decrypting that ACK.

## 4. Discovery and authentication

The NFC session binding is:

```text
hex(HMAC-SHA256(binding_key,
    "nfcauth-v3-credential-discovery-binding"))
```

`D0 05` contains the service, profile, manifest hash, fresh nonce, and binding.
The phone requires an unchanged approved registration and returns its
service-issued `credential_id` plus all locally available `key_epochs`.
The backend chooses the highest epoch both sides have.

`D0 02` carries an AES-GCM challenge under that credential key. The phone
validates all outer and inner identities, nonce, epoch, manifest hash, and
transport binding. The authentication signature binds:

```text
service_origin, service_id, credential_id, profile, key_epoch,
nonce, transport_binding, manifest_hash
```

For the biometric AID, Android Keystore marks the signing key as
user-authentication-required and the app requires a recent biometric prompt.
The possession AID uses a separate key with no biometric requirement.

## 5. Key rotation and recovery

After verifying the proof at epoch `n`, both peers derive:

```text
K[n+1] = HKDF-SHA256(K[n], salt=authentication_nonce,
  info="nfcauth-v3-key-update|service_id|credential_id|profile|n+1")
```

The phone durably records `K[n+1]` as pending before returning its proof. The
service durably promotes it while retaining `K[n]`, then sends `D0 07`
`KEY_COMMIT` encrypted under `K[n+1]`. The phone decrypts the commit,
promotes while retaining the old key, and returns an ACK encrypted under the
new key. The service discards the previous key only after the ACK.

Neither side stores commit/ACK message bodies. Durable state is only the active
and fallback epochs (plus a pending phone epoch during the exchange).
`key_epochs` discovery finds the highest common epoch after a crash or lost
response, preventing permanent drift. Receiving a valid challenge under a
locally pending epoch is also proof that the service promoted that epoch, so the
phone promotes it while retaining its fallback before continuing.
A valid proof under an unacknowledged service-side active epoch likewise
implicitly acknowledges the preceding commit; the service then removes that
fallback before deriving another epoch. This avoids both permanent drift and
an unbounded chain of fallback keys when an ACK is lost.

## APDU transport

Encrypted messages use short-APDU fragments:

```text
CLA D0, INS, P1 sequence, P2 (80 more / 00 final), Lc, ciphertext fragment
```

`00 C0 00 00 Le` retrieves response fragments. AES-GCM authenticated data
binds protocol version, session ID, direction, a length-prefixed purpose, and
the monotonically increasing directional sequence. Replays, gaps, reordering,
purpose substitution, and direction reflection fail.
