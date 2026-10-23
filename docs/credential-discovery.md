# Username-free credential discovery

Readers first identify an enrolled credential, then verify its authenticity. A
service-specific ID is a lookup hint, never proof of identity. No global username,
phone UID, account roles or private signing key is disclosed by discovery.

## Wire flow

1. Select the nfcauth AID and establish the existing protocol-v2 ephemeral NFC
   session. Both peers compute the same `transport_binding`:
   `hex(HMAC-SHA256(session_key, ASCII("nfcauth-v2-credential-discovery-binding")))`.
2. The service signs a discovery request for that binding. `D0 05` transfers the
   request using existing encrypted fragmentation and purpose `credential-discovery`.
3. The phone verifies the signed manifest and requires a previously approved
   registration with unchanged keys, operator, data scope, purposes and notice
   version. It verifies the additional discovery signature and compares its own
   fresh-session binding before returning any credential reference.
4. The phone returns its service-specific ID and echoed request context, encrypted
   under the NFC session. The service matches the manifest hash, nonce, binding and
   service ID, then looks up exactly that credential. It does not try every stored
   symmetric key or pick the first account in its database.
5. The existing encrypted challenge/signature exchange proves possession of the
   selected credential. Unknown, revoked, expired, replayed or invalid proofs fail.

The NFC command uses the existing chunk header/GET RESPONSE mechanism:
`CLA D0, INS 05, P1 fragment sequence, P2 continuation flag, Lc, encrypted data`.

Request:

```json
{
  "signed_manifest": {"protocol_version": 2, "manifest": "…", "manifest_signing_public_key": "…", "manifest_signature": "…"},
  "discovery_nonce": "64 lowercase hex characters",
  "transport_binding": "64 lowercase hex characters",
  "discovery_signature": "base64 DER ECDSA signature"
}
```

The example abbreviates the existing signed-manifest object. The extra signature
is SHA256withECDSA/P-256 over this exact byte concatenation:

```text
ASCII("nfcauth-v2-credential-discovery-request") || 00 ||
uint16_be(length(UTF8(service_id))) || UTF8(service_id) ||
unhex(manifest_hash) || unhex(discovery_nonce) || unhex(transport_binding)
```

Response:

```json
{
  "protocol_version": 2,
  "service_id": "example.service",
  "service_user_id": "opaque ID created at enrollment",
  "manifest_hash": "64 lowercase hex characters",
  "discovery_nonce": "same nonce as request",
  "transport_binding": "same binding as request"
}
```

The signed request is bound to the current NFC session. Replaying a captured
manifest/signature in a new independently terminated NFC session fails the binding
check. This does **not** implement distance bounding or prevent a transparent live
relay of the entire exchange. An authorized service reader can observe the
service-specific ID; other services cannot request it using unrelated keys.

## Backend reference

`python/nfc_authenticator/backend.py` implements the service boundary independently
of NFC hardware. It uses the existing enrolled credential store, maintains bounded
120-second single-use attempts, and returns an ID from `complete()` only after
verification. Store credentials from the existing consent/acknowledgement registration
flow. Enrollment/account authorization is the calling application's responsibility.

```python
backend = ReferenceBackend(service_identity, privacy_config, credential_store)
discovery = backend.start_discovery(reader_transport_binding)
# Relay discovery["request"] to the phone using D0 05.
challenge = backend.create_challenge(discovery["id"], encrypted_transport_response)
# Relay challenge["request"] using the existing authentication instruction.
authenticated_id = backend.complete(challenge["login_id"], encrypted_phone_proof)
# Resolve this ID to the registered account; only now grant application permissions.
```

`python/examples/backend_service.py --config backend.json` exposes the same stages
as `/discovery`, `/challenges` and `/authenticate`. It requires mTLS and an explicit
allow-list of reader certificate SHA-256 fingerprints. Each authorized reader has
its own attempt store, while readers share the logical service identity/credential
database. Example configuration:

```json
{
  "host": "127.0.0.1",
  "port": 8443,
  "service_identity": "/secure/service-identity.json",
  "credential_database": "/secure/auth.db",
  "certificate": "/secure/backend.crt",
  "private_key": "/secure/backend.key",
  "reader_ca": "/secure/reader-ca.crt",
  "reader_certificate_sha256": ["authorized reader leaf-certificate SHA256 hex"],
  "privacy": {
    "service_id": "example.service", "service_name": "Example Service",
    "operator_name": "Example Operator", "privacy_policy_url": "https://example.com/privacy",
    "privacy_notice_version": "1",
    "requested_fields": ["service_user_id", "authentication_public_key"],
    "purposes": {"service_user_id": "Identify enrollment", "authentication_public_key": "Verify login"},
    "data_deletion_url_or_contact": "privacy@example.com"
  }
}
```

This single-process example is for development behind trusted networking. Production
services need durable transactional attempts/idempotency, lifecycle/revocation checks,
rate limits, account/session authorization, protected credentials, and operational
hardening. The Python reader uses the same `ReferenceBackend` in process and now
supports selecting among multiple enrolled users without entering their username.

## Compatibility and assurance

This is an additive protocol-v2 instruction: existing enrollment and authentication
messages remain unchanged and existing registrations are preserved. Old Android
builds do not implement D0 05; new discovery readers fail closed rather than guessing
the first account. Install an updated app before testing username-free login.

Tests cover proof binding, rejected changed service approval, nonce/context mismatch,
multiple accounts, cross-reader attempt isolation, expiry, revocation and signature
failure. Physical-phone interoperability and relay resistance are not certified.
Biometric enforcement remains the existing application's policy; this change does
not claim fresh hardware-enforced biometric verification or alter signing-key policy.
