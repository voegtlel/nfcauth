# v4 wire reference

This describes the checked-in prerelease protocol. There is no v1-v3 fallback.
Use the Python/Kotlin implementations and tests together when implementing a
new transport; independently implemented conformance has not been certified.

## Encodings and signed messages

JSON uses UTF-8, sorted object keys recursively, no whitespace separators and
unescaped Unicode (`ensure_ascii=False` in Python). Do not apply Unicode
normalization or convert integers to floating point. Signed fields use integer
Unix seconds. No general RFC 8785/JCS compatibility is claimed. Scopes in an
authorization document are sorted. Hashes are lowercase SHA-256 hex.

The signing input is domain bytes (including the final NUL) followed by canonical
JSON. These domains are distinct:

| Object | Domain before JSON |
| --- | --- |
| Manifest | `NFCAuth-v4-provider-manifest\0` |
| Authorization request | `NFCAuth-v4-authorization-request\0` |
| Phone assertion, omitting `signature` | `NFCAuth-v4-authorization-assertion\0` |
| Second-tap delivery request | `NFCAuth-v4-assertion-delivery\0` |
| Renewal document | `NFCAuth-v4-registration-renewal\0` |

Registration completion is NOT JSON: sign
`NFCAuth-v4-registration-complete\0 || registration_id UTF8 || 00 || completion_code UTF8`.

Provider envelopes contain `request`, `message_type` (`authorization` or
`assertion_delivery`), `signature_algorithm`, `signature`, `certificate_chain`.
Discovery uses `manifest` instead of `request` and has no `message_type`.
Provider signatures and DER certificates use standard padded Base64, leaf first.
`ECDSA_SHA256` uses ASN.1 DER ECDSA; `RSA_PSS_SHA256` uses SHA-256, MGF1-SHA256,
32-byte salt. The phone checks Web-PKI trust, domain, EKU, dates and its pin.
Discovery additionally requires exact equality with the HTTPS leaf certificate.

Phone assertion signatures use DER ECDSA P-256/SHA-256, encoded as unpadded
Base64URL. Registration public keys are standard Base64 of DER SPKI. Registration
completion and renewal signatures are standard Base64, unlike NFC assertions.

| Message | Fields (all required unless noted) |
| --- | --- |
| Session binding | `session_id`, `phone_challenge`, `terminal_ephemeral_public_key`, `phone_ephemeral_public_key` (unpadded Base64URL) |
| Authorization | `protocol_version=4`, `transaction_id`, `service_id`, `service_origin`, `manifest_hash`, `terminal_id`, `audience`, `scopes`, `action`, `assurance`, `issued_at`, `expires_at`, `session` |
| Assertion | `protocol_version=4`, `transaction_id`, `request_hash`, `service_id`, `terminal_id`, `credential_id`, `assurance`, `approved_at`, `signature` |
| Delivery | `protocol_version=4`, `transaction_id`, `request_hash`, `service_id`, `service_origin`, `terminal_id`, `issued_at`, `expires_at`, `session` |

`request_hash = SHA256(authorization domain || canonical authorization JSON)`.
Authorization validity is at most 120 seconds (30-second future-clock tolerance).
Delivery validity is at most 30 seconds (10-second future-clock tolerance).
The original transaction still expires after 120 seconds. Assertions must match
the request/context and have approval time within 120 seconds of bridge time.

## HTTPS and NFC wire formats

### HTTPS API sequence

The `/v1/` path is the bridge API namespace, not NFC protocol version 1.

| Endpoint | Request / response |
| --- | --- |
| `GET /.well-known/nfc-authenticator` | Signed manifest envelope |
| `POST /v1/registrations` | `{profile, public_key}` → `{registration_id, authorization_url, expires_at}` |
| `GET /v1/oidc/callback?state=…&code=…` | Browser callback → `nfcauth://registration-complete?registration_id=…&completion_code=…` |
| `POST /v1/registrations/{id}/complete` | `{completion_code, signature}` → `{credential_id, service_id, profile, registration_expires_at}` |
| `POST /v1/registration-renewals` | `{credential_id}` → `{renewal: document}` |
| `POST /v1/registration-renewals/{id}/complete` | `{signature}` → `{credential_id, registration_expires_at, renewed_at}` |
| `POST /v1/transactions` | `{audience, scopes, action, assurance}` → `{transaction_id, expires_at}` |
| `POST /v1/transactions/{id}/bind-nfc-session` | Session binding → signed authorization envelope |
| `POST /v1/transactions/{id}/bind-delivery-session` | Fresh session binding → signed delivery envelope |
| `POST /v1/transactions/{id}/complete` | Signed phone assertion → `{access_token, token_type, expires_in, scope, registration_expires_at}` |

All transaction routes require `Authorization: Bearer <terminal M2M JWT>`.
Registration is not pre-authenticated with a terminal token; account linking
happens through browser OIDC and completion requires the new phone key.
Renewal requires proof by the existing active credential. Never expose the
callback code or terminal bearer token on NFC. Invalid completion signatures
return controlled 4xx responses; timeouts may mean completion already consumed
the transaction, so start a new attempt rather than assuming safe replay.

Renewal documents include `renewal_id`, `credential_id`, `service_id`, `profile`,
`challenge`, `issued_at`, `challenge_expires_at`, `current_registration_expires_at`,
`proposed_registration_expires_at`, `protocol_version=4` and
`action="registration.renew"`. Sign all those document fields, not its wrapper.

### Tap key derivation

All integers below are unsigned big-endian; lengths are bytes. P-256 public
points are 65-byte uncompressed SEC1 (`04 || X || Y`). Each tap starts fresh:

```text
terminal hello = 04 || session_id[16] || terminal_point[65]
phone hello    = 04 || session_id[16] || phone_point[65] || phone_challenge[32]
```

The initial `04` is protocol version, not a point prefix. Derive a 32-byte root
with HKDF-SHA256 over the ECDH shared secret, salt=session_id,
info=`nfcauth-v4-provisional-session`. Derive the 32-byte AES transport key with
HKDF-SHA256 over that root, same salt, info=`nfcauth-v4-transport`.

Only purpose `session-authentication` is permitted in this provisional phase.
After provider proof verification, derive a new 32-byte root using HKDF-SHA256
over the provisional root, same salt, info=
`nfcauth-v4-authenticated-session || transcript_hash[32]`, then derive a new
transport key as above. First-tap transcript_hash is the binary request_hash;
second-tap transcript_hash is SHA256(delivery domain || canonical delivery JSON).
Reset send/receive counters to zero when switching phase.

```text
envelope = version[1] || session_id[16] || sequence[8] || random_IV[12]
           || AES256GCM_ciphertext || tag[16]
AAD      = version[1] || session_id[16] || direction[1]
           || UTF8_purpose_length[2] || UTF8_purpose || sequence[8]
```

Direction is 0 terminal-to-phone, 1 phone-to-terminal. There is one transport
key per phase, not separate directional keys; AAD separates directions and
independent counters enforce exact in-order delivery. Authenticated response
purposes are `authorization-assertion` and `assertion-delivery`. Reject wrong
session/version/counter, invalid tag and counter exhaustion; never reuse a
previous tap's state or release identifying data before provider verification.

## APDU framing

SELECT uses `00 A4 04 00 Lc AID`; possession AID is
`F064652E696E666F726E617574696B01`, biometric ends in `02` instead.
Session initiation is `D0 00 00 00 Lc hello`. Authorization and delivery use
INS `08` and `09` respectively with CLA `D0`.

Encrypted JSON envelopes are split into at most 249-byte command fragments:
`D0 INS sequence[1] more[1] Lc[1] fragment`. Sequence begins at zero; `more` is
`80` except for the last fragment (`00`). More than 256 fragments is rejected.
Intermediate fragments require `9000`. These fragment counters are distinct
from the 8-byte AEAD sequence inside the reassembled envelope.

`61 LL` means response bytes are available: issue `00 C0 00 00 LL`, concatenate
response data (excluding SW1/SW2), and repeat while SW1 is `61`. The last status
must be `9000`. `6300` after authorization means biometric approval is pending;
remove the phone, approve in-app, then perform a fresh second-tap session and
signed delivery. Unexpected/error statuses abort the exchange. Do not treat
transport errors or a repeated HTTP completion as permission to issue twice.

## Reproducible signing-input vector

This small vector checks canonicalization and domain separation, not a complete
NFC/certificate conformance suite:

```python
from nfc_authenticator.protocol_v4 import canonical_json, REQUEST_DOMAIN

assert canonical_json({"b": 2, "a": 1}) == b'{"a":1,"b":2}'
assert REQUEST_DOMAIN + canonical_json({"b": 2, "a": 1}) == (
    b'NFCAuth-v4-authorization-request\x00{"a":1,"b":2}'
)
```

See `protocol_v4.py`, `protocol_crypto.py`, `terminal_apdu.py` and
`tests/test_protocol_v4.py` for executable schemas/signature examples. Tests of
the bridge do not establish physical APDU interoperability; use the
[release validation checklist](release-validation.md).
