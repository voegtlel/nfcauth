# NFC Authenticator

NFC Authenticator is an Android host-card-emulation app and a Python reference
reader/backend for privacy-aware, service-specific authentication. The app has
no developer-operated authentication backend, analytics, advertising, or
tracking.

This branch implements protocol version 3. It is intentionally incompatible
with earlier prerelease protocols and uses a new Android and Python database.

## Protocol v3 in brief

- A service allocates an opaque `credential_id` and may associate it with an
  existing account. The phone does not create an account identifier.
- The reader selects either the possession AID or biometric AID. Credentials
  and Android Keystore signing keys are unique to `(service, profile)`.
- Every presentation starts with ephemeral P-256 ECDH. Before any application
  data is accepted, the service signs the session transcript with a Web-PKI
  certificate valid for its HTTPS origin.
- The phone validates the certificate chain, DNS SAN, validity, digital
  signature key usage, `serverAuth` EKU, and transcript signature offline.
  It then rekeys the provisional session with the transcript hash.
- Registration data is additionally encrypted directly to the service's
  long-term P-256 encryption key. All later credential messages are protected
  with a credential key known only to that phone and service.
- After a successful proof, both sides derive the next credential key with
  HKDF. A commit encrypted under the new key and an encrypted ACK prevent
  either side from discarding the last common epoch prematurely.
- Discovery advertises the phone's current/fallback epochs. This recovers from
  an interrupted commit without persisting authentication attempts.

The detailed wire protocol is in
[`docs/credential-discovery.md`](docs/credential-discovery.md). The security
analysis and known limitations are in
[`docs/protocol-security-analysis.md`](docs/protocol-security-analysis.md).

## Consent and local data

Before registration, the app shows the recipient service and operator, the
certificate-verified domain, exact requested fields and purposes, policy and
deletion links, authentication profile, and confirmation that data is
encrypted directly to the service. **Agree and register** authorizes only that
specific transfer.

The app asks again when the operator, requested fields, purposes, encryption
identity, profile, or materially changed privacy notice differs. Routine
authentication within the approved scope does not prompt.

The Android app persists:

- service disclosure and approval metadata;
- the service-issued opaque credential reference;
- one profile-specific private signing key in Android Keystore; and
- active/fallback credential-key epochs in encrypted preferences.

Authentication challenges and attempts are transient. The Python
`SQLiteStore.attempts` dictionary and Android HCE service keep them only in
memory. Durable overlap is limited to credential key epochs needed for
commit/ACK recovery.

Deleting a local registration removes its database record, profile-specific
signing key, and credential keys. It does not delete the service's copy; use
the displayed service deletion instructions for that.

## Service session authentication

The reader can call a service signing API or use a local certificate key for
development. The signing API receives typed transcript fields, not arbitrary
bytes. Its certificate must:

- chain to a trust anchor accepted by Android;
- contain a DNS SAN matching `service_origin`;
- permit digital signatures; and
- contain the TLS `serverAuth` extended key usage.

The reference HTTP client waits 2 seconds for the signing API. The phone
accepts the initial certificate proof for 5 seconds after issuing its
challenge. Readers should complete ordinary API calls well within this bound
and must not hold a single APDU open during the network call.

Public CA validation proves control of the service domain, not that an operator
name or policy is legally correct. Revocation freshness is unavailable during
offline NFC use; certificate expiry is still checked.

## Python interface

`ReferenceBackend` is transport-independent. Credentials persist in
`registered_credentials`; pending discovery/proof objects live only in the
process-local `SQLiteStore.attempts` dictionary.

```python
from nfc_authenticator.backend import ReferenceBackend
from nfc_authenticator.service_manifest import (
    FIELD_AUTHENTICATION_PUBLIC_KEY,
    PROFILE_BIOMETRIC,
    ServiceIdentity,
    ServicePrivacyConfig,
)
from nfc_authenticator.storage import SQLiteStore

privacy = ServicePrivacyConfig(
    service_origin="https://login.example.com",
    service_id="example",
    service_name="Example",
    operator_name="Example GmbH",
    privacy_policy_url="https://login.example.com/privacy",
    privacy_notice_version="3",
    requested_fields=(FIELD_AUTHENTICATION_PUBLIC_KEY,),
    purposes={FIELD_AUTHENTICATION_PUBLIC_KEY: "Verify login"},
    data_deletion_url_or_contact="https://login.example.com/delete",
    authentication_profile=PROFILE_BIOMETRIC,
)
identity = ServiceIdentity.load_or_create("service-identity-v3.json")
with SQLiteStore("auth-v3.db") as store:
    backend = ReferenceBackend(identity, privacy, store, reader_id="reader-1")
    discovery = backend.start_discovery(transport_binding)
    challenge = backend.create_challenge(discovery["id"], phone_selection)
    result = backend.complete(challenge["login_id"], encrypted_proof)
    backend.confirm_rotation(result, encrypted_commit_ack)
```

The service should allocate `credential_id` before registration and map it to
its account internally. Do not encode an email, username, or database primary
key into it.

## Run the reference reader

Requirements are Python 3.9+, `cryptography`, and the optional PN532/Raspberry
Pi packages:

```bash
cd python
uv sync --extra reader

# Development: local certificate key and chain.
uv run --extra reader nfc-reader-auth register \
  --credential-id "$(openssl rand -hex 16)" \
  --auth-profile biometric \
  --service-origin https://login.example.com \
  --certificate-key server-key.pem \
  --certificate-chain fullchain.pem

# Production-style: scoped API credential is read from NFC_AUTH_SIGNING_API_KEY.
uv run --extra reader nfc-reader-auth auth \
  --auth-profile biometric \
  --service-origin https://login.example.com \
  --signing-api-url https://login.example.com/nfcauth/session-signature
```

Prefer a unique, scoped, rotatable reader credential or mTLS for the
reader-to-service call. The signing endpoint must construct and canonicalize
the protocol transcript itself; it must not become an arbitrary signing oracle.

## Build and test

Android requirements: JDK 17, Android SDK 36, Gradle 8.11.1.

```bash
gradle :app:testDebugUnitTest
gradle :app:lint
gradle :app:bundleRelease

cd python
uv run --with pytest pytest -q
uv run --extra dev ruff check .
```

The app/package release is 2.0.0; the wire protocol version is 3.

## Privacy policy

The app policy is [`docs/privacy-policy.html`](docs/privacy-policy.html) and is
also available inside the app. With GitHub Pages enabled, use
<https://voegtlel.github.io/nfcauth/privacy-policy.html> in Play Console.

## Logging

Logs must never contain names, credential IDs, service IDs, cryptographic keys,
certificate material, raw APDUs, plaintext/decrypted payloads, nonces, or
signatures.

## License

MIT; see [`LICENSE`](LICENSE).
