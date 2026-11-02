# NFC Authenticator

NFC Authenticator is an Android HCE authenticator and a provider-operated Python
bridge for privacy-aware, service-specific authorization. The phone can be
offline during NFC use; the terminal is online and receives a scoped access
token valid for at most ten minutes.

The app developer operates no authentication backend, analytics, advertising,
or tracking. Each provider independently operates its bridge and controls the
subsequent processing of data transferred to it.

## Protocol v4

- Registration starts from an HTTPS provider URL and uses a signed manifest,
  explicit data disclosure, Authorization Code plus PKCE, and an immutable OIDC
  `(issuer, sub)` account mapping.
- The provider assigns the opaque credential ID. The phone creates a separate,
  non-exportable P-256 signing key for every provider and assurance profile.
- Every NFC tap uses fresh P-256 ECDH, HKDF-SHA-256 and AES-256-GCM.
- The provider bridge signs the exact terminal, action, audience, scopes,
  assurance requirement, expiry, phone challenge and both ephemeral NFC keys
  with its Web-PKI `serverAuth` certificate.
- Possession authorization can complete in one tap. Biometric authorization is
  intentionally two-tap: receive the request, move the phone away to approve,
  then tap the same terminal again to deliver the in-memory assertion.
- The bridge consumes each transaction once and issues or exchanges a token
  with a maximum lifetime of 600 seconds. No refresh token is issued.
- Terminals authenticate to the bridge over ordinary HTTPS with short-lived
  OAuth/OIDC M2M bearer tokens. Identity comes from the verified token subject,
  not a proxy header or client certificate.
- Provider registrations default to an 18-month (548-day) lease. Each verified
  authentication extends the lease. A user can also explicitly renew with the
  existing service-specific credential; there is no background heartbeat.
- Authentication attempts, assertions, NFC session keys and terminal tokens are
  never persisted.

## Implementations

The repository contains:

- the Android authenticator under `app/`;
- the asynchronous FastAPI bridge under
  `python/nfc_authenticator/bridge/`;
- reader-independent terminal orchestration in
  `python/nfc_authenticator/terminal.py`;
- APDU framing over a caller-supplied `NfcTransport` in
  `python/nfc_authenticator/terminal_apdu.py`;
- Docker Compose deployment material under `deploy/`; and
- an optional PN532 adapter under `examples/terminal/`.

PN532 and Raspberry Pi packages are not base dependencies. Applications may
provide PC/SC, USB, serial, vendor-SDK, or entirely custom transports.

## Documentation

- [Architecture](docs/architecture-v4.md)
- [Protocol and two-tap biometric flow](docs/protocol-v4.md)
- [Terminal integration tutorial](docs/terminal-integration.md)
- [Bridge deployment tutorial](docs/bridge-deployment.md)
- [Optional Authentik integration](docs/authentik-integration.md)
- [Security model and residual risks](docs/security-model-v4.md)
- [Wire reference](docs/protocol-wire-v4.md)
- [Operations and recovery](docs/operations.md)
- [Release validation checklist](docs/release-validation.md)
- [Google Play privacy and Data safety checklist](docs/google-play-data-safety.md)
- [App privacy policy](docs/privacy-policy.html)

## Build and test

Android requires JDK 17, Android SDK 36 and Gradle 8.11.1:

```shell
gradle :app:testDebugUnitTest
gradle :app:lint
gradle :app:bundleRelease
```

Python requires 3.11 or newer:

```shell
cd python
uv sync --extra dev
uv run --extra dev ruff check .
uv run --extra dev pytest -q
```

Run the bridge through Docker Compose as described in
[the deployment guide](docs/bridge-deployment.md), or configure the
`NFCAUTH_BRIDGE_*` environment variables and run `nfc-auth-bridge`.

The repository includes two Compose modes:

```shell
# Standalone bridge + PostgreSQL + Caddy
cp deploy/.env.example deploy/.env
docker compose --env-file deploy/.env -f deploy/docker-compose.yml up --build -d

# Optional: also join Authentik's existing Docker network
docker compose --env-file deploy/.env \
  -f deploy/docker-compose.yml \
  -f deploy/docker-compose.authentik.yml \
  up --build -d
```

PN532 is unrelated to bridge deployment and remains an optional terminal
adapter.

## Privacy and logging

The phone persists provider disclosure and consent metadata, a provider-assigned
credential ID, registration expiry, and the Android Keystore alias. Local
deletion removes those records and keys but does not delete the provider's copy;
the app retains the provider's deletion URL or contact. The app sends no
periodic heartbeat or other background provider traffic.

Logs must never contain names, account or credential IDs, service IDs, keys,
certificates, signatures, tokens, raw APDUs, nonces, plaintext, or decrypted
objects.

## License

MIT; see [LICENSE](LICENSE).
