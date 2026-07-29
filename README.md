# NFC MFC Authenticator

NFC MFC Authenticator is an Android host-card-emulation app and a reference
Python reader for privacy-aware, service-specific authentication. The app has
no developer-operated authentication backend, analytics, advertising, or
tracking.

## Privacy model

Independent NFC services control the data they receive. The app is responsible
for validating each service's signed registration manifest, showing the user a
specific transfer disclosure, and securely transferring only the approved
fields.

Before registration the app displays:

- the recipient service and operator;
- whether the service signing identity is verified or unverified;
- every requested field and its purpose;
- the service privacy policy and deletion instructions;
- the service signing and encryption identities; and
- confirmation that identifying data is encrypted directly to the service.

The affirmative **Agree and register** action authorizes only that displayed
transfer. A changed operator, scope, purpose, privacy notice, signing identity,
or encryption identity is highlighted and requires confirmation again. Routine
authentication inside an approved scope does not repeatedly prompt.

Each service receives a distinct random user ID and a distinct P-256
authentication signing key. Keys and identifiers are never reused across
services.

## Cryptographic protocol

Protocol version 2 has two encryption layers:

1. Every NFC presentation starts a fresh ephemeral P-256 ECDH session. Both
   sides derive an AES-256-GCM key with HKDF-SHA-256. All application payloads,
   including the signed manifest, are authenticated and encrypted on the NFC
   transport. Independent 64-bit counters for each direction are included in
   the AES-GCM authenticated data, so duplicate, skipped, or out-of-order
   encrypted messages are rejected.
2. Registration data is additionally encrypted to the service's signed,
   long-term P-256 encryption key. The derived service session secret protects
   all later authentication requests and responses. This makes the selected
   service—not an NFC relay or the app developer—the decryption endpoint.

Version 1 plaintext traffic is rejected. Large encrypted manifests are split
across sequenced short APDUs and reassembled before authenticated decryption.

The reader submits this signed manifest:

```text
service_id
service_name
operator_name
privacy_policy_url
privacy_notice_version
requested_fields
purposes
data_deletion_url_or_contact
encryption_public_key
registration_nonce
privacy_notice_material_change
```

The signature binds the encryption key and every disclosure field to the
presented service signing key. A valid self-signature proves integrity but not
who operates the service. The Android app labels a service **Verified** only
when its signing-key fingerprint is pinned in `ServiceTrustRegistry`; otherwise
it is clearly labeled **Unverified**.

## Local data and deletion

The Android app stores service metadata, approved scope, a service-specific user
ID, an optional alias, fingerprints, and approval time in its local SQLite
database. Private authentication keys stay in Android Keystore. Service session
secrets are stored through Android encrypted preferences. Android backup is
disabled.

Tap a registered service to revisit its privacy policy, notice version, approved
fields and purposes, encryption fingerprint, and deletion instructions. **Delete
local registration** removes the local database record, service-specific
signing key, and service secret. It does not delete the service's copy; use the
displayed service deletion instructions for that.

Upgrading from protocol version 1 intentionally removes legacy registrations
because their global signing key and unauthenticated plaintext protocol cannot
be migrated safely. Users must approve a new service-specific registration.

## App privacy policy

The repository contains the app-level policy at
[`docs/privacy-policy.html`](docs/privacy-policy.html), and the same policy is
available inside the Android app.

To publish it for Google Play:

1. In GitHub, open **Settings → Pages**.
2. Choose **Deploy from a branch**.
3. Select the release branch (normally `main`) and the `/docs` folder.
4. After deployment, enter
   `https://voegtlel.github.io/nfcauth/privacy-policy.html` in Play Console's
   privacy-policy field.

Verify the public URL after every policy deployment. It must remain active,
publicly accessible, non-geofenced, readable without JavaScript, and not be a
PDF. The developer contact mechanism in the policy is the repository issue
tracker.

## Build the Android app

Requirements:

- JDK 17
- Android SDK 36
- Gradle 8.11.1

```bash
gradle :app:testDebugUnitTest
gradle :app:lint
gradle :app:bundleRelease
```

Release builds enable R8 and embed the deobfuscation mapping in the Android App
Bundle. Release signing must still be supplied through a secure local or CI
configuration before uploading an AAB to Play Console.

## Run the Python reference reader

The Python reader requires Python 3.9+, the `cryptography` package, and the
Adafruit PN532/Raspberry Pi dependencies declared in `python/pyproject.toml`.

```bash
cd python
uv sync
uv run nfc-reader-auth register
uv run nfc-reader-auth auth
```

On first use, the reader creates a persistent P-256 service signing/encryption
identity in `.nfc_auth_service_identity.json` with private-file permissions and
stores registrations in `auth.db`; both are ignored by Git. The default
configuration is an explicitly non-production example whose notice is
[`docs/example-service-privacy.html`](docs/example-service-privacy.html).
Configure the service ID, name, operator, HTTPS privacy-policy URL, notice
version, requested fields and purposes, and deletion contact before using it
outside development.

The service must retain its identity keys. Unexpected signing or encryption key
changes are shown to the user and require a new confirmation.

## Logging

Logs contain only operational state. They must never contain names, service or
user IDs, cryptographic keys, raw APDUs, plaintext payloads, decrypted
registration/authentication data, nonces, or signatures.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
