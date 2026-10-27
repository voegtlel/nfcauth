# NFC Auth protocol v4

## Registration

1. The user enters an HTTPS provider origin.
2. The phone downloads `/.well-known/nfc-authenticator` and validates HTTPS.
3. The returned manifest is signed by the same `serverAuth` certificate used by
   the provider HTTPS endpoint. The phone verifies the detached signature and
   exact TLS certificate.
4. The phone checks that the HTTPS privacy policy is reachable and displays the
   exact operator, fields, purposes, audiences, scopes, profiles and deletion
   instructions.
5. After explicit consent, the phone creates a provider/profile-specific P-256
   key in Android Keystore.
6. The bridge performs Authorization Code plus PKCE against its configured OIDC
   provider and identifies the account by immutable `(issuer, sub)`.
7. The bridge assigns the credential ID. Completion requires a one-use code and
   proof from the new phone key.

## NFC transport

Each tap creates an independent P-256 ECDH exchange. HKDF-SHA-256 derives
directional AES-256-GCM transport keys. AEAD associated data contains protocol
version, session ID, direction, purpose and sequence number. Only ephemeral
public keys, a random session ID and a phone challenge exist before encryption.

## Possession authentication

Possession can complete in one tap: the bridge-signed request authenticates the
provisional NFC session, the phone signs the assertion, and the terminal sends
it to the bridge.

## Biometric authentication

Biometric authentication intentionally uses two taps:

1. First tap delivers and verifies the signed request.
2. The phone leaves the NFC field and uses an auth-per-use `CryptoObject` to
   sign the exact request after displaying its action, audience and scopes.
3. Second tap establishes fresh ECDH keys. The bridge signs an assertion-delivery
   message bound to the original request, original terminal and new NFC session.
4. The phone releases the in-memory assertion once and clears it.

Process death, reboot, cancellation or expiry discards the request. No attempt
is written to disk.

## Token issuance

The bridge atomically consumes the transaction before issuance. Tokens contain
one audience, the intersection of requested and terminal-allowed scopes, the
terminal actor, assurance method and transaction ID. The maximum lifetime is
600 seconds and no refresh token is issued.
