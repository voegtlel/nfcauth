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
5. After explicit consent, the phone creates a P-256 key in Android Keystore
   scoped to the provider's canonical HTTPS origin, service ID and profile.
6. The bridge performs Authorization Code plus PKCE against its configured OIDC
   provider and identifies the account by immutable `(issuer, sub)`.
7. The bridge assigns the credential ID. Completion requires a one-use code and
   proof from the new phone key.
8. The bridge returns the provider-disclosed registration expiry. The phone
   stores and displays it.

## Registration lifetime and explicit renewal

The example lifetime is 548 days so a person who authenticates roughly once a
year normally remains registered. Every successfully verified NFC
authentication resets the server-side expiry to the configured lifetime.

Manual renewal is deliberately user initiated:

1. The phone re-fetches the signed provider manifest over HTTPS, validates the
   current Web-PKI identity, confirms the signed manifest is unchanged, and
   rechecks the privacy-policy URL.
2. The bridge creates a 120-second, one-use renewal document containing the
   credential, service, profile, current expiry, proposed expiry and random
   challenge.
3. The phone shows the operator and proposed expiry. Only after confirmation
   does it sign the domain-separated canonical document with the existing
   service-specific credential key.
4. The bridge verifies the signature and atomically extends the active
   registration.

An expired registration cannot be renewed and must be enrolled again through
the provider login. The app does not run a renewal worker or heartbeat.

## Terminal HTTPS authentication

Every bridge transaction endpoint requires a short-lived OAuth/OIDC bearer
token over HTTPS. The bridge validates the JWT signature against the configured
JWKS, requires the exact issuer and bridge audience, requires the
`nfcauth:terminal` scope, limits the token lifetime, and uses the verified `sub`
claim as the terminal identity. That subject must exist in the provider's
terminal policy registry.

The terminal never supplies a separate trusted identity header. Its M2M token
is distinct from the user access token produced after NFC authorization and is
never sent to the phone. Any reverse proxy can be used because terminal
authentication is part of the bridge's standard HTTPS API.

## NFC transport

Each tap creates an independent P-256 ECDH exchange. HKDF-SHA-256 derives
an AES-256-GCM transport key per phase. Direction-separated AEAD associated data contains protocol
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

After token issuance succeeds, the bridge records the successful
authentication and extends the active registration lease. The response exposes
the new expiry to the terminal for operational visibility; it is not an access
token claim and grants no additional authority.

Because the terminal contacts the bridge after receiving the phone assertion,
the offline phone cannot know whether token issuance succeeded. It therefore
does not optimistically extend its local date after NFC. The displayed date is
the last expiry confirmed during registration or explicit online renewal and
may be earlier than the bridge's authoritative expiry. Explicit renewal safely
refreshes it; no authorization decision relies on the phone's local date.

For byte layouts, message schemas, signing inputs and APDU status handling, see
the [v4 wire reference](protocol-wire-v4.md). For deployment constraints and
recovery, see the [operations runbook](operations.md).
