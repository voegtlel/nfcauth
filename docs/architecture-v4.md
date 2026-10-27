# NFC Auth v4 architecture

NFC Auth v4 turns the Android app into an offline-capable user authenticator.
The terminal is online and obtains a short-lived, scoped access token from a
provider-operated bridge. The app developer operates no central service.

## Components and ownership

| Component | Operated by | Purpose |
| --- | --- | --- |
| Android authenticator | User | Holds one non-exportable key per provider origin, service ID and assurance profile |
| NFC terminal | Provider or customer | Requests a bounded action and consumes the resulting token |
| FastAPI bridge | Provider | Authenticates terminals, verifies phone assertions and issues tokens |
| OIDC identity provider | Provider-selected | Links a phone credential to an account during online enrollment |
| Protected API | Provider | Validates the final token's signature, audience, scope and expiry |

The bridge has four replaceable ports: `IdentityProvider`, `TokenIssuer`,
`EnrollmentStore`, and `RequestSigner`. Authentik is an adapter, not a core
dependency. A local bridge-signed JWT issuer is included for deployments whose
APIs trust the bridge directly.

## Durable and transient state

The phone stores the provider identity, consent receipt, bridge-assigned
credential ID, and Android Keystore alias. It never stores access tokens or
authentication attempts. The bridge durably stores account-to-public-key
enrollments. Registration state and authentication transactions expire from
memory; a restart simply requires the user to try again. Terminals retain their
mTLS identity but keep transaction state and access tokens in memory only.

## Trust boundaries

The terminal authenticates to the bridge with an individual mTLS certificate.
The bridge signs only typed authorization and delivery messages; it cannot be
used as an arbitrary signing oracle. The phone validates the Web-PKI chain,
DNS SAN, `serverAuth` EKU, certificate fingerprint accepted at registration,
request signature, transaction expiry, terminal identity, audience, scopes,
assurance profile, phone challenge, session ID and both ephemeral NFC keys.

The bridge is an authentication authority and must be hosted accordingly. Its
certificate and token keys belong in KMS/HSM-backed storage in production. The
PEM signer exists for small self-hosted installations and tests.
