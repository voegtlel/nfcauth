# Optional Authentik integration

Authentik is not required. Registration and terminal authentication use generic
OIDC/OAuth adapters, while the user token returned after NFC can use either
bridge-signed JWTs or RFC 8693 token exchange.

## Account linking

Create a confidential OAuth2/OIDC application with an exact redirect URI:

```text
https://auth.example.com/v1/oidc/callback
```

Configure the issuer, authorization endpoint, token endpoint, JWKS endpoint,
client ID and secret in the bridge environment. The bridge uses Authorization
Code plus PKCE, validates issuer, audience, expiry, nonce and signature, and
stores only immutable `(issuer, sub)` as the account mapping.

Do not request `offline_access`. The bridge does not store user refresh tokens.
Routine authentication and explicit registration renewal do not send the user
through Authentik again. Renewal proves control of the already enrolled
service-specific phone key. Authentik login is used only for first registration
or re-registration after expiry/key loss.

The included deployment supports both an external Authentik URL and a
same-host Compose deployment. For the latter, set `AUTHENTIK_DOCKER_NETWORK`
and apply `deploy/docker-compose.authentik.yml` in addition to the base Compose
file. The base stack deliberately gives only the bridge outbound network
access; PostgreSQL and the bridge's inbound port remain private.

## Terminal machine-to-machine authentication

Create an OAuth2 provider that permits the client-credentials grant and issues
asymmetrically signed access tokens. Configure the bridge with that provider's
exact issuer, JWKS URI and an audience dedicated to the bridge. Add an OAuth
scope mapping for `nfcauth:terminal` and set access-token validity to no more
than ten minutes.

Give every physical terminal a distinct service account and app password. A
terminal exchanges those credentials at Authentik's token endpoint, then sends
the returned JWT to the bridge as `Authorization: Bearer ...`. Put the stable
JWT `sub` value in `deploy/config/terminals.json`; the bridge derives the signed
terminal ID from that claim and independently caps audiences, scopes and
assurance using the registry. Never share one provider client secret across all
terminals when per-terminal revocation and audit are required.

The terminal M2M token authorizes calls to the bridge only. It is not the user
access token returned after NFC approval. Use distinct audiences and scopes so
the two token classes cannot be confused.

## Token exchange

Authentik 2026.8 or newer can be configured to trust the bridge as a federated
OIDC/JWT issuer and enable the token-exchange grant. Set the bridge
`TOKEN_EXCHANGE_*` values. The target Authentik provider must have access-token
validity set to ten minutes and must explicitly trust the exchange provider.

The adapter creates a 60-second subject assertion only after successful NFC
verification and exchanges it inside the bridge. The assertion is never given
to the terminal. Authentik returns a bearer access token; its current key
binding does not sender-constrain token-exchange access tokens. Keep the result
in terminal memory, use narrow audiences and scopes, and send it only over
authenticated encrypted transport. Deployments that require sender-constrained
downstream tokens need an additional API-gateway or proof-of-possession
mechanism.

Token exchange is optional. Leaving all `TOKEN_EXCHANGE_*` values empty makes
the bridge issue its own ten-minute ES256 JWTs instead; protected APIs must then
trust the bridge's `/v1/jwks.json`. Before enabling Authentik exchange, verify
with a test account that the federated subject resolves to the intended human
account rather than a generated service account.
