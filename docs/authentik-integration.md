# Optional Authentik integration

Authentik is not required. Registration uses the generic OIDC adapter, while
terminal-token issuance can use either bridge-signed JWTs or RFC 8693 token
exchange.

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

The included deployment supports both an external Authentik URL and a
same-host Compose deployment. For the latter, set `AUTHENTIK_DOCKER_NETWORK`
and apply `deploy/docker-compose.authentik.yml` in addition to the base Compose
file. The base stack deliberately gives only the bridge outbound network
access; PostgreSQL and the bridge's inbound port remain private.

## Token exchange

Authentik 2026.8 or newer can be configured to trust the bridge as a federated
OIDC/JWT issuer and enable the token-exchange grant. Set the bridge
`TOKEN_EXCHANGE_*` values. The target Authentik provider must have access-token
validity set to ten minutes and must explicitly trust the exchange provider.

The adapter creates a 60-second subject assertion only after successful NFC
verification and exchanges it inside the bridge. The assertion is never given
to the terminal. Authentik returns a bearer access token; its current key
binding does not sender-constrain token-exchange access tokens. Sensitive APIs
should therefore additionally require terminal mTLS or place the API behind a
provider gateway that validates terminal identity.

Token exchange is optional. Leaving all `TOKEN_EXCHANGE_*` values empty makes
the bridge issue its own ten-minute ES256 JWTs instead; protected APIs must then
trust the bridge's `/v1/jwks.json`. Before enabling Authentik exchange, verify
with a test account that the federated subject resolves to the intended human
account rather than a generated service account.
