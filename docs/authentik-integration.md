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
