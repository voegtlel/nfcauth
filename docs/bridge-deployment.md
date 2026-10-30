# Provider bridge deployment

`python/nfc_authenticator/bridge` is an asynchronous FastAPI service. HTTP,
OIDC, database and token-exchange operations use async clients. The included
Compose deployment runs the bridge as a non-root process with a read-only root
filesystem and a PostgreSQL enrollment database.

## Prepare configuration

1. Copy `deploy/config/provider-manifest.example.json` to
   `provider-manifest.json` and replace every placeholder.
2. Copy `deploy/config/terminals.example.json` to `terminals.json`.
3. Place the provider certificate chain in
   `deploy/config/provider-certificate-chain.pem`.
4. Place its matching private key in
   `deploy/secrets/provider-signing-key.pem`.
5. Generate a separate P-256 token-signing key as
   `deploy/secrets/token-signing-key.pem`.
6. Configure the account-linking and terminal-token OIDC values used by
   `docker-compose.yml`.

The manifest's `registration_lifetime_days` must match
`NFCAUTH_CREDENTIAL_LIFETIME_DAYS` (548 by default). The bridge extends an
active credential after each verified authentication or explicit renewal. It
deletes credentials only after expiry plus
`NFCAUTH_CREDENTIAL_CLEANUP_GRACE_DAYS` (30 by default), checking once per
`NFCAUTH_CREDENTIAL_CLEANUP_INTERVAL_SECONDS` (one day by default). Phones do
not ping the bridge in the background.

Start from the checked-in template:

```shell
cp deploy/.env.example deploy/.env
```

Keep `deploy/.env`, `deploy/secrets/`, and private PKI material out of version
control. The default Compose configuration builds and tags
`nfcauth-bridge:4.0.0`; set `NFCAUTH_BRIDGE_IMAGE` to a registry reference if
you publish the image separately.

The provider signing key must be available to the bridge because it signs typed
NFC requests. Its certificate must be a currently valid Web-PKI `serverAuth`
certificate for the provider origin and is pinned during phone registration.
The HTTPS reverse proxy may use a separate valid TLS certificate for the same
origin, so an independently deployed Traefik, nginx, cloud ingress or Caddy does
not need access to the bridge's protocol-signing private key.

## HTTPS reverse proxy

The example Caddy configuration exposes one ordinary HTTPS origin for provider
discovery, callbacks, registration and authenticated terminal transactions.
Terminal routes validate OAuth bearer tokens inside the bridge, so the reverse
proxy does not authenticate terminals or inject trusted identity headers.

Another proxy may run in a separate deployment. Route the provider origin to
the bridge, preserve the `Authorization` header, and keep bridge port 8080
private to that proxy. If the proxy-to-bridge hop crosses a network boundary,
protect it with a private network, service mesh or backend TLS. Do not expose
port 8080 directly.

## Run

### Standalone Compose stack

```shell
docker compose \
  --env-file deploy/.env \
  -f deploy/docker-compose.yml \
  up --build -d
```

This starts the bridge, PostgreSQL, and the included Caddy reverse proxy. Only
Caddy publishes port 443. PostgreSQL and port 8080 remain on an internal
network. The bridge alone also joins an egress network so it can make outbound
HTTPS calls to Authentik.

To use an already-published image rather than building locally, set
`NFCAUTH_BRIDGE_IMAGE` and omit `--build`.

### Join an existing Authentik Docker network

If Authentik runs in Compose on the same host, set
`AUTHENTIK_DOCKER_NETWORK` to its actual Docker network name and add the
override:

```shell
docker compose \
  --env-file deploy/.env \
  -f deploy/docker-compose.yml \
  -f deploy/docker-compose.authentik.yml \
  up --build -d
```

Use Authentik's container-network URL for the OIDC endpoints only when its TLS
certificate and hostname still validate from the bridge. Otherwise, use its
normal public HTTPS URL; the bridge has outbound access for that purpose.

The Authentik override does not weaken the public boundary: Caddy still owns
the provider HTTPS endpoint and terminal JWTs are still validated by the
bridge. Do not publish the bridge's port 8080.

Verify `/health/ready`, fetch and validate the signed well-known document, then
perform an enrollment before provisioning a terminal. Back up PostgreSQL and
the enrollment/token-signing keys. Transient authentication requests are not
recoverable and do not need backup.

The database schema is prerelease. Recreate the development database or volume
after schema changes. Production operators should add schema migration
management before accepting real enrollments.

For production, replace PEM signing with a `RequestSigner` backed by KMS/HSM,
apply request rate limits, centralize security events without sensitive fields,
and alert on repeated terminal authentication or assertion failures.

Authentication transactions stay in memory, with a global capacity of 4096 and
a per-terminal capacity of 64. Every store operation prunes expired entries;
the background cleanup loop also prunes them during idle periods. Capacity
checks and one-use consumption are protected by the store lock. These limits
bound memory use; proxy request-rate and request-body limits are still required.

The included bridge and Caddy configurations leave access logging disabled.
Keep OIDC callback query strings (`code` and `state`), redirect `Location` headers,
Authorization headers and request/response bodies out of logs. Apply the same
rule to separately deployed Traefik, load balancers, tracing and error-reporting
systems. If access logs are needed, log only explicitly allowlisted non-sensitive
fields, such as route templates and status codes, never the raw request URI.
