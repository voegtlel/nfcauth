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
6. Configure the environment values used by `docker-compose.yml`.

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

The certificate key must be available to the bridge because it signs typed NFC
requests. The certificate presented by the public HTTPS endpoint must be the
same leaf certificate returned in signed manifests and NFC messages. Use a
dedicated provider origin rather than a CDN that hides the TLS private key.

## Public and terminal origins

The example Caddy configuration uses two DNS names. The public hostname serves
discovery, privacy, OIDC callbacks and registration. The terminal hostname
requires a client certificate and exposes only transaction and health routes.
Both reverse proxy to an internal-only bridge port. Do not expose port 8080.

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
the provider HTTPS endpoint and the separate terminal mTLS endpoint. Do not
publish the bridge's port 8080 or allow clients to supply the trusted terminal
identity headers directly.

Verify `/health/ready`, fetch and validate the signed well-known document, then
perform an enrollment before provisioning a terminal. Back up PostgreSQL and
the enrollment/token-signing keys. Transient authentication requests are not
recoverable and do not need backup.

Protocol v4 is a new prerelease database schema and provides no migration from
older prerelease schemas. Recreate the development database/volume before
deploying this version. Production operators should add schema migration
management before accepting real enrollments.

For production, replace PEM signing with a `RequestSigner` backed by KMS/HSM,
apply request rate limits, centralize security events without sensitive fields,
and alert on repeated terminal authentication or assertion failures.
