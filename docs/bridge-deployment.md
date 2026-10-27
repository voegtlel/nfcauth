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

```shell
docker compose --env-file .env -f deploy/docker-compose.yml up --build -d
```

Verify `/health/ready`, fetch and validate the signed well-known document, then
perform an enrollment before provisioning a terminal. Back up PostgreSQL and
the enrollment/token-signing keys. Transient authentication requests are not
recoverable and do not need backup.

For production, replace PEM signing with a `RequestSigner` backed by KMS/HSM,
apply request rate limits, centralize security events without sensitive fields,
and alert on repeated terminal authentication or assertion failures.
