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
The HTTPS reverse proxy MUST present the exact same leaf certificate used by
the bridge signer. The phone compares the DER certificates, not just their
hostnames or public keys. A separate valid certificate for the same hostname
will fail registration and online renewal. Independently deployed Traefik,
nginx or Caddy must therefore be provisioned with the matching TLS certificate
and private key (or equivalent key access). This is a current implementation
constraint, not a requirement imposed by OAuth. Do not enable independent
automatic TLS renewal at the proxy without coordinating the bridge signer.

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

## Complete setup and verification

Run shell examples from the repository root on a Linux deployment host with
Docker Compose v2 and OpenSSL installed. Obtain a public DNS name and a Web-PKI
certificate covering it before starting; a self-signed certificate is not a
production substitute. The certificate needs digital-signature usage and
`serverAuth` EKU. The PEM chain starts with the leaf, followed by intermediates.

```shell
mkdir -p deploy/secrets
chmod 700 deploy/secrets
cp deploy/config/provider-manifest.example.json deploy/config/provider-manifest.json
cp deploy/config/terminals.example.json deploy/config/terminals.json
cp deploy/.env.example deploy/.env
chmod 600 deploy/.env
umask 077
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
  -out deploy/secrets/token-signing-key.pem
```

Copy the CA-issued chain and its matching unencrypted signing key to the paths
listed above; never generate a replacement key for an existing certificate.
Protect keys using ownership/ACLs: the non-root bridge container must be able
to read them, while unrelated host users must not. Inspect the image's `id`
using `docker compose --env-file deploy/.env -f deploy/docker-compose.yml run
--rm --no-deps --entrypoint id bridge` after building it; do not assume its UID
matches the host account. Grant only that container identity read access.

Edit all placeholders in the manifest, terminal registry and `.env`. Keep the
public origin, manifest endpoints, service ID and lifetime consistent. Set a
strong database password, and configure the exact OIDC callback URI from the
[Authentik guide](authentik-integration.md). Keep generated credentials out of
shell history, screenshots and support bundles.

```shell
docker compose --env-file deploy/.env -f deploy/docker-compose.yml config -q
docker compose --env-file deploy/.env -f deploy/docker-compose.yml up --build -d
curl --fail https://nfc-auth.example.com/health/ready
curl --fail https://nfc-auth.example.com/.well-known/nfc-authenticator
```

Replace the hostname. Expect `{"status":"ready"}` and a JSON manifest envelope
with `manifest`, `signature_algorithm`, `signature`, and `certificate_chain`.
Readiness is a basic process route, not an OIDC/database/token-exchange probe.
The app's registration flow performs the certificate/signature checks; curl
success alone does not validate the manifest signature.

Complete the [release validation checklist](release-validation.md) before
serving real users. In particular, prove the final token works at the intended
API and is rejected for another audience or insufficient scope.

## Process model

Run one bridge process/worker and one instance. Registration attempts, renewal
challenges and NFC transactions live in process-local Python variables, not
PostgreSQL. A restart intentionally loses attempts, not enrollments; ask users
to start again. Do not add `--workers`, replicas or round-robin load balancing.
Sticky routing alone is not sufficient unless ALL browser, phone and terminal
requests for the same attempt reach the owning process. Multi-instance support
requires explicit transient-state routing or a redesigned shared transient
store; it is not implemented by this Compose stack.

See the [operations runbook](operations.md) for renewal, revocation and recovery.
