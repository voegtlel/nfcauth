# Operations and recovery

This runbook describes the current prerelease implementation, not features of
a hypothetical admin UI. Use one bridge worker/instance; see
[deployment](bridge-deployment.md). All examples assume the checked-in Compose
stack and must be adapted to the operator's access-control and backup policy.

## Certificate renewal

1. Obtain a new CA-issued `serverAuth` certificate and matching key for the
   same canonical public provider origin. Keep the provider manifest unchanged
   unless you intend to require new registration consent.
2. In a maintenance window, install the same leaf/chain and matching key at the
   HTTPS proxy and bridge signer. Preserve secure file access. The proxy may
   be separate, but it cannot present an independently issued certificate.
3. Restart the bridge (the PEM signer loads at startup) and reload/restart the
   proxy. In-flight requests are intentionally lost; retry from the beginning.
4. Verify public HTTPS, chain, hostname, signed discovery, and a test enrollment.
5. Existing phones pin the old certificate. Have users open registration details
   and explicitly renew online before their server lease expires. With an
   unchanged manifest, renewal verifies current HTTPS/discovery, uses the
   existing credential key, and updates the stored certificate fingerprint.
   Offline NFC will reject the new fingerprint until that succeeds.
6. If the disclosure changed, the app requires reviewed re-registration instead.
   Expired registrations or lost phone keys also require provider login again.

Do not promise seamless offline renewal or automatically trust a new fingerprint.
Plan certificate expiry notifications independently of the 548-day enrollment
lease. A certificate compromise requires incident response, not routine renewal.

## Lost phone, revocation and deletion

Local deletion removes only phone metadata and keys. It does not revoke a
server record. The provider must publish working deletion instructions and
authenticate ownership before making server-side changes.

`EnrollmentStore.revoke_credential()` is implemented by the SQL adapter. There
is no bundled HTTP revocation endpoint or administrator portal. Integrate that
method into a provider-authenticated management tool, or have an authorized
database administrator perform a parameterized update of the specific record:

```sql
UPDATE nfc_credentials SET revoked = TRUE WHERE credential_id = :credential_id;
```

`:credential_id` is a bound parameter supplied by your database client, not a
literal psql command. Check the affected-row count, and test that the credential
can no longer authenticate or renew. Do not log the identifier. Provider-side
deletion requires deleting the authorized record and applying the provider's
backup retention policy. Already issued bearer tokens can remain valid for up
to ten minutes; revocation does not retroactively invalidate them at APIs.

To disable a compromised terminal, revoke its OAuth credential and remove its
subject from `terminals.json`, then restart the bridge to reload policy. Protect
the registry and validate the edited JSON before restart. Consider already
issued user tokens separately.

## Backup and restore

Back up PostgreSQL enrollments, manifest/terminal configuration and required
signing keys using encrypted, access-controlled storage. Keep passwords and keys
out of diagnostic archives. A database-only backup is not a complete deployment.
Do not back up phone keys or transient transactions.

For this Compose stack, an authorized operator can create a custom-format dump:

```shell
umask 077
docker compose --env-file deploy/.env -f deploy/docker-compose.yml \
  exec -T postgres pg_dump -U nfcauth -d nfcauth -Fc > enrollments.dump
```

The dump contains account mappings: encrypt it immediately using the operator's
backup system. Test recovery in an isolated deployment: provision compatible
PostgreSQL, matching app version/config/keys, then use `pg_restore` into an EMPTY
database. Do not restore over production blindly or use destructive cleanup
flags. Verify enrollment counts and test authentication with a dedicated test
account before reopening traffic. Reapply revocations/deletions made after the
backup; restoring old data can resurrect revoked credentials.

## Schema changes

The current adapter creates tables but does not migrate existing columns. Keep
the deployed version and database schema paired. For disposable development
data, recreate the development database deliberately; never delete production
volumes to resolve a startup error. Real enrollments require reviewed migrations,
a backup, staging verification and a rollback plan before upgrading.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| TLS or manifest rejection | Exact TLS/signing leaf match, chain order, SAN, EKU, validity and phone clock |
| Offline NFC stops after certificate renewal | Explicit online registration renewal on that phone |
| Terminal receives 401 | Issuer, audience, scope, signature/JWKS, token lifetime and provisioned subject |
| Transaction creation rejected | Terminal policy and 64-per-terminal/4096-global active capacities |
| Completion rejected | Expiry, one-use consumption, matching transaction/profile/key; start again |
| Renewal asks to re-register | Manifest changed, registration expired, or key unavailable |
| Readiness succeeds but login fails | Readiness is not an OIDC/DB/API end-to-end check |
| Works intermittently behind a proxy | Unsupported multiple workers/instances, routing, network latency or NFC loss |
| Key permission denied | Non-root container UID/GID and mounted secret permissions |

Use status codes and sanitized route-level events. Never enable raw callback
query, Authorization header, token, key, APDU or payload logging to diagnose.
