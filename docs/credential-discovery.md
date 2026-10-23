# Username-free credential discovery

Readers first identify an enrolled credential, then verify its authenticity. A
service-specific ID is a lookup hint, never proof of identity. No global username,
phone UID, account roles or private signing key is disclosed by discovery.

## Wire flow

1. Select the nfcauth AID and establish the existing protocol-v2 ephemeral NFC
   session. Both peers compute the same `transport_binding`:
   `hex(HMAC-SHA256(session_key, ASCII("nfcauth-v2-credential-discovery-binding")))`.
2. The service signs a discovery request for that binding. `D0 05` transfers the
   request using existing encrypted fragmentation and purpose `credential-discovery`.
3. The phone verifies the signed manifest and requires a previously approved
   registration with unchanged keys, operator, data scope, purposes and notice
   version. It verifies the additional discovery signature and compares its own
   fresh-session binding before returning any credential reference.
4. The phone returns its service-specific ID and echoed request context, encrypted
   under the NFC session. The service matches the manifest hash, nonce, binding and
   service ID, then looks up exactly that credential. It does not try every stored
   symmetric key or pick the first account in its database.
5. The existing encrypted challenge/signature exchange proves possession of the
   selected credential. Unknown, revoked, expired, replayed or invalid proofs fail.

The NFC command uses the existing chunk header/GET RESPONSE mechanism:
`CLA D0, INS 05, P1 fragment sequence, P2 continuation flag, Lc, encrypted data`.

Request:

```json
{
  "signed_manifest": {"protocol_version": 2, "manifest": "…", "manifest_signing_public_key": "…", "manifest_signature": "…"},
  "discovery_nonce": "64 lowercase hex characters",
  "transport_binding": "64 lowercase hex characters",
  "discovery_signature": "base64 DER ECDSA signature"
}
```

The example abbreviates the existing signed-manifest object. The extra signature
is SHA256withECDSA/P-256 over this exact byte concatenation:

```text
ASCII("nfcauth-v2-credential-discovery-request") || 00 ||
uint16_be(length(UTF8(service_id))) || UTF8(service_id) ||
unhex(manifest_hash) || unhex(discovery_nonce) || unhex(transport_binding)
```

Response:

```json
{
  "protocol_version": 2,
  "service_id": "example.service",
  "service_user_id": "opaque ID created at enrollment",
  "manifest_hash": "64 lowercase hex characters",
  "discovery_nonce": "same nonce as request",
  "transport_binding": "same binding as request"
}
```

The signed request is bound to the current NFC session. Replaying a captured
manifest/signature in a new independently terminated NFC session fails the binding
check. This does **not** implement distance bounding or prevent a transparent live
relay of the entire exchange. An authorized service reader can observe the
service-specific ID; other services cannot request it using unrelated keys.

## Local backend adapter

`ReferenceBackend` is an ordinary typed Python object. `SQLiteStore` stores enrolled
credentials and pending authentication attempts in a local SQLite file. Neither
component opens a socket, chooses a web framework or requires NFC hardware. Install
from the `python/` directory with `pip install .` (or `uv sync`). Hardware dependencies
are optional: only physical readers need `pip install '.[reader]'`.

```python
from nfc_authenticator.backend import ReferenceBackend
from nfc_authenticator.service_manifest import ServiceIdentity, ServicePrivacyConfig
from nfc_authenticator.storage import SQLiteStore

privacy = ServicePrivacyConfig(
    service_id="example.service",
    service_name="Example Service",
    operator_name="Example Operator",
    privacy_policy_url="https://example.com/privacy",
    privacy_notice_version="1",
    requested_fields=("service_user_id", "authentication_public_key"),
    purposes={"service_user_id": "Identify enrollment", "authentication_public_key": "Verify login"},
    data_deletion_url_or_contact="privacy@example.com",
)
identity = ServiceIdentity.load_or_create("service-identity.json")
with SQLiteStore("auth.db") as store:
    backend = ReferenceBackend(identity, privacy, store, reader_id="local-reader")
    # Call the methods below using your reader/transport integration.
```

The three methods pass plain Python dictionaries; their implementation never sends
or receives data. For example, an application can inject its own exchange function:

```python
from collections.abc import Callable

from nfc_authenticator.backend import ReferenceBackend
from nfc_authenticator.storage import JsonObject


def authenticate(
    backend: ReferenceBackend,
    transport_binding: str,
    exchange: Callable[[str, JsonObject], JsonObject],
) -> str:
    discovery = backend.start_discovery(transport_binding)
    selection = exchange("credential-discovery", discovery["request"])
    challenge = backend.create_challenge(discovery["id"], selection)
    proof = exchange("authentication", challenge["request"])
    return backend.complete(challenge["login_id"], proof)
```

`exchange` is supplied by your application: it relays messages through the existing
NFC encrypted transport (directly or via your proxy), and returns the decoded NFC
transport response. The authentication proof inside remains credential-encrypted.
Establish that session before calling this function and use its derived binding.
Only the returned, cryptographically verified ID may be mapped to an account/session.
Discovery and challenge creation alone never authenticate the caller.

### Persistence and enrollment

`SQLiteStore` preserves the existing `registered_devices_v2` schema and adds the
`authentication_attempts_v2` table. Existing reader databases work without exporting
credentials. The reader's `AuthDatabase` import remains a compatibility alias.
The Python reader uses this same adapter locally and selects the phone's enrolled
ID rather than guessing the first registration.

Credentials are supplied by the existing consent/acknowledgement registration flow;
`register_device(...)` and `remove_registration(...)` allow the host application to
persist validated enrollment and revoke credentials. They do not perform account
authorization. Never expose raw credential insertion as an unauthenticated proxy API.
The service signing/encryption identity remains in its existing private identity file.
Retain those keys and protect both files: SQLite secrets are not encrypted at rest.

Attempts last 120 seconds and are scoped to `(service_id, reader_id)`, with at most
256 pending attempts per scope. Wall-clock expiry persists across restarts. Consumption
is committed in a SQLite transaction before validating the response, so a failed
proof or another process cannot reuse that attempt. Expired rows are pruned on the
next creation in that scope. Concurrent connections share the bound and consumption
state. After a lost response/restart, a caller can continue using its attempt ID;
if consumption already happened, start a fresh attempt rather than replaying it.
The `clock` injection is for tests; a persistent store requires a consistent wall clock.

### Custom proxies and other databases

An application can call these methods directly, wrap them in HTTP, IPC or another
transport, or implement `BackendStore` for different persistence. No HTTP endpoints,
server, certificate layout or communication protocol are prescribed by the adapter.

A remote proxy must authorize the reader and derive `reader_id` from its trusted
connection/session context, not an arbitrary request field. Use a stable reader ID
for every request from that reader; separate workers for the same reader should
use the same ID and database. Different readers share service identity/credentials
but cannot consume one another's attempts. The default `local` reader ID is suitable
for one local reader. The host application owns input bounds, secure transport,
rate limiting, account authorization and session issuance. The SQLite adapter only
provides storage and protocol verification; it is not an account or network server.

## Compatibility and assurance

This is an additive protocol-v2 instruction: existing enrollment and authentication
messages remain unchanged and existing registrations are preserved. Old Android
builds do not implement D0 05; new discovery readers fail closed rather than guessing
the first account. Install an updated app before testing username-free login.

Tests cover proof binding, rejected changed service approval, nonce/context mismatch,
multiple accounts, cross-reader attempt isolation, expiry, revocation and signature
failure. Physical-phone interoperability and relay resistance are not certified.
Biometric enforcement remains the existing application's policy; this change does
not claim fresh hardware-enforced biometric verification or alter signing-key policy.
