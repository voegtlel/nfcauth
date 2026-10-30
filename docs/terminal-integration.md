# Terminal integration tutorial

The terminal package does not depend on PN532, GPIO, PC/SC, USB, serial, or any
vendor SDK. Integrators provide either the low-level `NfcTransport` interface or
the higher-level `PhoneChannel` interface.

## Implement a reader transport

```python
class MyTransport:
    async def wait_for_device(self) -> None:
        ...

    async def transceive(
        self, command: bytes, *, timeout_seconds: float = 2.0
    ) -> bytes:
        ...

    async def close(self) -> None:
        ...
```

Pass it to `ApduPhoneChannel`. That class owns AID selection, fragmentation,
GET RESPONSE handling, encrypted-session setup and the one/two-tap state
machine. Applications that already have an APDU framework can implement
`PhoneChannel` directly. `examples/terminal/authorize.py` is deliberately
hardware-neutral: call its `authorize(transport)` function with your adapter.

The example refuses to send bearer tokens over plain HTTP by default. HTTPS is
required for remote APIs, while loopback HTTP is accepted for a same-host API.
If an internal service mesh or equivalent authenticated encrypted transport
protects an HTTP hop, list each permitted origin exactly in the comma-separated
`NFCAUTH_TERMINAL_INSECURE_HTTP_ORIGINS` environment variable. Private IP ranges
and internal DNS names are never trusted implicitly.

The optional PN532 launcher is `examples/terminal/authorize_pn532.py`. Install
its hardware dependencies explicitly with
`pip install 'nfc-authenticator[pn532]'`. They are never installed by the base
package.

## Provision a terminal

1. Create a distinct Authentik or generic OAuth service account for the
   terminal and issue an app password or client credential.
2. Configure its access tokens for the bridge audience, the
   `nfcauth:terminal` scope and a lifetime of at most ten minutes.
3. Put the token's stable `sub` claim, allowed audiences, scopes and assurance
   profiles in `deploy/config/terminals.json`.
4. Keep the credential in protected terminal storage and rotate it normally.
5. Connect to the provider's ordinary HTTPS bridge origin. No client
   certificate or proxy-specific identity header is required.
6. Provide a human-readable action for every request. Never derive the phone UI
   from unsigned local terminal text.

`OAuthClientCredentialsTokenProvider` obtains tokens on demand and caches them
in process memory until shortly before expiry. It supports standard
`client_secret` authentication and Authentik's per-service-account
`username`/app-password form. `BridgeClient` adds the resulting bearer token to
each bridge request; it does not accept a caller-supplied terminal ID.

## Use the result

`TerminalController.authorize()` returns a `TerminalToken`. Keep it in a local
variable, send it only to the intended API, and discard it after the operation.
Never place tokens, assertions, identifiers, public keys, APDUs or decrypted
messages in logs. For biometric requests, tell the user to remove the phone,
approve the request, and tap the same terminal again.

## Configure and invoke the hardware-neutral example

Install the package from the checkout into your terminal virtual environment:

```shell
python -m pip install ./python
export NFCAUTH_TERMINAL_TOKEN_ENDPOINT=https://auth.example.com/application/o/token/
export NFCAUTH_TERMINAL_OAUTH_CLIENT_ID=YOUR_TERMINAL_CLIENT_ID
export NFCAUTH_TERMINAL_OAUTH_USERNAME=YOUR_TERMINAL_SERVICE_ACCOUNT
export NFCAUTH_TERMINAL_BRIDGE_URL=https://nfc-auth.example.com
export INVENTORY_API_URL=https://inventory.example.com/api/inventory
```

Inject `NFCAUTH_TERMINAL_OAUTH_APP_PASSWORD` from protected storage, not a
literal command recorded in shell history. This example uses Authentik's
username/app-password grant form; generic OAuth integrations should construct
`OAuthClientCredentialsTokenProvider` with `client_secret` instead. Keep the
terminal policy's audience/scope aligned with `inventory-api` and
`inventory.read` in the example, or change those example constants together.

The example is a library entry point, not a universal hardware launcher. From
your application (with the repository's `examples/terminal` on the import path):

```python
import asyncio
from authorize import authorize

# my_transport is your NfcTransport implementation, connected to real hardware.
asyncio.run(authorize(my_transport))
```

Transport `transceive` returns complete response bytes including SW1/SW2 and
defaults to a two-second exchange timeout. Bridge HTTP calls default to five
seconds. Waiting for the user/device is separate from a single APDU timeout;
do not wait for biometric approval while holding an NFC exchange open. An
interrupted/expired flow must restart; never automatically replay a completion
request expecting a second token. See [wire details](protocol-wire-v4.md).
