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

1. Create a distinct client certificate and private key for the terminal.
2. Put the certificate fingerprint, allowed audiences, scopes and assurance
   profiles in `deploy/config/terminals.json`.
3. Keep the private key in a TPM or secure element where possible.
4. Connect to the bridge's terminal-only mTLS hostname.
5. Provide a human-readable action for every request. Never derive the phone UI
   from unsigned local terminal text.

## Use the result

`TerminalController.authorize()` returns a `TerminalToken`. Keep it in a local
variable, send it only to the intended API, and discard it after the operation.
Never place tokens, assertions, identifiers, public keys, APDUs or decrypted
messages in logs. For biometric requests, tell the user to remove the phone,
approve the request, and tap the same terminal again.
