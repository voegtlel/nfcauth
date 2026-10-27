"""Reader-independent NFC transport boundary.

The base package deliberately has no GPIO, PN532, PC/SC, USB, or vendor SDK
dependency. Applications provide this interface; optional examples live under
``examples/terminal``.
"""

from __future__ import annotations

from typing import Protocol


class NfcTransport(Protocol):
    async def wait_for_device(self) -> None: ...

    async def transceive(self, command: bytes, *, timeout_seconds: float = 2.0) -> bytes: ...

    async def close(self) -> None: ...


class NfcTransportError(RuntimeError):
    pass
