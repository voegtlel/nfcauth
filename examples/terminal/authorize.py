"""Minimal terminal integration; replace Pn532Transport with your reader SDK."""

from __future__ import annotations

import asyncio
import os

from pn532_transport import Pn532Transport

from nfc_authenticator.terminal import BridgeClient, TerminalController
from nfc_authenticator.terminal_apdu import ApduPhoneChannel


async def main() -> None:
    transport = Pn532Transport()  # Any object implementing NfcTransport works.
    bridge = BridgeClient(
        os.environ["NFCAUTH_TERMINAL_BRIDGE_URL"],
        os.environ["NFCAUTH_TERMINAL_ID"],
        certificate=(os.environ["NFCAUTH_TERMINAL_CERT"], os.environ["NFCAUTH_TERMINAL_KEY"]),
    )
    controller = TerminalController(bridge, ApduPhoneChannel(transport, "biometric"))
    try:
        token = await controller.authorize(
            audience="inventory-api",
            scopes=("inventory.read",),
            action="Load the current inventory",
            assurance="biometric",
        )
        # Keep this variable in memory. Do not print or persist it.
        access_token = token.access_token
        await call_protected_api(access_token)
    finally:
        await controller.close()


async def call_protected_api(access_token: str) -> None:
    import httpx

    async with httpx.AsyncClient(timeout=5) as client:
        response = await client.get(
            os.environ["INVENTORY_API_URL"],
            headers={"Authorization": f"Bearer {access_token}"},
        )
        response.raise_for_status()


if __name__ == "__main__":
    asyncio.run(main())
