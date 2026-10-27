"""Hardware-neutral terminal integration using a caller-supplied NFC transport."""

from __future__ import annotations

import os

from nfc_authenticator.terminal import BridgeClient, TerminalController, validate_protected_api_url
from nfc_authenticator.terminal_apdu import ApduPhoneChannel
from nfc_authenticator.terminal_transport import NfcTransport


async def authorize(transport: NfcTransport) -> None:
    """Authorize with any PC/SC, USB, serial, vendor-SDK, or custom adapter."""
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

    allowed_http = tuple(
        value.strip()
        for value in os.environ.get("NFCAUTH_TERMINAL_INSECURE_HTTP_ORIGINS", "").split(",")
        if value.strip()
    )
    api_url = validate_protected_api_url(
        os.environ["INVENTORY_API_URL"],
        allowed_insecure_origins=allowed_http,
    )
    async with httpx.AsyncClient(timeout=5) as client:
        response = await client.get(
            api_url,
            headers={"Authorization": f"Bearer {access_token}"},
        )
        response.raise_for_status()
