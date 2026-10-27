"""Credential discovery inside a certificate-authenticated NFC Auth v3 session."""

from __future__ import annotations

import hmac
import secrets
from typing import Any

from .service_manifest import PROTOCOL_VERSION, manifest_hash

JsonObject = dict[str, Any]
PURPOSE_DISCOVERY = "credential-discovery"


def create_request(manifest: JsonObject, binding: str) -> JsonObject:
    return {
        "protocol_version": PROTOCOL_VERSION,
        "service_id": manifest["service_id"],
        "authentication_profile": manifest["authentication_profile"],
        "manifest_hash": manifest_hash(manifest),
        "discovery_nonce": secrets.token_hex(32),
        "transport_binding": binding,
    }


def identify(request: JsonObject, response: JsonObject) -> tuple[str, tuple[int, ...]]:
    """Return an exact lookup hint and supported key epochs, never auth proof."""

    if not isinstance(response, dict):
        raise TypeError("Discovery response must be an object")
    expected = {
        "service_id": request["service_id"],
        "authentication_profile": request["authentication_profile"],
        "manifest_hash": request["manifest_hash"],
        "discovery_nonce": request["discovery_nonce"],
        "transport_binding": request["transport_binding"],
    }
    if response.get("protocol_version") != PROTOCOL_VERSION or not all(
        isinstance(response.get(key), str) and hmac.compare_digest(response[key], value)
        for key, value in expected.items()
    ):
        raise ValueError("Discovery response does not match this service/session/request")
    credential_id = response.get("credential_id")
    if not isinstance(credential_id, str) or not 16 <= len(credential_id) <= 255:
        raise ValueError("Invalid service-issued credential reference")
    raw_epochs = response.get("key_epochs")
    if (
        not isinstance(raw_epochs, list)
        or not raw_epochs
        or len(raw_epochs) > 3
        or any(not isinstance(epoch, int) or epoch < 0 for epoch in raw_epochs)
    ):
        raise ValueError("Invalid credential key epochs")
    return credential_id, tuple(sorted(set(raw_epochs), reverse=True))
