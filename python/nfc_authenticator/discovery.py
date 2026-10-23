"""Signed, session-bound credential discovery for NFC Auth v2.

Identification chooses a stored credential; only the subsequent signature proves
authentication. This module does not grant sessions or trust phone-supplied roles.
"""

from __future__ import annotations

import base64
import hmac
import re
import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from .service_manifest import PROTOCOL_VERSION, manifest_hash

PURPOSE_DISCOVERY = "credential-discovery"
DOMAIN = b"nfcauth-v2-credential-discovery-request\x00"


def signature_payload(service_id: str, digest: str, nonce: str, binding: str) -> bytes:
    if not all(isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) for value in (digest, nonce, binding)):
        raise ValueError("Discovery hash, nonce and binding must be 32-byte lowercase hex")
    encoded = service_id.encode("utf-8")
    if not 1 <= len(encoded) <= 255:
        raise ValueError("Invalid service ID")
    return DOMAIN + len(encoded).to_bytes(2, "big") + encoded + bytes.fromhex(digest + nonce + binding)


def create_request(identity, privacy, binding: str) -> dict:
    signed = identity.signed_manifest(privacy)
    nonce = secrets.token_hex(32)
    payload = signature_payload(privacy.service_id, manifest_hash(signed["manifest"]), nonce, binding)
    return {
        "signed_manifest": signed,
        "discovery_nonce": nonce,
        "transport_binding": binding,
        "discovery_signature": base64.b64encode(
            identity.signing_private_key.sign(payload, ec.ECDSA(hashes.SHA256()))
        ).decode("ascii"),
    }


def identify(request: dict, response: dict) -> str:
    """Validate response context, then return a lookup hint, never an auth proof."""
    if not isinstance(response, dict):
        raise TypeError("Discovery response must be an object")
    expected = {
        "service_id": request["signed_manifest"]["manifest"]["service_id"],
        "manifest_hash": manifest_hash(request["signed_manifest"]["manifest"]),
        "discovery_nonce": request["discovery_nonce"],
        "transport_binding": request["transport_binding"],
    }
    if response.get("protocol_version") != PROTOCOL_VERSION or not all(
        isinstance(response.get(key), str) and hmac.compare_digest(response[key], value)
        for key, value in expected.items()
    ):
        raise ValueError("Discovery response does not match this service/session/request")
    user_id = response.get("service_user_id")
    if not isinstance(user_id, str) or not 1 <= len(user_id) <= 255:
        raise ValueError("Invalid service-specific credential reference")
    return user_id
