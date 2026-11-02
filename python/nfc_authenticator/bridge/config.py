from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, cast

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from .models import TerminalIdentity


class BridgeSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="NFCAUTH_BRIDGE_", env_file=".env", extra="ignore")

    service_id: str
    service_origin: str
    manifest_path: Path
    request_signing_key_path: Path
    certificate_chain_path: Path
    token_signing_key_path: Path
    terminal_registry_path: Path
    database_url: str = "sqlite+aiosqlite:///./nfc-auth-bridge.db"
    oidc_issuer: str
    oidc_authorization_endpoint: str
    oidc_token_endpoint: str
    oidc_jwks_uri: str
    oidc_client_id: str
    oidc_client_secret: str
    oidc_redirect_uri: str
    terminal_oidc_issuer: str
    terminal_oidc_audience: str
    terminal_oidc_jwks_uri: str
    terminal_required_scope: str = "nfcauth:terminal"
    terminal_token_max_lifetime_seconds: int = Field(default=600, ge=60, le=3600)
    token_exchange_endpoint: str | None = None
    token_exchange_client_id: str | None = None
    token_exchange_client_secret: str | None = None
    credential_lifetime_days: int = Field(default=548, ge=365, le=730)
    credential_cleanup_grace_days: int = Field(default=30, ge=0, le=365)
    credential_cleanup_interval_seconds: int = Field(default=86400, ge=60, le=604800)


def load_manifest(path: Path) -> tuple[dict[str, Any], str]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("Provider manifest must be a JSON object")
    value = cast(dict[str, Any], raw)
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return value, hashlib.sha256(canonical).hexdigest()


def load_terminals(path: Path) -> dict[str, TerminalIdentity]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("Terminal registry must be a JSON object")
    document = cast(dict[str, Any], raw)
    if set(document) != {"terminals"} or not isinstance(document["terminals"], list):
        raise ValueError("Terminal registry must contain exactly one terminals array")
    values: dict[str, TerminalIdentity] = {}
    for raw_value in document["terminals"]:
        if not isinstance(raw_value, dict):
            raise ValueError("Terminal entry must be a JSON object")
        value = cast(dict[str, Any], raw_value)
        required = {"subject", "allowed_audiences", "allowed_scopes"}
        optional = {"allowed_assurance"}
        if not isinstance(value, dict) or not required <= set(value) or not set(value) <= required | optional:
            raise ValueError("Terminal entry has missing or unsupported fields")
        subject = value["subject"]
        if not isinstance(subject, str) or not subject or len(subject) > 255:
            raise ValueError("Terminal subject must be a nonempty string of at most 255 characters")
        if subject in values:
            raise ValueError("Terminal subjects must be unique")
        terminal = TerminalIdentity(
            subject,
            _string_set(value["allowed_audiences"], "allowed_audiences"),
            _string_set(value["allowed_scopes"], "allowed_scopes"),
            _string_set(value.get("allowed_assurance", ["possession", "biometric"]), "allowed_assurance"),
        )
        if not terminal.allowed_audiences or not terminal.allowed_scopes:
            raise ValueError("Terminal audiences and scopes must be nonempty")
        if not terminal.allowed_assurance <= {"possession", "biometric"} or not terminal.allowed_assurance:
            raise ValueError("Terminal assurance profiles are invalid")
        values[terminal.terminal_id] = terminal
    return values


def _string_set(value: Any, field: str) -> frozenset[str]:
    if (
        not isinstance(value, list)
        or not value
        or len(value) > 64
        or any(not isinstance(item, str) or not item or len(item) > 255 for item in value)
        or len(set(value)) != len(value)
    ):
        raise ValueError(f"Terminal {field} must be a nonempty list of unique strings")
    return frozenset(cast(list[str], value))
