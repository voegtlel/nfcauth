from __future__ import annotations

import hashlib
import json
from pathlib import Path

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
    token_exchange_endpoint: str | None = None
    token_exchange_client_id: str | None = None
    token_exchange_client_secret: str | None = None
    credential_lifetime_days: int = Field(default=548, ge=365, le=730)
    credential_cleanup_grace_days: int = Field(default=30, ge=0, le=365)
    credential_cleanup_interval_seconds: int = Field(default=86400, ge=60, le=604800)


def load_manifest(path: Path) -> tuple[dict, str]:
    value = json.loads(path.read_text(encoding="utf-8"))
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return value, hashlib.sha256(canonical).hexdigest()


def load_terminals(path: Path) -> dict[str, TerminalIdentity]:
    document = json.loads(path.read_text(encoding="utf-8"))
    values: dict[str, TerminalIdentity] = {}
    for value in document["terminals"]:
        terminal = TerminalIdentity(
            value["terminal_id"],
            value["certificate_fingerprint"],
            frozenset(value["allowed_audiences"]),
            frozenset(value["allowed_scopes"]),
            frozenset(value.get("allowed_assurance", ["possession", "biometric"])),
        )
        values[terminal.terminal_id] = terminal
    return values
