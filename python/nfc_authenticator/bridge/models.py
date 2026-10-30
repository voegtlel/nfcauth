from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from nfc_authenticator.protocol_v4 import AuthorizationRequest, SessionBinding


class TransactionState(StrEnum):
    CREATED = "created"
    REQUEST_SIGNED = "request_signed"
    TOKEN_ISSUED = "token_issued"
    CANCELLED = "cancelled"


@dataclass(frozen=True)
class TerminalIdentity:
    terminal_id: str
    allowed_audiences: frozenset[str]
    allowed_scopes: frozenset[str]
    allowed_assurance: frozenset[str] = field(default_factory=lambda: frozenset({"possession", "biometric"}))


@dataclass(frozen=True)
class Credential:
    credential_id: str
    issuer: str
    subject: str
    service_id: str
    profile: str
    public_key: str
    registered_at: int
    expires_at: int
    last_authenticated_at: int | None = None
    last_renewed_at: int | None = None
    key_version: int = 1
    revoked: bool = False


@dataclass
class Transaction:
    transaction_id: str
    terminal: TerminalIdentity
    audience: str
    scopes: tuple[str, ...]
    action: str
    assurance: str
    created_at: int
    expires_at: int
    state: TransactionState = TransactionState.CREATED
    request: AuthorizationRequest | None = None
    session: SessionBinding | None = None


@dataclass(frozen=True)
class Subject:
    issuer: str
    subject: str


@dataclass(frozen=True)
class IssuedToken:
    access_token: str
    token_type: str
    expires_in: int
    scope: str
