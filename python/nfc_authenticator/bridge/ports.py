from __future__ import annotations

from datetime import timedelta
from typing import Protocol

from nfc_authenticator.protocol_v4 import AssertionDeliveryRequest, AuthorizationRequest

from .models import Credential, IssuedToken, Subject, TerminalIdentity, Transaction


class EnrollmentStore(Protocol):
    async def get_credential(self, credential_id: str) -> Credential | None: ...

    async def save_credential(self, credential: Credential) -> None: ...

    async def revoke_credential(self, credential_id: str) -> bool: ...

    async def renew_credential(
        self,
        credential_id: str,
        *,
        now: int,
        expires_at: int,
        authenticated: bool,
    ) -> Credential | None: ...

    async def purge_expired_credentials(self, cutoff: int) -> int: ...


class TransactionStore(Protocol):
    async def create(self, transaction: Transaction) -> None: ...

    async def get(self, transaction_id: str) -> Transaction | None: ...

    async def update(self, transaction: Transaction) -> None: ...

    async def consume(self, transaction_id: str) -> Transaction: ...


class RequestSigner(Protocol):
    async def sign(self, request: AuthorizationRequest | AssertionDeliveryRequest) -> dict: ...

    async def sign_manifest(self, manifest: dict) -> dict: ...


class TokenIssuer(Protocol):
    async def issue(
        self,
        subject: Subject,
        terminal: TerminalIdentity,
        audience: str,
        scopes: tuple[str, ...],
        assurance: str,
        transaction_id: str,
        lifetime: timedelta,
    ) -> IssuedToken: ...


class TerminalAuthenticator(Protocol):
    async def authenticate(self, access_token: str) -> TerminalIdentity: ...

    async def close(self) -> None: ...


class IdentityProvider(Protocol):
    async def authorization_url(self, registration_id: str, state: str) -> str: ...

    async def complete(self, code: str, state: str) -> Subject: ...
