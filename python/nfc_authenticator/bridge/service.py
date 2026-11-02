from __future__ import annotations

import secrets
import time
from datetime import timedelta

from nfc_authenticator.protocol_v4 import (
    AssertionDeliveryRequest,
    AuthorizationAssertion,
    AuthorizationRequest,
    SessionBinding,
)

from .models import Subject, TerminalIdentity, Transaction, TransactionState
from .ports import EnrollmentStore, RequestSigner, TokenIssuer, TransactionStore


class BridgeService:
    def __init__(
        self,
        service_id: str,
        service_origin: str,
        manifest_hash: str,
        transactions: TransactionStore,
        enrollments: EnrollmentStore,
        signer: RequestSigner,
        issuer: TokenIssuer,
        *,
        credential_lifetime_seconds: int = 548 * 86400,
        clock=time.time,
    ) -> None:
        self.service_id = service_id
        self.service_origin = service_origin.rstrip("/")
        self.manifest_hash = manifest_hash
        self.transactions = transactions
        self.enrollments = enrollments
        self.signer = signer
        self.issuer = issuer
        self.credential_lifetime_seconds = credential_lifetime_seconds
        self.clock = clock

    async def create_transaction(
        self,
        terminal: TerminalIdentity,
        audience: str,
        scopes: tuple[str, ...],
        action: str,
        assurance: str,
    ) -> Transaction:
        requested = frozenset(scopes)
        if audience not in terminal.allowed_audiences or not requested <= terminal.allowed_scopes:
            raise PermissionError("Terminal is not authorized for the requested audience or scopes")
        if assurance not in terminal.allowed_assurance:
            raise PermissionError("Terminal is not authorized for this assurance profile")
        now = int(self.clock())
        transaction = Transaction(
            secrets.token_urlsafe(24), terminal, audience, tuple(sorted(requested)), action, assurance, now, now + 120
        )
        await self.transactions.create(transaction)
        return transaction

    async def bind_session(self, transaction_id: str, terminal: TerminalIdentity, session: SessionBinding) -> dict:
        transaction = await self.transactions.get(transaction_id)
        if transaction is None or transaction.terminal != terminal or transaction.state != TransactionState.CREATED:
            raise ValueError("Transaction is unavailable")
        now = int(self.clock())
        request = AuthorizationRequest(
            transaction_id=transaction.transaction_id,
            service_id=self.service_id,
            service_origin=self.service_origin,
            manifest_hash=self.manifest_hash,
            terminal_id=terminal.terminal_id,
            audience=transaction.audience,
            scopes=transaction.scopes,
            action=transaction.action,
            assurance=transaction.assurance,
            issued_at=now,
            expires_at=min(transaction.expires_at, now + 120),
            session=session,
        )
        request.validate(now=now)
        transaction.request = request
        transaction.session = session
        transaction.state = TransactionState.REQUEST_SIGNED
        await self.transactions.update(transaction)
        return await self.signer.sign(request)

    async def complete(
        self, transaction_id: str, terminal: TerminalIdentity, assertion: AuthorizationAssertion
    ):
        transaction = await self.transactions.consume(transaction_id)
        request = transaction.request
        if request is None or transaction.terminal != terminal:
            raise ValueError("Transaction terminal does not match")
        now = int(self.clock())
        credential = await self.enrollments.get_credential(assertion.credential_id)
        if credential is None or credential.revoked or credential.expires_at <= now:
            raise PermissionError("Credential is unknown, revoked, or expired")
        if credential.service_id != self.service_id or credential.profile != transaction.assurance:
            raise PermissionError("Credential is not valid for this service or profile")
        assertion.verify(credential.public_key, request, now=now)
        token = await self.issuer.issue(
            Subject(credential.issuer, credential.subject),
            terminal,
            transaction.audience,
            transaction.scopes,
            transaction.assurance,
            transaction.transaction_id,
            timedelta(minutes=10),
        )
        renewed = await self.enrollments.renew_credential(
            credential.credential_id,
            now=now,
            expires_at=now + self.credential_lifetime_seconds,
            authenticated=True,
        )
        if renewed is None:
            raise PermissionError("Credential could not be extended after authentication")
        return token, renewed.expires_at

    async def bind_delivery_session(
        self, transaction_id: str, terminal: TerminalIdentity, session: SessionBinding
    ) -> dict:
        transaction = await self.transactions.get(transaction_id)
        if (
            transaction is None
            or transaction.terminal != terminal
            or transaction.state != TransactionState.REQUEST_SIGNED
            or transaction.request is None
        ):
            raise ValueError("Transaction is unavailable for assertion delivery")
        now = int(self.clock())
        delivery = AssertionDeliveryRequest(
            transaction.transaction_id,
            transaction.request.request_hash,
            self.service_id,
            self.service_origin,
            terminal.terminal_id,
            now,
            min(transaction.expires_at, now + 30),
            session,
        )
        delivery.validate(now=now)
        return await self.signer.sign(delivery)
