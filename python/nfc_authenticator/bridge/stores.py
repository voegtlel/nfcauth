from __future__ import annotations

import asyncio
import time

from .models import Credential, Transaction, TransactionState


class MemoryEnrollmentStore:
    """Test/development store. Production deployments use an adapter with durable storage."""

    def __init__(self) -> None:
        self._credentials: dict[str, Credential] = {}
        self._lock = asyncio.Lock()

    async def get_credential(self, credential_id: str) -> Credential | None:
        async with self._lock:
            return self._credentials.get(credential_id)

    async def save_credential(self, credential: Credential) -> None:
        async with self._lock:
            if credential.credential_id in self._credentials:
                raise ValueError("Credential already exists")
            self._credentials[credential.credential_id] = credential

    async def revoke_credential(self, credential_id: str) -> bool:
        async with self._lock:
            current = self._credentials.get(credential_id)
            if current is None:
                return False
            self._credentials[credential_id] = Credential(**{**current.__dict__, "revoked": True})
            return True

    async def renew_credential(
        self,
        credential_id: str,
        *,
        now: int,
        expires_at: int,
        authenticated: bool,
    ) -> Credential | None:
        async with self._lock:
            current = self._credentials.get(credential_id)
            if current is None or current.revoked or current.expires_at <= now:
                return None
            values = {**current.__dict__, "expires_at": expires_at}
            values["last_authenticated_at" if authenticated else "last_renewed_at"] = now
            renewed = Credential(**values)
            self._credentials[credential_id] = renewed
            return renewed

    async def purge_expired_credentials(self, cutoff: int) -> int:
        async with self._lock:
            expired = [key for key, value in self._credentials.items() if value.expires_at <= cutoff]
            for key in expired:
                del self._credentials[key]
            return len(expired)


class MemoryTransactionStore:
    """One-use transient transaction store with process-local state only."""

    def __init__(self) -> None:
        self._transactions: dict[str, Transaction] = {}
        self._lock = asyncio.Lock()

    async def create(self, transaction: Transaction) -> None:
        async with self._lock:
            if transaction.transaction_id in self._transactions:
                raise ValueError("Transaction already exists")
            self._transactions[transaction.transaction_id] = transaction

    async def get(self, transaction_id: str) -> Transaction | None:
        async with self._lock:
            value = self._transactions.get(transaction_id)
            if value is not None and value.expires_at <= int(time.time()):
                self._transactions.pop(transaction_id, None)
                return None
            return value

    async def update(self, transaction: Transaction) -> None:
        async with self._lock:
            current = self._transactions.get(transaction.transaction_id)
            if current is None or current.state in {TransactionState.TOKEN_ISSUED, TransactionState.CANCELLED}:
                raise ValueError("Transaction is unavailable")
            self._transactions[transaction.transaction_id] = transaction

    async def consume(self, transaction_id: str) -> Transaction:
        async with self._lock:
            value = self._transactions.pop(transaction_id, None)
            if value is None or value.expires_at <= int(time.time()):
                raise ValueError("Transaction is unavailable or expired")
            if value.state != TransactionState.REQUEST_SIGNED:
                raise ValueError("Transaction is not ready for completion")
            return value
