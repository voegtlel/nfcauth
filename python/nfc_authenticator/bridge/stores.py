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

    def __init__(self, *, maximum_entries: int = 4096, maximum_per_terminal: int = 64, clock=time.time) -> None:
        if maximum_entries < 1 or maximum_per_terminal < 1:
            raise ValueError("Transaction capacity must be positive")
        self.maximum_entries = maximum_entries
        self.maximum_per_terminal = maximum_per_terminal
        self.clock = clock
        self._transactions: dict[str, Transaction] = {}
        self._lock = asyncio.Lock()

    def _prune(self) -> None:
        now = int(self.clock())
        for key in [key for key, value in self._transactions.items() if value.expires_at <= now]:
            del self._transactions[key]

    async def prune_expired(self) -> None:
        async with self._lock:
            self._prune()

    async def create(self, transaction: Transaction) -> None:
        async with self._lock:
            self._prune()
            if transaction.transaction_id in self._transactions:
                raise ValueError("Transaction already exists")
            if len(self._transactions) >= self.maximum_entries:
                raise ValueError("Transaction capacity reached")
            terminal_count = sum(
                value.terminal.terminal_id == transaction.terminal.terminal_id
                for value in self._transactions.values()
            )
            if terminal_count >= self.maximum_per_terminal:
                raise ValueError("Terminal transaction capacity reached")
            if transaction.expires_at <= int(self.clock()):
                raise ValueError("Transaction is expired")
            self._transactions[transaction.transaction_id] = transaction

    async def get(self, transaction_id: str) -> Transaction | None:
        async with self._lock:
            self._prune()
            return self._transactions.get(transaction_id)

    async def update(self, transaction: Transaction) -> None:
        async with self._lock:
            self._prune()
            current = self._transactions.get(transaction.transaction_id)
            if current is None or current.state in {TransactionState.TOKEN_ISSUED, TransactionState.CANCELLED}:
                raise ValueError("Transaction is unavailable")
            self._transactions[transaction.transaction_id] = transaction

    async def consume(self, transaction_id: str) -> Transaction:
        async with self._lock:
            self._prune()
            value = self._transactions.pop(transaction_id, None)
            if value is None:
                raise ValueError("Transaction is unavailable or expired")
            if value.state != TransactionState.REQUEST_SIGNED:
                raise ValueError("Transaction is not ready for completion")
            return value
