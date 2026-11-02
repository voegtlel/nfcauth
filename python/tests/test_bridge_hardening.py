from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock

import pytest
from cryptography.exceptions import InvalidSignature
from fastapi.testclient import TestClient

from nfc_authenticator.bridge.app import create_app
from nfc_authenticator.bridge.models import TerminalIdentity, Transaction, TransactionState
from nfc_authenticator.bridge.stores import MemoryTransactionStore


def transaction(identifier: str, terminal_id: str = "terminal-1", expires_at: int = 200) -> Transaction:
    return Transaction(
        identifier, TerminalIdentity(terminal_id, frozenset({"api"}), frozenset({"read"})),
        "api", ("read",), "Read", "possession", 100, expires_at,
    )


@pytest.mark.asyncio
async def test_transaction_limits_and_global_expiry_pruning() -> None:
    now = 100
    store = MemoryTransactionStore(maximum_entries=2, maximum_per_terminal=1, clock=lambda: now)
    await store.create(transaction("one"))
    with pytest.raises(ValueError, match="Terminal transaction capacity"):
        await store.create(transaction("two"))
    await store.create(transaction("two", "terminal-2"))
    with pytest.raises(ValueError, match="Transaction capacity"):
        await store.create(transaction("three", "terminal-3"))
    now = 200
    # Creating a different transaction reclaims all abandoned expired entries.
    await store.create(transaction("three", "terminal-3", 300))
    assert await store.get("one") is None
    assert await store.get("two") is None
    assert await store.get("three") is not None
    now = 300
    await store.prune_expired()
    assert not store._transactions


@pytest.mark.asyncio
async def test_concurrent_create_cannot_exceed_terminal_quota() -> None:
    store = MemoryTransactionStore(maximum_per_terminal=1, clock=lambda: 100)
    results = await asyncio.gather(
        *(store.create(transaction(str(index))) for index in range(20)), return_exceptions=True,
    )
    assert sum(result is None for result in results) == 1
    assert sum(isinstance(result, ValueError) for result in results) == 19


@pytest.mark.asyncio
async def test_concurrent_consume_is_one_use() -> None:
    store = MemoryTransactionStore(clock=lambda: 100)
    value = transaction("one")
    value.state = TransactionState.REQUEST_SIGNED
    await store.create(value)
    results = await asyncio.gather(*(store.consume("one") for _ in range(20)), return_exceptions=True)
    assert sum(isinstance(result, Transaction) for result in results) == 1
    assert sum(isinstance(result, ValueError) for result in results) == 19


@pytest.mark.parametrize("endpoint,body,status", [
    ("/v1/registrations/registration-id/complete", {"completion_code": "code", "signature": "bad"}, 400),
    ("/v1/registration-renewals/renewal-id/complete", {"signature": "bad"}, 400),
    ("/v1/transactions/transaction-id/complete", {
        "protocol_version": 4, "transaction_id": "transaction-id", "request_hash": "hash",
        "service_id": "example", "terminal_id": "terminal-1", "credential_id": "credential-id",
        "assurance": "possession", "approved_at": 100, "signature": "bad",
    }, 403),
])
def test_invalid_signature_is_controlled_http_rejection(endpoint, body, status) -> None:
    # Exercise the API boundary with the exact exception raised by cryptography.
    service = AsyncMock()
    registrations = AsyncMock()
    renewals = AsyncMock()
    for coordinator in (service, registrations, renewals):
        coordinator.complete.side_effect = InvalidSignature()
    authenticator = AsyncMock()
    authenticator.authenticate.return_value = transaction("one").terminal
    client = TestClient(create_app(
        service=service, terminal_authenticator=authenticator, manifest={},
        registrations=registrations, renewals=renewals,
    ))
    response = client.post(endpoint, json=body, headers={"Authorization": "Bearer test-token"})
    assert response.status_code == status
    assert "signature" in response.json()["detail"].lower()
