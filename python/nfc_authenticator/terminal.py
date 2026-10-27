"""Reader-neutral terminal orchestration for NFC Auth v4."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import urlsplit

import httpx

from .protocol_v4 import AuthorizationAssertion, SessionBinding


class PhoneChannel(Protocol):
    """Application-protocol boundary implemented on top of any NFC reader SDK."""

    async def wait_for_phone(self) -> None: ...

    async def begin_encrypted_session(self) -> SessionBinding: ...

    async def deliver_authorization(self, signed_request: dict[str, Any]) -> AuthorizationAssertion | None:
        """Return an immediate possession assertion, or None when user confirmation is pending."""

    async def fetch_approved_assertion(self, signed_delivery_request: dict[str, Any]) -> AuthorizationAssertion: ...

    async def close(self) -> None: ...


@dataclass(frozen=True)
class TerminalToken:
    access_token: str
    token_type: str
    expires_in: int
    scope: str


def validate_protected_api_url(
    url: str,
    *,
    allowed_insecure_origins: tuple[str, ...] = (),
) -> str:
    """Reject bearer-token destinations without TLS or an explicit local exception.

    Loopback HTTP is suitable for a same-host resource server. Other HTTP
    origins must be allowlisted exactly and are intended only for deployments
    where a service mesh or equivalent authenticated transport protects the hop.
    """
    parsed = urlsplit(url)
    if parsed.username is not None or parsed.password is not None or parsed.hostname is None:
        raise ValueError("Protected API URL must have a host and no user information")
    if parsed.scheme == "https":
        return url
    if parsed.scheme != "http":
        raise ValueError("Protected API URL must use HTTPS")

    hostname = parsed.hostname.lower()
    is_loopback = hostname == "localhost"
    try:
        is_loopback = is_loopback or ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        pass
    if is_loopback:
        return url

    origin = f"http://{parsed.netloc.lower()}"
    allowed = {value.rstrip("/").lower() for value in allowed_insecure_origins}
    if origin not in allowed:
        raise ValueError(
            "Plain HTTP is allowed only for loopback or an exact origin in "
            "NFCAUTH_TERMINAL_INSECURE_HTTP_ORIGINS",
        )
    return url


class BridgeClient:
    def __init__(
        self,
        base_url: str,
        terminal_id: str,
        *,
        certificate: tuple[str, str] | None = None,
        development_certificate_fingerprint: str | None = None,
        timeout_seconds: float = 5.0,
    ) -> None:
        if not base_url.startswith("https://"):
            raise ValueError("Bridge URL must use HTTPS")
        self.base_url = base_url.rstrip("/")
        self.terminal_id = terminal_id
        self.headers = {"X-NFCAuth-Terminal-ID": terminal_id, "Accept": "application/json"}
        # Production reverse proxies strip this header and inject the verified
        # client-certificate fingerprint. This option is for local development.
        if development_certificate_fingerprint:
            self.headers["X-NFCAuth-Terminal-Cert-SHA256"] = development_certificate_fingerprint
        self.client = httpx.AsyncClient(
            base_url=self.base_url,
            headers=self.headers,
            cert=certificate,
            timeout=timeout_seconds,
        )

    async def create_transaction(self, audience: str, scopes: tuple[str, ...], action: str, assurance: str) -> dict:
        response = await self.client.post(
            "/v1/transactions",
            json={"audience": audience, "scopes": scopes, "action": action, "assurance": assurance},
        )
        response.raise_for_status()
        return response.json()

    async def bind_session(self, transaction_id: str, session: SessionBinding, *, delivery: bool = False) -> dict:
        suffix = "bind-delivery-session" if delivery else "bind-nfc-session"
        response = await self.client.post(
            f"/v1/transactions/{transaction_id}/{suffix}",
            json=session.__dict__,
        )
        response.raise_for_status()
        return response.json()

    async def complete(self, transaction_id: str, assertion: AuthorizationAssertion) -> TerminalToken:
        response = await self.client.post(
            f"/v1/transactions/{transaction_id}/complete",
            json=assertion.__dict__,
        )
        response.raise_for_status()
        return TerminalToken(**response.json())

    async def close(self) -> None:
        await self.client.aclose()


class TerminalController:
    def __init__(self, bridge: BridgeClient, phone: PhoneChannel) -> None:
        self.bridge = bridge
        self.phone = phone

    async def authorize(
        self,
        *,
        audience: str,
        scopes: tuple[str, ...],
        action: str,
        assurance: str,
    ) -> TerminalToken:
        transaction = await self.bridge.create_transaction(audience, scopes, action, assurance)
        transaction_id = transaction["transaction_id"]

        await self.phone.wait_for_phone()
        first_session = await self.phone.begin_encrypted_session()
        signed_request = await self.bridge.bind_session(transaction_id, first_session)
        assertion = await self.phone.deliver_authorization(signed_request)

        if assertion is None:
            # The phone is intentionally free to leave the NFC field while the
            # user reviews and signs the request with an auth-per-use key.
            await self.phone.wait_for_phone()
            second_session = await self.phone.begin_encrypted_session()
            delivery = await self.bridge.bind_session(transaction_id, second_session, delivery=True)
            assertion = await self.phone.fetch_approved_assertion(delivery)

        return await self.bridge.complete(transaction_id, assertion)

    async def close(self) -> None:
        await self.phone.close()
        await self.bridge.close()
