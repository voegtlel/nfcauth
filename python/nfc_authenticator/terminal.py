"""Reader-neutral terminal orchestration for NFC Auth v4."""

from __future__ import annotations

import asyncio
import ipaddress
import time
from dataclasses import dataclass
from collections.abc import Mapping
from typing import Any, Protocol, cast
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


class AccessTokenProvider(Protocol):
    async def get_access_token(self) -> str: ...

    async def close(self) -> None: ...


class OAuthClientCredentialsTokenProvider:
    """Obtain and cache an OAuth client-credentials token in process memory only."""

    def __init__(
        self,
        token_endpoint: str,
        client_id: str,
        *,
        scope: str,
        client_secret: str | None = None,
        username: str | None = None,
        password: str | None = None,
        timeout_seconds: float = 5.0,
    ) -> None:
        if not token_endpoint.startswith("https://"):
            raise ValueError("OAuth token endpoint must use HTTPS")
        if not client_id or not scope:
            raise ValueError("OAuth client ID and scope must be nonempty")
        uses_secret = client_secret is not None
        uses_user = username is not None or password is not None
        if uses_secret == uses_user or uses_user and (not username or not password):
            raise ValueError("Provide either client_secret or both username and password")
        self.token_endpoint = token_endpoint
        self.client_id = client_id
        self.scope = scope
        self.client_secret = client_secret
        self.username = username
        self.password = password
        self.client = httpx.AsyncClient(timeout=timeout_seconds, headers={"Accept": "application/json"})
        self._access_token = ""
        self._refresh_at = 0.0
        self._lock = asyncio.Lock()

    async def get_access_token(self) -> str:
        now = time.monotonic()
        if self._access_token and now < self._refresh_at:
            return self._access_token
        async with self._lock:
            now = time.monotonic()
            if self._access_token and now < self._refresh_at:
                return self._access_token
            data = {
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "scope": self.scope,
            }
            if self.client_secret is not None:
                data["client_secret"] = self.client_secret
            else:
                data["username"] = self.username or ""
                data["password"] = self.password or ""
            response = await self.client.post(self.token_endpoint, data=data)
            response.raise_for_status()
            value = response.json()
            if not isinstance(value, dict):
                raise ValueError("OAuth token response must be a JSON object")
            access_token = value.get("access_token")
            token_type = value.get("token_type", "Bearer")
            expires_in = int(value.get("expires_in", 0))
            if (
                not isinstance(access_token, str)
                or not access_token
                or len(access_token) > 16 * 1024
                or not isinstance(token_type, str)
                or token_type.lower() != "bearer"
                or expires_in <= 0
            ):
                raise ValueError("OAuth token response is invalid")
            refresh_margin = min(30, max(1, expires_in // 10))
            self._access_token = access_token
            self._refresh_at = now + max(1, expires_in - refresh_margin)
            return access_token

    async def close(self) -> None:
        self._access_token = ""
        self._refresh_at = 0.0
        await self.client.aclose()


@dataclass(frozen=True)
class TerminalToken:
    access_token: str
    token_type: str
    expires_in: int
    scope: str
    registration_expires_at: int | None = None


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
        token_provider: AccessTokenProvider,
        *,
        timeout_seconds: float = 5.0,
    ) -> None:
        if not base_url.startswith("https://"):
            raise ValueError("Bridge URL must use HTTPS")
        self.base_url = base_url.rstrip("/")
        self.token_provider = token_provider
        self.client = httpx.AsyncClient(
            base_url=self.base_url,
            headers={"Accept": "application/json"},
            timeout=timeout_seconds,
        )

    async def _post(self, path: str, value: Mapping[str, Any]) -> httpx.Response:
        access_token = await self.token_provider.get_access_token()
        return await self.client.post(path, json=value, headers={"Authorization": f"Bearer {access_token}"})

    @staticmethod
    def _json_object(response: httpx.Response) -> dict[str, Any]:
        value = response.json()
        if not isinstance(value, dict):
            raise ValueError("Bridge response must be a JSON object")
        return cast(dict[str, Any], value)

    async def create_transaction(
        self, audience: str, scopes: tuple[str, ...], action: str, assurance: str
    ) -> dict[str, Any]:
        response = await self._post(
            "/v1/transactions",
            {"audience": audience, "scopes": scopes, "action": action, "assurance": assurance},
        )
        response.raise_for_status()
        return self._json_object(response)

    async def bind_session(
        self, transaction_id: str, session: SessionBinding, *, delivery: bool = False
    ) -> dict[str, Any]:
        suffix = "bind-delivery-session" if delivery else "bind-nfc-session"
        response = await self._post(
            f"/v1/transactions/{transaction_id}/{suffix}",
            session.__dict__,
        )
        response.raise_for_status()
        return self._json_object(response)

    async def complete(self, transaction_id: str, assertion: AuthorizationAssertion) -> TerminalToken:
        response = await self._post(
            f"/v1/transactions/{transaction_id}/complete",
            assertion.__dict__,
        )
        response.raise_for_status()
        return TerminalToken(**self._json_object(response))

    async def close(self) -> None:
        await self.client.aclose()
        await self.token_provider.close()


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
