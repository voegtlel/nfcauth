from __future__ import annotations

import asyncio
import time
from collections.abc import Mapping
from typing import Any, cast

import httpx
import jwt

from .models import TerminalIdentity


class TerminalAuthenticationError(ValueError):
    """The supplied bearer token cannot authenticate an authorized terminal."""


class TerminalAuthenticationUnavailable(RuntimeError):
    """The configured identity provider cannot currently validate terminal tokens."""


class OidcTerminalAuthenticator:
    """Validate short-lived OAuth/OIDC bearer tokens and derive terminal identity from ``sub``."""

    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        jwks_uri: str,
        terminals: Mapping[str, TerminalIdentity],
        required_scope: str = "nfcauth:terminal",
        allowed_algorithms: tuple[str, ...] = ("RS256", "ES256"),
        maximum_token_lifetime_seconds: int = 600,
        jwks_cache_seconds: int = 300,
        timeout_seconds: float = 5.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        if not issuer.startswith("https://") or not jwks_uri.startswith("https://"):
            raise ValueError("Terminal token issuer and JWKS endpoint must use HTTPS")
        if not audience or not required_scope:
            raise ValueError("Terminal token audience and required scope must be nonempty")
        if not allowed_algorithms or not set(allowed_algorithms) <= {"RS256", "ES256"}:
            raise ValueError("Terminal token algorithms must be an explicit RS256/ES256 allowlist")
        if maximum_token_lifetime_seconds < 60:
            raise ValueError("Terminal token maximum lifetime is too short")
        # OIDC issuer identifiers are exact, including a possible trailing slash.
        # Authentik commonly emits one, so normalizing it would reject valid tokens.
        self.issuer = issuer
        self.audience = audience
        self.jwks_uri = jwks_uri
        self.terminals = dict(terminals)
        self.required_scope = required_scope
        self.allowed_algorithms = allowed_algorithms
        self.maximum_token_lifetime_seconds = maximum_token_lifetime_seconds
        self.jwks_cache_seconds = jwks_cache_seconds
        self._client = client or httpx.AsyncClient(timeout=timeout_seconds, headers={"Accept": "application/json"})
        self._owns_client = client is None
        self._keys: tuple[dict[str, Any], ...] = ()
        self._keys_expire_at = 0.0
        self._keys_fetched_at = 0.0
        self._lock = asyncio.Lock()

    async def authenticate(self, access_token: str) -> TerminalIdentity:
        if not access_token or len(access_token) > 16 * 1024:
            raise TerminalAuthenticationError("Invalid terminal bearer token")
        try:
            header = jwt.get_unverified_header(access_token)
            algorithm = header.get("alg")
            key_id = header.get("kid")
            if not isinstance(algorithm, str) or algorithm not in self.allowed_algorithms:
                raise TerminalAuthenticationError("Invalid terminal bearer token")
            if not isinstance(key_id, str) or not key_id:
                raise TerminalAuthenticationError("Invalid terminal bearer token")
            candidates = self._matching_keys(await self._jwks(), key_id, algorithm)
            if len(candidates) != 1:
                candidates = self._matching_keys(await self._jwks(force=True), key_id, algorithm)
            if len(candidates) != 1:
                raise TerminalAuthenticationError("Terminal signing key is unavailable or ambiguous")
            key = jwt.PyJWK.from_dict(candidates[0]).key
            claims = jwt.decode(
                access_token,
                key,
                algorithms=[algorithm],
                audience=self.audience,
                issuer=self.issuer,
                leeway=30,
                options={"require": ["iss", "sub", "aud", "exp", "iat"]},
            )
            issued_at = int(claims["iat"])
            expires_at = int(claims["exp"])
            if expires_at <= issued_at or expires_at - issued_at > self.maximum_token_lifetime_seconds:
                raise TerminalAuthenticationError("Terminal bearer token lifetime is invalid")
            scopes = self._scopes(claims.get("scope", ""))
            if self.required_scope not in scopes:
                raise TerminalAuthenticationError("Terminal bearer token lacks the required scope")
            subject = claims["sub"]
            if not isinstance(subject, str) or not subject:
                raise TerminalAuthenticationError("Terminal bearer token subject is invalid")
            terminal = self.terminals.get(subject)
            if terminal is None:
                raise TerminalAuthenticationError("Terminal is not provisioned")
            return terminal
        except TerminalAuthenticationError:
            raise
        except (jwt.PyJWTError, KeyError, TypeError, ValueError) as error:
            raise TerminalAuthenticationError("Invalid terminal bearer token") from error

    async def close(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def _jwks(self, *, force: bool = False) -> tuple[dict[str, Any], ...]:
        now = time.monotonic()
        if not force and self._keys and now < self._keys_expire_at:
            return self._keys
        async with self._lock:
            now = time.monotonic()
            if not force and self._keys and now < self._keys_expire_at:
                return self._keys
            if force and self._keys and now - self._keys_fetched_at < 30:
                return self._keys
            try:
                response = await self._client.get(self.jwks_uri)
                response.raise_for_status()
                if len(response.content) > 256 * 1024:
                    raise ValueError("JWKS document is too large")
                document = response.json()
                if not isinstance(document, dict):
                    raise ValueError("JWKS document is invalid")
                keys = document.get("keys")
                if not isinstance(keys, list) or not keys or len(keys) > 64 or not all(isinstance(key, dict) for key in keys):
                    raise ValueError("JWKS document is invalid")
            except (httpx.HTTPError, KeyError, TypeError, ValueError) as error:
                raise TerminalAuthenticationUnavailable("Terminal identity provider is unavailable") from error
            self._keys = tuple(cast(dict[str, Any], key) for key in keys)
            self._keys_fetched_at = now
            self._keys_expire_at = now + self.jwks_cache_seconds
            return self._keys

    @staticmethod
    def _matching_keys(
        keys: tuple[dict[str, Any], ...], key_id: str, algorithm: str
    ) -> list[dict[str, Any]]:
        return [
            key
            for key in keys
            if key.get("kid") == key_id
            and key.get("alg", algorithm) == algorithm
            and key.get("use", "sig") == "sig"
            and "verify" in key.get("key_ops", ["verify"])
        ]

    @staticmethod
    def _scopes(value: object) -> frozenset[str]:
        if isinstance(value, str):
            return frozenset(value.split())
        if isinstance(value, list) and all(isinstance(scope, str) for scope in value):
            return frozenset(value)
        raise TerminalAuthenticationError("Terminal bearer token scope is invalid")
