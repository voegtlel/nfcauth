from __future__ import annotations

from dataclasses import asdict
from typing import Any

import httpx
from cryptography.exceptions import InvalidSignature
from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field

from nfc_authenticator.protocol_v4 import AuthorizationAssertion, SessionBinding

from .models import TerminalIdentity
from .ports import TerminalAuthenticator
from .registration import RegistrationCoordinator
from .renewal import RenewalCoordinator
from .service import BridgeService
from .terminal_auth import TerminalAuthenticationError, TerminalAuthenticationUnavailable


class TransactionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    audience: str = Field(min_length=1, max_length=255)
    scopes: tuple[str, ...] = Field(min_length=1, max_length=32)
    action: str = Field(min_length=1, max_length=512)
    assurance: str


class SessionBindingBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    session_id: str
    phone_challenge: str
    terminal_ephemeral_public_key: str
    phone_ephemeral_public_key: str


class AssertionBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    protocol_version: int
    transaction_id: str
    request_hash: str
    service_id: str
    terminal_id: str
    credential_id: str
    assurance: str
    approved_at: int
    signature: str


class RegistrationStart(BaseModel):
    model_config = ConfigDict(extra="forbid")
    profile: str
    public_key: str


class RegistrationComplete(BaseModel):
    model_config = ConfigDict(extra="forbid")
    completion_code: str
    signature: str


class RenewalStart(BaseModel):
    model_config = ConfigDict(extra="forbid")
    credential_id: str = Field(min_length=16, max_length=255)


class RenewalComplete(BaseModel):
    model_config = ConfigDict(extra="forbid")
    signature: str = Field(min_length=1, max_length=2048)


def create_app(
    *,
    service: BridgeService,
    terminal_authenticator: TerminalAuthenticator,
    manifest: dict[str, Any],
    registrations: RegistrationCoordinator | None = None,
    renewals: RenewalCoordinator | None = None,
) -> FastAPI:
    app = FastAPI(
        title="NFC Auth Provider Bridge",
        version="4.0.0",
        docs_url="/docs",
        redoc_url=None,
    )

    bearer = HTTPBearer(auto_error=False)

    async def terminal(
        credentials: HTTPAuthorizationCredentials | None = Depends(bearer),  # noqa: B008
    ) -> TerminalIdentity:
        if credentials is None or credentials.scheme.lower() != "bearer":
            raise HTTPException(401, "Terminal bearer token is required", headers={"WWW-Authenticate": "Bearer"})
        try:
            return await terminal_authenticator.authenticate(credentials.credentials)
        except TerminalAuthenticationUnavailable as error:
            raise HTTPException(503, "Terminal authentication is temporarily unavailable") from error
        except TerminalAuthenticationError as error:
            raise HTTPException(401, "Invalid terminal bearer token", headers={"WWW-Authenticate": "Bearer"}) from error

    @app.get("/.well-known/nfc-authenticator")
    async def provider_manifest() -> dict[str, Any]:
        return await service.signer.sign_manifest(manifest)

    @app.get("/health/live")
    async def live() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/health/ready")
    async def ready() -> dict[str, str]:
        return {"status": "ready"}

    @app.get("/v1/jwks.json")
    async def jwks() -> dict:
        provider = getattr(service.issuer, "jwks", None)
        if provider is None:
            raise HTTPException(404, "This token issuer does not publish bridge keys")
        return provider()

    @app.post("/v1/transactions", status_code=201)
    async def create_transaction(
        body: TransactionCreate,
        identity: TerminalIdentity = Depends(terminal),  # noqa: B008
    ) -> dict:
        try:
            value = await service.create_transaction(
                identity, body.audience, body.scopes, body.action, body.assurance
            )
            return {"transaction_id": value.transaction_id, "expires_at": value.expires_at}
        except (ValueError, PermissionError) as error:
            raise HTTPException(403, str(error)) from error

    @app.post("/v1/transactions/{transaction_id}/bind-nfc-session")
    async def bind_session(
        transaction_id: str,
        body: SessionBindingBody,
        identity: TerminalIdentity = Depends(terminal),  # noqa: B008
    ) -> dict:
        try:
            return await service.bind_session(transaction_id, identity, SessionBinding(**body.model_dump()))
        except ValueError as error:
            raise HTTPException(409, str(error)) from error

    @app.post("/v1/transactions/{transaction_id}/complete")
    async def complete_transaction(
        transaction_id: str,
        body: AssertionBody,
        identity: TerminalIdentity = Depends(terminal),  # noqa: B008
    ) -> dict:
        if transaction_id != body.transaction_id:
            raise HTTPException(400, "Transaction ID does not match request body")
        try:
            token, registration_expires_at = await service.complete(
                transaction_id, identity, AuthorizationAssertion(**body.model_dump())
            )
            return {**asdict(token), "registration_expires_at": registration_expires_at}
        except InvalidSignature as error:
            raise HTTPException(403, "Invalid authorization signature") from error
        except PermissionError as error:
            raise HTTPException(403, str(error)) from error
        except (ValueError, TypeError) as error:
            raise HTTPException(409, str(error)) from error

    @app.post("/v1/transactions/{transaction_id}/bind-delivery-session")
    async def bind_delivery_session(
        transaction_id: str,
        body: SessionBindingBody,
        identity: TerminalIdentity = Depends(terminal),  # noqa: B008
    ) -> dict:
        try:
            return await service.bind_delivery_session(
                transaction_id, identity, SessionBinding(**body.model_dump())
            )
        except ValueError as error:
            raise HTTPException(409, str(error)) from error

    @app.post("/v1/registrations", status_code=201)
    async def start_registration(body: RegistrationStart) -> dict:
        if registrations is None:
            raise HTTPException(503, "Account-linking adapter is not configured")
        try:
            attempt, authorization_url = await registrations.start(body.profile, body.public_key)
            return {
                "registration_id": attempt.registration_id,
                "authorization_url": authorization_url,
                "expires_at": attempt.expires_at,
            }
        except ValueError as error:
            raise HTTPException(400, str(error)) from error

    @app.get("/v1/oidc/callback")
    async def oidc_callback(state: str = Query(), code: str = Query()):
        if registrations is None:
            raise HTTPException(503, "Account-linking adapter is not configured")
        try:
            attempt = await registrations.callback(state, code)
        except (ValueError, httpx.HTTPError) as error:
            raise HTTPException(400, "OIDC registration failed") from error
        target = (
            "nfcauth://registration-complete?registration_id="
            + attempt.registration_id
            + "&completion_code="
            + (attempt.completion_code or "")
        )
        return RedirectResponse(target, status_code=303)

    @app.post("/v1/registrations/{registration_id}/complete")
    async def complete_registration(registration_id: str, body: RegistrationComplete) -> dict:
        if registrations is None:
            raise HTTPException(503, "Account-linking adapter is not configured")
        try:
            credential = await registrations.complete(registration_id, body.completion_code, body.signature)
            return {
                "credential_id": credential.credential_id,
                "service_id": credential.service_id,
                "profile": credential.profile,
                "registration_expires_at": credential.expires_at,
            }
        except InvalidSignature as error:
            raise HTTPException(400, "Invalid registration signature") from error
        except (ValueError, TypeError) as error:
            raise HTTPException(400, "Registration completion failed") from error

    @app.post("/v1/registration-renewals", status_code=201)
    async def start_renewal(body: RenewalStart) -> dict:
        if renewals is None:
            raise HTTPException(503, "Registration renewal is not configured")
        try:
            attempt = await renewals.start(body.credential_id)
            return {"renewal": attempt.document()}
        except ValueError as error:
            raise HTTPException(404, "Registration is unavailable or expired") from error

    @app.post("/v1/registration-renewals/{renewal_id}/complete")
    async def complete_renewal(renewal_id: str, body: RenewalComplete) -> dict:
        if renewals is None:
            raise HTTPException(503, "Registration renewal is not configured")
        try:
            credential = await renewals.complete(renewal_id, body.signature)
            return {
                "credential_id": credential.credential_id,
                "registration_expires_at": credential.expires_at,
                "renewed_at": credential.last_renewed_at,
            }
        except InvalidSignature as error:
            raise HTTPException(400, "Invalid renewal signature") from error
        except (ValueError, TypeError) as error:
            raise HTTPException(400, "Registration renewal failed") from error

    return app
