from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from .app import create_app
from .config import BridgeSettings, load_manifest, load_terminals
from .database import SqlAlchemyEnrollmentStore
from .issuers import LocalJwtTokenIssuer, Rfc8693TokenIssuer
from .registration import GenericOidcIdentityProvider, RegistrationAttempts, RegistrationCoordinator
from .security import CertificateRequestSigner
from .service import BridgeService
from .stores import MemoryTransactionStore


def app_from_environment() -> FastAPI:
    settings = BridgeSettings()  # type: ignore[call-arg]
    manifest, manifest_hash = load_manifest(settings.manifest_path)
    enrollments = SqlAlchemyEnrollmentStore(settings.database_url)
    transactions = MemoryTransactionStore()
    signer = CertificateRequestSigner(settings.request_signing_key_path, settings.certificate_chain_path)
    token_key = settings.token_signing_key_path.read_bytes()
    if settings.token_exchange_endpoint:
        if not settings.token_exchange_client_id or not settings.token_exchange_client_secret:
            raise ValueError("Token exchange client credentials are required")
        issuer = Rfc8693TokenIssuer(
            settings.token_exchange_endpoint,
            settings.token_exchange_client_id,
            settings.token_exchange_client_secret,
            settings.service_origin,
            token_key,
        )
    else:
        issuer = LocalJwtTokenIssuer(settings.service_origin, token_key)
    service = BridgeService(
        settings.service_id,
        settings.service_origin,
        manifest_hash,
        transactions,
        enrollments,
        signer,
        issuer,
    )
    oidc = GenericOidcIdentityProvider(
        issuer=settings.oidc_issuer,
        authorization_endpoint=settings.oidc_authorization_endpoint,
        token_endpoint=settings.oidc_token_endpoint,
        jwks_uri=settings.oidc_jwks_uri,
        client_id=settings.oidc_client_id,
        client_secret=settings.oidc_client_secret,
        redirect_uri=settings.oidc_redirect_uri,
    )
    registrations = RegistrationCoordinator(
        settings.service_id,
        RegistrationAttempts(),
        enrollments,
        oidc,
    )
    app = create_app(
        service=service,
        terminals=load_terminals(settings.terminal_registry_path),
        manifest=manifest,
        registrations=registrations,
    )

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        await enrollments.initialize()
        yield
        await enrollments.close()

    app.router.lifespan_context = lifespan
    return app


app = app_from_environment()


def run() -> None:
    import uvicorn

    uvicorn.run(
        "nfc_authenticator.bridge.main:app",
        host="0.0.0.0",
        port=8080,
        proxy_headers=True,
        access_log=False,
    )
