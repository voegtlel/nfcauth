from __future__ import annotations

from sqlalchemy import BigInteger, Boolean, String, delete, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from .models import Credential


class Base(DeclarativeBase):
    pass


class CredentialRow(Base):
    __tablename__ = "nfc_credentials"

    credential_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    issuer: Mapped[str] = mapped_column(String(2048), nullable=False)
    subject: Mapped[str] = mapped_column(String(255), nullable=False)
    service_id: Mapped[str] = mapped_column(String(255), nullable=False)
    profile: Mapped[str] = mapped_column(String(32), nullable=False)
    public_key: Mapped[str] = mapped_column(String(2048), nullable=False)
    registered_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    expires_at: Mapped[int] = mapped_column(BigInteger, nullable=False, index=True)
    last_authenticated_at: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    last_renewed_at: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class SqlAlchemyEnrollmentStore:
    def __init__(self, database_url: str) -> None:
        self.engine = create_async_engine(database_url, pool_pre_ping=True)
        self.sessions = async_sessionmaker(self.engine, expire_on_commit=False, class_=AsyncSession)

    async def initialize(self) -> None:
        async with self.engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)

    async def close(self) -> None:
        await self.engine.dispose()

    async def get_credential(self, credential_id: str) -> Credential | None:
        async with self.sessions() as session:
            row = await session.get(CredentialRow, credential_id)
            return None if row is None else _credential(row)

    async def save_credential(self, credential: Credential) -> None:
        async with self.sessions() as session, session.begin():
            existing = await session.get(CredentialRow, credential.credential_id)
            if existing is not None:
                raise ValueError("Credential already exists")
            session.add(CredentialRow(**credential.__dict__))

    async def revoke_credential(self, credential_id: str) -> bool:
        async with self.sessions() as session, session.begin():
            result = await session.execute(
                update(CredentialRow)
                .where(CredentialRow.credential_id == credential_id, CredentialRow.revoked.is_(False))
                .values(revoked=True)
            )
            return bool(result.rowcount)

    async def renew_credential(
        self,
        credential_id: str,
        *,
        now: int,
        expires_at: int,
        authenticated: bool,
    ) -> Credential | None:
        values = {"expires_at": expires_at}
        values["last_authenticated_at" if authenticated else "last_renewed_at"] = now
        async with self.sessions() as session, session.begin():
            result = await session.execute(
                update(CredentialRow)
                .where(
                    CredentialRow.credential_id == credential_id,
                    CredentialRow.revoked.is_(False),
                    CredentialRow.expires_at > now,
                )
                .values(**values)
            )
            if not result.rowcount:
                return None
            row = await session.get(CredentialRow, credential_id)
            return None if row is None else _credential(row)

    async def purge_expired_credentials(self, cutoff: int) -> int:
        async with self.sessions() as session, session.begin():
            result = await session.execute(delete(CredentialRow).where(CredentialRow.expires_at <= cutoff))
            return int(result.rowcount or 0)


def _credential(row: CredentialRow) -> Credential:
    return Credential(
        row.credential_id,
        row.issuer,
        row.subject,
        row.service_id,
        row.profile,
        row.public_key,
        row.registered_at,
        row.expires_at,
        row.last_authenticated_at,
        row.last_renewed_at,
        row.revoked,
    )
