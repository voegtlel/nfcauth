"""Reference reader/service implementation for the privacy-aware NFC protocol."""

from __future__ import annotations

import argparse
import base64
import json
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Literal

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .backend import ReferenceBackend
from .discovery import PURPOSE_DISCOVERY
from .protocol_crypto import NfcSession, ProtocolCryptoError, SessionInitiator
from .service_crypto import (
    decrypt_registration_response,
    encrypt_registration_acknowledgement,
)
from .service_manifest import (
    FIELD_ALIAS,
    FIELD_AUTHENTICATION_PUBLIC_KEY,
    FIELD_SERVICE_USER_ID,
    ServiceIdentity,
    ServicePrivacyConfig,
    manifest_hash,
)
from .storage import RegisteredDevice as RegisteredDevice  # noqa: PLC0414 - compatibility re-export.
from .storage import SQLiteStore as AuthDatabase

SELECT_APPLICATION = b"\x00\xa4\x04\x00"
SESSION_INIT = b"\xd0\x00\x00\x00"
REGISTRATION = b"\xd0\x01\x00\x00"
AUTHENTICATION = b"\xd0\x02\x00\x00"
REGISTRATION_COMPLETE = b"\xd0\x04\x00\x00"
DISCOVERY = b"\xd0\x05\x00\x00"
GET_RESPONSE = b"\x00\xc0\x00\x00"
SUCCESS = b"\x90\x00"
MORE_DATA = 0x61
MAX_COMMAND_DATA = 249

PURPOSE_REGISTRATION = "registration"
PURPOSE_AUTHENTICATION = "authentication"
PURPOSE_REGISTRATION_COMPLETE = "registration-complete"

logger = logging.getLogger(__name__)


class NFCReaderException(Exception):
    """A protocol, transport, or validation operation failed."""


@dataclass(frozen=True)
class ReaderConfig:
    privacy: ServicePrivacyConfig
    auth: Literal["background", "biometric"]
    aid: bytes = bytes.fromhex("F064652E696E666F726E617574696B")
    nonce_length: int = 16


class NFCConnector(ABC):
    @abstractmethod
    def in_data_exchange(self, command: bytes, response_length: int = 2) -> bytes:
        """Send one APDU and return its data plus status word."""

    @abstractmethod
    def wait_for_card(self) -> bytes:
        """Wait for a phone to be presented."""


class AdafruitPN532NFCConnector(NFCConnector):
    _COMMAND_INDATAEXCHANGE = 0x40

    def __init__(self):
        # Hardware-only imports remain lazy so protocol tests do not need Raspberry Pi modules.
        import board
        import busio
        from adafruit_pn532.i2c import PN532_I2C

        i2c = busio.I2C(board.SCL, board.SDA)
        self.pn532 = PN532_I2C(i2c, debug=False)
        self.pn532.SAM_configuration()
        logger.info("NFC reader ready")

    def in_data_exchange(self, command: bytes, response_length: int = 2) -> bytes:
        if len(command) > 254 or response_length > 258:
            raise NFCReaderException("NFC frame exceeds the reader limit")
        response = self.pn532.call_function(
            self._COMMAND_INDATAEXCHANGE,
            params=[0x01] + list(command),
            response_length=response_length,
        )
        if response is None or not response or response[0] != 0x00:
            raise NFCReaderException("NFC command failed")
        return bytes(response[1:])

    def wait_for_card(self) -> bytes:
        while True:
            uid = self.pn532.read_passive_target(timeout=0.5)
            if uid:
                return bytes(uid)
            time.sleep(0.1)

    def disconnect(self) -> None:
        self.pn532.reset()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.disconnect()


class NFCAuthenticator:
    def __init__(
        self,
        connector: NFCConnector,
        config: ReaderConfig,
        identity: ServiceIdentity,
        database: AuthDatabase,
    ):
        self.connector = connector
        self.config = config
        self.identity = identity
        self.db = database
        self.is_running = False
        self.session: NfcSession | None = None
        self.pending_signed_manifest: dict | None = None

    def select_application(self) -> None:
        self.session = None
        aid = self.config.aid
        if len(aid) > 16:
            raise NFCReaderException("Application identifier is too long")
        response = self.connector.in_data_exchange(
            SELECT_APPLICATION + bytes((len(aid),)) + aid,
            response_length=2,
        )
        if response != SUCCESS:
            raise NFCReaderException("NFC Authenticator application was not selected")

    def establish_encrypted_session(self) -> None:
        self.session = None
        initiator = SessionInitiator.create()
        response = self.connector.in_data_exchange(
            self.command_with_data(SESSION_INIT, initiator.request),
            response_length=2,
        )
        if len(response) != 2 or response[0] != MORE_DATA:
            raise NFCReaderException("Encrypted NFC session was not accepted")
        try:
            self.session = initiator.complete(self.get_response(response[1]))
        except ProtocolCryptoError as error:
            raise NFCReaderException("Encrypted NFC session response was invalid") from error

    def send_encrypted_command(
        self,
        command: bytes,
        plaintext: bytes,
        purpose: str,
    ) -> bytes:
        if self.session is None:
            raise NFCReaderException("Encrypted NFC session has not been established")
        encrypted = self.session.encrypt(plaintext, purpose)
        chunks = [
            encrypted[offset : offset + MAX_COMMAND_DATA] for offset in range(0, len(encrypted), MAX_COMMAND_DATA)
        ]
        if not chunks or len(chunks) > 256:
            raise NFCReaderException("Encrypted NFC request exceeds protocol limits")

        response = b""
        for sequence, chunk in enumerate(chunks):
            more = sequence < len(chunks) - 1
            header = bytes((command[0], command[1], sequence, 0x80 if more else 0x00))
            response = self.connector.in_data_exchange(
                self.command_with_data(header, chunk),
                response_length=2,
            )
            if more and response != SUCCESS:
                raise NFCReaderException("Encrypted NFC request chunk was rejected")
        return response

    def decrypt_response(self, status: bytes, purpose: str) -> bytes:
        if self.session is None:
            raise NFCReaderException("Encrypted NFC session has not been established")
        if len(status) != 2 or status[0] != MORE_DATA:
            raise NFCReaderException("Encrypted NFC response was not available")
        try:
            return self.session.decrypt(self.get_response(status[1]), purpose)
        except Exception as error:
            raise NFCReaderException("Encrypted NFC response authentication failed") from error

    def get_response(self, frame_size: int = 0) -> bytes:
        received: list[bytes] = []
        while True:
            requested = 250 if frame_size == 0 or frame_size > 250 else frame_size
            response = self.connector.in_data_exchange(
                GET_RESPONSE + bytes((requested,)),
                response_length=requested + 2,
            )
            if len(response) < 2:
                raise NFCReaderException("NFC response frame was malformed")
            received.append(response[:-2])
            status = response[-2:]
            if status == SUCCESS:
                return b"".join(received)
            if status[0] != MORE_DATA:
                raise NFCReaderException("NFC response transfer failed")
            frame_size = status[1]

    @staticmethod
    def command_with_data(command: bytes, data: bytes) -> bytes:
        if len(command) != 4 or len(data) > MAX_COMMAND_DATA:
            raise NFCReaderException("Invalid short APDU")
        return command + bytes((len(data),)) + data

    def registration_manifest(self) -> dict:
        if self.pending_signed_manifest is None:
            self.pending_signed_manifest = self.identity.signed_manifest(self.config.privacy)
        return self.pending_signed_manifest

    def request_registration(self) -> bytes | None:
        signed_manifest = self.registration_manifest()
        plaintext = json.dumps(
            signed_manifest,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        status = self.send_encrypted_command(
            REGISTRATION,
            plaintext,
            PURPOSE_REGISTRATION,
        )
        if status == SUCCESS:
            return None
        return self.decrypt_response(status, PURPOSE_REGISTRATION)

    def complete_registration(self, encrypted_response: bytes) -> None:
        signed_manifest = self.registration_manifest()
        try:
            envelope = json.loads(encrypted_response)
            plaintext, session_key = decrypt_registration_response(
                envelope,
                signed_manifest,
                self.identity.encryption_private_key,
            )
            fields = plaintext["fields"]
        except Exception as error:
            raise NFCReaderException("Registration response was invalid") from error

        requested = set(self.config.privacy.requested_fields)
        if not isinstance(fields, dict) or set(fields) != requested:
            raise NFCReaderException("Registration returned undisclosed or missing fields")
        if any(not isinstance(value, str) or not value for value in fields.values()):
            raise NFCReaderException("Registration returned a malformed field")

        user_id = fields[FIELD_SERVICE_USER_ID]
        public_key = fields[FIELD_AUTHENTICATION_PUBLIC_KEY]
        alias = fields.get(FIELD_ALIAS)
        self._validate_authentication_public_key(public_key)

        self.db.register_device(
            self.config.privacy.service_id,
            user_id,
            alias,
            public_key,
            session_key,
        )
        try:
            acknowledgement = encrypt_registration_acknowledgement(
                self.config.privacy.service_id,
                signed_manifest["manifest"]["registration_nonce"],
                manifest_hash(signed_manifest["manifest"]),
                session_key,
            )
            status = self.send_encrypted_command(
                REGISTRATION_COMPLETE,
                json.dumps(acknowledgement, separators=(",", ":")).encode("utf-8"),
                PURPOSE_REGISTRATION_COMPLETE,
            )
            if status != SUCCESS:
                raise NFCReaderException("Registration acknowledgement was rejected")
        except Exception:
            self.db.remove_registration(user_id)
            raise
        finally:
            session_key = b"\x00" * len(session_key)

        self.pending_signed_manifest = None

    def authenticate(self) -> None:
        if self.session is None:
            raise NFCReaderException("Establish an encrypted NFC session before discovery")
        backend = ReferenceBackend(self.identity, self.config.privacy, self.db, self.config.auth)
        discovery = backend.start_discovery(self.session.discovery_binding)
        status = self.send_encrypted_command(
            DISCOVERY,
            json.dumps(discovery["request"], separators=(",", ":")).encode(),
            PURPOSE_DISCOVERY,
        )
        try:
            response = json.loads(self.decrypt_response(status, PURPOSE_DISCOVERY))
            challenge = backend.create_challenge(discovery["id"], response)
            status = self.send_encrypted_command(
                AUTHENTICATION,
                json.dumps(challenge["request"], separators=(",", ":")).encode(),
                PURPOSE_AUTHENTICATION,
            )
            proof = json.loads(self.decrypt_response(status, PURPOSE_AUTHENTICATION))
            backend.complete(challenge["login_id"], proof)
        except Exception as error:
            raise NFCReaderException("Credential discovery or authentication proof was rejected") from error

    @staticmethod
    def _validate_authentication_public_key(encoded: str) -> None:
        try:
            key = serialization.load_der_public_key(base64.b64decode(encoded, validate=True))
        except (ValueError, TypeError) as error:
            raise NFCReaderException("Authentication public key was malformed") from error
        if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(
            key.curve,
            ec.SECP256R1,
        ):
            raise NFCReaderException("Authentication public key must use P-256")

    def run(self, mode: Literal["register", "auth"]) -> None:
        self.is_running = True
        logger.info("Waiting for an NFC device")
        try:
            while self.is_running:
                try:
                    self.connector.wait_for_card()
                    logger.info("NFC device detected")
                    self.select_application()
                    self.establish_encrypted_session()
                    if mode == "register":
                        response = self.request_registration()
                        if response is None:
                            logger.info("Registration consent is pending on the phone")
                        else:
                            self.complete_registration(response)
                            logger.info("Registration completed")
                            return
                    else:
                        self.authenticate()
                        logger.info("Authentication completed")
                        return
                except KeyboardInterrupt:
                    return
                except NFCReaderException:
                    logger.warning("NFC operation did not complete; present the phone again")
                    time.sleep(1)
        finally:
            self.is_running = False
            self.db.close()


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Privacy-aware NFC authentication service")
    parser.add_argument("mode", choices=["register", "auth"])
    parser.add_argument("--service-id", default="example-service")
    parser.add_argument("--service-name", default="Example Service")
    parser.add_argument("--operator-name", default="Example Service Operator")
    parser.add_argument(
        "--privacy-policy-url",
        default="https://voegtlel.github.io/nfcauth/example-service-privacy.html",
    )
    parser.add_argument(
        "--deletion-contact",
        default="https://voegtlel.github.io/nfcauth/example-service-privacy.html#deletion",
    )
    parser.add_argument("--notice-version", default="2026-07-29")
    parser.add_argument("--auth", choices=["background", "biometric"], default="background")
    parser.add_argument("--identity-file", default=".nfc_auth_service_identity.json")
    parser.add_argument("--database", default="auth.db")
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    privacy = ServicePrivacyConfig(
        service_id=args.service_id,
        service_name=args.service_name,
        operator_name=args.operator_name,
        privacy_policy_url=args.privacy_policy_url,
        privacy_notice_version=args.notice_version,
        requested_fields=(
            FIELD_ALIAS,
            FIELD_SERVICE_USER_ID,
            FIELD_AUTHENTICATION_PUBLIC_KEY,
        ),
        purposes={
            FIELD_ALIAS: "Display your chosen name in this service.",
            FIELD_SERVICE_USER_ID: "Identify your account only within this service.",
            FIELD_AUTHENTICATION_PUBLIC_KEY: "Verify authentication signatures.",
        },
        data_deletion_url_or_contact=args.deletion_contact,
    )
    config = ReaderConfig(privacy=privacy, auth=args.auth)
    identity = ServiceIdentity.load_or_create(args.identity_file)
    database = AuthDatabase(args.database)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )
    with AdafruitPN532NFCConnector() as connector:
        NFCAuthenticator(connector, config, identity, database).run(args.mode)


if __name__ == "__main__":
    main()
