"""Reference NFC reader for certificate-authenticated NFC Auth protocol v3."""

from __future__ import annotations

import argparse
import base64
import json
import logging
import secrets
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .backend import ReferenceBackend
from .certificate_auth import (
    CertificateSessionSigner,
    HttpSessionSigningClient,
    SessionAuthenticationContext,
    SessionSigningClient,
    transcript_hash,
)
from .discovery import PURPOSE_DISCOVERY
from .protocol_crypto import NfcSession, SessionInitiator
from .service_crypto import decrypt_registration_response, encrypt_registration_acknowledgement
from .service_manifest import (
    FIELD_ALIAS,
    FIELD_AUTHENTICATION_PUBLIC_KEY,
    PROFILE_BIOMETRIC,
    PROFILE_POSSESSION,
    ServiceIdentity,
    ServicePrivacyConfig,
    manifest_hash,
)
from .storage import SQLiteStore as AuthDatabase

SELECT_APPLICATION = b"\x00\xa4\x04\x00"
SESSION_INIT = b"\xd0\x00\x00\x00"
REGISTRATION = b"\xd0\x01\x00\x00"
AUTHENTICATION = b"\xd0\x02\x00\x00"
REGISTRATION_COMPLETE = b"\xd0\x04\x00\x00"
DISCOVERY = b"\xd0\x05\x00\x00"
SESSION_AUTHENTICATION = b"\xd0\x06\x00\x00"
AUTHENTICATION_COMPLETE = b"\xd0\x07\x00\x00"
GET_RESPONSE = b"\x00\xc0\x00\x00"
SUCCESS = b"\x90\x00"
MORE_DATA = 0x61
MAX_COMMAND_DATA = 249
AIDS = {
    PROFILE_POSSESSION: bytes.fromhex("F064652E696E666F726E617574696B01"),
    PROFILE_BIOMETRIC: bytes.fromhex("F064652E696E666F726E617574696B02"),
}
PURPOSE_SESSION_AUTHENTICATION = "session-authentication"
PURPOSE_REGISTRATION = "registration"
PURPOSE_AUTHENTICATION = "authentication"
PURPOSE_REGISTRATION_COMPLETE = "registration-complete"
PURPOSE_AUTHENTICATION_COMPLETE = "authentication-complete"
logger = logging.getLogger(__name__)


class NFCReaderException(Exception):
    """A protocol, transport, or validation operation failed."""


@dataclass(frozen=True)
class ReaderConfig:
    privacy: ServicePrivacyConfig
    credential_id: str | None = None

    @property
    def aid(self) -> bytes:
        return AIDS[self.privacy.authentication_profile]


class NFCConnector(ABC):
    @abstractmethod
    def in_data_exchange(self, command: bytes, response_length: int = 2) -> bytes:
        """Send one APDU and return its data plus status word."""

    @abstractmethod
    def wait_for_card(self) -> bytes:
        """Wait for a phone to be presented."""


class AdafruitPN532NFCConnector(NFCConnector):
    _COMMAND_INDATAEXCHANGE = 0x40

    def __init__(self) -> None:
        import board
        import busio
        from adafruit_pn532.i2c import PN532_I2C

        self.pn532 = PN532_I2C(busio.I2C(board.SCL, board.SDA), debug=False)
        self.pn532.SAM_configuration()

    def in_data_exchange(self, command: bytes, response_length: int = 2) -> bytes:
        if len(command) > 254 or response_length > 258:
            raise NFCReaderException("NFC frame exceeds the reader limit")
        response = self.pn532.call_function(
            self._COMMAND_INDATAEXCHANGE,
            params=[0x01] + list(command),
            response_length=response_length,
        )
        if response is None or not response or response[0] != 0:
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

    def __exit__(self, *_: object) -> None:
        self.disconnect()


class NFCAuthenticator:
    def __init__(
        self,
        connector: NFCConnector,
        config: ReaderConfig,
        identity: ServiceIdentity,
        database: AuthDatabase,
        signer: SessionSigningClient,
    ) -> None:
        self.connector = connector
        self.config = config
        self.identity = identity
        self.db = database
        self.signer = signer
        self.session: NfcSession | None = None
        self.manifest = identity.manifest(config.privacy)
        self.registration_offer: dict | None = None

    def select_application(self) -> None:
        self.session = None
        response = self.connector.in_data_exchange(
            SELECT_APPLICATION + bytes((len(self.config.aid),)) + self.config.aid,
            response_length=2,
        )
        if response != SUCCESS:
            raise NFCReaderException("NFC Authenticator profile was not selected")

    def establish_authenticated_session(self) -> None:
        self.session = None
        initiator = SessionInitiator.create()
        status = self.connector.in_data_exchange(self.command_with_data(SESSION_INIT, initiator.request))
        if len(status) != 2 or status[0] != MORE_DATA:
            raise NFCReaderException("Encrypted NFC session was not accepted")
        try:
            completed = initiator.complete(self.get_response(status[1]))
            context = SessionAuthenticationContext(
                self.config.privacy.service_origin.rstrip("/"),
                self.config.privacy.service_id,
                self.config.privacy.authentication_profile,
                manifest_hash(self.manifest),
                completed.context.session_id,
                completed.context.phone_challenge,
                completed.context.reader_ephemeral_public_key,
                completed.context.phone_ephemeral_public_key,
            )
            authentication = self.signer.sign(context)
            self.session = completed.session
            status = self.send_encrypted_command(
                SESSION_AUTHENTICATION,
                _json_bytes(authentication.as_dict(self.manifest)),
                PURPOSE_SESSION_AUTHENTICATION,
            )
            if status != SUCCESS:
                raise NFCReaderException("Service certificate or session signature was rejected")
            self.session.authenticate(transcript_hash(context))
        except NFCReaderException:
            self.session = None
            raise
        except Exception as error:
            self.session = None
            raise NFCReaderException("Service-authenticated NFC session failed") from error

    def send_encrypted_command(self, command: bytes, plaintext: bytes, purpose: str) -> bytes:
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
            header = bytes((command[0], command[1], sequence, 0x80 if more else 0))
            response = self.connector.in_data_exchange(self.command_with_data(header, chunk))
            if more and response != SUCCESS:
                raise NFCReaderException("Encrypted NFC request chunk was rejected")
        return response

    def decrypt_response(self, status: bytes, purpose: str) -> bytes:
        if self.session is None or len(status) != 2 or status[0] != MORE_DATA:
            raise NFCReaderException("Encrypted NFC response was not available")
        try:
            return self.session.decrypt(self.get_response(status[1]), purpose)
        except Exception as error:
            raise NFCReaderException("Encrypted NFC response authentication failed") from error

    def get_response(self, frame_size: int = 0) -> bytes:
        received: list[bytes] = []
        while True:
            requested = 250 if frame_size == 0 or frame_size > 250 else frame_size
            response = self.connector.in_data_exchange(GET_RESPONSE + bytes((requested,)), requested + 2)
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

    def request_registration(self) -> bytes | None:
        credential_id = self.config.credential_id
        if credential_id is None or not 16 <= len(credential_id) <= 255:
            raise NFCReaderException("Registration requires a service-issued credential ID")
        if self.registration_offer is None:
            self.registration_offer = {
                "protocol_version": 3,
                "service_id": self.config.privacy.service_id,
                "credential_id": credential_id,
                "authentication_profile": self.config.privacy.authentication_profile,
                "manifest_hash": manifest_hash(self.manifest),
                "registration_nonce": secrets.token_hex(32),
            }
        offer = self.registration_offer
        status = self.send_encrypted_command(REGISTRATION, _json_bytes(offer), PURPOSE_REGISTRATION)
        return None if status == SUCCESS else self.decrypt_response(status, PURPOSE_REGISTRATION)

    def complete_registration(self, encrypted_response: bytes) -> None:
        offer = self.registration_offer
        if offer is None:
            raise NFCReaderException("No registration offer is pending")
        credential_id = offer["credential_id"]
        try:
            plaintext, key = decrypt_registration_response(
                json.loads(encrypted_response),
                self.manifest,
                credential_id,
                offer["registration_nonce"],
                self.identity.encryption_private_key,
            )
            fields = plaintext["fields"]
            if not isinstance(fields, dict) or set(fields) != set(self.config.privacy.requested_fields):
                raise ValueError("Registration fields differ from the approved manifest")
            if any(not isinstance(value, str) or not value for value in fields.values()):
                raise ValueError("Registration field is malformed")
            public_key = fields[FIELD_AUTHENTICATION_PUBLIC_KEY]
            self._validate_authentication_public_key(public_key)
            self.db.register_device(
                self.config.privacy.service_id,
                credential_id,
                fields.get(FIELD_ALIAS),
                self.config.privacy.authentication_profile,
                public_key,
                key,
            )
            acknowledgement = encrypt_registration_acknowledgement(
                self.manifest,
                credential_id,
                offer["registration_nonce"],
                key,
            )
            status = self.send_encrypted_command(
                REGISTRATION_COMPLETE,
                _json_bytes(acknowledgement),
                PURPOSE_REGISTRATION_COMPLETE,
            )
            if status != SUCCESS:
                self.db.remove_registration(self.config.privacy.service_id, credential_id)
                raise NFCReaderException("Registration acknowledgement was rejected")
        except NFCReaderException:
            raise
        except Exception as error:
            raise NFCReaderException("Registration response was invalid") from error
        finally:
            if "key" in locals():
                key = b"\x00" * len(key)

    def authenticate(self) -> None:
        if self.session is None:
            raise NFCReaderException("Establish an authenticated NFC session first")
        backend = ReferenceBackend(self.identity, self.config.privacy, self.db)
        try:
            discovery = backend.start_discovery(self.session.discovery_binding)
            status = self.send_encrypted_command(DISCOVERY, _json_bytes(discovery["request"]), PURPOSE_DISCOVERY)
            discovery_response = json.loads(self.decrypt_response(status, PURPOSE_DISCOVERY))
            challenge = backend.create_challenge(discovery["id"], discovery_response)
            status = self.send_encrypted_command(
                AUTHENTICATION,
                _json_bytes(challenge["request"]),
                PURPOSE_AUTHENTICATION,
            )
            proof = json.loads(self.decrypt_response(status, PURPOSE_AUTHENTICATION))
            result = backend.complete(challenge["login_id"], proof)
            status = self.send_encrypted_command(
                AUTHENTICATION_COMPLETE,
                _json_bytes(result["commit"]),
                PURPOSE_AUTHENTICATION_COMPLETE,
            )
            ack = json.loads(self.decrypt_response(status, PURPOSE_AUTHENTICATION_COMPLETE))
            backend.confirm_rotation(result, ack)
        except Exception as error:
            raise NFCReaderException("Credential authentication or key rotation failed") from error

    @staticmethod
    def _validate_authentication_public_key(encoded: str) -> None:
        key = serialization.load_der_public_key(base64.b64decode(encoded, validate=True))
        if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
            raise NFCReaderException("Authentication public key must use P-256")

    def run(self, mode: Literal["register", "auth"]) -> None:
        logger.info("Waiting for an NFC device")
        while True:
            try:
                self.connector.wait_for_card()
                self.select_application()
                self.establish_authenticated_session()
                if mode == "register":
                    response = self.request_registration()
                    if response is None:
                        logger.info("Registration consent is pending on the phone; present it again")
                    else:
                        self.complete_registration(response)
                        logger.info("Registration completed")
                        return
                else:
                    self.authenticate()
                    logger.info("Authentication and key rotation completed")
                    return
            except KeyboardInterrupt:
                return
            except NFCReaderException as error:
                logger.warning("%s; present the phone again", error)
                time.sleep(1)


def _json_bytes(value: dict) -> bytes:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="NFC Auth protocol-v3 service reader")
    parser.add_argument("mode", choices=["register", "auth"])
    parser.add_argument("--service-origin", default="https://example.com")
    parser.add_argument("--service-id", default="example-service")
    parser.add_argument("--service-name", default="Example Service")
    parser.add_argument("--operator-name", default="Example Service Operator")
    parser.add_argument("--privacy-policy-url", default="https://example.com/privacy")
    parser.add_argument("--deletion-contact", default="https://example.com/delete")
    parser.add_argument("--notice-version", default="1")
    parser.add_argument("--auth-profile", choices=[PROFILE_POSSESSION, PROFILE_BIOMETRIC], default=PROFILE_POSSESSION)
    parser.add_argument("--credential-id", help="Opaque ID allocated by the service; required for registration")
    parser.add_argument("--identity-file", default=".nfc_auth_service_identity_v3.json")
    parser.add_argument("--database", default="auth-v3.db")
    signing = parser.add_mutually_exclusive_group(required=True)
    signing.add_argument("--signing-api-url")
    signing.add_argument("--certificate-key")
    parser.add_argument("--certificate-chain")
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    if args.mode == "register" and not args.credential_id:
        raise SystemExit("--credential-id is required in registration mode")
    if args.certificate_key and not args.certificate_chain:
        raise SystemExit("--certificate-chain is required with --certificate-key")
    privacy = ServicePrivacyConfig(
        service_origin=args.service_origin,
        service_id=args.service_id,
        service_name=args.service_name,
        operator_name=args.operator_name,
        privacy_policy_url=args.privacy_policy_url,
        privacy_notice_version=args.notice_version,
        requested_fields=(FIELD_ALIAS, FIELD_AUTHENTICATION_PUBLIC_KEY),
        purposes={
            FIELD_ALIAS: "Display your chosen name in this service.",
            FIELD_AUTHENTICATION_PUBLIC_KEY: "Verify authentication signatures for this profile.",
        },
        data_deletion_url_or_contact=args.deletion_contact,
        authentication_profile=args.auth_profile,
    )
    signer: SessionSigningClient
    if args.signing_api_url:
        signer = HttpSessionSigningClient(args.signing_api_url)
    else:
        signer = CertificateSessionSigner(Path(args.certificate_key), Path(args.certificate_chain))
    identity = ServiceIdentity.load_or_create(args.identity_file)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
    with AdafruitPN532NFCConnector() as connector, AuthDatabase(args.database) as database:
        NFCAuthenticator(
            connector,
            ReaderConfig(privacy, args.credential_id),
            identity,
            database,
            signer,
        ).run(args.mode)


if __name__ == "__main__":
    main()
