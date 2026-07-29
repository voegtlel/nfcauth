"""Application-layer encryption for NFC Auth protocol version 2."""

from __future__ import annotations

from dataclasses import dataclass, field
import hmac
import secrets

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


PROTOCOL_VERSION = 2
SESSION_ID_LENGTH = 16
PUBLIC_KEY_LENGTH = 65
GCM_IV_LENGTH = 12
GCM_TAG_LENGTH = 16
SEQUENCE_LENGTH = 8
MAX_SEQUENCE = (1 << 64) - 1
DIRECTION_READER_TO_PHONE = 0
DIRECTION_PHONE_TO_READER = 1
HKDF_INFO = b"nfcauth-nfc-session-v2"


class ProtocolCryptoError(ValueError):
    """Raised when an encrypted NFC session or payload is invalid."""


@dataclass
class NfcSession:
    """One ephemeral NFC presentation session."""

    session_id: bytes
    key: bytes
    send_direction: int
    receive_direction: int
    _send_counter: int = field(default=0, init=False, repr=False)
    _receive_counter: int = field(default=0, init=False, repr=False)
    _terminated: bool = field(default=False, init=False, repr=False)

    def encrypt(self, plaintext: bytes, purpose: str) -> bytes:
        if not purpose:
            raise ProtocolCryptoError("NFC encryption purpose must not be empty")
        if self._terminated:
            raise ProtocolCryptoError("Encrypted NFC session is terminated")
        if self._send_counter == MAX_SEQUENCE:
            self._terminated = True
            raise ProtocolCryptoError("Encrypted NFC send sequence exhausted")
        sequence = self._send_counter
        encoded_sequence = sequence.to_bytes(SEQUENCE_LENGTH, "big", signed=False)
        iv = secrets.token_bytes(GCM_IV_LENGTH)
        ciphertext = AESGCM(self.key).encrypt(
            iv,
            plaintext,
            self._authenticated_data(self.send_direction, purpose, encoded_sequence),
        )
        envelope = bytes((PROTOCOL_VERSION,)) + self.session_id + encoded_sequence + iv + ciphertext
        self._send_counter = sequence + 1
        return envelope

    def decrypt(self, envelope: bytes, purpose: str) -> bytes:
        if self._terminated:
            raise ProtocolCryptoError("Encrypted NFC session is terminated")
        minimum_length = 1 + SESSION_ID_LENGTH + SEQUENCE_LENGTH + GCM_IV_LENGTH + GCM_TAG_LENGTH
        if len(envelope) < minimum_length:
            raise ProtocolCryptoError("Encrypted NFC payload is too short")
        if envelope[0] != PROTOCOL_VERSION:
            raise ProtocolCryptoError("Unsupported encrypted NFC payload version")

        envelope_session_id = envelope[1 : 1 + SESSION_ID_LENGTH]
        if not hmac.compare_digest(self.session_id, envelope_session_id):
            raise ProtocolCryptoError("Encrypted NFC payload belongs to another session")

        if self._receive_counter == MAX_SEQUENCE:
            self._terminated = True
            raise ProtocolCryptoError("Encrypted NFC receive sequence exhausted")
        sequence_start = 1 + SESSION_ID_LENGTH
        iv_start = sequence_start + SEQUENCE_LENGTH
        encoded_sequence = envelope[sequence_start:iv_start]
        sequence = int.from_bytes(encoded_sequence, "big", signed=False)
        if sequence != self._receive_counter:
            raise ProtocolCryptoError(
                f"Unexpected encrypted NFC sequence: expected {self._receive_counter}, received {sequence}"
            )

        ciphertext_start = iv_start + GCM_IV_LENGTH
        iv = envelope[iv_start:ciphertext_start]
        ciphertext = envelope[ciphertext_start:]
        plaintext = AESGCM(self.key).decrypt(
            iv,
            ciphertext,
            self._authenticated_data(self.receive_direction, purpose, encoded_sequence),
        )
        self._receive_counter += 1
        return plaintext

    def _authenticated_data(self, direction: int, purpose: str, encoded_sequence: bytes) -> bytes:
        if not purpose:
            raise ProtocolCryptoError("NFC encryption purpose must not be empty")
        if direction not in (DIRECTION_READER_TO_PHONE, DIRECTION_PHONE_TO_READER):
            raise ProtocolCryptoError("Invalid encrypted NFC direction")
        if len(encoded_sequence) != SEQUENCE_LENGTH:
            raise ProtocolCryptoError("Invalid encrypted NFC sequence length")
        return (
            bytes((PROTOCOL_VERSION,))
            + self.session_id
            + bytes((direction,))
            + purpose.encode()
            + encoded_sequence
        )


@dataclass(frozen=True)
class SessionInitiator:
    """Reader-side state for an ephemeral P-256 ECDH handshake."""

    session_id: bytes
    private_key: ec.EllipticCurvePrivateKey

    @classmethod
    def create(cls) -> SessionInitiator:
        return cls(
            session_id=secrets.token_bytes(SESSION_ID_LENGTH),
            private_key=ec.generate_private_key(ec.SECP256R1()),
        )

    @property
    def request(self) -> bytes:
        return _encode_handshake(self.session_id, self.private_key.public_key())

    def complete(self, response: bytes) -> NfcSession:
        session_id, peer_public_key = _parse_handshake(response)
        if not hmac.compare_digest(self.session_id, session_id):
            raise ProtocolCryptoError("NFC session ID mismatch")
        return _derive_session(self.session_id, self.private_key, peer_public_key, is_initiator=True)


def _derive_session(
    session_id: bytes,
    private_key: ec.EllipticCurvePrivateKey,
    peer_public_key: ec.EllipticCurvePublicKey,
    *,
    is_initiator: bool,
) -> NfcSession:
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=session_id,
        info=HKDF_INFO,
    ).derive(shared_secret)
    if is_initiator:
        send_direction = DIRECTION_READER_TO_PHONE
        receive_direction = DIRECTION_PHONE_TO_READER
    else:
        send_direction = DIRECTION_PHONE_TO_READER
        receive_direction = DIRECTION_READER_TO_PHONE
    return NfcSession(
        session_id=session_id,
        key=key,
        send_direction=send_direction,
        receive_direction=receive_direction,
    )


def _encode_handshake(session_id: bytes, public_key: ec.EllipticCurvePublicKey) -> bytes:
    if len(session_id) != SESSION_ID_LENGTH:
        raise ProtocolCryptoError("Invalid NFC session ID length")
    encoded_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    if len(encoded_public_key) != PUBLIC_KEY_LENGTH:
        raise ProtocolCryptoError("Invalid P-256 public key length")
    return bytes((PROTOCOL_VERSION,)) + session_id + encoded_public_key


def _parse_handshake(payload: bytes) -> tuple[bytes, ec.EllipticCurvePublicKey]:
    expected_length = 1 + SESSION_ID_LENGTH + PUBLIC_KEY_LENGTH
    if len(payload) != expected_length:
        raise ProtocolCryptoError("Invalid NFC handshake length")
    if payload[0] != PROTOCOL_VERSION:
        raise ProtocolCryptoError("Unsupported NFC protocol version")

    session_id = payload[1 : 1 + SESSION_ID_LENGTH]
    encoded_public_key = payload[1 + SESSION_ID_LENGTH :]
    try:
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), encoded_public_key)
    except ValueError as error:
        raise ProtocolCryptoError("Invalid peer P-256 public key") from error
    return session_id, public_key
