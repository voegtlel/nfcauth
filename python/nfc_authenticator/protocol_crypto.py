"""Certificate-authenticated NFC transport encryption for protocol version 3."""

from __future__ import annotations

import hmac
import secrets
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PROTOCOL_VERSION = 3
SESSION_ID_LENGTH = 16
PHONE_CHALLENGE_LENGTH = 32
PUBLIC_KEY_LENGTH = 65
GCM_IV_LENGTH = 12
GCM_TAG_LENGTH = 16
SEQUENCE_LENGTH = 8
MAX_SEQUENCE = (1 << 64) - 1
DIRECTION_READER_TO_PHONE = 0
DIRECTION_PHONE_TO_READER = 1
PURPOSE_SESSION_AUTHENTICATION = "session-authentication"
HKDF_PROVISIONAL_INFO = b"nfcauth-v3-provisional-session"
HKDF_AUTHENTICATED_INFO = b"nfcauth-v3-authenticated-session"
HKDF_TRANSPORT_INFO = b"nfcauth-v3-transport"
HKDF_BINDING_INFO = b"nfcauth-v3-binding"


class ProtocolCryptoError(ValueError):
    """Raised when an encrypted NFC session or payload is invalid."""


@dataclass(frozen=True)
class SessionContext:
    session_id: bytes
    phone_challenge: bytes
    reader_ephemeral_public_key: bytes
    phone_ephemeral_public_key: bytes


@dataclass
class NfcSession:
    """One NFC presentation session, provisional until its certificate proof verifies."""

    session_id: bytes
    root_key: bytes
    send_direction: int
    receive_direction: int
    authenticated: bool = False
    _send_counter: int = field(default=0, init=False, repr=False)
    _receive_counter: int = field(default=0, init=False, repr=False)
    _terminated: bool = field(default=False, init=False, repr=False)
    _transport_key: bytes = field(default=b"", init=False, repr=False)
    _binding_key: bytes = field(default=b"", init=False, repr=False)

    def __post_init__(self) -> None:
        self._derive_subkeys(self.root_key)

    def _derive_subkeys(self, root_key: bytes) -> None:
        self._transport_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.session_id,
            info=HKDF_TRANSPORT_INFO,
        ).derive(root_key)
        self._binding_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.session_id,
            info=HKDF_BINDING_INFO,
        ).derive(root_key)

    def authenticate(self, transcript_hash: bytes) -> None:
        if self.authenticated or len(transcript_hash) != 32:
            raise ProtocolCryptoError("NFC session authentication state is invalid")
        authenticated_root = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.session_id,
            info=HKDF_AUTHENTICATED_INFO + transcript_hash,
        ).derive(self.root_key)
        self.root_key = authenticated_root
        self._derive_subkeys(authenticated_root)
        self._send_counter = 0
        self._receive_counter = 0
        self.authenticated = True

    @property
    def discovery_binding(self) -> str:
        if not self.authenticated:
            raise ProtocolCryptoError("NFC session identity is not authenticated")
        return hmac.new(
            self._binding_key,
            b"nfcauth-v3-credential-discovery-binding",
            "sha256",
        ).hexdigest()

    def encrypt(self, plaintext: bytes, purpose: str) -> bytes:
        self._require_purpose(purpose)
        if self._terminated:
            raise ProtocolCryptoError("Encrypted NFC session is terminated")
        if self._send_counter == MAX_SEQUENCE:
            self._terminated = True
            raise ProtocolCryptoError("Encrypted NFC send sequence exhausted")
        sequence = self._send_counter
        encoded_sequence = sequence.to_bytes(SEQUENCE_LENGTH, "big", signed=False)
        iv = secrets.token_bytes(GCM_IV_LENGTH)
        ciphertext = AESGCM(self._transport_key).encrypt(
            iv,
            plaintext,
            self._authenticated_data(self.send_direction, purpose, encoded_sequence),
        )
        self._send_counter = sequence + 1
        return bytes((PROTOCOL_VERSION,)) + self.session_id + encoded_sequence + iv + ciphertext

    def decrypt(self, envelope: bytes, purpose: str) -> bytes:
        self._require_purpose(purpose)
        if self._terminated:
            raise ProtocolCryptoError("Encrypted NFC session is terminated")
        minimum_length = 1 + SESSION_ID_LENGTH + SEQUENCE_LENGTH + GCM_IV_LENGTH + GCM_TAG_LENGTH
        if len(envelope) < minimum_length or envelope[0] != PROTOCOL_VERSION:
            raise ProtocolCryptoError("Encrypted NFC payload is malformed or unsupported")
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
        plaintext = AESGCM(self._transport_key).decrypt(
            envelope[iv_start:ciphertext_start],
            envelope[ciphertext_start:],
            self._authenticated_data(self.receive_direction, purpose, encoded_sequence),
        )
        self._receive_counter += 1
        return plaintext

    def _require_purpose(self, purpose: str) -> None:
        if not purpose:
            raise ProtocolCryptoError("NFC encryption purpose must not be empty")
        if not self.authenticated and purpose != PURPOSE_SESSION_AUTHENTICATION:
            raise ProtocolCryptoError("Service identity must be authenticated first")

    def _authenticated_data(self, direction: int, purpose: str, sequence: bytes) -> bytes:
        if direction not in (DIRECTION_READER_TO_PHONE, DIRECTION_PHONE_TO_READER):
            raise ProtocolCryptoError("Invalid encrypted NFC direction")
        return (
            bytes((PROTOCOL_VERSION,))
            + self.session_id
            + bytes((direction,))
            + len(purpose.encode()).to_bytes(2, "big")
            + purpose.encode()
            + sequence
        )


@dataclass(frozen=True)
class CompletedSession:
    session: NfcSession
    context: SessionContext


@dataclass(frozen=True)
class SessionInitiator:
    session_id: bytes
    private_key: ec.EllipticCurvePrivateKey

    @classmethod
    def create(cls) -> SessionInitiator:
        return cls(secrets.token_bytes(SESSION_ID_LENGTH), ec.generate_private_key(ec.SECP256R1()))

    @property
    def reader_public_key(self) -> bytes:
        return _encode_public_key(self.private_key.public_key())

    @property
    def request(self) -> bytes:
        return bytes((PROTOCOL_VERSION,)) + self.session_id + self.reader_public_key

    def complete(self, response: bytes) -> CompletedSession:
        expected = 1 + SESSION_ID_LENGTH + PUBLIC_KEY_LENGTH + PHONE_CHALLENGE_LENGTH
        if len(response) != expected or response[0] != PROTOCOL_VERSION:
            raise ProtocolCryptoError("Invalid NFC session response")
        session_id = response[1 : 1 + SESSION_ID_LENGTH]
        if not hmac.compare_digest(self.session_id, session_id):
            raise ProtocolCryptoError("NFC session ID mismatch")
        phone_public_encoded = response[1 + SESSION_ID_LENGTH : 1 + SESSION_ID_LENGTH + PUBLIC_KEY_LENGTH]
        phone_public_key = _decode_public_key(phone_public_encoded)
        phone_challenge = response[-PHONE_CHALLENGE_LENGTH:]
        return CompletedSession(
            _derive_session(self.session_id, self.private_key, phone_public_key, is_initiator=True),
            SessionContext(
                self.session_id,
                phone_challenge,
                self.reader_public_key,
                phone_public_encoded,
            ),
        )


@dataclass(frozen=True)
class AcceptedSession:
    session: NfcSession
    response: bytes
    context: SessionContext


def accept_session(request: bytes) -> AcceptedSession:
    expected = 1 + SESSION_ID_LENGTH + PUBLIC_KEY_LENGTH
    if len(request) != expected or request[0] != PROTOCOL_VERSION:
        raise ProtocolCryptoError("Invalid NFC session request")
    session_id = request[1 : 1 + SESSION_ID_LENGTH]
    reader_public_encoded = request[1 + SESSION_ID_LENGTH :]
    reader_public_key = _decode_public_key(reader_public_encoded)
    phone_key = ec.generate_private_key(ec.SECP256R1())
    phone_public_encoded = _encode_public_key(phone_key.public_key())
    challenge = secrets.token_bytes(PHONE_CHALLENGE_LENGTH)
    session = _derive_session(session_id, phone_key, reader_public_key, is_initiator=False)
    return AcceptedSession(
        session,
        bytes((PROTOCOL_VERSION,)) + session_id + phone_public_encoded + challenge,
        SessionContext(session_id, challenge, reader_public_encoded, phone_public_encoded),
    )


def _derive_session(
    session_id: bytes,
    private_key: ec.EllipticCurvePrivateKey,
    peer_public_key: ec.EllipticCurvePublicKey,
    *,
    is_initiator: bool,
) -> NfcSession:
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    root_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=session_id,
        info=HKDF_PROVISIONAL_INFO,
    ).derive(shared_secret)
    return NfcSession(
        session_id,
        root_key,
        DIRECTION_READER_TO_PHONE if is_initiator else DIRECTION_PHONE_TO_READER,
        DIRECTION_PHONE_TO_READER if is_initiator else DIRECTION_READER_TO_PHONE,
    )


def _encode_public_key(public_key: ec.EllipticCurvePublicKey) -> bytes:
    encoded = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    if len(encoded) != PUBLIC_KEY_LENGTH:
        raise ProtocolCryptoError("Invalid P-256 public key length")
    return encoded


def _decode_public_key(encoded: bytes) -> ec.EllipticCurvePublicKey:
    if len(encoded) != PUBLIC_KEY_LENGTH:
        raise ProtocolCryptoError("Invalid peer P-256 public key")
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), encoded)
    except ValueError as error:
        raise ProtocolCryptoError("Invalid peer P-256 public key") from error
