"""NFC Auth v4 APDU protocol over a caller-supplied transport."""

from __future__ import annotations

import json

from .protocol_crypto import PURPOSE_SESSION_AUTHENTICATION, NfcSession, SessionInitiator
from .protocol_v4 import AssertionDeliveryRequest, AuthorizationAssertion, AuthorizationRequest, SessionBinding
from .terminal_transport import NfcTransport, NfcTransportError

SELECT = b"\x00\xa4\x04\x00"
SESSION_INIT = b"\xd0\x00\x00\x00"
AUTHORIZATION = b"\xd0\x08\x00\x00"
ASSERTION_DELIVERY = b"\xd0\x09\x00\x00"
GET_RESPONSE = b"\x00\xc0\x00\x00"
SUCCESS = b"\x90\x00"
BIOMETRIC_REQUIRED = b"\x63\x00"
MORE_DATA = 0x61
MAX_COMMAND_DATA = 249
AIDS = {
    "possession": bytes.fromhex("F064652E696E666F726E617574696B01"),
    "biometric": bytes.fromhex("F064652E696E666F726E617574696B02"),
}


class ApduPhoneChannel:
    def __init__(self, transport: NfcTransport, assurance: str) -> None:
        if assurance not in AIDS:
            raise ValueError("Unsupported assurance profile")
        self.transport = transport
        self.assurance = assurance
        self.session: NfcSession | None = None

    async def wait_for_phone(self) -> None:
        await self.transport.wait_for_device()
        aid = AIDS[self.assurance]
        response = await self.transport.transceive(SELECT + bytes((len(aid),)) + aid)
        if response != SUCCESS:
            raise NfcTransportError("Phone did not select the requested NFC Auth profile")

    async def begin_encrypted_session(self) -> SessionBinding:
        initiator = SessionInitiator.create()
        status = await self.transport.transceive(_command_with_data(SESSION_INIT, initiator.request))
        response = await self._response(status)
        completed = initiator.complete(response)
        self.session = completed.session
        context = completed.context
        return SessionBinding(
            _b64(context.session_id),
            _b64(context.phone_challenge),
            _b64(context.reader_ephemeral_public_key),
            _b64(context.phone_ephemeral_public_key),
        )

    async def deliver_authorization(self, signed_request: dict) -> AuthorizationAssertion | None:
        request = _authorization_request(signed_request["request"])
        status = await self._send_encrypted(AUTHORIZATION, signed_request, PURPOSE_SESSION_AUTHENTICATION)
        session = self._session()
        session.authenticate(bytes.fromhex(request.request_hash))
        if status == BIOMETRIC_REQUIRED:
            return None
        encrypted = await self._response(status)
        plaintext = session.decrypt(encrypted, "authorization-assertion")
        return AuthorizationAssertion(**json.loads(plaintext))

    async def fetch_approved_assertion(self, signed_delivery_request: dict) -> AuthorizationAssertion:
        delivery = _delivery_request(signed_delivery_request["request"])
        status = await self._send_encrypted(
            ASSERTION_DELIVERY,
            signed_delivery_request,
            PURPOSE_SESSION_AUTHENTICATION,
        )
        session = self._session()
        session.authenticate(_sha256(delivery.payload()))
        encrypted = await self._response(status)
        plaintext = session.decrypt(encrypted, "assertion-delivery")
        return AuthorizationAssertion(**json.loads(plaintext))

    async def close(self) -> None:
        self.session = None
        await self.transport.close()

    async def _send_encrypted(self, instruction: bytes, value: dict, purpose: str) -> bytes:
        session = self._session()
        plaintext = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()
        encrypted = session.encrypt(plaintext, purpose)
        chunks = [encrypted[index : index + MAX_COMMAND_DATA] for index in range(0, len(encrypted), MAX_COMMAND_DATA)]
        status = SUCCESS
        for sequence, chunk in enumerate(chunks):
            if sequence > 255:
                raise NfcTransportError("NFC message has too many APDU fragments")
            more = 0x80 if sequence < len(chunks) - 1 else 0
            command = instruction[:2] + bytes((sequence, more, len(chunk))) + chunk
            status = await self.transport.transceive(command)
            if sequence < len(chunks) - 1 and status != SUCCESS:
                raise NfcTransportError("Phone rejected an NFC message fragment")
        return status

    async def _response(self, status: bytes) -> bytes:
        if len(status) != 2 or status[0] != MORE_DATA:
            raise NfcTransportError(f"Expected NFC response data, received status {status.hex()}")
        output = bytearray()
        while status[0] == MORE_DATA:
            requested = status[1]
            response = await self.transport.transceive(GET_RESPONSE + bytes((requested,)))
            if len(response) < 2:
                raise NfcTransportError("Truncated NFC response")
            output.extend(response[:-2])
            status = response[-2:]
        if status != SUCCESS:
            raise NfcTransportError(f"Phone returned NFC status {status.hex()}")
        return bytes(output)

    def _session(self) -> NfcSession:
        if self.session is None:
            raise NfcTransportError("Encrypted NFC session has not been established")
        return self.session


def _command_with_data(prefix: bytes, value: bytes) -> bytes:
    if len(value) > 255:
        raise NfcTransportError("NFC command exceeds one APDU")
    return prefix + bytes((len(value),)) + value


def _authorization_request(value: dict) -> AuthorizationRequest:
    value = dict(value)
    value["scopes"] = tuple(value["scopes"])
    value["session"] = SessionBinding(**value["session"])
    return AuthorizationRequest(**value)


def _delivery_request(value: dict) -> AssertionDeliveryRequest:
    value = dict(value)
    value["session"] = SessionBinding(**value["session"])
    return AssertionDeliveryRequest(**value)


def _b64(value: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _sha256(value: bytes) -> bytes:
    import hashlib

    return hashlib.sha256(value).digest()
