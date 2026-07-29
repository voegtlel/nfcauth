import unittest

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import ec

from nfc_authenticator.protocol_crypto import (
    MAX_SEQUENCE,
    PROTOCOL_VERSION,
    PUBLIC_KEY_LENGTH,
    SEQUENCE_LENGTH,
    SESSION_ID_LENGTH,
    ProtocolCryptoError,
    SessionInitiator,
    _derive_session,
    _parse_handshake,
)


FIXED_SESSION_ID = bytes(range(16))
FIXED_READER_PRIVATE_KEY = ec.derive_private_key(1, ec.SECP256R1())
FIXED_PHONE_PRIVATE_KEY = ec.derive_private_key(2, ec.SECP256R1())


def create_session_pair():
    reader = SessionInitiator.create()
    session_id, reader_public_key = _parse_handshake(reader.request)

    phone = SessionInitiator.create()
    phone_session = _derive_session(
        session_id,
        phone.private_key,
        reader_public_key,
        is_initiator=False,
    )
    phone_response = bytes((PROTOCOL_VERSION,)) + session_id + phone.request[-PUBLIC_KEY_LENGTH:]
    reader_session = reader.complete(phone_response)
    return reader_session, phone_session


def fixed_session(*, is_initiator):
    private_key = FIXED_READER_PRIVATE_KEY if is_initiator else FIXED_PHONE_PRIVATE_KEY
    peer_public_key = (
        FIXED_PHONE_PRIVATE_KEY.public_key() if is_initiator else FIXED_READER_PRIVATE_KEY.public_key()
    )
    return _derive_session(
        FIXED_SESSION_ID,
        private_key,
        peer_public_key,
        is_initiator=is_initiator,
    )


def sequence(envelope):
    start = 1 + SESSION_ID_LENGTH
    return int.from_bytes(envelope[start : start + SEQUENCE_LENGTH], "big", signed=False)


class ProtocolCryptoTest(unittest.TestCase):
    def test_encrypted_payload_round_trips_with_independent_directional_sequences(self):
        reader, phone = create_session_pair()

        request = b'{"reader_id":"reader-1","user_name":"private"}'
        encrypted_request = reader.encrypt(request, "registration")
        self.assertNotIn(b"private", encrypted_request)
        self.assertEqual(sequence(encrypted_request), 0)
        self.assertEqual(phone.decrypt(encrypted_request, "registration"), request)

        response = b'{"user_id":"user-1","signature":"secret"}'
        encrypted_response = phone.encrypt(response, "authentication")
        self.assertEqual(sequence(encrypted_response), 0)
        self.assertEqual(reader.decrypt(encrypted_response, "authentication"), response)

        self.assertEqual(sequence(reader.encrypt(b"second", "registration")), 1)
        self.assertEqual(sequence(phone.encrypt(b"second", "authentication")), 1)

    def test_tampering_does_not_advance_receive_sequence(self):
        reader, phone = create_session_pair()
        encrypted = reader.encrypt(b"private", "registration")
        tampered = bytearray(encrypted)
        tampered[-1] ^= 0x01

        with self.assertRaises(InvalidTag):
            phone.decrypt(bytes(tampered), "registration")
        self.assertEqual(phone.decrypt(encrypted, "registration"), b"private")

    def test_duplicate_sequence_is_rejected(self):
        reader, phone = create_session_pair()
        encrypted = reader.encrypt(b"private", "registration")
        phone.decrypt(encrypted, "registration")

        with self.assertRaises(ProtocolCryptoError):
            phone.decrypt(encrypted, "registration")

    def test_skipped_and_out_of_order_sequences_are_rejected_without_advancing_counter(self):
        reader, phone = create_session_pair()
        first = reader.encrypt(b"first", "registration")
        second = reader.encrypt(b"second", "registration")

        with self.assertRaises(ProtocolCryptoError):
            phone.decrypt(second, "registration")
        self.assertEqual(phone.decrypt(first, "registration"), b"first")
        self.assertEqual(phone.decrypt(second, "registration"), b"second")

    def test_sequence_direction_and_purpose_are_authenticated(self):
        reader = fixed_session(is_initiator=True)
        phone = fixed_session(is_initiator=False)
        encrypted = reader.encrypt(b"private", "registration")

        with self.assertRaises(InvalidTag):
            reader.decrypt(encrypted, "registration")
        with self.assertRaises(InvalidTag):
            phone.decrypt(encrypted, "authentication")

        changed_sequence = bytearray(encrypted)
        changed_sequence[1 + SESSION_ID_LENGTH + SEQUENCE_LENGTH - 1] = 1
        receiver_expecting_one = fixed_session(is_initiator=False)
        receiver_expecting_one._receive_counter = 1
        with self.assertRaises(InvalidTag):
            receiver_expecting_one.decrypt(bytes(changed_sequence), "registration")

        self.assertEqual(phone.decrypt(encrypted, "registration"), b"private")

    def test_failed_encryption_does_not_advance_send_sequence(self):
        reader, _ = create_session_pair()

        with self.assertRaises(ProtocolCryptoError):
            reader.encrypt(b"private", "")

        self.assertEqual(sequence(reader.encrypt(b"private", "registration")), 0)

    def test_new_sessions_reset_both_directional_counters(self):
        first_reader, first_phone = create_session_pair()
        first_reader.encrypt(b"one", "registration")
        first_phone.encrypt(b"one", "authentication")

        second_reader, second_phone = create_session_pair()
        self.assertEqual(sequence(second_reader.encrypt(b"two", "registration")), 0)
        self.assertEqual(sequence(second_phone.encrypt(b"two", "authentication")), 0)

    def test_exhausted_counters_cannot_wrap(self):
        exhausted_sender = fixed_session(is_initiator=True)
        exhausted_sender._send_counter = MAX_SEQUENCE
        with self.assertRaises(ProtocolCryptoError):
            exhausted_sender.encrypt(b"private", "registration")
        phone_envelope = fixed_session(is_initiator=False).encrypt(b"private", "authentication")
        with self.assertRaises(ProtocolCryptoError):
            exhausted_sender.decrypt(phone_envelope, "authentication")

        sender = fixed_session(is_initiator=True)
        exhausted_receiver = fixed_session(is_initiator=False)
        exhausted_receiver._receive_counter = MAX_SEQUENCE
        encrypted = sender.encrypt(b"private", "registration")
        with self.assertRaises(ProtocolCryptoError):
            exhausted_receiver.decrypt(encrypted, "registration")
        with self.assertRaises(ProtocolCryptoError):
            exhausted_receiver.encrypt(b"private", "authentication")

    def test_matches_shared_reference_vector(self):
        session = fixed_session(is_initiator=True)
        android_reference_envelope = bytes.fromhex(
            "02000102030405060708090a0b0c0d0e0f0000000000000000000102030405060708090a0b"
            "8df733b07a43a68613ff843eff9f722748b8cecc728ceab45b1b4fabc0341a00d6bd7fc118"
        )

        self.assertEqual(
            session.decrypt(android_reference_envelope, "registration"),
            b'{"user_name":"Alice"}',
        )


if __name__ == "__main__":
    unittest.main()
