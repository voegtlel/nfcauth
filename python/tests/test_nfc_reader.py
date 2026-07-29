from pathlib import Path

from nfc_authenticator.nfc_reader import (
    AUTHENTICATION,
    MAX_COMMAND_DATA,
    AuthDatabase,
    NFCAuthenticator,
    NFCConnector,
    ReaderConfig,
)
from nfc_authenticator.protocol_crypto import (
    DIRECTION_PHONE_TO_READER,
    DIRECTION_READER_TO_PHONE,
    NfcSession,
)
from nfc_authenticator.service_manifest import ServiceIdentity, ServicePrivacyConfig


class RecordingConnector(NFCConnector):
    def __init__(self):
        self.commands: list[bytes] = []

    def in_data_exchange(self, command: bytes, response_length: int = 2) -> bytes:
        self.commands.append(command)
        return b"\x90\x00"

    def wait_for_card(self) -> bytes:
        return b"\x01"


def test_encrypted_command_is_chunked_after_encryption(tmp_path: Path):
    connector = RecordingConnector()
    database = AuthDatabase(tmp_path / "reader.db")
    config = ReaderConfig(
        privacy=ServicePrivacyConfig(
            service_id="service",
            service_name="Service",
            operator_name="Operator",
            privacy_policy_url="https://example.com/privacy",
            privacy_notice_version="1",
            requested_fields=(
                "service_user_id",
                "authentication_public_key",
            ),
            purposes={
                "service_user_id": "Identify the local account.",
                "authentication_public_key": "Verify authentication.",
            },
            data_deletion_url_or_contact="privacy@example.com",
        ),
        auth="background",
    )
    authenticator = NFCAuthenticator(
        connector,
        config,
        ServiceIdentity.load_or_create(tmp_path / "identity.json"),
        database,
    )
    authenticator.session = NfcSession(
        b"s" * 16,
        b"k" * 32,
        DIRECTION_READER_TO_PHONE,
        DIRECTION_PHONE_TO_READER,
    )
    plaintext = b"private-registration-data" * 40

    assert authenticator.send_encrypted_command(
        AUTHENTICATION,
        plaintext,
        "authentication",
    ) == b"\x90\x00"

    assert len(connector.commands) > 1
    assert all(command[4] <= MAX_COMMAND_DATA for command in connector.commands)
    assert [command[2] for command in connector.commands] == list(
        range(len(connector.commands))
    )
    assert all(command[3] == 0x80 for command in connector.commands[:-1])
    assert connector.commands[-1][3] == 0x00

    encrypted = b"".join(command[5:] for command in connector.commands)
    assert plaintext not in encrypted
    phone_session = NfcSession(
        b"s" * 16,
        b"k" * 32,
        DIRECTION_PHONE_TO_READER,
        DIRECTION_READER_TO_PHONE,
    )
    assert phone_session.decrypt(encrypted, "authentication") == plaintext
    database.close()
