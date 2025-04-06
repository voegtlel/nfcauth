import os
import traceback
from typing import Literal
import json
import time
import logging
import base64
import argparse
import uuid
from dataclasses import dataclass
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from ctypes import *
import nfc

# NFC Commands
_COMMAND_INDATAEXCHANGE = 0x40

_CMD_ADPU_SELECT_APPLICATION = b"\x00\xA4\x04\x00"
_CMD_ADPU_USER_REGISTRATION = b"\xD0\x01\x00\x00"
_CMD_ADPU_USER_REGISTRATION_COMPLETE = b"\xD0\x01\x00\x01"
_CMD_ADPU_USER_AUTHENTICATION = b"\xD0\x02\x00\x00"

_CMD_ADPU_GET_RESPONSE = b"\x00\xC0\x00\x00"

# FALCON parameters
FALCON_SIG_LENGTH = 690  # Length of Falcon-512 signature in bytes
FALCON_PUBLIC_KEY_LENGTH = 897  # Length of Falcon-512 public key in bytes
FALCON_SECRET_KEY_LENGTH = 1281  # Length of Falcon-512 private key in bytes

# Set up detailed logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class NFCReaderException(Exception):
    pass

# Mock reader configuration
@dataclass
class ReaderConfig:
    reader_id: str
    reader_name: str
    app_id: str
    protocol_version: int
    auth: Literal["background", "biometric"]
    aid: bytes
    nonce_length: int

# Global reader configuration
READER_CONFIG = ReaderConfig(
    reader_id="test-reader-1234",
    reader_name="Test NFC Reader",
    app_id="de.infornautik.nfcauth",
    protocol_version=1,
    auth="background",
    aid=bytes.fromhex("F064652E696E666F726E617574696B"),
    nonce_length=16,
)

def create_apdu_command(command: int, data: bytes = b'') -> bytearray:
    """Create an APDU command"""
    apdu = bytearray([command])  # Command byte
    apdu.extend(len(data).to_bytes(1, 'big'))  # Length of data
    apdu.extend(data)  # Data
    return apdu


class AuthDatabase:
    def __init__(self, db_path="auth.db"):
        import sqlite3
        self.db_path = db_path
        logger.debug(f"Initializing database at {db_path}")
        self.conn = sqlite3.connect(db_path)
        self.cursor = self.conn.cursor()
        self._create_tables()

    def _create_tables(self):
        """Create necessary database tables if they don't exist"""
        logger.debug("Creating database tables if they don't exist")
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS registered_devices (
                user_id TEXT PRIMARY KEY,
                user_name TEXT NOT NULL,
                public_key TEXT NOT NULL,
                registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS reader_config (
                id INTEGER PRIMARY KEY,
                reader_id TEXT UNIQUE NOT NULL,
                reader_name TEXT NOT NULL
            )
        ''')
        self.conn.commit()
        logger.debug("Database tables created/verified")

    def setup_reader(self, reader_name: str) -> str:
        """Set up reader configuration and return reader ID"""
        reader_id = str(uuid.uuid4())
        self.cursor.execute(
            'INSERT INTO reader_config (reader_id, reader_name) VALUES (?, ?)',
            (reader_id, reader_name)
        )
        self.conn.commit()
        logger.info(f"Reader configured with ID: {reader_id}, Name: {reader_name}")
        return reader_id

    def get_reader_info(self) -> tuple:
        """Get reader ID and name"""
        self.cursor.execute('SELECT reader_id, reader_name FROM reader_config LIMIT 1')
        result = self.cursor.fetchone()
        if not result:
            return None, None
        return result

    def register_device(self, user_id: str, user_name: str, public_key: str) -> bool:
        """Register a new device with user info and public key"""
        logger.debug(f"Attempting to register device for user: {user_name} (ID: {user_id})")
        self.cursor.execute(
            'INSERT INTO registered_devices (user_id, user_name, public_key) VALUES (?, ?, ?)',
            (user_id, user_name, public_key)
        )
        self.conn.commit()
        logger.info(f"Successfully registered device for user: {user_name}")
        return True
    
    def remove_registration(self, user_id: str) -> bool:
        """Remove registration for a user"""
        self.cursor.execute('DELETE FROM registered_devices WHERE user_id = ?', (user_id,))
        self.conn.commit()
        logger.info(f"Successfully removed registration for user: {user_id}")
        return True

    def get_device_info(self, user_id: str) -> tuple:
        """Get device information including user name and public key"""
        logger.debug(f"Retrieving device info for user_id: {user_id}")
        self.cursor.execute(
            'SELECT user_name, public_key FROM registered_devices WHERE user_id = ?',
            (user_id,)
        )
        result = self.cursor.fetchone()
        if result:
            logger.debug(f"Found device info for user: {result[0]}")
            return result
        logger.debug("No device info found")
        return None, None

    def get_user_public_key(self, user_id: str) -> bytes:
        """Get user public key"""
        self.cursor.execute(
            'SELECT public_key FROM registered_devices WHERE user_id = ?',
            (user_id,)
        )
        return self.cursor.fetchone()[0]

    def close(self):
        """Close database connection"""
        logger.debug("Closing database connection")
        self.conn.close()
        logger.debug("Database connection closed")


class NFCAuthenticator:
    def __init__(self):
        self.context = None
        self.device = None
        self.is_running = False
        self.db = AuthDatabase()
        self.pending_registration = None
        logger.debug("Initializing NFC Authenticator")

    def connect(self) -> bool:
        """Connect to the NFC reader using libnfc"""
        try:
            logger.debug("Opening NFC context")
            self.context = nfc.Context()
            
            logger.debug("Looking for available NFC devices")
            connstrings = self.context.list_devices()
            if not connstrings:
                raise NFCReaderException("No NFC device found")
            
            logger.debug(f"Found device: {connstrings[0]}")
            self.device = self.context.open(connstrings[0])
            
            logger.debug("Initializing NFC device as initiator")
            self.device.initiator_init()
            
            logger.info(f"Connected to NFC device: {self.device}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to connect to NFC device: {e}")
            raise NFCReaderException("Failed to connect to NFC device") from e

    def in_data_exchange(self, cmd: bytes, response_length: int = 2) -> bytes:
        """Send a command to the NFC tag and return the response using libnfc"""
        assert len(cmd) <= 254
        assert response_length <= 258
        
        try:
            print(f"Sending command: {', '.join(f'0x{x:02X}' for x in cmd)}")
            
            # Send command and receive response
            response = self.device.initiator_transceive_bytes(cmd, response_length)
            
            if not response:
                raise NFCReaderException("Failed to send command")
                
            print(f"Received response: {', '.join(f'0x{x:02X}' for x in response)}")
            
            # Check status byte
            if response[0] != 0x00:
                raise NFCReaderException(f"Command failed: {', '.join(f'0x{x:02X}' for x in response)}")
                
            return response[1:]
            
        except Exception as e:
            logger.error(f"Error in data exchange: {e}")
            raise NFCReaderException("Failed to exchange data with card") from e

    def cmd_select_application(self) -> bool:
        """Select the application using its AID"""
        assert len(READER_CONFIG.aid) <= 16
        # Create SELECT APDU command
        select_apdu = _CMD_ADPU_SELECT_APPLICATION + len(READER_CONFIG.aid).to_bytes(1, 'big') + READER_CONFIG.aid
        
        # Send SELECT command using InDataExchange
        response = self.in_data_exchange(select_apdu, response_length=2)
        
        # Check response status (0x9000 means success)
        if len(response) >= 2 and response[-2:] == b'\x90\x00':
            logger.info("Application selected successfully")
            return True
        else:
            raise NFCReaderException(f"Failed to select application: {', '.join(f'0x{x:02X}' for x in response)}")

    def cmd_registration_request(self, header: bytes) -> bytes | None:
        """Send registration request to device"""
        # Create command
        assert len(header) <= 250
        select_apdu = _CMD_ADPU_USER_REGISTRATION + len(header).to_bytes(1, 'big') + header
        logger.info(f"Sending registration request: {select_apdu}")
        res = self.in_data_exchange(select_apdu, response_length=2)
        if res == b'\x90\x00':
            logger.info("Registration request sent successfully, still needs processing")
            return None
        elif res[0] == 0x61:
            logger.info("Registration request sent successfully, receiving response")
            return self.get_response(res[1])
        else:
            raise NFCReaderException(f"Failed to send registration request: {res}")
    
    def cmd_registration_complete(self) -> None:
        """Send registration complete to device"""
        select_apdu = _CMD_ADPU_USER_REGISTRATION_COMPLETE
        logger.info(f"Sending registration complete: {select_apdu}")
        res = self.in_data_exchange(select_apdu, response_length=2)
        if res != b'\x90\x00':
            raise NFCReaderException(f"Failed to send registration complete: {res}")
    
    def cmd_authentication_request(self, header: bytes) -> bytes:
        """Send authentication request to device"""
        # Create command
        assert len(header) <= 250
        select_apdu = _CMD_ADPU_USER_AUTHENTICATION + len(header).to_bytes(1, 'big') + header
        logger.info(f"Sending authentication request: {select_apdu}")
        res = self.in_data_exchange(select_apdu, response_length=2)
        if res[0] == 0x61:
            logger.info("Authentication request sent successfully, receiving response")
            return self.get_response(res[1])
        else:
            raise NFCReaderException(f"Failed to send authentication request: {res}")

    def get_response(self, frame_size: int = 0) -> bytes:
        """Get response from device"""
        received = []
        while True:
            if frame_size == 0 or frame_size > 250:
                frame_size = 250
            # Use the GET RESPONSE ADPU
            res = self.in_data_exchange(_CMD_ADPU_GET_RESPONSE + bytes((frame_size,)), response_length=frame_size + 2)
            if len(res) == frame_size + 2 and res[-2:] == b'\x90\x00':
                # Last chunk
                received.append(res[:-2])
                break
            elif len(res) == frame_size + 2 and res[-2] == 0x61:
                # More chunks
                received.append(res[:-2])
                # Next chunk size is in the first byte
                frame_size = res[-1]
            else:
                raise NFCReaderException(f"Failed to get response: {res}")
        return b''.join(received)

    def verify_signature(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify an ECDSA signature"""
        try:
            # Load the public key from DER format
            public_key_obj = serialization.load_der_public_key(base64.b64decode(public_key))

            if not isinstance(public_key_obj, ec.EllipticCurvePublicKey):
                raise NFCReaderException("Invalid public key type, expected EC key")

            # Verify the signature
            public_key_obj.verify(
                base64.b64decode(signature),
                message,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except InvalidSignature:
            return False
        except Exception as e:
            logger.error(f"Error verifying signature: {e}")
            raise NFCReaderException("Error verifying signature") from e

    def handle_registration_request(self) -> bytes | None:
        """Handle initial registration request"""
        # Use global reader config instead of database
        logger.info(f"Using reader: {READER_CONFIG.reader_name} (ID: {READER_CONFIG.reader_id})")
            
        # Send reader info to device
        registration_request = {
            "reader_id": READER_CONFIG.reader_id,
            "reader_name": READER_CONFIG.reader_name,
            "version": READER_CONFIG.protocol_version,
        }
        logger.info(f"Sending registration request: {registration_request}")

        json_data = json.dumps(registration_request)
        json_bytes = json_data.encode()

        return self.cmd_registration_request(json_bytes)
            
    def handle_registration_response(self, response: bytes) -> None:
        """Handle registration response from device"""
        if len(response) == 0:
            raise NFCReaderException("No registration response received")

        try:
            response = json.loads(response)
        except Exception as e:
            raise NFCReaderException(f"Failed to parse registration response {response}: {e}")

        # Extract registration data
        user_id = response.get("user_id")
        user_name = response.get("user_name")
        public_key = response.get("public_key")
        reader_id = response.get("reader_id")
        
        if not all([user_id, user_name, public_key, reader_id]):
            raise NFCReaderException("Invalid registration response")
            
        # Verify device UUID matches
        if reader_id != READER_CONFIG.reader_id:
            raise NFCReaderException("Device UUID mismatch")
            
        # Store registration
        if not self.db.register_device(user_id, user_name, public_key):
            raise NFCReaderException("Failed to store registration")

        try:
            # Send registration complete
            self.cmd_registration_complete()
        except Exception as e:
            self.db.remove_registration(user_id)
            raise
        logger.info("Registration completed successfully")

    def run_registration_mode(self):
        """Run in registration mode"""
        logger.info("Starting registration mode")
        logger.info("Waiting for NFC card to be presented...")
        
        while self.is_running:
            try:
                # Wait for a card using libnfc
                target = self.device.initiator_select_passive_target()
                if not target:
                    time.sleep(0.1)  # Small delay to prevent busy-waiting
                    continue
                    
                uid = target.nti.nai.abtUid[:target.nti.nai.szUidLen]
                logger.info(f"Card detected with UID: {uid.hex()}")

                if not self.cmd_select_application():
                    logger.error("Failed to select application")
                    continue
                
                # Now proceed with registration
                response = self.handle_registration_request()
                if response is not None:
                    # Read registration data
                    self.handle_registration_response(response)
                    logger.info("Registration successful")
                    self.is_running = False
                    break

                time.sleep(1)
            except KeyboardInterrupt:
                self.is_running = False
            except Exception as e:
                traceback.print_exc()
                logger.error(f"Error in registration mode: {e}")
                time.sleep(1)
        return False
    
    def generate_nonce(self) -> str:
        """Generate a random nonce"""
        return os.urandom(READER_CONFIG.nonce_length).hex()
    
    def handle_auth_request(self) -> bool:
        """Handle authentication request"""
        auth_request = {
            "reader_id": READER_CONFIG.reader_id,
            "version": READER_CONFIG.protocol_version,
            "auth": READER_CONFIG.auth,
            "nonce": self.generate_nonce(),
        }
        raw_request_data = json.dumps(auth_request).encode()
        raw_response = self.cmd_authentication_request(raw_request_data)
        
        if len(raw_response) == 0:
            raise NFCReaderException("No authentication response received")

        response = json.loads(raw_response)
        user_id = response.get("user_id")
        signature = response.get("signature")

        if not all([user_id, signature]):
            raise NFCReaderException("Invalid authentication response")
        
        public_key = self.db.get_user_public_key(user_id)
        if not public_key:
            raise NFCReaderException(f"User {user_id} not found")
        
        public_key = base64.b64decode(public_key)
            
        # Verify signature
        signature_bytes = base64.b64decode(signature)
        if not self.verify_signature(raw_request_data + user_id.encode(), signature_bytes, public_key):
            raise NFCReaderException(f"Invalid signature for user {user_id}")

        return True

    def run_authentication_mode(self):
        """Run in authentication mode"""
        logger.info("Starting authentication mode")
        logger.info("Waiting for NFC card to be presented...")
        
        while self.is_running:
            try:
                # Wait for a card using libnfc
                target = self.device.initiator_select_passive_target()
                if not target:
                    time.sleep(0.1)  # Small delay to prevent busy-waiting
                    continue
                    
                uid = target.nti.nai.abtUid[:target.nti.nai.szUidLen]
                logger.info(f"Card detected with UID: {uid.hex()}")

                self.cmd_select_application()
                
                if self.handle_auth_request():
                    logger.info("Authentication successful")
                    self.is_running = False
                    break

                time.sleep(1)
            except KeyboardInterrupt:
                self.is_running = False
            except Exception as e:
                traceback.print_exc()
                logger.error(f"Error in authentication mode: {e}")
                time.sleep(1)

    def run(self, mode: str):
        """Main entry point"""
        self.connect()

        self.is_running = True
        
        try:
            if mode == 'register':
                self.run_registration_mode()
            else:  # auth mode
                self.run_authentication_mode()
        finally:
            self.is_running = False
            if self.device:
                self.device.close()
            if self.context:
                self.context.close()
            self.db.close()


def main():
    parser = argparse.ArgumentParser(description='NFC Authentication System')
    parser.add_argument('mode', choices=['register', 'auth'], 
                      help='Mode to run in: register (for new device registration) or auth (for authentication)')
    args = parser.parse_args()

    authenticator = NFCAuthenticator()
    authenticator.run(args.mode)


if __name__ == '__main__':
    main() 