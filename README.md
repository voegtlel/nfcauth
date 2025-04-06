# NFC Authentication System

A secure Android application that acts as an NFC tag for authentication, working in conjunction with a Python NFC reader. The system uses public-key cryptography for secure authentication.

## Features

### Device Registration
- Secure registration of Android devices with unique names
- Generation of unique user IDs and key pairs for each device
- Local SQLite database storage for device information
- User-friendly registration dialog interface
- Real-time status updates during registration process

### Authentication
- Fast and secure NFC-based device authentication
- Public-key cryptography for secure authentication
- Timestamp-based authentication data
- Support for multiple registered devices
- Background NFC service for continuous operation

### Security
- Uses Android KeyStore for secure key storage
- Implements asymmetric encryption for authentication
- Unique user IDs for each registered device
- Secure storage of public keys
- Protected NFC communication

### Workflows

Data structures on the reader (the Python NFC reader app):
 - Database with the user data
   - Public key of the user registered reader
   - Name of the user
   - UID of the user
 - Config:
   - It's own human readable name
   - A unique identifier (UID)
Data structures on the Android App:
 - Database with registered readers
   - The reader UID
   - The reader name
   - Own UID for this reader
   - Own name for this reader
 - Own private/public key for this reader (using a post-quantum algorithm)

#### Registration Workflow
1. The reader is put into registration mode (here: run with "register" cmd argument)
2. The user hold the android device to the NFC reader
3. During the initial exchange, the android app will detect that the reader is in registration mode, and receive name and uid for the reader.
4. The device may be removed now.
5. The android app will open and prompt the user with their name and generate a private/public key pair and random userid
6. The android app will, after confirmation, prompt the user to hold the device at the reader again.
7. (consequently, the reader will send it's identification again, which must match what was previously sent)
8. The app sends the name, user id and public key to the reader
9. A trial authentication with those credentials is performed (show info to the user in the app).
10. If successful, the android app and reader will each store the corresponding information in their databases

#### Authentication Workflow
1. The reader is in authentication mode (here: run with "authenticate" cmd argument)
2. The android device is held to the reader
3. The reader sends it's uid and name to the app with a timestamp
4. The android app fetches the registered entry for the readers uid from it's database and gets the public/private key
5. If valid, the app requests biometric authentication if available
6. The android app computes a signature for the reader's request and sends that with the user's uid to the reader
7. The reader verifies the signature using the known public key for the app user and if valid, triggers the user authentication

### Technical Details

#### NFC Communication
- Android device emulates an NFC tag
- NDEF message format for data exchange
- Foreground dispatch system for priority handling
- Wake lock implementation for reliable background operation with minimal user annoyance

## Requirements

### Android Device
- Android 9.0 (API level 28) or higher
- NFC hardware support
- Biometric hardware (optional)

### Python NFC Reader
- Python 3.7+
- NFC reader hardware (e.g., pn532)
- Required Python packages:
  - RPi.GPIO
  - adafruit_pn532
  - SQLite3

### Development
- Android Studio Arctic Fox or newer
- Kotlin 1.5+
- Gradle 7.0+
- Android SDK 28+

## Installation

### Android App
1. Clone the repository:
```bash
git clone https://github.com/yourusername/androidauth.git
```

2. Open the project in Android Studio

3. Build and run:
```bash
./gradlew installDebug
```

### Python NFC Reader
1. Install required Python packages:
```bash
pip install RPi.GPIO MFRC522
```

2. Connect the NFC reader hardware to your Raspberry Pi

3. Run the Python script:
```bash
python nfc_reader.py
```

## Usage

## Architecture

### Components
- `MainActivity`: Handles user interface and device registration
- `NfcService`: Background service for NFC tag emulation
- `AuthDatabase`: SQLite database management
- `KeyManager`: Cryptographic operations and key management
- `nfc_reader.py`: Python script for NFC reader operations

### Security Considerations
- Keys are generated and stored in the Android KeyStore
- Each device has a unique identifier and key pair
- Authentication data includes timestamps
- Background service runs with minimal privileges

## Debugging

The application includes comprehensive logging for debugging purposes:
- NFC operations
- Database transactions
- Cryptographic operations
- Registration process
- Authentication flow

Logs can be viewed using:
```bash
adb logcat | grep -E "MainActivity|NfcService"
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details. 