"""Offline Web-PKI authentication for the NFC Auth v3 session transcript."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import ssl
import struct
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from .service_manifest import PROTOCOL_VERSION

DOMAIN = b"NFCAuth-v3-server-auth\x00"
SIGNATURE_ECDSA_SHA256 = "ECDSA_SHA256"
SIGNATURE_RSA_PSS_SHA256 = "RSA_PSS_SHA256"


def _field(value: bytes) -> bytes:
    return struct.pack(">I", len(value)) + value


@dataclass(frozen=True)
class SessionAuthenticationContext:
    service_origin: str
    service_id: str
    authentication_profile: str
    manifest_hash: str
    session_id: bytes
    phone_challenge: bytes
    reader_ephemeral_public_key: bytes
    phone_ephemeral_public_key: bytes

    def payload(self) -> bytes:
        if len(self.session_id) != 16 or len(self.phone_challenge) != 32:
            raise ValueError("Invalid session authentication nonce")
        if len(self.reader_ephemeral_public_key) != 65 or len(self.phone_ephemeral_public_key) != 65:
            raise ValueError("Invalid session authentication public key")
        if len(self.manifest_hash) != 64:
            raise ValueError("Invalid manifest hash")
        values = (
            self.service_origin.encode(),
            self.service_id.encode(),
            self.authentication_profile.encode(),
            bytes.fromhex(self.manifest_hash),
            self.session_id,
            self.phone_challenge,
            self.reader_ephemeral_public_key,
            self.phone_ephemeral_public_key,
        )
        return DOMAIN + bytes((PROTOCOL_VERSION,)) + b"".join(_field(value) for value in values)

    def to_json(self) -> dict:
        return {
            "protocol_version": PROTOCOL_VERSION,
            "service_origin": self.service_origin,
            "service_id": self.service_id,
            "authentication_profile": self.authentication_profile,
            "manifest_hash": self.manifest_hash,
            "session_id": self.session_id.hex(),
            "phone_challenge": self.phone_challenge.hex(),
            "reader_ephemeral_public_key": base64.b64encode(self.reader_ephemeral_public_key).decode("ascii"),
            "phone_ephemeral_public_key": base64.b64encode(self.phone_ephemeral_public_key).decode("ascii"),
        }

    @classmethod
    def from_json(cls, value: dict) -> SessionAuthenticationContext:
        if value.get("protocol_version") != PROTOCOL_VERSION:
            raise ValueError("Unsupported signing request protocol")
        return cls(
            service_origin=value["service_origin"],
            service_id=value["service_id"],
            authentication_profile=value["authentication_profile"],
            manifest_hash=value["manifest_hash"],
            session_id=bytes.fromhex(value["session_id"]),
            phone_challenge=bytes.fromhex(value["phone_challenge"]),
            reader_ephemeral_public_key=base64.b64decode(value["reader_ephemeral_public_key"], validate=True),
            phone_ephemeral_public_key=base64.b64decode(value["phone_ephemeral_public_key"], validate=True),
        )


@dataclass(frozen=True)
class SessionAuthentication:
    certificate_chain: tuple[str, ...]
    signature_algorithm: str
    signature: str

    def as_dict(self, manifest: dict) -> dict:
        return {
            "protocol_version": PROTOCOL_VERSION,
            "manifest": manifest,
            "certificate_chain": list(self.certificate_chain),
            "signature_algorithm": self.signature_algorithm,
            "transcript_signature": self.signature,
        }


class SessionSigningClient(Protocol):
    def sign(self, context: SessionAuthenticationContext) -> SessionAuthentication: ...


class CertificateSessionSigner:
    """Local signing implementation and reference for a restricted signing API."""

    def __init__(self, private_key_path: str | Path, certificate_chain_path: str | Path) -> None:
        self.private_key = serialization.load_pem_private_key(Path(private_key_path).read_bytes(), password=None)
        certificates = _load_pem_certificates(Path(certificate_chain_path).read_bytes())
        if not certificates:
            raise ValueError("Certificate chain is empty")
        leaf_public = (
            certificates[0]
            .public_key()
            .public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        private_public = self.private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if leaf_public != private_public:
            raise ValueError("Certificate leaf does not match the signing private key")
        self.chain = tuple(
            base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode("ascii") for cert in certificates
        )

    def sign(self, context: SessionAuthenticationContext) -> SessionAuthentication:
        payload = context.payload()
        if isinstance(self.private_key, ec.EllipticCurvePrivateKey):
            algorithm = SIGNATURE_ECDSA_SHA256
            signature = self.private_key.sign(payload, ec.ECDSA(hashes.SHA256()))
        elif isinstance(self.private_key, rsa.RSAPrivateKey):
            algorithm = SIGNATURE_RSA_PSS_SHA256
            signature = self.private_key.sign(
                payload,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=hashes.SHA256().digest_size),
                hashes.SHA256(),
            )
        else:
            raise TypeError("NFC session signing requires an EC or RSA certificate key")
        return SessionAuthentication(self.chain, algorithm, base64.b64encode(signature).decode("ascii"))


class HttpSessionSigningClient:
    """Reader client for a narrowly scoped service signing endpoint."""

    def __init__(
        self,
        url: str,
        *,
        api_key_env: str = "NFC_AUTH_SIGNING_API_KEY",
        timeout_seconds: float = 2.0,
    ) -> None:
        if not url.startswith("https://"):
            raise ValueError("The signing API must use HTTPS")
        self.url = url
        self.api_key_env = api_key_env
        self.timeout_seconds = timeout_seconds

    def sign(self, context: SessionAuthenticationContext) -> SessionAuthentication:
        api_key = os.environ.get(self.api_key_env)
        if not api_key:
            raise RuntimeError(f"Signing API credential is missing from {self.api_key_env}")
        request = urllib.request.Request(
            self.url,
            data=json.dumps(context.to_json(), separators=(",", ":")).encode(),
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(
            request,
            timeout=self.timeout_seconds,
            context=ssl.create_default_context(),
        ) as response:
            document = json.loads(response.read(64 * 1024))
        chain = document.get("certificate_chain")
        if not isinstance(chain, list) or not chain or not all(isinstance(item, str) for item in chain):
            raise ValueError("Signing API returned an invalid certificate chain")
        return SessionAuthentication(
            tuple(chain),
            str(document["signature_algorithm"]),
            str(document["transcript_signature"]),
        )


def transcript_hash(context: SessionAuthenticationContext) -> bytes:
    return hashlib.sha256(context.payload()).digest()


def verify_signature(authentication: SessionAuthentication, context: SessionAuthenticationContext) -> None:
    """Test/reference verification; Android additionally validates PKIX and hostname."""

    leaf = x509.load_der_x509_certificate(base64.b64decode(authentication.certificate_chain[0], validate=True))
    signature = base64.b64decode(authentication.signature, validate=True)
    public_key = leaf.public_key()
    if authentication.signature_algorithm == SIGNATURE_ECDSA_SHA256 and isinstance(
        public_key, ec.EllipticCurvePublicKey
    ):
        public_key.verify(signature, context.payload(), ec.ECDSA(hashes.SHA256()))
    elif authentication.signature_algorithm == SIGNATURE_RSA_PSS_SHA256 and isinstance(public_key, rsa.RSAPublicKey):
        public_key.verify(
            signature,
            context.payload(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=hashes.SHA256().digest_size),
            hashes.SHA256(),
        )
    else:
        raise ValueError("Certificate key and signature algorithm do not match")


def _load_pem_certificates(encoded: bytes) -> list[x509.Certificate]:
    marker = b"-----END CERTIFICATE-----"
    certificates = []
    for block in encoded.split(marker):
        if b"-----BEGIN CERTIFICATE-----" not in block:
            continue
        certificates.append(x509.load_pem_x509_certificate(block + marker + b"\n"))
    return certificates
