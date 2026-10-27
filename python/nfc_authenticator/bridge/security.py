from __future__ import annotations

import base64
import json
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from nfc_authenticator.protocol_v4 import AssertionDeliveryRequest, AuthorizationRequest


class CertificateRequestSigner:
    """Sign typed v4 requests; this can be replaced by a KMS/HSM adapter."""

    def __init__(self, private_key_path: str | Path, certificate_chain_path: str | Path) -> None:
        self._key = serialization.load_pem_private_key(Path(private_key_path).read_bytes(), password=None)
        self._certificates = _load_certificates(Path(certificate_chain_path).read_bytes())
        if not self._certificates:
            raise ValueError("Certificate chain is empty")
        leaf = self._certificates[0].public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        own = self._key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        if leaf != own:
            raise ValueError("Certificate does not match request signing key")

    async def sign(self, request: AuthorizationRequest | AssertionDeliveryRequest) -> dict:
        payload = request.payload()
        if isinstance(self._key, ec.EllipticCurvePrivateKey):
            algorithm = "ECDSA_SHA256"
            signature = self._key.sign(payload, ec.ECDSA(hashes.SHA256()))
        elif isinstance(self._key, rsa.RSAPrivateKey):
            algorithm = "RSA_PSS_SHA256"
            signature = self._key.sign(
                payload,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=hashes.SHA256().digest_size),
                hashes.SHA256(),
            )
        else:
            raise TypeError("Request signing key must be EC or RSA")
        return {
            "request": request.document(),
            "message_type": "assertion_delivery" if isinstance(request, AssertionDeliveryRequest) else "authorization",
            "signature_algorithm": algorithm,
            "signature": base64.b64encode(signature).decode("ascii"),
            "certificate_chain": [
                base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode("ascii")
                for cert in self._certificates
            ],
        }

    async def sign_manifest(self, manifest: dict) -> dict:
        payload = b"NFCAuth-v4-provider-manifest\x00" + json.dumps(
            manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        if isinstance(self._key, ec.EllipticCurvePrivateKey):
            algorithm = "ECDSA_SHA256"
            signature = self._key.sign(payload, ec.ECDSA(hashes.SHA256()))
        elif isinstance(self._key, rsa.RSAPrivateKey):
            algorithm = "RSA_PSS_SHA256"
            signature = self._key.sign(
                payload,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=hashes.SHA256().digest_size),
                hashes.SHA256(),
            )
        else:
            raise TypeError("Manifest signing key must be EC or RSA")
        return {
            "manifest": manifest,
            "signature_algorithm": algorithm,
            "signature": base64.b64encode(signature).decode("ascii"),
            "certificate_chain": [
                base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode("ascii")
                for cert in self._certificates
            ],
        }


def verify_signed_request(value: dict, request: AuthorizationRequest | AssertionDeliveryRequest) -> None:
    leaf = x509.load_der_x509_certificate(base64.b64decode(value["certificate_chain"][0], validate=True))
    signature = base64.b64decode(value["signature"], validate=True)
    public_key = leaf.public_key()
    if value["signature_algorithm"] == "ECDSA_SHA256" and isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key.verify(signature, request.payload(), ec.ECDSA(hashes.SHA256()))
    elif value["signature_algorithm"] == "RSA_PSS_SHA256" and isinstance(public_key, rsa.RSAPublicKey):
        public_key.verify(
            signature,
            request.payload(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=hashes.SHA256().digest_size),
            hashes.SHA256(),
        )
    else:
        raise ValueError("Certificate and request signature algorithm do not match")


def _load_certificates(encoded: bytes) -> list[x509.Certificate]:
    marker = b"-----END CERTIFICATE-----"
    return [
        x509.load_pem_x509_certificate(block + marker + b"\n")
        for block in encoded.split(marker)
        if b"-----BEGIN CERTIFICATE-----" in block
    ]
