"""Minimal mTLS reference API for enrolled nfcauth credentials.

This serial, single-process example demonstrates the protocol boundary, not a
production account/session server. Provision credentials with the reader's
registration mode first. Configure TLS and allowed reader certificate hashes;
there is no unauthenticated or plaintext mode.
"""

import argparse
import hashlib
import json
import ssl
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag

from nfc_authenticator.backend import ReferenceBackend
from nfc_authenticator.nfc_reader import AuthDatabase
from nfc_authenticator.service_manifest import ServiceIdentity, ServicePrivacyConfig


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    if not Path(config["service_identity"]).is_file():
        parser.error("Provision the service identity before starting this API")
    identity = ServiceIdentity.load_or_create(config["service_identity"])
    privacy = ServicePrivacyConfig(**config["privacy"])
    database = AuthDatabase(config["credential_database"])
    readers = {
        fingerprint: ReferenceBackend(identity, privacy, database)
        for fingerprint in config["reader_certificate_sha256"]
    }
    if not readers:
        parser.error("Authorize at least one reader certificate fingerprint")

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass  # Do not log identity hints or cryptographic envelopes.

        def respond(self, code, value):
            raw = json.dumps(value).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(raw)

        def do_POST(self):
            certificate = self.connection.getpeercert(binary_form=True)
            backend = readers.get(hashlib.sha256(certificate or b"").hexdigest())
            if backend is None:
                self.respond(403, {"error": "Reader certificate is not authorized"})
                return
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 < size <= 65536:
                    raise TypeError()
                body = json.loads(self.rfile.read(size))
                if not isinstance(body, dict):
                    raise TypeError()
                if self.path == "/discovery":
                    result = backend.start_discovery(body["transport_binding"])
                elif self.path == "/challenges":
                    result = backend.create_challenge(body["discovery_id"], body["response"])
                elif self.path == "/authenticate":
                    result = {"user_id": backend.complete(body["login_id"], body["response"])}
                else:
                    self.respond(404, {"error": "Unknown endpoint"})
                    return
                self.respond(200, result)
            except (ValueError, KeyError, TypeError, InvalidSignature, InvalidTag):
                self.respond(401, {"error": "Request invalid or authentication failed"})

    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_cert_chain(config["certificate"], config["private_key"])
    tls.load_verify_locations(config["reader_ca"])
    tls.verify_mode = ssl.CERT_REQUIRED
    server = HTTPServer((config.get("host", "127.0.0.1"), config.get("port", 8443)), Handler)
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        database.close()


if __name__ == "__main__":
    main()
