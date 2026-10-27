# Protocol v3 security analysis

## Who talks to whom

1. **Reader → service signing API:** Over HTTPS using a scoped reader
   credential (mTLS preferred), the reader submits typed ephemeral transcript
   fields. The service signs with the private key corresponding to its public
   Web-PKI certificate. This API is the only network-dependent step.
2. **Reader ↔ phone:** NFC transports an ephemeral P-256 ECDH exchange. The
   phone challenges the service; the reader returns the certificate chain and
   ECDSA/SHA-256 or RSA-PSS/SHA-256 transcript signature inside a provisional
   AES-256-GCM channel. After offline certificate verification, both rekey.
3. **Phone → service:** During registration, the phone sends the approved alias
   and profile-specific public authentication key under P-256 ECDH,
   HKDF-SHA-256, and AES-256-GCM directly to the service encryption key.
4. **Service ↔ phone:** Later discovery and authentication travel under the
   authenticated NFC session and credential AES-256-GCM key. The phone proves
   its profile-specific P-256 private key by ECDSA/SHA-256.
5. **Service ↔ phone after success:** Both derive the next credential key with
   HKDF-SHA-256. AES-GCM commit/ACK messages demonstrate possession of that new
   key before either peer drops the previous epoch.

The app developer and NFC intermediaries have no protocol key that can decrypt
registration or authentication contents.

## Security properties

- Passive NFC capture reveals ephemeral public keys, random session IDs, and
  ciphertext, but no personal identifier or authentication payload.
- Fresh challenges, directional counters, transcript binding, nonces, and
  transport binding reject offline replay, reflection, reordering, and
  cross-session substitution.
- The service certificate authenticates the exact manifest, profile, challenge,
  session, and both ephemeral keys. Merely encrypting to a key is not treated as
  service authentication.
- Service/profile-specific credential references and signing keys prevent
  normal cross-service and biometric/possession correlation.
- Exact-field validation prevents the phone from transmitting fields not
  disclosed in the approved manifest.
- Biometric downgrade is prevented by distinct AIDs and keys. A reader cannot
  request possession behavior after selecting the biometric endpoint.
- Crash-safe epoch overlap prevents key drift without persisting an
  authentication attempt or commit/ACK payload.

## Gaps and attack vectors

### Live relay

NFC timing and transcript binding stop recording/replay but do not implement
distance bounding. An attacker that transparently relays the live APDU exchange
can extend NFC range. A fresh biometric and transaction-specific confirmation
reduce impact; high-value deployments need relay-resistant hardware or distance
bounding outside this protocol.

### Public CA semantics

A valid chain and DNS SAN establish control of `service_origin`, not the legal
truth of `operator_name`, purposes, or policy. The UI therefore says
domain-verified and does not claim that the operator is trustworthy or legally
compliant.

### Offline revocation

The phone checks validity dates and its local trust store, but offline NFC
cannot reliably fetch OCSP or CRLs. A revoked certificate may remain accepted
until the device learns updated state or the certificate expires. Services
should use short-lived certificates and protect signing keys.

### Reader-to-service signing API

A stolen reader API credential can request valid session signatures. Use a
unique, scoped, rotatable credential per reader; prefer mTLS or hardware-backed
credentials; rate-limit and audit without logging transcript secrets. The API
must accept typed fields, reconstruct the canonical payload, authorize the
service/profile, and reject arbitrary data so it cannot become a general
signing oracle.

Compromise between a reader and its service API can also authorize malicious
NFC sessions for that service. The backend must treat the reader boundary as a
security boundary and revoke compromised readers promptly.

### Phone and service compromise

Malware with sufficient Android privileges or a compromised service backend can
act as that endpoint. Android Keystore limits private-key export but cannot
protect a fully compromised device UI. The Python reference stores credential
keys in SQLite for clarity; production services should encrypt them with
KMS/HSM-backed keys and enforce account authorization around registration.

### Consent and privacy-policy validation

The phone validates HTTPS syntax and reachability, not legal sufficiency. A
service can publish misleading text. Policy fetching must retain strict HTTPS,
redirect, response-size, and private-address protections to avoid SSRF-like
behavior when implementations move validation to a server.

### Metadata and traffic analysis

Ciphertext length, NFC timing, AID/profile selection, certificate chain, and
service origin are observable. Padding is not currently specified. The protocol
protects contents, not all traffic metadata.

### Denial of service

An attacker can occupy NFC, trigger certificate validation, or exhaust signing
API rate limits. Payload/chain sizes, fragment counts, challenge lifetime, and
pending-attempt counts are bounded. Availability attacks do not reveal
credentials but can prevent login.

## Operational requirements

- Never log names, service or credential IDs, keys, certificates, raw APDUs,
  nonces, signatures, plaintext, or decrypted objects.
- Keep service encryption keys and certificate signing keys separate.
- Rotate reader API credentials independently of Web-PKI and credential keys.
- Retain only active/fallback credential epochs; clear fallback after ACK.
- Treat a changed manifest, operator, purposes, profile, or encryption identity
  as a new consent event.
- Verify certificate and Android trust-store behavior on physical devices.
