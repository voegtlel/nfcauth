# NFC Auth v4 security model

## Defended attacks

- Passive NFC capture exposes no identifier or authorization content.
- AEAD counters and session IDs reject replay, reflection and reordering.
- Provider signatures bind both ephemeral NFC keys, the phone challenge,
  terminal identity, exact audience/scopes/action, manifest and expiry.
- Phone assertions bind the provider request hash and cannot be widened by the
  terminal.
- Transactions are consumed once before token issuance.
- Keys are namespaced by canonical provider origin, service ID and profile to
  prevent cross-provider correlation, identifier collisions and biometric downgrade.
- Terminal policy independently caps audiences, scopes and assurance.
- Terminal M2M JWTs require the configured issuer, bridge audience, scope,
  RS256/ES256 signature, bounded lifetime and a provisioned subject. The signed
  NFC request derives its terminal identity from that verified subject.
- A stolen callback completion code cannot enroll without the phone key.
- Registration and renewal challenges are bounded, expire in memory, and are
  one-use. Expired credentials cannot authenticate or renew.
- OIDC signing algorithms are explicitly limited to RS256 and ES256; the
  provider's JWKS cannot select an arbitrary JWT algorithm.

## Residual risks

NFC does not provide distance bounding, so a live relay remains possible. The
phone displays the signed action and a biometric transaction requires a second
tap to the same terminal identity. A compromised terminal can still request any
operation allowed by its policy and steal a bearer token returned to it.
Stealing its long-lived OAuth credential also permits new terminal tokens until
that credential is revoked; use one service account per terminal, protected
storage, expiration and rotation.

Offline phones cannot obtain fresh OCSP/CRL data. They validate certificate
dates and Android trust anchors, and require the exact certificate fingerprint
accepted during online registration. Certificate renewal therefore requires
online re-verification rather than silent offline acceptance.

Bridge compromise is equivalent to compromise of an authorization server. Use
KMS/HSM, least-privilege terminal rules, typed signing inputs, rate limits and
minimal security-event logs. Never log names, account or credential IDs, keys,
certificates, signatures, tokens, raw APDUs, plaintext or decrypted objects.

The biometric and possession labels are authenticator-asserted. The bridge
trusts the registered phone to enforce its selected profile and therefore does
not emit a hardware-key or attestation claim. A rooted or compromised phone can
misrepresent local user verification. Deployments that cannot accept that trust
model need platform attestation or standard FIDO/WebAuthn rather than relabeling
this protocol.

Registration expiry limits stale database records; it does not prove that a
phone is still controlled by its original user and is not a substitute for
revocation. A lost device should be removed through the provider's credential
management/deletion interface. The 30-day post-expiry cleanup grace is
operational only and does not permit authentication.
