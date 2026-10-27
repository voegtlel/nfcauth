# NFC Auth v4 security model

## Defended attacks

- Passive NFC capture exposes no identifier or authorization content.
- AEAD counters and session IDs reject replay, reflection and reordering.
- Provider signatures bind both ephemeral NFC keys, the phone challenge,
  terminal identity, exact audience/scopes/action, manifest and expiry.
- Phone assertions bind the provider request hash and cannot be widened by the
  terminal.
- Transactions are consumed once before token issuance.
- Per-provider and per-profile keys prevent normal cross-service correlation
  and biometric downgrade.
- Terminal policy independently caps audiences, scopes and assurance.
- A stolen callback completion code cannot enroll without the phone key.

## Residual risks

NFC does not provide distance bounding, so a live relay remains possible. The
phone displays the signed action and a biometric transaction requires a second
tap to the same terminal identity. A compromised terminal can still request any
operation allowed by its policy and steal a bearer token returned to it.

Offline phones cannot obtain fresh OCSP/CRL data. They validate certificate
dates and Android trust anchors, and require the exact certificate fingerprint
accepted during online registration. Certificate renewal therefore requires
online re-verification rather than silent offline acceptance.

Bridge compromise is equivalent to compromise of an authorization server. Use
KMS/HSM, least-privilege terminal rules, typed signing inputs, rate limits and
minimal security-event logs. Never log names, account or credential IDs, keys,
certificates, signatures, tokens, raw APDUs, plaintext or decrypted objects.
