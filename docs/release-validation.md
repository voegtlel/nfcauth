# Release validation checklist

Passing CI establishes automated coverage, not production interoperability or
Play approval. Record the app/bridge commit, phone/Android version, reader SDK,
OIDC provider version, proxy configuration and date for each live test. Use only
dedicated test accounts and keep credentials and identifiers out of reports.

## Automated baseline

From `python/`, run `uv sync --frozen --extra dev`, `uv run ruff check .
../examples/terminal`, and `uv run pytest -q`. CI also checks selected strict
types, package/container builds and both Compose configurations. Android CI
builds APK/AAB artifacts. Run Android unit tests and lint as described in the
root README. Inspect workflow results for the exact candidate commit.

The Python suite covers one-use issuance, scope limits, terminal JWT validation,
enrollment/renewal/expiry, transaction capacity/concurrency and bad signatures.
It is not a substitute for real APDU interoperability or a live OIDC provider.

## Live provider and terminal (required before release)

- [ ] Deploy from the instructions on a clean host; replace every placeholder.
- [ ] Register from the phone through browser login and explicit transfer consent.
- [ ] Verify the saved account is the intended `(issuer, sub)` human account.
- [ ] Complete possession and biometric authentication to the protected API.
- [ ] Confirm the API rejects wrong audience, missing scopes, expired tokens and
      terminal M2M tokens used as user tokens.
- [ ] Confirm user token lifetime is at most 600 seconds and no refresh token exists.
- [ ] If using Authentik token exchange, verify federation/account mapping and
      audience/scope restrictions with the deployed version. Local JWT mode
      passing does not establish token-exchange compatibility.
- [ ] Revoke a test phone and terminal; verify subsequent attempts fail.
- [ ] Test coordinated certificate renewal and phone online renewal.
- [ ] Test backup recovery and schema/version matching in isolated staging.
- [ ] Inspect proxy/bridge/tracing logs for sensitive fields using synthetic data.

## Physical phone / NFC (required before release)

- [ ] Remove phone after first tap; approve biometrics; return to same terminal.
- [ ] Cancel biometrics, reject disclosure, or change terminal on second tap.
- [ ] Kill/restart the app or bridge during each phase; retry safely from scratch.
- [ ] Lose NFC mid-fragment, replay messages, and exceed the 120-second window.
- [ ] Verify offline phone operation and rejection of changed provider certificates.
- [ ] Revisit policy/deletion links and delete a local registration and its key.
- [ ] Verify accessible layouts and update store screenshots for this candidate.

Live Authentik and physical-phone validation have not been established by the
automated regression suite. Do not mark these boxes complete without evidence.
Follow the separate [Play checklist](google-play-data-safety.md); it is not a
guarantee of compliance or acceptance.
