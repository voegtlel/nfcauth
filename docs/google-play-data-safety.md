# Google Play privacy and Data safety checklist

This is an implementation checklist, not legal advice. Re-evaluate it whenever
the app, dependencies, provider protocol, or developer-operated infrastructure
changes.

## Current app behavior

- The app developer operates no authentication backend and receives no user
  data.
- The app contains no analytics, advertising, crash-reporting, or tracking SDK.
- Provider registration, authentication, and renewal are initiated by an
  explicit user action. There is no background heartbeat or periodic provider
  contact.
- The phone stores provider disclosure/consent metadata, an opaque
  provider-assigned credential ID, expiry, and service/profile-specific Android
  Keystore keys locally. Android backup is disabled.
- Online registration and renewal use HTTPS with the selected provider. NFC
  payloads use authenticated application-layer encryption between the phone and
  selected terminal, which submits the signed approval to its bridge over
  HTTPS. The provider is the intended recipient and can process the approved
  data; the app developer does not operate those endpoints or receive it.
- Each provider independently controls its server-side account mapping and
  credential record. The app shows its policy and deletion instructions before
  registration and keeps those links available afterward.
- The app can delete its local registration and key. This does not delete the
  provider's copy; the provider's displayed deletion mechanism must be used.

## Suggested Play Console answers

Google's end-to-end-encryption exception depends on data being unreadable by the
developer and unrelated intermediaries, with only the sender and intended
recipient able to process it. The selected provider, its provisioned terminal,
and its provider-controlled TLS termination are the recipient side of this
design. Ordinary HTTPS through an unrelated TLS-terminating CDN or proxy does
not by itself satisfy that exception. The declaration is the developer's
responsibility; inspect every bundled SDK and every production network path
before submission.

- Ads: **No**.
- Data safety collection/sharing: **No** only when the production deployment
  satisfies the end-to-end-encryption exception above and the developer remains
  outside the provider path; otherwise disclose the provider transfer.
- Encryption in transit: **Yes**.
- Account creation: the app does not create an account operated by the app
  developer. It links a device credential to an independently operated
  provider account. Explain this distinction in review notes if the registration
  UI is interpreted as app account creation.
- Account/local-data deletion: available from each registration's details.
  Provider-side deletion uses the provider-specific link/contact shown there.
- Privacy policy URL:
  `https://voegtlel.github.io/nfcauth/privacy-policy.html`.

Do not use the “no collection or sharing” answer if a future release adds a
developer backend, telemetry, crash reporting that includes identifiers,
analytics, ads, a third-party SDK that transmits data, readable intermediary
logging, or transfers outside the selected provider protocol.

## Submission checks

1. Confirm the GitHub Pages privacy policy is public worldwide, uses a valid
   HTTPS certificate, requires no login, is an ordinary non-editable web page,
   and remains consistent with the in-app policy.
2. Keep the policy link in Play Console and the in-app policy accessible.
3. Give reviewers a test provider/terminal and complete access instructions;
   the core flow otherwise requires external provider infrastructure and NFC.
4. Verify the release artifact itself contains no unreviewed SDK and that
   production logs contain no names, IDs, keys, signatures, tokens, plaintext,
   decrypted data, or raw APDUs.
5. Keep provider disclosure, affirmative registration consent, explicit manual
   renewal confirmation, policy/deletion links, and local deletion covered by
   automated release checks.
6. Re-submit the Data safety form whenever behavior changes.

Official references:

- [Provide information for Google Play's Data safety
  section](https://support.google.com/googleplay/android-developer/answer/10787469)
- [Prepare your app for
  review](https://support.google.com/googleplay/android-developer/answer/9859455)
- [Google Play Developer Program Policy: User
  Data](https://support.google.com/googleplay/android-developer/answer/18258653)
