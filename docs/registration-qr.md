# Registration links and printed QR codes

## One QR code for installed and new users

Encode this ordinary HTTPS link in your QR code, replacing the provider origin:

```text
https://voegtlel.github.io/nfcauth/register.html?provider=https%3A%2F%2Fauth.example.com
```

Only put the provider's canonical HTTPS origin in `provider`, URL-encoded as a
query parameter. Do not include usernames, credentials, OAuth/completion tokens,
paths or personal identifiers. The QR is public and reusable, not an enrollment
secret. An offline phone needs internet for registration, though subsequent NFC
authentication can work offline.

The default camera/QR scanner opens the HTTPS page in the browser. The page:

1. Shows the provider address, explicitly without claiming it has verified it.
2. Offers **Register in app** for an installed compatible app.
3. Offers **Install from Google Play** otherwise. During internal testing, the
   user must also be an invited tester and join using the correct Google account.
4. Asks users to return to the page or rescan after installation. There is no
   deferred-link backend, clipboard tracking, automatic installation detection
   or promise of automatic continuation through Play installation.

The page uses a package-targeted Android `intent:` link with a fixed Play Store
fallback for supporting browsers. A separate `nfcauth:` link is provided for
other browsers. Both require a user click; scanners/browsers can restrict app
opening, so manual **Register with provider** remains available in the app.
The current 4.0.0 app does not implement these registration links; this feature
must ship in an updated app before printed codes are used for onboarding.

To generate a printable PNG using the optional `qrencode` command-line tool:

```shell
qrencode -s 12 -m 4 -o registration.png \
  'https://voegtlel.github.io/nfcauth/register.html?provider=https%3A%2F%2Fauth.example.com'
```

Print the provider address in human-readable text next to the QR. Test the
printed code with the intended scanners before distributing it. No QR-generation
dependency is required by the Android app or provider bridge.

## Direct links for an installed app

```text
nfcauth://register?provider=https%3A%2F%2Fauth.example.com
```

The app also recognizes the exact HTTPS landing-page URL when Android routes it
to the app. It accepts one `provider` parameter only, and rejects credentials,
non-HTTPS providers, fragments, unexpected routes and duplicate/extra parameters.
It prompts before discovery, verifies the signed manifest against HTTPS, and
requires the existing per-transfer disclosure and **Agree and register** action.
The disclosure is a full, scrollable screen with 24 dp outer margins and a
600 dp content-width cap on tablets. It uses plain-language sign-in choices;
the provider's exact purpose text is retained, with raw access identifiers
available under **View sign-in permissions**. Privacy/deletion information and
the approval action remain available without leaving the registration flow.
Neither the QR address nor a custom scheme establishes provider authenticity.
An active registration cannot be overwritten by scanning another link.

The OAuth return remains a separate `nfcauth://registration-complete` route.
Do not encode that callback URL or its one-use code in a printed QR.

## Verified HTTPS App Links are a separate hosting step

On modern Android, unverified HTTPS links generally open in the browser. This
is why the landing-page fallback exists. For automatic app opening, Android
requires an association file at the HOST ROOT:

```text
https://voegtlel.github.io/.well-known/assetlinks.json
```

Publishing `nfcauth/.well-known/assetlinks.json` in this repository is not
equivalent. Host-root configuration belongs to the GitHub user site (or a
dedicated domain) and is not configured by this change. Verified App Links also
need the app manifest's `autoVerify` configuration and the Play APP SIGNING
certificate SHA-256 fingerprint, not the upload certificate. A custom host needs
matching app route validation and intent-filter changes; do not change only the
printed URL. Until those deployment steps are completed, do not claim automatic
verified HTTPS routing. Custom schemes may be claimed by other installed apps;
the package-targeted browser button avoids that ambiguity where supported.

References: [Android deep links](https://developer.android.com/training/app-links/create-deeplinks),
[App Link verification](https://developer.android.com/training/app-links/verify-applinks).

## Validation

Run `node docs/registration-link.test.cjs` for landing-page input/link tests.
Android unit tests cover accepted/rejected URI formats; instrumentation tests
cover the first confirmation screen without provider network access. Before
release, test default camera → browser → app on a real phone, installed and
uninstalled cases, internal-test membership, cancel/retry and an active browser
registration followed by a second QR scan. The HTML must be deployed by GitHub
Pages before the printed HTTPS link is usable.
