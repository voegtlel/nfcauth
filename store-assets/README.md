# Google Play assets

Run the **Play Store Assets** workflow manually in GitHub Actions. It launches
two Android emulators and creates:

- seven 1080 x 1920 phone screenshots;
- seven 800 x 1280 7-inch tablet screenshots; and
- the 1024 x 500 feature graphic in this directory.

Download the workflow artifact named `play-store-assets`. Screenshot fixtures
use a clearly named fictional `Example Service`; no user or production data is
included. Generated screenshots are ignored locally so rerunning the workflow
does not add binary churn to Git.
