# Pre-release screenshot review

Run **Play Store Assets** on the PR branch, not a release tag. The resulting
`play-store-assets` artifact includes seven store screenshots per Android device
profile, plus a `review/` subdirectory of additional views and a separate web
preview directory. Only the seven top-level phone/tablet PNGs are store-upload
deliverables; the additional captures are for review.

Views covered: empty and registered home screens; provider address dialog; overflow
and About menus; QR/deep-link confirmation; registration disclosure and lower
actions; service details and lower links; local deletion dialog;
expired registration and its details; unregistered-provider notice; app policy
and lower text; renewal confirmation and biometric-approved notice; QR landing
page on phone/tablet browsers and invalid-link feedback.

All data is a fictional Example Service. Renewal and biometric-approved captures
use debug-only UI previews: they do not create challenges, authenticate a user,
produce assertions or contact providers. Production builds ignore those preview
extras. The actual Android biometric prompt and provider-controlled browser login
are not reproduced by these fixtures: those need an enrolled test device and a
live test provider. No screenshot should be treated as evidence that those live
integrations were exercised.

The release remains on hold until the screenshots and final behavior are approved.
