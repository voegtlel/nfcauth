# Project-specific R8 rules.
# Android Gradle Plugin generates keep rules for manifest components, while
# library consumer rules cover the AndroidX dependencies used by this app.

# Tink uses these compile-time annotations only for static analysis.
-dontwarn javax.annotation.Nullable
-dontwarn javax.annotation.concurrent.GuardedBy
