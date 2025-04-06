# https://github.com/casey/just

# List justfile recipes
help:
    just --list

install-sdkman:
    # Install sdkman to userdir
    curl -s "https://get.sdkman.io" | bash
    source "$HOME/.sdkman/bin/sdkman-init.sh"

install:
    # Install gradle
    sdk install gradle 8.5 || echo "Run install-sdkman first"

# Build the release package
build:
    ./gradlew build

device-debug:
    ./gradlew installDebug

release:
    ./gradlew release

device-logs:
    adb logcat -s NfcService:D CardEmulationService:D libnfc_nci:D KeyManager:D -v time
