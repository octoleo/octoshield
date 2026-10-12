#!/usr/bin/env bats
# SPDX-License-Identifier: Apache-2.0
# Real packages, signatures and APT indexes in disposable directories only.
# No host package installation, repository configuration or keyring is changed.
# shellcheck disable=SC2317,SC2329,SC2030,SC2031

setup_file() {
    local tool
    for tool in dpkg-deb apt-ftparchive gpg gpgv gzip sha256sum; do
        command -v "$tool" >/dev/null || return 1
    done
    export APT_TEST_KEY_HOME="$BATS_FILE_TMPDIR/signing-key"
    export APT_TEST_PASSPHRASE='disposable test key passphrase'
    mkdir -m 0700 "$APT_TEST_KEY_HOME"
}

ensure_signing_key() {
    if [[ ! -s $BATS_FILE_TMPDIR/signing-key.asc ]]; then
        printf '%s\n' "$APT_TEST_PASSPHRASE" |
            gpg --homedir "$APT_TEST_KEY_HOME" --batch --pinentry-mode loopback \
                --passphrase-fd 0 --quick-generate-key \
                'OctoShield test repository <repository@example.invalid>' ed25519 sign 1d >/dev/null
    fi
    APT_TEST_FINGERPRINT=$(gpg --homedir "$APT_TEST_KEY_HOME" --batch --with-colons --list-secret-keys 2>/dev/null |
        awk -F: '$1 == "fpr" { print $10; exit }')
    export APT_TEST_FINGERPRINT
    if [[ ! -s $BATS_FILE_TMPDIR/signing-key.asc ]]; then
        printf '%s\n' "$APT_TEST_PASSPHRASE" |
            gpg --homedir "$APT_TEST_KEY_HOME" --batch --pinentry-mode loopback \
                --passphrase-fd 0 --armor --export-secret-keys \
                "$APT_TEST_FINGERPRINT" >"$BATS_FILE_TMPDIR/signing-key.asc"
        gpg --homedir "$APT_TEST_KEY_HOME" --batch --armor --export \
            "$APT_TEST_FINGERPRINT" >"$BATS_FILE_TMPDIR/public-key.asc"
    fi
}

teardown_file() {
    if [[ -n ${APT_TEST_KEY_HOME:-} ]] && command -v gpgconf >/dev/null; then
        gpgconf --homedir "$APT_TEST_KEY_HOME" --kill all
    fi
}

setup() {
    APT_REPOSITORY_SCRIPT="$BATS_TEST_DIRNAME/../scripts/apt-repository.sh"
    APT_TEST_INPUT="$BATS_TEST_TMPDIR/release input"
    APT_TEST_OUTPUT="$BATS_TEST_TMPDIR/repository"
    APT_TEST_ASSETS="$BATS_TEST_TMPDIR/release assets"
    mkdir "$APT_TEST_INPUT"
    unset APT_SIGNING_KEY APT_SIGNING_PASSPHRASE APT_SIGNING_KEY_FINGERPRINT APT_REPOSITORY_URL
    export GNUPGHOME="$BATS_TEST_TMPDIR/caller-keyring"
    mkdir -m 0700 "$GNUPGHOME"
    printf 'Do not modify the caller keyring.\n' >"$GNUPGHOME/sentinel"
    fixture_deb ubuntu24.04
    fixture_deb ubuntu26.04
    fixture_assets
}

fixture_assets() {
    local page theme fixture="$BATS_TEST_TMPDIR/pixel.png"
    mkdir -p "$APT_TEST_ASSETS/data" "$APT_TEST_ASSETS/gallery" "$APT_TEST_ASSETS/branding"
    printf '%s\n' '{"application_id":"io.vdm.OctoShield","version":"1.2.3"}' >"$APT_TEST_ASSETS/manifest.json"
    sed -E 's@[0-9]+\.[0-9]+\.[0-9]+@1.2.3@g' \
        "$BATS_TEST_DIRNAME/../data/io.vdm.OctoShield.metainfo.xml" \
        >"$APT_TEST_ASSETS/data/io.vdm.OctoShield.metainfo.xml"
    # A valid one-pixel PNG is test data, not a replacement application capture.
    printf '%s' 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9Wl6GHoAAAAASUVORK5CYII=' |
        base64 --decode >"$fixture"
    for theme in light dark; do
        cp "$fixture" "$APT_TEST_ASSETS/branding/OctoShield-$theme.png"
        for page in overview protections usb office monitoring recovery; do
            cp "$fixture" "$APT_TEST_ASSETS/gallery/OctoShield-$page-$theme.png"
        done
    done
}

fixture_deb() {
    local release=$1 version=${2:-1.2.3} architecture=${3:-amd64} package=${4:-octoshield}
    local name=${5:-octoshield_1.2.3_${release}_amd64.deb}
    local root="$BATS_TEST_TMPDIR/package-$release"
    mkdir -p "$root/DEBIAN" "$root/usr/share/doc/octoshield"
    cat >"$root/DEBIAN/control" <<CONTROL
Package: $package
Version: $version
Architecture: $architecture
Maintainer: Test Fixture <fixture@example.invalid>
Description: Disposable OctoShield repository test package
CONTROL
    printf '%s\n' "$release" >"$root/usr/share/doc/octoshield/release"
    dpkg-deb --build --root-owner-group "$root" "$APT_TEST_INPUT/$name" >/dev/null
}

signing_environment() {
    ensure_signing_key
    APT_SIGNING_KEY=$(cat "$BATS_FILE_TMPDIR/signing-key.asc")
    export APT_SIGNING_KEY APT_SIGNING_PASSPHRASE="$APT_TEST_PASSPHRASE"
    export APT_SIGNING_KEY_FINGERPRINT="$APT_TEST_FINGERPRINT"
    export APT_REPOSITORY_URL=https://packages.example.test/octoshield
}

build_repository() {
    bash "$APT_REPOSITORY_SCRIPT" --input "$APT_TEST_INPUT" --assets "$APT_TEST_ASSETS" --output "$APT_TEST_OUTPUT"
}

assert_no_staging() {
    local leftovers
    leftovers=$(find "$BATS_TEST_TMPDIR" -maxdepth 1 -name '.octoshield-apt.*' -print)
    [ -z "$leftovers" ]
    [ "$(find "$GNUPGHOME" -mindepth 1 -printf '%f\n')" = sentinel ]
    [ "$(cat "$GNUPGHOME/sentinel")" = 'Do not modify the caller keyring.' ]
}

assert_rejected() {
    local before
    before=$(sha256sum "$APT_TEST_INPUT"/*.deb)
    run build_repository
    [ "$status" -ne 0 ]
    [ ! -e "$APT_TEST_OUTPUT" ]
    [ "$(sha256sum "$APT_TEST_INPUT"/*.deb)" = "$before" ]
    assert_no_staging
}

verify_suite() {
    local suite=$1 release=$2 filename relative expected hash size
    filename="octoshield_1.2.3_${release}_amd64.deb"
    relative="pool/$suite/main/o/octoshield/$filename"
    local index="$APT_TEST_OUTPUT/dists/$suite/main/binary-amd64/Packages"
    local metadata="$APT_TEST_OUTPUT/dists/$suite/Release"
    [ -f "$APT_TEST_OUTPUT/$relative" ]
    cmp "$APT_TEST_INPUT/$filename" "$APT_TEST_OUTPUT/$relative"
    [ "$(grep -c '^Package:' "$index")" -eq 1 ]
    grep -Fxq 'Package: octoshield' "$index"
    grep -Fxq 'Version: 1.2.3' "$index"
    grep -Fxq 'Architecture: amd64' "$index"
    grep -Fxq "Filename: $relative" "$index"
    expected=$(sha256sum "$APT_TEST_OUTPUT/$relative")
    grep -Fxq "SHA256: ${expected%% *}" "$index"
    grep -Fxq "Size: $(stat -c %s "$APT_TEST_OUTPUT/$relative")" "$index"
    gzip -dc "$index.gz" >"$BATS_TEST_TMPDIR/uncompressed"
    cmp "$index" "$BATS_TEST_TMPDIR/uncompressed"
    grep -Fxq "Suite: $suite" "$metadata"
    grep -Fxq "Codename: $suite" "$metadata"
    grep -Fxq 'Architectures: amd64' "$metadata"
    grep -Fxq 'Components: main' "$metadata"
    for filename in main/binary-amd64/Packages main/binary-amd64/Packages.gz main/dep11/Components-amd64.yml.gz; do
        expected=$(sha256sum "$APT_TEST_OUTPUT/dists/$suite/$filename")
        read -r hash size < <(awk -v name="$filename" '
            /^SHA256:/ { section = 1; next }
            /^[^ ]/ { section = 0 }
            section && $3 == name { print $1, $2 }
        ' "$metadata")
        [ "$hash" = "${expected%% *}" ]
        [ "$size" = "$(stat -c %s "$APT_TEST_OUTPUT/dists/$suite/$filename")" ]
    done
}

apt_client() {
    local client="$BATS_TEST_TMPDIR/apt-client"
    mkdir -p "$client/etc" "$client/state/lists/partial" "$client/cache/archives/partial" "$client/log"
    cat >"$client/status" <<'STATUS'
Package: octoshield
Status: install ok installed
Architecture: amd64
Version: 1.2.2
Maintainer: Test Fixture <fixture@example.invalid>
Description: Disposable installed-version fixture, never installed on this host
STATUS
    cat >"$client/apt.conf" <<CONFIG
Dir::Etc "$client/etc";
Dir::Etc::main "-";
Dir::Etc::parts "-";
Dir::Etc::sourcelist "sources.list";
Dir::Etc::sourceparts "-";
Dir::Etc::trusted "trusted.gpg";
Dir::Etc::trustedparts "-";
Dir::State "$client/state";
Dir::State::status "$client/status";
Dir::Cache "$client/cache";
Dir::Log "$client/log";
APT::Architecture "amd64";
APT::Architectures { "amd64"; };
APT::Sandbox::User "$(id -un)";
APT::Update::Error-Mode "any";
Acquire::Languages "none";
Debug::NoLocking "true";
CONFIG
    cat >"$client/etc/sources.list" <<SOURCES
deb [arch=amd64 signed-by=$APT_TEST_OUTPUT/octoshield-archive-keyring.gpg] file:$APT_TEST_OUTPUT noble main
deb [arch=amd64 signed-by=$APT_TEST_OUTPUT/octoshield-archive-keyring.gpg] file:$APT_TEST_OUTPUT resolute main
SOURCES
    export APT_CONFIG="$client/apt.conf"
}

@test 'unsigned test output preserves each suite artifact and its complete hash chain' {
    printf 'ignored release documentation\n' >"$APT_TEST_INPUT/README.txt"
    run build_repository
    [ "$status" -eq 0 ]
    verify_suite noble ubuntu24.04
    verify_suite resolute ubuntu26.04
    [ -f "$APT_TEST_OUTPUT/UNSIGNED-TEST-ONLY" ]
    [ ! -e "$APT_TEST_OUTPUT/octoshield-archive-keyring.gpg" ]
    [ ! -e "$APT_TEST_OUTPUT/octoshield-archive-keyring.asc" ]
    [ ! -e "$APT_TEST_OUTPUT/dists/noble/InRelease" ]
    [ ! -e "$APT_TEST_OUTPUT/dists/noble/Release.gpg" ]
    [ ! -e "$APT_TEST_OUTPUT/dists/resolute/InRelease" ]
    [ ! -e "$APT_TEST_OUTPUT/dists/resolute/Release.gpg" ]
    assert_no_staging
}

@test 'an existing output directory is never overwritten' {
    mkdir "$APT_TEST_OUTPUT"
    printf 'existing publication\n' >"$APT_TEST_OUTPUT/sentinel"
    run build_repository
    [ "$status" -ne 0 ]
    [ "$(find "$APT_TEST_OUTPUT" -mindepth 1 -printf '%f\n')" = sentinel ]
    [ "$(cat "$APT_TEST_OUTPUT/sentinel")" = 'existing publication' ]
    assert_no_staging
}

@test 'an output symlink never redirects a publication into another directory' {
    local target="$BATS_TEST_TMPDIR/existing-target"
    mkdir "$target"
    printf 'existing publication\n' >"$target/sentinel"
    ln -s "$target" "$APT_TEST_OUTPUT"
    run build_repository
    [ "$status" -ne 0 ]
    [ -L "$APT_TEST_OUTPUT" ]
    [ "$(find "$target" -mindepth 1 -printf '%f\n')" = sentinel ]
    [ "$(cat "$target/sentinel")" = 'existing publication' ]
    assert_no_staging
}

@test 'a missing suite or an extra deb artifact rejects the entire publication' {
    mv "$APT_TEST_INPUT/octoshield_1.2.3_ubuntu26.04_amd64.deb" "$BATS_TEST_TMPDIR/held.deb"
    assert_rejected
    mv "$BATS_TEST_TMPDIR/held.deb" "$APT_TEST_INPUT/octoshield_1.2.3_ubuntu26.04_amd64.deb"
    cp "$APT_TEST_INPUT/octoshield_1.2.3_ubuntu24.04_amd64.deb" "$APT_TEST_INPUT/extra.deb"
    assert_rejected
}

@test 'suite artifact names must use the declared Ubuntu releases and semver version' {
    local invalid original=octoshield_1.2.3_ubuntu24.04_amd64.deb
    for invalid in octoshield_1.2.3_ubuntu25.10_amd64.deb octoshield_01.2.3_ubuntu24.04_amd64.deb octoshield_1.2.3-rc1_ubuntu24.04_amd64.deb; do
        mv "$APT_TEST_INPUT/$original" "$APT_TEST_INPUT/$invalid"
        assert_rejected
        mv "$APT_TEST_INPUT/$invalid" "$APT_TEST_INPUT/$original"
    done
}

@test 'package control identity must match artifact name version and architecture' {
    fixture_deb ubuntu24.04 1.2.3 amd64 another-package
    assert_rejected
    fixture_deb ubuntu24.04 9.8.7
    assert_rejected
    fixture_deb ubuntu24.04 1.2.3 arm64
    assert_rejected
}

@test 'both suites must publish the same version' {
    rm "$APT_TEST_INPUT/octoshield_1.2.3_ubuntu26.04_amd64.deb"
    fixture_deb ubuntu26.04 1.2.4 amd64 octoshield octoshield_1.2.4_ubuntu26.04_amd64.deb
    assert_rejected
}

@test 'malformed deb archives and linked artifacts fail without publishing' {
    local artifact="$APT_TEST_INPUT/octoshield_1.2.3_ubuntu24.04_amd64.deb"
    printf 'not a Debian archive\n' >"$artifact"
    assert_rejected
    fixture_deb ubuntu24.04
    mv "$artifact" "$BATS_TEST_TMPDIR/original.deb"
    ln -s "$BATS_TEST_TMPDIR/original.deb" "$artifact"
    assert_rejected
    [ -L "$artifact" ]
}

@test 'missing catalog media or a mismatched asset version prevents publication' {
    rm "$APT_TEST_ASSETS/gallery/OctoShield-overview-dark.png"
    assert_rejected
    fixture_assets
    printf '%s\n' '{"application_id":"io.vdm.OctoShield","version":"1.2.4"}' >"$APT_TEST_ASSETS/manifest.json"
    assert_rejected
}

@test 'incomplete signing configuration never silently publishes unsigned output' {
    export APT_SIGNING_KEY_FINGERPRINT=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    assert_rejected
    unset APT_SIGNING_KEY_FINGERPRINT
    export APT_SIGNING_PASSPHRASE="$APT_TEST_PASSPHRASE"
    assert_rejected
    signing_environment
    unset APT_SIGNING_KEY_FINGERPRINT
    assert_rejected
    signing_environment
    unset APT_REPOSITORY_URL
    assert_rejected
}

@test 'signing rejects wrong fingerprints malformed keys and public-only key material' {
    signing_environment
    export APT_SIGNING_KEY_FINGERPRINT=0000000000000000000000000000000000000000
    assert_rejected
    signing_environment
    export APT_SIGNING_KEY_FINGERPRINT=short
    assert_rejected
    signing_environment
    export APT_SIGNING_KEY='not a private key'
    assert_rejected
    signing_environment
    APT_SIGNING_KEY=$(cat "$BATS_FILE_TMPDIR/public-key.asc")
    export APT_SIGNING_KEY
    assert_rejected
}

@test 'a protected signing key requires its correct passphrase' {
    signing_environment
    export APT_SIGNING_PASSPHRASE='incorrect passphrase'
    assert_rejected
}

@test 'signed publication rejects an insecure repository URL' {
    signing_environment
    export APT_REPOSITORY_URL=http://packages.example.test/octoshield
    assert_rejected
}

@test 'both signed suites verify with the exported public key and detect tampering' {
    local suite verification="$BATS_TEST_TMPDIR/verification"
    signing_environment
    run build_repository
    [ "$status" -eq 0 ]
    verify_suite noble ubuntu24.04
    verify_suite resolute ubuntu26.04
    [ ! -e "$APT_TEST_OUTPUT/UNSIGNED-TEST-ONLY" ]
    grep -Fxq -- '-----BEGIN PGP PUBLIC KEY BLOCK-----' "$APT_TEST_OUTPUT/octoshield-archive-keyring.asc"
    [ "$(cat "$APT_TEST_OUTPUT/octoshield-archive-keyring.fingerprint")" = "$APT_TEST_FINGERPRINT" ]
    (cd "$APT_TEST_OUTPUT" && sha256sum --check --quiet SHA256SUMS)
    mkdir -m 0700 "$verification"
    for suite in noble resolute; do
        grep -Fxq 'Types: deb' "$APT_TEST_OUTPUT/octoshield-$suite.sources"
        grep -Fxq "URIs: $APT_REPOSITORY_URL" "$APT_TEST_OUTPUT/octoshield-$suite.sources"
        grep -Fxq "Suites: $suite" "$APT_TEST_OUTPUT/octoshield-$suite.sources"
        grep -Fxq 'Signed-By: /etc/apt/keyrings/octoshield-archive-keyring.gpg' "$APT_TEST_OUTPUT/octoshield-$suite.sources"
        run gpgv --homedir "$verification" --keyring "$APT_TEST_OUTPUT/octoshield-archive-keyring.gpg" \
            "$APT_TEST_OUTPUT/dists/$suite/InRelease"
        [ "$status" -eq 0 ]
        run gpgv --homedir "$verification" --keyring "$APT_TEST_OUTPUT/octoshield-archive-keyring.gpg" \
            "$APT_TEST_OUTPUT/dists/$suite/Release.gpg" "$APT_TEST_OUTPUT/dists/$suite/Release"
        [ "$status" -eq 0 ]
    done
    sed -i 's/Suite: noble/Suite: forged/' "$APT_TEST_OUTPUT/dists/noble/InRelease"
    run gpgv --homedir "$verification" --keyring "$APT_TEST_OUTPUT/octoshield-archive-keyring.gpg" \
        "$APT_TEST_OUTPUT/dists/noble/InRelease"
    [ "$status" -ne 0 ]
    printf 'tampered\n' >>"$APT_TEST_OUTPUT/dists/resolute/Release"
    run gpgv --homedir "$verification" --keyring "$APT_TEST_OUTPUT/octoshield-archive-keyring.gpg" \
        "$APT_TEST_OUTPUT/dists/resolute/Release.gpg" "$APT_TEST_OUTPUT/dists/resolute/Release"
    [ "$status" -ne 0 ]
    assert_no_staging
}

@test 'isolated APT accepts both signed suites and rejects a tampered package index' {
    signing_environment
    run build_repository
    [ "$status" -eq 0 ]
    apt_client
    # Absolute paths bypass environment wrappers that may rewrite system sources.
    run /usr/bin/apt-get update
    [ "$status" -eq 0 ]
    run /usr/bin/apt-cache policy octoshield
    [ "$status" -eq 0 ]
    [[ $output == *'Installed: 1.2.2'* && $output == *'Candidate: 1.2.3'* ]]
    [[ $output == *'noble/main'* && $output == *'resolute/main'* ]]
    printf 'tampered\n' >>"$APT_TEST_OUTPUT/dists/noble/main/binary-amd64/Packages"
    gzip -n -c "$APT_TEST_OUTPUT/dists/noble/main/binary-amd64/Packages" \
        >"$APT_TEST_OUTPUT/dists/noble/main/binary-amd64/Packages.gz"
    rm -rf "$BATS_TEST_TMPDIR/apt-client/state/lists"
    mkdir -p "$BATS_TEST_TMPDIR/apt-client/state/lists/partial"
    run /usr/bin/apt-get update
    [ "$status" -ne 0 ]
    [[ $output == *'Hash Sum mismatch'* || $output == *'unexpected size'* ]]
    assert_no_staging
}
