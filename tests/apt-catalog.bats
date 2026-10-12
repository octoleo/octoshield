#!/usr/bin/env bats
# SPDX-License-Identifier: Apache-2.0
# No network, package installation or host APT configuration is used here.

setup() {
    bats_require_minimum_version 1.5.0
    SCRIPT="$BATS_TEST_DIRNAME/../scripts/apt-catalog.sh"
    ASSETS="$BATS_TEST_TMPDIR/assets"
    REPOSITORY="$BATS_TEST_TMPDIR/repository"
    URL=https://packages.example.test/octoshield
    mkdir -p "$ASSETS/data" "$ASSETS/gallery" "$ASSETS/branding" "$REPOSITORY"
    printf '%s\n' '{"application_id":"io.vdm.OctoShield","version":"0.2.0"}' >"$ASSETS/manifest.json"
    fixture_metadata
    # A complete small PNG fixture; native UI tests own capture verification.
    printf '%s' 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jh4kAAAAASUVORK5CYII=' |
        base64 --decode >"$BATS_TEST_TMPDIR/pixel.png"
    local page theme
    for theme in light dark; do
        cp "$BATS_TEST_TMPDIR/pixel.png" "$ASSETS/branding/OctoShield-$theme.png"
        for page in overview protections usb office monitoring recovery; do
            cp "$BATS_TEST_TMPDIR/pixel.png" "$ASSETS/gallery/OctoShield-$page-$theme.png"
        done
    done
}

fixture_metadata() {
    # Keep these fixtures independent of the next real product release.
    sed -E 's@[0-9]+\.[0-9]+\.[0-9]+@0.2.0@g' \
        "$BATS_TEST_DIRNAME/../data/io.vdm.OctoShield.metainfo.xml" \
        >"$ASSETS/data/io.vdm.OctoShield.metainfo.xml"
}

build_catalog() {
    bash "$SCRIPT" "$REPOSITORY" "$ASSETS" "${1:-noble}" "$URL" 0.2.0
}

assert_no_catalog() {
    [ ! -e "$REPOSITORY/dists/noble/main/dep11/Components-amd64.yml.gz" ]
    [ -z "$(find "$REPOSITORY" -maxdepth 1 -name '.octoshield-catalog.*' -print)" ]
}

@test 'official conversion maps the native package and rewrites screenshot and icon URLs' {
    run build_catalog
    [ "$status" -eq 0 ]
    local catalog="$REPOSITORY/dists/noble/main/dep11"
    gzip -dc "$catalog/Components-amd64.yml.gz" >"$BATS_TEST_TMPDIR/decoded.yml"
    cmp "$catalog/Components-amd64.yml" "$BATS_TEST_TMPDIR/decoded.yml"
    grep -Fx 'ID: io.vdm.OctoShield' "$catalog/Components-amd64.yml"
    grep -Fx 'Package: octoshield' "$catalog/Components-amd64.yml"
    grep -Fx 'Origin: octoshield-noble-main' "$catalog/Components-amd64.yml"
    grep -F "$URL/media/v0.2.0/OctoShield-light.png" "$catalog/Components-amd64.yml"
    python3 - "$catalog/Components-amd64.xml" "$URL" <<'PY'
import sys
import xml.etree.ElementTree as ET
root = ET.parse(sys.argv[1]).getroot()
component = root.find('component')
assert root.attrib['architecture'] == 'amd64'
assert component.findtext('pkgname') == 'octoshield'
assert component.findtext('launchable') == 'io.vdm.OctoShield.desktop'
assert 'Vast Development Method' in component.findtext('developer/name')
images = component.findall('screenshots/screenshot/image')
assert len(images) == 6
assert all(image.text.startswith(sys.argv[2] + '/media/v0.2.0/') for image in images)
assert all(image.attrib['width'] == '1' and image.attrib['height'] == '1' for image in images)
assert component.find('icon').attrib['type'] == 'remote'
PY
    [ -z "$(find "$REPOSITORY" -maxdepth 1 -name '.octoshield-catalog.*' -print)" ]
}

@test 'all twelve screenshots and both original artwork files remain byte identical' {
    printf 'must not be published\n' >"$ASSETS/credential.txt"
    run build_catalog
    [ "$status" -eq 0 ]
    [ "$(find "$REPOSITORY/media/v0.2.0" -type f | wc -l)" -eq 14 ]
    local input
    for input in "$ASSETS/gallery"/*.png "$ASSETS/branding"/*.png; do
        cmp "$input" "$REPOSITORY/media/v0.2.0/${input##*/}"
    done
    [ ! -e "$REPOSITORY/media/v0.2.0/credential.txt" ]
}

@test 'two Ubuntu suites share identical versioned media' {
    run build_catalog noble
    [ "$status" -eq 0 ]
    run build_catalog resolute
    [ "$status" -eq 0 ]
    grep -Fx 'Origin: octoshield-resolute-main' "$REPOSITORY/dists/resolute/main/dep11/Components-amd64.yml"
    [ "$(find "$REPOSITORY/media/v0.2.0" -type f | wc -l)" -eq 14 ]
}

@test 'manifest or metainfo version mismatch cannot publish a catalog' {
    printf '%s\n' '{"application_id":"io.vdm.OctoShield","version":"9.0.0"}' >"$ASSETS/manifest.json"
    run build_catalog
    [ "$status" -ne 0 ]
    assert_no_catalog
    printf '%s\n' '{"application_id":"io.vdm.OctoShield","version":"0.2.0"}' >"$ASSETS/manifest.json"
    sed -i 's/release version="0.2.0"/release version="9.0.0"/' "$ASSETS/data/io.vdm.OctoShield.metainfo.xml"
    run build_catalog
    [ "$status" -ne 0 ]
    [[ $output == *'latest metadata release differs'* ]]
    assert_no_catalog
}

@test 'unsafe URL or unknown suite is rejected before output is created' {
    local invalid
    for invalid in 'http://example.test/repo' 'https://user:secret@example.test/repo' \
        'https://example.test/../repo' 'https://example.test/repo?token=secret'; do
        URL=$invalid run build_catalog
        [ "$status" -ne 0 ]
        assert_no_catalog
    done
    run build_catalog ../../escape
    [ "$status" -ne 0 ]
    assert_no_catalog
}

@test 'missing or symlinked captures cannot publish a catalog' {
    rm "$ASSETS/gallery/OctoShield-recovery-dark.png"
    run build_catalog
    [ "$status" -ne 0 ]
    assert_no_catalog
    ln -s "$BATS_TEST_TMPDIR/pixel.png" "$ASSETS/gallery/OctoShield-recovery-dark.png"
    run build_catalog
    [ "$status" -ne 0 ]
    assert_no_catalog
}

@test 'malformed PNG data is refused' {
    printf 'not PNG\n' >"$ASSETS/branding/OctoShield-light.png"
    run build_catalog
    [ "$status" -ne 0 ]
    assert_no_catalog
}

@test 'metadata with entities or unbundled screenshot URLs is refused' {
    local metadata="$ASSETS/data/io.vdm.OctoShield.metainfo.xml"
    sed -i '2i<!DOCTYPE component [<!ENTITY local SYSTEM "file:///etc/hostname">]>' "$metadata"
    run build_catalog
    [ "$status" -ne 0 ]
    [[ $output == *'document type/entity declarations'* ]]
    assert_no_catalog
    fixture_metadata
    sed -i 's/OctoShield-overview-light.png/unrelated.png/' "$metadata"
    run build_catalog
    [ "$status" -ne 0 ]
    [[ $output == *'not one of the bundled application captures'* ]]
    assert_no_catalog
}

@test 'a converter failure cannot be hidden by a successful compression or copy' {
    mkdir "$BATS_TEST_TMPDIR/bin"
    cat >"$BATS_TEST_TMPDIR/bin/appstreamcli" <<'STUB'
#!/usr/bin/env bash
if [[ $1 == validate ]]; then exit 0; fi
printf 'converter failure\n' >&2
exit 27
STUB
    chmod +x "$BATS_TEST_TMPDIR/bin/appstreamcli"
    PATH="$BATS_TEST_TMPDIR/bin:$PATH" run build_catalog
    [ "$status" -ne 0 ]
    [[ $output == *'converter failure'* ]]
    assert_no_catalog
    [ ! -e "$REPOSITORY/media" ]
}

@test 'existing catalog and differing media are preserved rather than replaced' {
    run build_catalog
    [ "$status" -eq 0 ]
    local catalog="$REPOSITORY/dists/noble/main/dep11/Components-amd64.yml.gz" original
    original=$(sha256sum "$catalog")
    run build_catalog
    [ "$status" -ne 0 ]
    [[ $output == *'Catalog already exists'* ]]
    [ "$(sha256sum "$catalog")" = "$original" ]
    printf 'existing media must remain\n' >"$REPOSITORY/media/v0.2.0/OctoShield-overview-light.png"
    run build_catalog resolute
    [ "$status" -ne 0 ]
    [[ $output == *'Existing media differs'* ]]
    [ "$(cat "$REPOSITORY/media/v0.2.0/OctoShield-overview-light.png")" = 'existing media must remain' ]
    [ ! -e "$REPOSITORY/dists/resolute/main/dep11/Components-amd64.yml.gz" ]
}

@test 'a symlinked output directory cannot redirect catalog or media writes' {
    mkdir "$BATS_TEST_TMPDIR/outside"
    ln -s "$BATS_TEST_TMPDIR/outside" "$REPOSITORY/dists"
    run build_catalog
    [ "$status" -ne 0 ]
    [ -z "$(find "$BATS_TEST_TMPDIR/outside" -mindepth 1 -print)" ]
    assert_no_catalog
}
