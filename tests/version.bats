#!/usr/bin/env bats
# SPDX-License-Identifier: Apache-2.0
# Release editing is exercised in disposable copies, never the real checkout.
# shellcheck disable=SC2317,SC2329

setup() {
    VERSION_REPO="$BATS_TEST_TMPDIR/release fixture"
    VERSION_SOURCE="$BATS_TEST_DIRNAME/.."
    VERSION_FILES=(src/octoshield src/lib/cli.sh src/ui/octoshield-gtk.c debian/changelog data/io.vdm.OctoShield.metainfo.xml)
    local file
    mkdir -p "$VERSION_REPO/scripts"
    cp "$VERSION_SOURCE/scripts/version.sh" "$VERSION_REPO/scripts/version.sh"
    for file in "${VERSION_FILES[@]}"; do
        mkdir -p "$VERSION_REPO/${file%/*}"
        cp -p "$VERSION_SOURCE/$file" "$VERSION_REPO/$file"
    done
    VERSION_INITIAL=$(bash "$VERSION_REPO/scripts/version.sh")
    VERSION_NEXT=900.4.2
}

snapshot() {
    local file
    for file in "${VERSION_FILES[@]}"; do sha256sum "$VERSION_REPO/$file"; done
}

@test 'default prints the consistent version from any working directory' {
    cd "$BATS_TEST_TMPDIR"
    run bash "$VERSION_REPO/scripts/version.sh"
    [ "$status" -eq 0 ]
    [ "$output" = "$VERSION_INITIAL" ]
    run bash "$VERSION_REPO/scripts/version.sh" --check "v$VERSION_INITIAL"
    [ "$status" -eq 0 ]
}

@test 'release tags must exactly match every declared version' {
    local before
    before=$(snapshot)
    run bash "$VERSION_REPO/scripts/version.sh" --check "v$VERSION_NEXT"
    [ "$status" -ne 0 ]
    [[ $output == *'Release tag must be'* ]]
    [ "$(snapshot)" = "$before" ]
}

@test 'invalid semantic versions and extra arguments never edit files' {
    local before value
    before=$(snapshot)
    for value in '' 1 1.2 01.2.3 1.02.3 1.2.03 v1.2.3 1.2.3-rc1 1.2.3+build '1.2.3;echo nope' $'1.2.3\n'; do
        run bash "$VERSION_REPO/scripts/version.sh" --set "$value"
        [ "$status" -ne 0 ]
        [ "$(snapshot)" = "$before" ]
    done
    run bash "$VERSION_REPO/scripts/version.sh" --set "$VERSION_NEXT" extra
    [ "$status" -ne 0 ]
    [ "$(snapshot)" = "$before" ]
}

@test 'mismatched GUI changelog release or screenshot versions block a bump' {
    local file before
    for file in src/lib/cli.sh src/ui/octoshield-gtk.c debian/changelog data/io.vdm.OctoShield.metainfo.xml; do
        sed -i "s/$VERSION_INITIAL/123.4.5/g" "$VERSION_REPO/$file"
        before=$(snapshot)
        run bash "$VERSION_REPO/scripts/version.sh" --set "$VERSION_NEXT"
        [ "$status" -ne 0 ]
        [ "$(snapshot)" = "$before" ]
        cp -p "$VERSION_SOURCE/$file" "$VERSION_REPO/$file"
    done
    sed -i "s@/v$VERSION_INITIAL/@/v123.4.5/@g" "$VERSION_REPO/data/io.vdm.OctoShield.metainfo.xml"
    before=$(snapshot)
    run bash "$VERSION_REPO/scripts/version.sh" --set "$VERSION_NEXT"
    [ "$status" -ne 0 ]
    [[ $output == *'Screenshot URL'* ]]
    [ "$(snapshot)" = "$before" ]
}

@test 'a bump updates runtime and screenshots while retaining history and identity' {
    local original_mode identity
    original_mode=$(stat -c %a "$VERSION_REPO/src/octoshield")
    identity=$(awk '/^ -- / { sub(/  .*/, ""); print; exit }' "$VERSION_REPO/debian/changelog")
    run bash "$VERSION_REPO/scripts/version.sh" --set "$VERSION_NEXT"
    [ "$status" -eq 0 ]
    [[ $output == *'Review the new Debian and AppStream release notes'* ]]
    run bash "$VERSION_REPO/scripts/version.sh" --check "v$VERSION_NEXT"
    [ "$status" -eq 0 ]
    run bash "$VERSION_REPO/src/octoshield" --version
    [ "$status" -eq 0 ]
    [ "$output" = "OctoShield $VERSION_NEXT" ]
    run bash -c 'source "$1"; cli::main --version' bash "$VERSION_REPO/src/lib/cli.sh"
    [ "$status" -eq 0 ]
    [ "$output" = "OctoShield $VERSION_NEXT" ]
    [ "$(stat -c %a "$VERSION_REPO/src/octoshield")" = "$original_mode" ]
    [ "$(awk '/^ -- / { sub(/  .*/, ""); print; exit }' "$VERSION_REPO/debian/changelog")" = "$identity" ]
    grep -Fq "octoshield ($VERSION_INITIAL)" "$VERSION_REPO/debian/changelog"
    grep -Fq "<release version=\"$VERSION_INITIAL\"" "$VERSION_REPO/data/io.vdm.OctoShield.metainfo.xml"
    grep -Fq "<release version=\"$VERSION_NEXT\" date=\"$(date -u +%F)\">" "$VERSION_REPO/data/io.vdm.OctoShield.metainfo.xml"
    run dpkg-parsechangelog -l "$VERSION_REPO/debian/changelog" -S Version
    [ "$status" -eq 0 ]
    [ "$output" = "$VERSION_NEXT" ]
}

@test 'setting the existing version is a byte-for-byte no-op' {
    local before
    before=$(snapshot)
    run bash "$VERSION_REPO/scripts/version.sh" --set "$VERSION_INITIAL"
    [ "$status" -eq 0 ]
    [ "$(snapshot)" = "$before" ]
}

@test 'patch minor and major bumps reset subordinate components and preserve history' {
    local expected component
    run bash "$VERSION_REPO/scripts/version.sh" --set "$VERSION_NEXT"
    [ "$status" -eq 0 ]
    for component in patch minor major; do
        case "$component" in
            patch) expected=900.4.3 ;;
            minor) expected=900.5.0 ;;
            major) expected=901.0.0 ;;
        esac
        run bash "$VERSION_REPO/scripts/version.sh" --bump "$component"
        [ "$status" -eq 0 ]
        run bash "$VERSION_REPO/scripts/version.sh" --check "v$expected"
        [ "$status" -eq 0 ]
        run bash "$VERSION_REPO/src/octoshield" --version
        [ "$status" -eq 0 ]
        [ "$output" = "OctoShield $expected" ]
        grep -Fq "octoshield ($VERSION_NEXT)" "$VERSION_REPO/debian/changelog"
        grep -Fq "<release version=\"$VERSION_NEXT\"" "$VERSION_REPO/data/io.vdm.OctoShield.metainfo.xml"
    done
}

@test 'malformed bump components and wrong argument counts never edit files' {
    local before value
    before=$(snapshot)
    for value in '' PATCH Major prerelease 1 'patch;echo nope' $'patch\n'; do
        run bash "$VERSION_REPO/scripts/version.sh" --bump "$value"
        [ "$status" -eq 2 ]
        [[ $output == *'--bump patch|minor|major'* ]]
        [ "$(snapshot)" = "$before" ]
    done
    run bash "$VERSION_REPO/scripts/version.sh" --bump
    [ "$status" -eq 2 ]
    [ "$(snapshot)" = "$before" ]
    run bash "$VERSION_REPO/scripts/version.sh" --bump patch extra
    [ "$status" -eq 2 ]
    [ "$(snapshot)" = "$before" ]
}

@test 'bumps cannot overflow signed machine integers and propagate decimal carry' {
    run bash "$VERSION_REPO/scripts/version.sh" --set 900.4.9223372036854775807
    [ "$status" -eq 0 ]
    run bash "$VERSION_REPO/scripts/version.sh" --bump patch
    [ "$status" -eq 0 ]
    run bash "$VERSION_REPO/scripts/version.sh" --check v900.4.9223372036854775808
    [ "$status" -eq 0 ]
    run bash "$VERSION_REPO/scripts/version.sh" --set 99999999999999999999.99999999999999999999.99999999999999999999
    [ "$status" -eq 0 ]
    run bash "$VERSION_REPO/scripts/version.sh" --bump patch
    [ "$status" -eq 0 ]
    run bash "$VERSION_REPO/scripts/version.sh" --check v99999999999999999999.99999999999999999999.100000000000000000000
    [ "$status" -eq 0 ]
    run bash "$VERSION_REPO/scripts/version.sh" --bump minor
    [ "$status" -eq 0 ]
    run bash "$VERSION_REPO/scripts/version.sh" --check v99999999999999999999.100000000000000000000.0
    [ "$status" -eq 0 ]
    run bash "$VERSION_REPO/scripts/version.sh" --bump major
    [ "$status" -eq 0 ]
    run bash "$VERSION_REPO/scripts/version.sh" --check v100000000000000000000.0.0
    [ "$status" -eq 0 ]
}

@test 'downgrades and missing maintainer identity do not edit files' {
    local before
    before=$(snapshot)
    run bash "$VERSION_REPO/scripts/version.sh" --set 0.0.0
    [ "$status" -ne 0 ]
    [ "$(snapshot)" = "$before" ]
    sed -i '/^ -- /d' "$VERSION_REPO/debian/changelog"
    before=$(snapshot)
    run bash "$VERSION_REPO/scripts/version.sh" --set "$VERSION_NEXT"
    [ "$status" -ne 0 ]
    [[ $output == *'maintainer identity'* ]]
    [ "$(snapshot)" = "$before" ]
}

@test 'promotion failure restores every original file' {
    local before
    before=$(snapshot)
    mkdir "$BATS_TEST_TMPDIR/bin"
    cat >"$BATS_TEST_TMPDIR/bin/mv" <<'MOCK'
#!/usr/bin/env bash
if [[ $* == */new/src/ui/octoshield-gtk.c* ]]; then exit 42; fi
exec /usr/bin/mv "$@"
MOCK
    chmod +x "$BATS_TEST_TMPDIR/bin/mv"
    run env PATH="$BATS_TEST_TMPDIR/bin:$PATH" bash "$VERSION_REPO/scripts/version.sh" --set "$VERSION_NEXT"
    [ "$status" -ne 0 ]
    [ "$(snapshot)" = "$before" ]
    run bash "$VERSION_REPO/scripts/version.sh" --check
    [ "$status" -eq 0 ]
}

@test 'linked version-bearing files are rejected before edits' {
    local before
    mv "$VERSION_REPO/debian/changelog" "$BATS_TEST_TMPDIR/changelog"
    ln -s "$BATS_TEST_TMPDIR/changelog" "$VERSION_REPO/debian/changelog"
    before=$(snapshot)
    run bash "$VERSION_REPO/scripts/version.sh" --set "$VERSION_NEXT"
    [ "$status" -ne 0 ]
    [[ $output == *'linked file'* ]]
    [ "$(snapshot)" = "$before" ]
    [ -L "$VERSION_REPO/debian/changelog" ]
}

@test 'maintenance patch increments stay small and carry nine into the next minor' {
    run bash "$VERSION_REPO/scripts/version.sh" --set 900.3.3
    [ "$status" -eq 0 ]
    for version in 900.3.4 900.3.5 900.3.6 900.3.7 900.3.8 900.3.9 900.4.0; do
        run bash "$VERSION_REPO/scripts/version.sh" --bump patch
        [ "$status" -eq 0 ]
        run bash "$VERSION_REPO/scripts/version.sh" --check "v$version"
        [ "$status" -eq 0 ]
    done
}
