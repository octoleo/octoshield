#!/usr/bin/env bats
# SPDX-License-Identifier: Apache-2.0
# Synthetic PNG fixtures exercise header validation; real captures come from CI.

setup() {
    bats_require_minimum_version 1.5.0
    FIXTURE="$BATS_TEST_TMPDIR/project"
    OUTPUT="$BATS_TEST_TMPDIR/release-assets"
    mkdir -p "$FIXTURE/scripts" "$FIXTURE/docs" "$FIXTURE/data/branding" "$FIXTURE/build/screenshots"
    cp "$BATS_TEST_DIRNAME/../scripts/release-assets.sh" "$FIXTURE/scripts/release-assets.sh"
    cat >"$FIXTURE/scripts/version.sh" <<'VERSION'
#!/usr/bin/env bash
if [[ ${1:-} == --check ]]; then printf 'Version declarations agree.\n'
else printf '0.2.0\n'; fi
VERSION
    for file in README.md LICENSE docs/features.md docs/distribution.md data/io.vdm.OctoShield.metainfo.xml data/io.vdm.OctoShield.desktop; do
        printf 'Fixture %s\n' "$file" >"$FIXTURE/$file"
    done
    # A complete 1x1 PNG fixture. Dimensions are not required to match release
    # media guidance here; native UI capture tests verify the actual screenshots.
    printf '%s' 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jh4kAAAAASUVORK5CYII=' |
        base64 --decode >"$BATS_TEST_TMPDIR/pixel.png"
    local page theme
    for page in overview protections usb office privacy diagnostics monitoring recovery; do
        for theme in light dark; do
            cp "$BATS_TEST_TMPDIR/pixel.png" "$FIXTURE/build/screenshots/OctoShield-$page-$theme.png"
        done
    done
    for theme in light dark; do
        cp "$BATS_TEST_TMPDIR/pixel.png" "$FIXTURE/data/branding/OctoShield-$theme.png"
    done
    git -C "$FIXTURE" -c init.defaultBranch=main init -q
    git -C "$FIXTURE" add .
    git -C "$FIXTURE" -c user.name='Fixture Author' -c user.email='fixture@example.invalid' commit -qm fixture
}

@test 'release assets include all sixteen captures, original branding and valid checksums' {
    run bash "$FIXTURE/scripts/release-assets.sh" "$OUTPUT"
    [ "$status" -eq 0 ]
    [ "$(find "$OUTPUT/gallery" -type f | wc -l)" -eq 16 ]
    cmp "$FIXTURE/data/branding/OctoShield-light.png" "$OUTPUT/branding/OctoShield-light.png"
    cmp "$FIXTURE/data/branding/OctoShield-dark.png" "$OUTPUT/branding/OctoShield-dark.png"
    cmp "$FIXTURE/build/screenshots/OctoShield-overview-light.png" "$OUTPUT/gallery/OctoShield-overview-light.png"
    [ -f "$OUTPUT/docs/features.md" ]
    [ -f "$OUTPUT/docs/distribution.md" ]
    [ -f "$OUTPUT/data/io.vdm.OctoShield.metainfo.xml" ]
    run bash -c 'cd "$1" && sha256sum --check SHA256SUMS' -- "$OUTPUT"
    [ "$status" -eq 0 ]
    [ "$(wc -l <"$OUTPUT/SHA256SUMS")" -eq "$(find "$OUTPUT" -type f ! -name SHA256SUMS | wc -l)" ]
}

@test 'manifest records version source commit clean state and measured dimensions' {
    run bash "$FIXTURE/scripts/release-assets.sh" "$OUTPUT"
    [ "$status" -eq 0 ]
    local commit
    commit=$(git -C "$FIXTURE" rev-parse HEAD)
    jq -e --arg commit "$commit" '.version == "0.2.0" and .application_id == "io.vdm.OctoShield" and
      .source.commit == $commit and .source.worktree_dirty == false and
      (.gallery | length) == 16 and (.branding | length) == 2 and
      all(.gallery[]; .width == 1 and .height == 1)' "$OUTPUT/manifest.json"
}

@test 'dirty source is reported and unrelated files or credentials are excluded' {
    printf 'credential-canary\n' >"$FIXTURE/unrelated-secret.txt"
    mkdir "$FIXTURE/private"
    printf 'private backup\n' >"$FIXTURE/private/backup"
    run bash "$FIXTURE/scripts/release-assets.sh" "$OUTPUT"
    [ "$status" -eq 0 ]
    jq -e '.source.worktree_dirty == true' "$OUTPUT/manifest.json"
    [ ! -e "$OUTPUT/unrelated-secret.txt" ]
    [ ! -e "$OUTPUT/private" ]
    [ ! -e "$OUTPUT/.git" ]
    [ ! -e "$OUTPUT/store" ]
    run ! grep -R -l 'credential-canary' "$OUTPUT"
}

@test 'existing output is refused without removing its contents' {
    mkdir "$OUTPUT"
    printf 'keep\n' >"$OUTPUT/sentinel"
    run bash "$FIXTURE/scripts/release-assets.sh" "$OUTPUT"
    [ "$status" -ne 0 ]
    [ "$(cat "$OUTPUT/sentinel")" = keep ]
    [ ! -e "$OUTPUT/manifest.json" ]
}

@test 'dangling output symlink is refused without creating its target' {
    ln -s "$BATS_TEST_TMPDIR/target" "$OUTPUT"
    run bash "$FIXTURE/scripts/release-assets.sh" "$OUTPUT"
    [ "$status" -ne 0 ]
    [ -L "$OUTPUT" ]
    [ ! -e "$BATS_TEST_TMPDIR/target" ]
}

@test 'missing capture or document fails before creating any output' {
    rm "$FIXTURE/build/screenshots/OctoShield-recovery-dark.png"
    run bash "$FIXTURE/scripts/release-assets.sh" "$OUTPUT"
    [ "$status" -ne 0 ]
    [ ! -e "$OUTPUT" ]
    cp "$BATS_TEST_TMPDIR/pixel.png" "$FIXTURE/build/screenshots/OctoShield-recovery-dark.png"
    rm "$FIXTURE/docs/features.md"
    run bash "$FIXTURE/scripts/release-assets.sh" "$OUTPUT"
    [ "$status" -ne 0 ]
    [ ! -e "$OUTPUT" ]
}

@test 'symlinked input assets are rejected rather than followed' {
    rm "$FIXTURE/data/branding/OctoShield-dark.png"
    ln -s "$BATS_TEST_TMPDIR/pixel.png" "$FIXTURE/data/branding/OctoShield-dark.png"
    run bash "$FIXTURE/scripts/release-assets.sh" "$OUTPUT"
    [ "$status" -ne 0 ]
    [ ! -e "$OUTPUT" ]
}

@test 'invalid PNG signature and zero dimensions are rejected' {
    local image="$FIXTURE/build/screenshots/OctoShield-usb-light.png"
    printf 'not a PNG\n' >"$image"
    run bash "$FIXTURE/scripts/release-assets.sh" "$OUTPUT"
    [ "$status" -ne 0 ]
    [ ! -e "$OUTPUT" ]
    cp "$BATS_TEST_TMPDIR/pixel.png" "$image"
    printf '\000\000\000\000' | dd of="$image" bs=1 seek=16 conv=notrunc status=none
    run bash "$FIXTURE/scripts/release-assets.sh" "$OUTPUT"
    [ "$status" -ne 0 ]
    [ ! -e "$OUTPUT" ]
}

@test 'version validation failure prevents output creation' {
    printf '#!/usr/bin/env bash\nexit 12\n' >"$FIXTURE/scripts/version.sh"
    run bash "$FIXTURE/scripts/release-assets.sh" "$OUTPUT"
    [ "$status" -ne 0 ]
    [ ! -e "$OUTPUT" ]
}

@test 'output paths with spaces work without shell evaluation' {
    local literal_output="$BATS_TEST_TMPDIR/release assets; literal"
    run bash "$FIXTURE/scripts/release-assets.sh" "$literal_output"
    [ "$status" -eq 0 ]
    [ -f "$literal_output/manifest.json" ]
    run bash -c 'cd "$1" && sha256sum --check SHA256SUMS' -- "$literal_output"
    [ "$status" -eq 0 ]
}

@test 'the release README describes native features permissions and unchanged protection on removal' {
    run bash "$FIXTURE/scripts/release-assets.sh" "$OUTPUT"
    [ "$status" -eq 0 ]
    grep -F 'native Debian package' "$OUTPUT/README.txt"
    grep -F 'administrator authorization' "$OUTPUT/README.txt"
    grep -F 'preserving native security policy' "$OUTPUT/README.txt"
    grep -F 'demonstration/initial states' "$OUTPUT/README.txt"
    grep -F 'A private GitHub release is not anonymously' "$OUTPUT/README.txt"
}
