#!/usr/bin/env bats
# SPDX-License-Identifier: Apache-2.0

setup() {
    bats_require_minimum_version 1.5.0
    export FIXTURE="$BATS_TEST_TMPDIR/project" PACKAGES="$BATS_TEST_TMPDIR/packages" ASSETS="$BATS_TEST_TMPDIR/assets"
    export GH_STATE="$BATS_TEST_TMPDIR/github" GH_REPO=octoleo/octoshield GH_TOKEN=fixture-token-canary
    export RELEASE_COMMIT=1111111111111111111111111111111111111111 GITHUB_OUTPUT="$BATS_TEST_TMPDIR/outputs"
    mkdir -p "$FIXTURE/scripts" "$FIXTURE/data" "$PACKAGES" "$ASSETS" "$GH_STATE" "$BATS_TEST_TMPDIR/bin"
    cp "$BATS_TEST_DIRNAME/../scripts/"{publish-release,release-assets}.sh "$FIXTURE/scripts/"
    cat >"$FIXTURE/scripts/version.sh" <<'VERSION'
#!/usr/bin/env bash
[[ $* == '--check v1.0.0' ]]
VERSION
    printf '<component><id>io.vdm.OctoShield</id></component>\n' >"$FIXTURE/data/io.vdm.OctoShield.metainfo.xml"
    local ubuntu
    for ubuntu in 24.04 26.04; do
        make_package "$ubuntu" 1.0.0 amd64
    done
    mkdir -p "$ASSETS/release-assets/gallery" "$ASSETS/release-assets/data"
    cp "$FIXTURE/data/io.vdm.OctoShield.metainfo.xml" "$ASSETS/release-assets/data/"
    jq -n --arg commit "$RELEASE_COMMIT" '{application_id:"io.vdm.OctoShield",version:"1.0.0",
      source:{commit:$commit,worktree_dirty:false},gallery:[range(12)],branding:[1,2]}' >"$ASSETS/release-assets/manifest.json"
    local page theme
    for page in overview protections usb office monitoring recovery; do
        for theme in light dark; do
            printf '%s' 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jh4kAAAAASUVORK5CYII=' |
                base64 --decode >"$ASSETS/release-assets/gallery/OctoShield-$page-$theme.png"
        done
    done
    package_assets
    cat >"$BATS_TEST_TMPDIR/bin/gh" <<'GH'
#!/usr/bin/env bash
set -Eeuo pipefail
printf '%s\n' "$*" >>"$GH_STATE/calls"
respond() {
    printf 'HTTP/2.0 %s fixture\r\nContent-Type: application/json\r\n\r\n' "$1"
    if [[ $1 == 200 ]]; then cat "$2"; else printf '{"message":"Fixture error"}\n'; exit 1; fi
}
if [[ $1 == api ]]; then
    if [[ $2 == --paginate && $3 == --slurp ]]; then
        if [[ ${MOCK_LIST_ERROR:-0} == 1 ]]; then exit 89; fi
        if [[ -f $GH_STATE/release.json ]]; then
            count=0; [[ ! -f $GH_STATE/draft-list-count ]] || count=$(cat "$GH_STATE/draft-list-count")
            count=$((count + 1)); printf '%s\n' "$count" >"$GH_STATE/draft-list-count"
            if [[ ${MOCK_CREATED_LIST_ERROR:-0} == 1 ]]; then exit 88; fi
            if ((count <= ${MOCK_HIDDEN_LISTS:-0})); then printf '[[]]\n'; exit; fi
        fi
        if [[ -f $GH_STATE/release.json ]]; then jq '[[.]]' "$GH_STATE/release.json"; else printf '[[]]\n'; fi
        exit
    fi
    [[ $2 == --include ]] || exit 90
    if [[ ${MOCK_HTTP_ERROR:-} ]]; then respond "$MOCK_HTTP_ERROR" unused; fi
    case "$3" in
        */releases/tags/*)
            [[ -f $GH_STATE/release.json ]] || respond 404 unused
            jq -e '.draft == false' "$GH_STATE/release.json" >/dev/null || respond 404 unused
            respond 200 "$GH_STATE/release.json"
            ;;
        */releases/100)
            respond 200 "$GH_STATE/release.json"
            ;;
        */git/ref/tags/*)
            [[ -f $GH_STATE/tag ]] || respond 404 unused
            jq -n --arg sha "$(cat "$GH_STATE/tag")" --arg type "${MOCK_TAG_TYPE:-commit}" '{object:{type:$type,sha:$sha}}' >"$GH_STATE/tag.json"
            respond 200 "$GH_STATE/tag.json"
            ;;
        */git/tags/*)
            jq -n --arg sha "$RELEASE_COMMIT" '{object:{type:"commit",sha:$sha}}' >"$GH_STATE/annotated.json"
            respond 200 "$GH_STATE/annotated.json"
            ;;
        *) exit 91 ;;
    esac
elif [[ $1 == release ]]; then
    case "$2" in
        create)
            tag=$3; shift 3
            while (($#)); do
                case "$1" in
                    --target) commit=$2; shift 2 ;;
                    --notes-file) cp "$2" "$GH_STATE/notes.md"; shift 2 ;;
                    --repo|--title) shift 2 ;;
                    --draft) shift ;;
                    *) exit 92 ;;
                esac
            done
            jq -n --arg tag "$tag" --arg commit "$commit" '{id:100,draft:true,tag_name:$tag,target_commitish:$commit,assets:[]}' >"$GH_STATE/release.json"
            ;;
        upload)
            file=$4; name=${file##*/}
            count=0; [[ ! -f $GH_STATE/upload-count ]] || count=$(cat "$GH_STATE/upload-count")
            count=$((count + 1)); printf '%s\n' "$count" >"$GH_STATE/upload-count"
            if [[ ${MOCK_FAIL_UPLOAD:-0} == "$count" ]]; then exit 93; fi
            size=$(stat -c %s "$file"); digest=$(sha256sum "$file"); digest="sha256:${digest%% *}"
            if [[ ${MOCK_CORRUPT_UPLOAD:-0} == 1 ]]; then digest=sha256:bad; fi
            if [[ ${MOCK_NULL_DIGEST:-0} == 1 ]]; then digest=''; fi
            jq --arg name "$name" --argjson size "$size" --arg digest "$digest" \
                '.assets = ([.assets[] | select(.name != $name)] + [{name:$name,size:$size,digest:(if $digest == "" then null else $digest end),state:"uploaded"}])' \
                "$GH_STATE/release.json" >"$GH_STATE/new.json"
            mv "$GH_STATE/new.json" "$GH_STATE/release.json"
            mkdir -p "$GH_STATE/uploads"
            cp "$file" "$GH_STATE/uploads/$name"
            ;;
        download)
            shift 3
            while (($#)); do
                case "$1" in
                    --repo) shift 2 ;;
                    --pattern) name=$2; shift 2 ;;
                    --dir) directory=$2; shift 2 ;;
                    *) exit 96 ;;
                esac
            done
            cp "$GH_STATE/uploads/$name" "$directory/$name"
            if [[ ${MOCK_CORRUPT_DOWNLOAD:-0} == 1 ]]; then printf x | dd of="$directory/$name" bs=1 count=1 conv=notrunc status=none; fi
            ;;
        edit)
            jq '.draft=false' "$GH_STATE/release.json" >"$GH_STATE/new.json"
            mv "$GH_STATE/new.json" "$GH_STATE/release.json"
            jq -r '.target_commitish' "$GH_STATE/release.json" >"$GH_STATE/tag"
            ;;
        *) exit 94 ;;
    esac
else exit 95; fi
GH
    chmod +x "$BATS_TEST_TMPDIR/bin/gh"
    export PATH="$BATS_TEST_TMPDIR/bin:$PATH"
}

make_package() {
    local ubuntu=$1 version=$2 architecture=$3
    mkdir -p "$BATS_TEST_TMPDIR/deb/DEBIAN"
    printf 'Package: octoshield\nVersion: %s\nArchitecture: %s\nMaintainer: Fixture <fixture@example.invalid>\nDescription: Release test fixture\n' \
        "$version" "$architecture" >"$BATS_TEST_TMPDIR/deb/DEBIAN/control"
    dpkg-deb --build "$BATS_TEST_TMPDIR/deb" "$PACKAGES/octoshield_1.0.0_ubuntu${ubuntu}_amd64.deb" >/dev/null
    (cd "$PACKAGES" && sha256sum "octoshield_1.0.0_ubuntu${ubuntu}_amd64.deb" >"SHA256SUMS-ubuntu$ubuntu")
}

package_assets() {
    (
        cd "$ASSETS/release-assets" || return 1
        # shellcheck disable=SC2094
        find . -type f ! -name SHA256SUMS -print0 | LC_ALL=C sort -z | xargs -0 sha256sum >SHA256SUMS
    )
    tar -C "$ASSETS" -czf "$ASSETS/octoshield-assets-1.0.0.tar.gz" release-assets
    (cd "$ASSETS" && sha256sum octoshield-assets-1.0.0.tar.gz >SHA256SUMS-assets)
}

release() {
    run bash "$FIXTURE/scripts/publish-release.sh" v1.0.0 "$RELEASE_COMMIT" "$PACKAGES" "$ASSETS"
}

draft() {
    jq -n --arg commit "${1:-$RELEASE_COMMIT}" '{id:100,draft:true,tag_name:"v1.0.0",target_commitish:$commit,assets:[]}' >"$GH_STATE/release.json"
}

@test 'publishes two packages checksums archive twelve screenshots and metadata only after verification' {
    release
    [ "$status" -eq 0 ]
    jq -e '.draft == false and (.assets | length) == 19' "$GH_STATE/release.json"
    grep -Fx 'available=true' "$GITHUB_OUTPUT"
    grep -Fx 'published=true' "$GITHUB_OUTPUT"
    grep -Fx 'tag=v1.0.0' "$GITHUB_OUTPUT"
    grep -F 'sudo apt install ./octoshield_1.0.0_ubuntu24.04_amd64.deb' "$GH_STATE/notes.md"
    grep -F 'Restic/S3 backup management is not included' "$GH_STATE/notes.md"
    [[ $output != *fixture-token-canary* ]]
    run ! grep -F 'fixture-token-canary' "$GH_STATE/calls"
}

@test 'existing public release at this commit is an immutable no-op' {
    release
    [ "$status" -eq 0 ]
    cp "$GH_STATE/release.json" "$GH_STATE/original.json"
    : >"$GH_STATE/calls"
    : >"$GITHUB_OUTPUT"
    release
    [ "$status" -eq 0 ]
    cmp "$GH_STATE/original.json" "$GH_STATE/release.json"
    grep -Fx 'available=true' "$GITHUB_OUTPUT"
    grep -Fx 'published=false' "$GITHUB_OUTPUT"
    run ! grep '^release ' "$GH_STATE/calls"
}

@test 'unchanged public version on a later commit skips without moving tag' {
    draft 2222222222222222222222222222222222222222
    jq '.draft=false' "$GH_STATE/release.json" >"$GH_STATE/new.json"
    mv "$GH_STATE/new.json" "$GH_STATE/release.json"
    printf '%s\n' 2222222222222222222222222222222222222222 >"$GH_STATE/tag"
    release
    [ "$status" -eq 0 ]
    grep -Fx 'available=false' "$GITHUB_OUTPUT"
    grep -Fx 'published=false' "$GITHUB_OUTPUT"
    run ! grep '^tag=' "$GITHUB_OUTPUT"
    run ! grep '^release ' "$GH_STATE/calls"
}

@test 'only HTTP 404 permits release creation; authentication and transport failures stop' {
    local code
    for code in 401 403 429 500; do
        export MOCK_HTTP_ERROR=$code
        release
        [ "$status" -ne 0 ]
        [ ! -f "$GH_STATE/release.json" ]
        run ! grep '^release ' "$GH_STATE/calls"
    done
}

@test 'different existing tag is never overwritten' {
    printf '%s\n' 2222222222222222222222222222222222222222 >"$GH_STATE/tag"
    release
    [ "$status" -ne 0 ]
    [[ $output == *'tag points to another commit'* ]]
    run ! grep '^release ' "$GH_STATE/calls"
}

@test 'annotated tag resolving to the release commit is accepted' {
    printf '%s\n' 2222222222222222222222222222222222222222 >"$GH_STATE/tag"
    export MOCK_TAG_TYPE=tag
    release
    [ "$status" -eq 0 ]
    grep '/git/tags/' "$GH_STATE/calls"
}

@test 'draft at a different target is refused without uploads' {
    draft 2222222222222222222222222222222222222222
    release
    [ "$status" -ne 0 ]
    [[ $output == *'draft does not match'* ]]
    run ! grep '^release upload' "$GH_STATE/calls"
}

@test 'interrupted draft resumes verified uploads and publishes complete asset set' {
    export MOCK_FAIL_UPLOAD=3
    release
    [ "$status" -ne 0 ]
    jq -e '.draft == true and (.assets | length) == 2' "$GH_STATE/release.json"
    unset MOCK_FAIL_UPLOAD
    : >"$GH_STATE/calls"
    release
    [ "$status" -eq 0 ]
    [ "$(grep -c '^release upload' "$GH_STATE/calls")" -eq 17 ]
    jq -e '.draft == false and (.assets | length) == 19' "$GH_STATE/release.json"
}

@test 'unexpected draft assets are preserved and block publication for manual review' {
    draft
    jq '.assets=[{name:"unexpected.txt",size:1,state:"uploaded"}]' "$GH_STATE/release.json" >"$GH_STATE/new.json"
    mv "$GH_STATE/new.json" "$GH_STATE/release.json"
    release
    [ "$status" -ne 0 ]
    [[ $output == *'unexpected or duplicate assets'* ]]
    run ! grep '^release upload' "$GH_STATE/calls"
}

@test 'uploaded digest mismatch leaves release as a draft' {
    export MOCK_CORRUPT_UPLOAD=1
    release
    [ "$status" -ne 0 ]
    jq -e '.draft == true' "$GH_STATE/release.json"
    run ! grep '^release edit' "$GH_STATE/calls"
}

@test 'incorrect package checksum fails before creating any release' {
    printf 'tamper' >>"$PACKAGES/octoshield_1.0.0_ubuntu24.04_amd64.deb"
    release
    [ "$status" -ne 0 ]
    [ ! -f "$GH_STATE/release.json" ]
}

@test 'wrong package version or architecture fails even with valid checksum' {
    make_package 24.04 9.0.0 amd64
    release
    [ "$status" -ne 0 ]
    make_package 24.04 1.0.0 arm64
    release
    [ "$status" -ne 0 ]
    [ ! -f "$GH_STATE/release.json" ]
}

@test 'extra package or missing expected package cannot be released' {
    cp "$PACKAGES/octoshield_1.0.0_ubuntu24.04_amd64.deb" "$PACKAGES/unexpected.deb"
    release
    [ "$status" -ne 0 ]
    [ ! -f "$GH_STATE/release.json" ]
}

@test 'invalid screenshot fails even after asset checksums are regenerated' {
    printf 'not a PNG' >"$ASSETS/release-assets/gallery/OctoShield-usb-light.png"
    package_assets
    release
    [ "$status" -ne 0 ]
    [ ! -f "$GH_STATE/release.json" ]
}

@test 'archive contents must match verified unpacked assets' {
    printf 'extra content\n' >"$ASSETS/release-assets/extra.txt"
    (cd "$ASSETS/release-assets" && sha256sum extra.txt >>SHA256SUMS)
    release
    [ "$status" -ne 0 ]
    [ ! -f "$GH_STATE/release.json" ]
}

@test 'source provenance must identify this clean commit' {
    jq '.source.worktree_dirty=true' "$ASSETS/release-assets/manifest.json" >"$ASSETS/new.json"
    mv "$ASSETS/new.json" "$ASSETS/release-assets/manifest.json"
    package_assets
    release
    [ "$status" -ne 0 ]
    [ ! -f "$GH_STATE/release.json" ]
}

@test 'wrong source metadata and symbolic links fail closed' {
    printf 'wrong metadata' >"$ASSETS/release-assets/data/io.vdm.OctoShield.metainfo.xml"
    package_assets
    release
    [ "$status" -ne 0 ]
    cp "$FIXTURE/data/io.vdm.OctoShield.metainfo.xml" "$ASSETS/release-assets/data/"
    ln -s "$FIXTURE/data/io.vdm.OctoShield.metainfo.xml" "$ASSETS/release-assets/linked.xml"
    package_assets
    release
    [ "$status" -ne 0 ]
    [ ! -f "$GH_STATE/release.json" ]
}

@test 'invalid tag or commit and missing credentials fail before GitHub calls' {
    run bash "$FIXTURE/scripts/publish-release.sh" v01.0.0 "$RELEASE_COMMIT" "$PACKAGES" "$ASSETS"
    [ "$status" -ne 0 ]
    run bash "$FIXTURE/scripts/publish-release.sh" v1.0.0 main "$PACKAGES" "$ASSETS"
    [ "$status" -ne 0 ]
    GH_TOKEN='' release
    [ "$status" -ne 0 ]
    [ ! -f "$GH_STATE/calls" ]
}

@test 'downloaded artifact metadata changes do not invalidate identical archive bytes' {
    find "$ASSETS/release-assets" -type f -exec touch -m -t 200001010000 {} +
    find "$ASSETS/release-assets" -type f -exec chmod 0644 {} +
    release
    [ "$status" -eq 0 ]
    grep -Fx 'published=true' "$GITHUB_OUTPUT"
}

@test 'draft listing failure is not interpreted as release absence' {
    export MOCK_LIST_ERROR=1
    release
    [ "$status" -ne 0 ]
    [ ! -f "$GH_STATE/release.json" ]
    run ! grep '^release create' "$GH_STATE/calls"
}

@test 'missing API digests require downloaded byte verification before publishing' {
    MOCK_NULL_DIGEST=1 release
    [ "$status" -eq 0 ]
    [ "$(grep -c '^release download' "$GH_STATE/calls")" -eq 19 ]
}

@test 'same-size corrupt bytes fail download verification when API digest is absent' {
    MOCK_NULL_DIGEST=1 MOCK_CORRUPT_DOWNLOAD=1 release
    [ "$status" -ne 0 ]
    jq -e '.draft == true' "$GH_STATE/release.json"
    run ! grep '^release edit' "$GH_STATE/calls"
}

@test 'new draft visibility delay retries absence without creating a duplicate release' {
    MOCK_HIDDEN_LISTS=2 release
    [ "$status" -eq 0 ]
    [[ $output == *'attempt 1/5'* && $output == *'attempt 2/5'* ]]
    [ "$(grep -c '^release create' "$GH_STATE/calls")" -eq 1 ]
    jq -e '.draft == false and (.assets | length) == 19' "$GH_STATE/release.json"
}

@test 'new draft permanent absence stops after five checks and leaves draft untouched' {
    MOCK_HIDDEN_LISTS=99 release
    [ "$status" -ne 0 ]
    [[ $output == *'not visible after five checks'* ]]
    [ "$(cat "$GH_STATE/draft-list-count")" -eq 5 ]
    [ "$(grep -c '^release create' "$GH_STATE/calls")" -eq 1 ]
    jq -e '.draft == true and (.assets | length) == 0' "$GH_STATE/release.json"
    run ! grep '^release upload' "$GH_STATE/calls"
}

@test 'new draft API errors fail immediately without visibility retries' {
    MOCK_CREATED_LIST_ERROR=1 release
    [ "$status" -ne 0 ]
    [[ $output == *'Could not inspect the created draft'* ]]
    [ "$(cat "$GH_STATE/draft-list-count")" -eq 1 ]
    jq -e '.draft == true and (.assets | length) == 0' "$GH_STATE/release.json"
    run ! grep '^release upload' "$GH_STATE/calls"
}
