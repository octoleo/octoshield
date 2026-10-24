#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Assemble native release documentation and real UI captures; never upload/resize.
set -Eeuo pipefail
IFS=$' \t\n'
umask 022

release_assets::error() {
    printf 'Release assets: %s\n' "$*" >&2
    return 1
}

# One canonical gallery is shared by assembly and publication. A new page must
# be captured in both themes before either stage can accept the release assets.
release_assets::gallery_names() {
    local page theme
    for page in overview protections usb office privacy diagnostics monitoring recovery; do
        for theme in light dark; do
            printf 'OctoShield-%s-%s.png\n' "$page" "$theme"
        done
    done
}

release_assets::require_file() {
    [[ -f $1 && ! -L $1 ]] || {
        release_assets::error "Missing regular input file: $1"
        return 1
    }
}

# Read only the PNG signature and IHDR dimensions. Full decoding belongs to UI
# capture verification; the supplied artwork and captured files stay unchanged.
release_assets::png_dimensions() {
    local path=$1 raw width height
    local -a bytes=()
    release_assets::require_file "$path" || return 1
    raw=$(od -An -v -tu1 -N24 -- "$path") || return 1
    read -r -a bytes <<<"${raw//$'\n'/ }"
    if [[ ${#bytes[@]} -ne 24 || ${bytes[*]:0:8} != '137 80 78 71 13 10 26 10' ||
        ${bytes[*]:8:8} != '0 0 0 13 73 72 68 82' ]]; then
        release_assets::error "Not a PNG with an IHDR header: $path"
        return 1
    fi
    width=$((bytes[16] * 16777216 + bytes[17] * 65536 + bytes[18] * 256 + bytes[19]))
    height=$((bytes[20] * 16777216 + bytes[21] * 65536 + bytes[22] * 256 + bytes[23]))
    if ((width < 1 || height < 1 || width > 2147483647 || height > 2147483647)); then
        release_assets::error "Invalid PNG dimensions: $path"
        return 1
    fi
    printf '%s %s\n' "$width" "$height"
}

release_assets::image_record() {
    local path=$1 dimensions=$2 width height
    read -r width height <<<"$dimensions"
    jq -cn --arg path "$path" --argjson width "$width" --argjson height "$height" \
        '{path:$path,width:$width,height:$height}'
}

release_assets::copy() {
    local root=$1 output=$2 source=$3 destination=${4:-$3}
    install -D -m 0644 -- "$root/$source" "$output/$destination"
}

release_assets::readme() {
    local output=$1 version=$2 commit=$3
    cat >"$output/README.txt" <<README
OctoShield $version — Native release assets
Maintained by Vast Development Method · Octoleo · https://www.vdm.io
Source: https://github.com/octoleo/octoshield
Commit: $commit

This directory contains documentation, metadata and images. Install the separate
native Debian package to use the complete graphical application, terminal CLI,
and monitor. The independent CLI installer is also supported.

Installing the application does not enable security controls or enroll devices.
System changes require explicit choices and administrator authorization; desktop
preferences remain in the logged-in user's session. Removing the package stops
its own services while preserving native security policy and recovery snapshots.
See docs/distribution.md for installation, updates and removal instructions.

Files:
  README.md                       Project usage and security-control documentation
  LICENSE                         Project license
  docs/features.md                Detailed application capabilities
  docs/distribution.md            Native installation and lifecycle instructions
  gallery/                        All light/dark application page captures
  branding/                       Original supplied PNG artwork, unchanged
  data/                           Standard AppStream and desktop-entry metadata
  manifest.json                   Version, source commit and image dimensions
  SHA256SUMS                      Checksums for every other file in this directory

The gallery shows the actual native application with its supplied branding,
captured by UI tests in demonstration/initial states. Displayed data is not a
measurement from a protected laptop. Do not describe the images as proof that
security controls are active. Artwork and screenshots are copied unchanged.
PNG signatures and dimensions are checked when assembling these assets.

Standard desktop metadata is included for native installation and possible future
catalogue integration. Screenshot URLs become available after their matching
tagged release is published. A private GitHub release is not anonymously
accessible; a public catalogue would require publicly accessible media. Creating
this directory does not upload files, publish a release or change visibility.

Repository-relative source links refer to the full source checkout. This asset
collection deliberately excludes source code, credentials and local machine state.
Verify all included files with: sha256sum --check SHA256SUMS
README
}

release_assets::main() {
    [[ $# -eq 1 && -n $1 ]] || {
        release_assets::error 'Usage: scripts/release-assets.sh OUTPUT_DIR (new directory; parent must exist)'
        return 2
    }
    local root output version commit dirty=false file theme name dimensions record changes
    local -a sources=(
        README.md LICENSE docs/features.md docs/distribution.md
        data/io.vdm.OctoShield.metainfo.xml data/io.vdm.OctoShield.desktop
    )
    local -a gallery_names=() gallery_records=() branding_records=()
    local -A image_dimensions=()
    for file in jq git od realpath install sha256sum find sort xargs; do
        command -v "$file" >/dev/null || {
            release_assets::error "Required tool is unavailable: $file"
            return 1
        }
    done
    root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P) || return 1
    [[ ! -e $1 && ! -L $1 ]] || {
        release_assets::error 'Output already exists; choose a new directory. Nothing was removed.'
        return 1
    }
    output=$(realpath -m -- "$1") || return 1
    [[ -d ${output%/*} && ! -e $output && ! -L $output ]] || {
        release_assets::error 'The output parent must exist and the output itself must be new.'
        return 1
    }
    release_assets::require_file "$root/scripts/version.sh" || return 1
    bash "$root/scripts/version.sh" --check >&2 || return 1
    version=$(bash "$root/scripts/version.sh") || return 1
    [[ $version =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || return 1
    for file in "${sources[@]}"; do release_assets::require_file "$root/$file" || return 1; done
    # Validate all input media before creating the output directory.
    mapfile -t gallery_names < <(release_assets::gallery_names)
    for name in "${gallery_names[@]}"; do
        dimensions=$(release_assets::png_dimensions "$root/build/screenshots/$name") || return 1
        image_dimensions[$name]=$dimensions
        record=$(release_assets::image_record "gallery/$name" "$dimensions") || return 1
        gallery_records+=("$record")
    done
    for theme in light dark; do
        dimensions=$(release_assets::png_dimensions "$root/data/branding/OctoShield-$theme.png") || return 1
        record=$(release_assets::image_record "branding/OctoShield-$theme.png" "$dimensions") || return 1
        branding_records+=("$record")
    done
    commit=$(git -C "$root" rev-parse --verify HEAD) || return 1
    [[ $commit =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]] || return 1
    changes=$(git -C "$root" status --porcelain --untracked-files=normal) || return 1
    if [[ -n $changes ]]; then dirty=true; fi
    mkdir -m 0755 -- "$output" || return 1
    # Leave partial output on failure for inspection; never recursively remove a
    # caller-selected directory. Only the explicit public source files are copied.
    for file in "${sources[@]}"; do release_assets::copy "$root" "$output" "$file" || return 1; done
    for name in "${!image_dimensions[@]}"; do
        release_assets::copy "$root" "$output" "build/screenshots/$name" "gallery/$name" || return 1
    done
    for theme in light dark; do
        release_assets::copy "$root" "$output" "data/branding/OctoShield-$theme.png" "branding/OctoShield-$theme.png" || return 1
    done
    release_assets::readme "$output" "$version" "$commit" || return 1
    jq -n --arg version "$version" --arg commit "$commit" --argjson dirty "$dirty" \
        --argjson gallery "$(printf '%s\n' "${gallery_records[@]}" | jq -s .)" \
        --argjson branding "$(printf '%s\n' "${branding_records[@]}" | jq -s .)" '
        {schema_version:1,application_id:"io.vdm.OctoShield",title:"OctoShield",version:$version,
         source:{repository:"https://github.com/octoleo/octoshield",commit:$commit,worktree_dirty:$dirty},
         distribution:"native-debian-and-standalone-cli",gallery:$gallery,branding:$branding}' \
        >"$output/manifest.json" || return 1
    (
        cd -- "$output" || return 1
        # The checksum file is explicitly excluded from the files being hashed.
        # shellcheck disable=SC2094
        find . -type f ! -name SHA256SUMS -print0 | LC_ALL=C sort -z | xargs -0 sha256sum >SHA256SUMS
    ) || return 1
    printf 'Created OctoShield %s release assets: %s\n' "$version" "$output"
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then release_assets::main "$@"; fi
