#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Publish only validated artifacts. Workflow gates reviewed main ancestry first.
set +x
set -Eeuo pipefail
IFS=$' \t\n'
umask 077

publish::error() {
    printf 'Release publication: %s\n' "$*" >&2
    return 1
}

# Return 4 only for an actual HTTP 404. Authentication, transport and malformed
# responses must never be mistaken for permission to create a release.
publish::get() {
    local endpoint=$1 output=$2 result=0 http
    gh api --include "$endpoint" >"$PUBLISH_TEMP/response" 2>"$PUBLISH_TEMP/error" || result=$?
    http=$(sed -nE '1s@^HTTP/[0-9.]+ ([0-9]{3}).*@\1@p' "$PUBLISH_TEMP/response")
    if [[ $http == 404 && $result != 0 ]]; then return 4; fi
    [[ $result == 0 && $http =~ ^2[0-9][0-9]$ ]] || {
        publish::error "GitHub API request failed (HTTP ${http:-unavailable}); nothing will be published."
        return 1
    }
    awk 'body { print } /^\r?$/ { body=1 }' "$PUBLISH_TEMP/response" >"$output"
    jq -e 'type == "object"' "$output" >/dev/null || {
        publish::error 'GitHub returned an invalid object.'
        return 1
    }
}

publish::release() {
    local tag=$1 output=$2 result=0 count id
    publish::get "repos/$GH_REPO/releases/tags/$tag" "$output" || result=$?
    [[ $result == 4 ]] || return "$result"
    # The tag endpoint only finds published releases. Drafts with pending tags
    # are visible through the authenticated list endpoint, then their numeric ID.
    gh api --paginate --slurp "repos/$GH_REPO/releases?per_page=100" >"$PUBLISH_TEMP/releases.json" || {
        publish::error 'Could not inspect draft releases; refusing to create a duplicate.'
        return 1
    }
    jq -e 'type == "array" and all(.[]; type == "array")' "$PUBLISH_TEMP/releases.json" >/dev/null || {
        publish::error 'GitHub returned an unexpected release list shape.'
        return 1
    }
    jq --arg tag "$tag" '[.[][] | select(.tag_name == $tag)]' "$PUBLISH_TEMP/releases.json" >"$PUBLISH_TEMP/matches.json"
    count=$(jq 'length' "$PUBLISH_TEMP/matches.json")
    [[ $count != 0 ]] || return 4
    [[ $count == 1 ]] || {
        publish::error 'Multiple releases use this tag; manual review is required.'
        return 1
    }
    id=$(jq -r '.[0].id' "$PUBLISH_TEMP/matches.json")
    [[ $id =~ ^[1-9][0-9]*$ ]] || {
        publish::error 'GitHub returned an invalid release identifier.'
        return 1
    }
    publish::get "repos/$GH_REPO/releases/$id" "$output"
}

publish::created_release() {
    local tag=$1 output=$2 attempt result
    # GitHub may acknowledge draft creation before its list/read endpoints can
    # see it. Retry only that temporary absence, never authentication or errors.
    for attempt in 1 2 3 4 5; do
        result=0
        publish::release "$tag" "$output" || result=$?
        if ((result == 0)); then return 0; fi
        if ((result != 4)); then
            publish::error 'Could not inspect the created draft; it remains unpublished for a safe retry.'
            return 1
        fi
        if ((attempt < 5)); then
            printf 'Created draft is not visible yet (attempt %s/5); checking again.\n' "$attempt" >&2
            sleep 1
        fi
    done
    publish::error 'Created draft was not visible after five checks; rerun publication to resume it safely.'
}

publish::tag_commit() {
    local tag=$1 result=0 type sha depth=0
    publish::get "repos/$GH_REPO/git/ref/tags/$tag" "$PUBLISH_TEMP/tag.json" || result=$?
    ((result == 0)) || return "$result"
    type=$(jq -r '.object.type' "$PUBLISH_TEMP/tag.json")
    sha=$(jq -r '.object.sha' "$PUBLISH_TEMP/tag.json")
    while [[ $type == tag && $depth -lt 8 ]]; do
        [[ $sha =~ ^[0-9a-f]{40}$ ]] || return 1
        publish::get "repos/$GH_REPO/git/tags/$sha" "$PUBLISH_TEMP/tag.json" || return 1
        type=$(jq -r '.object.type' "$PUBLISH_TEMP/tag.json")
        sha=$(jq -r '.object.sha' "$PUBLISH_TEMP/tag.json")
        depth=$((depth + 1))
    done
    [[ $type == commit && $sha =~ ^[0-9a-f]{40}$ ]] || {
        publish::error 'Release tag does not resolve to a commit.'
        return 1
    }
    printf '%s\n' "$sha"
}

publish::outputs() {
    local available=$1 published=$2 tag=$3
    printf 'Release available for this commit: %s; newly published: %s\n' "$available" "$published"
    if [[ -n ${GITHUB_OUTPUT:-} ]]; then
        printf 'available=%s\npublished=%s\n' "$available" "$published" >>"$GITHUB_OUTPUT"
        if [[ $available == true ]]; then printf 'tag=%s\n' "$tag" >>"$GITHUB_OUTPUT"; fi
    fi
}

publish::regular() {
    [[ -f $1 && ! -L $1 ]] || publish::error "Missing regular artifact: $1"
}

publish::checksum() {
    local directory=$1 manifest=$2 name=$3 hash
    publish::regular "$directory/$manifest" || return 1
    publish::regular "$directory/$name" || return 1
    hash=$(sha256sum "$directory/$name")
    printf '%s  %s\n' "${hash%% *}" "$name" >"$PUBLISH_TEMP/checksum"
    cmp -s "$PUBLISH_TEMP/checksum" "$directory/$manifest" || {
        publish::error "Checksum or expected filename mismatch in $manifest."
        return 1
    }
}

publish::validate() {
    local root=$1 tag=$2 commit=$3 packages=$4 assets=$5 version=${2#v} ubuntu path name gallery_paths dimensions width height
    local -a debs=() gallery_names=()
    # The same header validation used when assembling the original captures.
    # shellcheck source=release-assets.sh
    source "$root/scripts/release-assets.sh"
    mapfile -t gallery_names < <(release_assets::gallery_names)
    gallery_paths=$(printf 'gallery/%s\n' "${gallery_names[@]}" | jq -Rsc 'split("\n")[:-1] | sort') || return 1
    shopt -s nullglob
    debs=("$packages"/*.deb)
    ((${#debs[@]} == 2)) || {
        publish::error 'Expected exactly two Ubuntu Debian packages.'
        return 1
    }
    for ubuntu in 24.04 26.04; do
        name="octoshield_${version}_ubuntu${ubuntu}_amd64.deb"
        path="$packages/$name"
        publish::checksum "$packages" "SHA256SUMS-ubuntu$ubuntu" "$name" || return 1
        [[ $(dpkg-deb -f "$path" Package) == octoshield &&
        $(dpkg-deb -f "$path" Version) == "$version" &&
        $(dpkg-deb -f "$path" Architecture) == amd64 ]] || {
            publish::error "Wrong package identity, version or architecture: $name"
            return 1
        }
        PUBLISH_FILES+=("$path" "$packages/SHA256SUMS-ubuntu$ubuntu")
    done
    name="octoshield-assets-$version.tar.gz"
    publish::checksum "$assets" SHA256SUMS-assets "$name" || return 1
    publish::regular "$assets/release-assets/manifest.json" || return 1
    jq -e --arg version "$version" --arg commit "$commit" '
      .application_id == "io.vdm.OctoShield" and .version == $version and
      .source.commit == $commit and .source.worktree_dirty == false' \
        "$assets/release-assets/manifest.json" >/dev/null || {
        publish::error 'Release asset provenance does not match the clean release commit.'
        return 1
    }
    jq -e --argjson expected "$gallery_paths" '
      (.gallery | type) == "array" and
      all(.gallery[]; type == "object" and (.path | type) == "string" and
        (.width | type) == "number" and (.height | type) == "number" and
        .width > 0 and .height > 0 and .width == (.width | floor) and .height == (.height | floor)) and
      ([.gallery[].path] | sort) == $expected and
      (.branding | type) == "array" and (.branding | length) == 2' \
        "$assets/release-assets/manifest.json" >/dev/null || {
        publish::error 'Release asset gallery does not match the expected application screenshots.'
        return 1
    }
    # Recompute the complete checksum manifest instead of allowing untrusted
    # manifest paths to make sha256sum read outside the artifact directory.
    [[ -z $(find "$assets/release-assets" ! -type f ! -type d -print -quit) ]] || {
        publish::error 'Release assets must contain only regular files and directories.'
        return 1
    }
    (
        cd "$assets/release-assets"
        find . -type f ! -name SHA256SUMS -print0 | LC_ALL=C sort -z | xargs -0 sha256sum
    ) >"$PUBLISH_TEMP/asset-checksums"
    cmp -s "$PUBLISH_TEMP/asset-checksums" "$assets/release-assets/SHA256SUMS" || {
        publish::error 'Release asset contents do not match their checksums.'
        return 1
    }
    # Require the tar to contain precisely this tree, then compare its contents
    # without extracting anything or following archive-provided paths.
    (cd "$assets" && find release-assets -printf '%p%y\n' | sed -E 's/d$/\//; s/f$//' | LC_ALL=C sort) >"$PUBLISH_TEMP/tree"
    tar -tzf "$assets/$name" | LC_ALL=C sort >"$PUBLISH_TEMP/archive-tree"
    cmp -s "$PUBLISH_TEMP/tree" "$PUBLISH_TEMP/archive-tree" || {
        publish::error 'Release archive member list differs from its verified asset tree.'
        return 1
    }
    tar -tvzf "$assets/$name" | awk 'substr($0,1,1) != "-" && substr($0,1,1) != "d" { bad=1 } END { exit bad }' || {
        publish::error 'Release archive contains a link or special file.'
        return 1
    }
    # Artifact download normalizes timestamps and permissions. Compare bytes
    # without extraction, ignoring those transport-dependent attributes.
    while IFS= read -r path; do
        [[ $path == */ ]] && continue
        tar -xOzf "$assets/$name" -- "$path" | cmp -s - "$assets/$path" || {
            publish::error "Release archive bytes differ for $path."
            return 1
        }
    done <"$PUBLISH_TEMP/tree"
    PUBLISH_FILES+=("$assets/$name" "$assets/SHA256SUMS-assets")
    for name in "${gallery_names[@]}"; do
        path="$assets/release-assets/gallery/$name"
        dimensions=$(release_assets::png_dimensions "$path") || return 1
        read -r width height <<<"$dimensions"
        jq -e --arg path "gallery/$name" --argjson width "$width" --argjson height "$height" \
            'any(.gallery[]; .path == $path and .width == $width and .height == $height)' \
            "$assets/release-assets/manifest.json" >/dev/null || {
            publish::error "Screenshot dimensions do not match the asset manifest: $name."
            return 1
        }
        PUBLISH_FILES+=("$path")
    done
    path="$assets/release-assets/data/io.vdm.OctoShield.metainfo.xml"
    publish::regular "$path" || return 1
    # Version consistency was checked from the source; the packaged metadata must
    # be byte-for-byte the reviewed source metadata as well.
    cmp -s "$path" "$root/data/io.vdm.OctoShield.metainfo.xml" || {
        publish::error 'Packaged AppStream metadata differs from the reviewed source.'
        return 1
    }
    PUBLISH_FILES+=("$path")
    : >"$PUBLISH_TEMP/expected.jsonl"
    for path in "${PUBLISH_FILES[@]}"; do
        local hash size
        hash=$(sha256sum "$path")
        size=$(stat -c %s "$path")
        jq -cn --arg name "${path##*/}" --argjson size "$size" --arg digest "sha256:${hash%% *}" \
            '{name:$name,size:$size,digest:$digest}' >>"$PUBLISH_TEMP/expected.jsonl"
    done
    jq -s 'sort_by(.name)' "$PUBLISH_TEMP/expected.jsonl" >"$PUBLISH_TEMP/expected.json"
}

publish::draft() {
    local release=$1 tag=$2 commit=$3
    jq -e --arg tag "$tag" --arg commit "$commit" '
      .draft == true and .tag_name == $tag and .target_commitish == $commit and
      (.assets | type == "array")' "$release" >/dev/null || {
        publish::error 'Existing draft does not match this exact release commit.'
        return 1
    }
    jq -e --slurpfile expected "$PUBLISH_TEMP/expected.json" '
      [.assets[].name] as $names | ($names | length) == ($names | unique | length) and
      all($names[]; . as $name | any($expected[0][]; .name == $name))' "$release" >/dev/null || {
        publish::error 'Draft contains unexpected or duplicate assets; manual review is required.'
        return 1
    }
}

publish::notes() {
    local tag=$1 commit=$2 version=${1#v} gallery_count
    gallery_count=$(release_assets::gallery_names | wc -l) || return 1
    cat <<NOTES
OctoShield $tag is a native Ubuntu security application maintained by **Vast Development Method**, part of the **Octoleo** suite. https://www.vdm.io

### Download and install

Download the package matching your Ubuntu release and its checksum file from the assets below. These are **amd64 (x86-64)** builds; other architectures and Ubuntu releases are not covered by these packages.

**Ubuntu 24.04 LTS:**
\`\`\`bash
sha256sum --check SHA256SUMS-ubuntu24.04
sudo apt install ./octoshield_${version}_ubuntu24.04_amd64.deb
\`\`\`

**Ubuntu 26.04 LTS:**
\`\`\`bash
sha256sum --check SHA256SUMS-ubuntu26.04
sudo apt install ./octoshield_${version}_ubuntu26.04_amd64.deb
\`\`\`

Launch **OctoShield** from the application menu, run \`octoshield-gtk\`, or use \`octoshield\` for the terminal interface. The Debian package includes both interfaces. The standalone CLI remains available using the source installation instructions.

### Included capabilities

- Firewall, network, service, update and AppArmor controls with explicit change previews.
- USB authorization, device inspection and reviewed enrollment.
- Office network, firewall and service exceptions.
- Direct firewall failure recovery with fresh native inspection, reviewed profile application, external-change reconciliation and verified original-policy restoration.
- Security monitoring and user-session notifications.
- GNOME desktop settings with light/dark appearance and user preference recovery.
- Local configuration recovery snapshots and action history; these are not full-file backups. Restic/S3 backup management is not included in this release.
- Reviewed system repair for retired OctoShield settings, including the removed zero-timeout sudo policy.

Installing the package does not automatically enable protections or enroll USB devices. Requested system changes require administrator authorization. Review the proposed changes before confirming them.

### Updates and removal

Install a newer matching Debian package with the same \`sudo apt install ./...deb\` command to upgrade. Automatic APT updates require the separately configured, signed OctoShield APT repository; downloading this package alone does not enroll it.

After upgrading, use **Recovery & updates → Repair system** or \`octoshield repair\` to review any retired settings reported by the application. Package installation preserves native policy until you approve that repair.

For a recorded firewall failure, open **Access & exceptions → Firewall status and recovery**. Inspect the current finding, then review application of the selected saved firewall profile or restoration of its original settings. Supported external changes have a separate tracking-only review. Recovery preserves a pending permission for a separate decision. UFW's normal forwarding-disabled display is now verified against native IPv4/IPv6 policy instead of being treated as a failure by itself.

Remove the application with \`sudo apt remove octoshield\`. Native security policies and private configuration recovery snapshots are preserved; consult the recovery guide before reversing protection settings.

- [Usage and setup](https://github.com/$GH_REPO/blob/$tag/README.md)
- [Features](https://github.com/$GH_REPO/blob/$tag/docs/features.md)
- [Installation, updates and removal](https://github.com/$GH_REPO/blob/$tag/docs/distribution.md)
- [Configuration recovery](https://github.com/$GH_REPO/blob/$tag/docs/recovery.md)

The asset archive contains documentation, metadata, original branding and $gallery_count real native-interface screenshots. Package and archive SHA-256 manifests are provided below.

Built from commit \`$commit\` after the automated test, lint, native-interface and Debian lifecycle checks passed for both supported Ubuntu releases.
NOTES
}

publish::main() (
    [[ $# == 4 && $1 =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ && $2 =~ ^[0-9a-f]{40}$ ]] || {
        publish::error 'Usage: scripts/publish-release.sh vX.Y.Z COMMIT PACKAGE_DIR ASSET_DIR'
        return 2
    }
    local tag=$1 commit=$2 packages=$3 assets=$4 root result=0 resolved path name
    local -a PUBLISH_FILES=()
    [[ ${GH_REPO:-} == octoleo/octoshield && -n ${GH_TOKEN:-} ]] || {
        publish::error 'GH_REPO=octoleo/octoshield and GH_TOKEN are required.'
        return 1
    }
    unset GH_DEBUG
    export GH_HOST=github.com GH_PROMPT_DISABLED=1
    root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
    bash "$root/scripts/version.sh" --check "$tag" || return 1
    local PUBLISH_TEMP
    PUBLISH_TEMP=$(mktemp -d)
    trap 'rm -rf -- "$PUBLISH_TEMP"' EXIT
    publish::release "$tag" "$PUBLISH_TEMP/release.json" || result=$?
    [[ $result == 0 || $result == 4 ]] || return 1
    if [[ $result == 0 ]] && jq -e '.draft == false' "$PUBLISH_TEMP/release.json" >/dev/null; then
        resolved=$(publish::tag_commit "$tag") || return 1
        if [[ $resolved == "$commit" ]]; then
            publish::outputs true false "$tag"
        else
            printf 'Version %s is already published from another commit; increment the version to release these changes.\n' "$tag"
            publish::outputs false false "$tag"
        fi
        return
    fi
    publish::validate "$root" "$tag" "$commit" "$packages" "$assets" || return 1
    local tag_result=0
    resolved=$(publish::tag_commit "$tag") || tag_result=$?
    [[ $tag_result == 0 || $tag_result == 4 ]] || return 1
    if [[ $tag_result == 0 && $resolved != "$commit" ]]; then
        publish::error 'The existing tag points to another commit; it will not be moved.'
        return 1
    fi
    if [[ $result == 4 ]]; then
        publish::notes "$tag" "$commit" >"$PUBLISH_TEMP/notes.md"
        gh release create "$tag" --repo "$GH_REPO" --draft --target "$commit" \
            --title "OctoShield $tag" --notes-file "$PUBLISH_TEMP/notes.md" || return 1
        publish::created_release "$tag" "$PUBLISH_TEMP/release.json" || return 1
    fi
    publish::draft "$PUBLISH_TEMP/release.json" "$tag" "$commit" || return 1
    # GitHub may delay creating the tag until a draft is published. An existing
    # tag was already checked above; --target pins a newly created tag to COMMIT.
    for path in "${PUBLISH_FILES[@]}"; do
        name=${path##*/}
        if jq -e --arg name "$name" --slurpfile expected "$PUBLISH_TEMP/expected.json" '
          ($expected[0][] | select(.name == $name)) as $want |
          any(.assets[]; .name == $name and .state == "uploaded" and .size == $want.size and
            .digest == $want.digest)' "$PUBLISH_TEMP/release.json" >/dev/null; then
            continue
        fi
        # Clobber is deliberately limited to a validated draft under the
        # workflow publication lock. Published assets are never overwritten.
        gh release upload "$tag" "$path" --repo "$GH_REPO" --clobber || return 1
    done
    publish::release "$tag" "$PUBLISH_TEMP/release.json" || return 1
    publish::draft "$PUBLISH_TEMP/release.json" "$tag" "$commit" || return 1
    jq -e --slurpfile expected "$PUBLISH_TEMP/expected.json" '
      (.assets | sort_by(.name)) as $actual | $expected[0] as $want |
      ($actual | length) == ($want | length) and
      all(range(0; $want | length); . as $i |
        $actual[$i].name == $want[$i].name and $actual[$i].state == "uploaded" and
        $actual[$i].size == $want[$i].size and
        ($actual[$i].digest == null or $actual[$i].digest == $want[$i].digest))' \
        "$PUBLISH_TEMP/release.json" >/dev/null || {
        publish::error 'Uploaded asset names, sizes or digests failed verification; release remains a draft.'
        return 1
    }
    for path in "${PUBLISH_FILES[@]}"; do
        name=${path##*/}
        if jq -e --arg name "$name" 'any(.assets[]; .name == $name and .digest == null)' "$PUBLISH_TEMP/release.json" >/dev/null; then
            mkdir -p "$PUBLISH_TEMP/download"
            gh release download "$tag" --repo "$GH_REPO" --pattern "$name" --dir "$PUBLISH_TEMP/download" || return 1
            cmp -s "$path" "$PUBLISH_TEMP/download/$name" || {
                publish::error "Uploaded asset bytes failed verification: $name; release remains a draft."
                return 1
            }
        fi
    done
    gh release edit "$tag" --repo "$GH_REPO" --draft=false --latest || return 1
    publish::release "$tag" "$PUBLISH_TEMP/release.json" || return 1
    jq -e '.draft == false' "$PUBLISH_TEMP/release.json" >/dev/null || return 1
    resolved=$(publish::tag_commit "$tag") || return 1
    [[ $resolved == "$commit" ]] || {
        publish::error 'Published tag commit verification failed.'
        return 1
    }
    publish::outputs true true "$tag"
)

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then publish::main "$@"; fi
