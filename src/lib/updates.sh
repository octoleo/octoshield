#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Read-only, on-demand release lookup. Never downloads or executes a package.

updates::valid_version() {
    [[ ${#1} -le 128 && $1 =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]
}

updates::newer() {
    local candidate=$1 current=$2 a b index
    local -a left right
    updates::valid_version "$candidate" && updates::valid_version "$current" || return 1
    IFS=. read -r -a left <<<"$candidate"
    IFS=. read -r -a right <<<"$current"
    for index in 0 1 2; do
        a=${left[$index]} b=${right[$index]}
        ((${#a} > ${#b})) && return 0
        ((${#a} < ${#b})) && return 1
        [[ $a > $b ]] && return 0
        [[ $a < $b ]] && return 1
    done
    return 1
}

updates::platform() {
    local distribution version architecture
    # os-release is data, not shell code. Accept only the two shipped targets.
    distribution=$(sed -n 's/^ID="\?\([a-z0-9]*\)"\?$/\1/p' /etc/os-release)
    version=$(sed -n 's/^VERSION_ID="\?\([0-9.]*\)"\?$/\1/p' /etc/os-release)
    architecture=$(dpkg --print-architecture 2>/dev/null) || return 1
    [[ $distribution == ubuntu && $architecture == amd64 ]] || return 1
    case "$version" in 24.04 | 26.04) printf 'ubuntu%s/amd64\n' "$version" ;; *) return 1 ;; esac
}

updates::_result() {
    jq -cn --arg current "$1" --arg latest "$2" --arg status "$3" \
        --arg release_url "$4" --arg download_url "$5" --arg platform "$6" --arg message "$7" \
        --argjson available "$8" \
        '{schema:1,current:$current,latest:$latest,status:$status,available:$available,release_url:$release_url,download_url:$download_url,platform:$platform,message:$message}'
}

updates::check() (
    local current=${OCTOSHIELD_VERSION:-} latest='' platform='' download='' release='' state=current available=false message response bytes asset
    local LC_ALL=C
    if ! updates::valid_version "$current"; then
        updates::_result '' '' error '' '' '' 'The installed application version could not be verified.' false
        return 1
    fi
    # No cached authentication, environment token, custom endpoint, redirect, or
    # shell configuration is sent. curl -q disables ~/.curlrc URL/options injection.
    response=$(mktemp) || return 1
    trap 'rm -f -- "$response"' EXIT
    if ! curl -q --fail --silent --show-error --proto '=https' --tlsv1.2 \
        --connect-timeout 5 --max-time 15 --max-filesize 1048576 \
        --header 'Accept: application/vnd.github+json' --header 'X-GitHub-Api-Version: 2022-11-28' \
        --output "$response" 'https://api.github.com/repos/octoleo/octoshield/releases/latest' 2>/dev/null; then
        updates::_result "$current" '' error '' '' '' 'Could not check releases. Check your connection and try again later.' false
        return 1
    fi
    bytes=$(wc -c <"$response") || return 1
    if ((bytes > 1048576)) || ! jq -e '
        type == "object" and .draft == false and .prerelease == false and
        (.tag_name | type == "string" and length <= 129 and test("^v(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\z")) and
        (.assets | type == "array")' "$response" >/dev/null 2>&1; then
        updates::_result "$current" '' error '' '' '' 'The release response was invalid; no download was offered.' false
        return 1
    fi
    latest=$(jq -r '.tag_name | ltrimstr("v")' "$response") || return 1
    updates::valid_version "$latest" || return 1
    release="https://github.com/octoleo/octoshield/releases/tag/v$latest"
    if updates::newer "$latest" "$current"; then
        available=true state=available
        message="OctoShield $latest is available. Open the official release and install the matching Debian package with your package manager."
    else
        message='No newer stable release is available.'
    fi
    if platform=$(updates::platform); then
        case "$platform" in ubuntu24.04/amd64 | ubuntu26.04/amd64) ;; *) platform='' ;; esac
    else platform=''; fi
    if [[ -n $platform ]]; then
        asset="octoshield_${latest}_${platform%/*}_amd64.deb"
        download="https://github.com/octoleo/octoshield/releases/download/v$latest/$asset"
        if ! jq -e --arg name "$asset" --arg url "$download" \
            '[.assets[] | select(.name == $name and .browser_download_url == $url and .state == "uploaded" and (.size | type == "number" and . > 0))] | length == 1' \
            "$response" >/dev/null 2>&1; then
            download='' state=unsupported
            message='The official release has no verified package link for this system. Open the release for supported builds.'
        fi
    else
        state=unsupported
        message='Automatic package selection supports Ubuntu 24.04 and 26.04 on amd64. Open the official release for source and build instructions.'
    fi
    # Development/review packages may be ahead of the current public release.
    # Never offer a direct package link that would downgrade this installation.
    if updates::newer "$current" "$latest"; then download=''; fi
    updates::_result "$current" "$latest" "$state" "$release" "$download" "$platform" "$message" "$available"
)

updates::show() {
    local result status=0
    result=$(updates::check) || status=$?
    jq -r '"Installed: \(.current)", (if .latest != "" then "Latest stable: \(.latest)" else empty end), .message,
        (if .release_url != "" then "Release: \(.release_url)" else empty end),
        (if .download_url != "" then "Package: \(.download_url)", "Download the package, then open it with your system package installer.",
            "Or, from the download directory: sudo apt install ./\(.download_url | split("/") | last)" else empty end)' <<<"$result" || return 1
    return "$status"
}
