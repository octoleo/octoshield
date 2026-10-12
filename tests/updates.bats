#!/usr/bin/env bats
# SPDX-License-Identifier: Apache-2.0
# shellcheck disable=SC2317,SC2329,SC2030,SC2031

setup() {
    source "$BATS_TEST_DIRNAME/../src/lib/updates.sh"
    OCTOSHIELD_VERSION=1.1.0
    UPDATE_RESPONSE="$BATS_TEST_TMPDIR/release.json"
    UPDATE_CURL_LOG="$BATS_TEST_TMPDIR/curl.log"
    export UPDATE_RESPONSE UPDATE_CURL_LOG
    updates::platform() { printf 'ubuntu24.04/amd64\n'; }
    curl() {
        printf '%s\n' "$@" >"$UPDATE_CURL_LOG"
        local output
        while (($#)); do
            if [[ $1 == --output ]]; then
                output=$2
                shift
            fi
            shift
        done
        cp "$UPDATE_RESPONSE" "$output"
    }
    release_fixture 1.2.0
}

release_fixture() {
    local version=$1
    jq -n --arg v "$version" '{draft:false,prerelease:false,tag_name:("v"+$v),assets:[{name:("octoshield_"+$v+"_ubuntu24.04_amd64.deb"),browser_download_url:("https://github.com/octoleo/octoshield/releases/download/v"+$v+"/octoshield_"+$v+"_ubuntu24.04_amd64.deb"),state:"uploaded",size:100}]}' >"$UPDATE_RESPONSE"
}

@test 'release lookup offers only the exact official matching Debian asset' {
    run updates::check
    [ "$status" -eq 0 ]
    jq -e '.schema == 1 and .current == "1.1.0" and .latest == "1.2.0" and .available and .status == "available" and .download_url == "https://github.com/octoleo/octoshield/releases/download/v1.2.0/octoshield_1.2.0_ubuntu24.04_amd64.deb"' <<<"$output"
    [ "$(head -1 "$UPDATE_CURL_LOG")" = -q ]
    grep -Fx -- '--max-filesize' "$UPDATE_CURL_LOG"
    grep -Fx -- '1048576' "$UPDATE_CURL_LOG"
    grep -Fx -- '--max-time' "$UPDATE_CURL_LOG"
    grep -Fx -- 'https://api.github.com/repos/octoleo/octoshield/releases/latest' "$UPDATE_CURL_LOG"
    run grep -Eq -- 'location|Authorization|token' "$UPDATE_CURL_LOG"
    [ "$status" -ne 0 ]
}

@test 'release lookup detects numeric semantic order without overflow' {
    run updates::newer 1.10.0 1.9.99
    [ "$status" -eq 0 ]
    run updates::newer 9223372036854775808.0.0 9223372036854775807.999.999
    [ "$status" -eq 0 ]
    run updates::newer 1.1.0 1.1.0
    [ "$status" -ne 0 ]
    run updates::newer 1.0.99 1.1.0
    [ "$status" -ne 0 ]
}

@test 'same or older latest release never proposes a downgrade' {
    local version
    for version in 1.1.0 1.0.9; do
        release_fixture "$version"
        run updates::check
        [ "$status" -eq 0 ]
        jq -e '.available == false and .status == "current"' <<<"$output"
        if [[ $version == 1.0.9 ]]; then jq -e '.download_url == ""' <<<"$output"; fi
    done
}

@test 'release lookup rejects drafts prereleases invalid JSON and noncanonical versions' {
    local filter
    for filter in '.draft=true' '.prerelease=true' '.tag_name="v01.2.3"' '.tag_name="v1.2.3-rc1"' '.tag_name="v1.2.3;id"' '.tag_name="v1.2.3\n"' '.assets={}' '[]'; do
        release_fixture 1.2.0
        jq "$filter" "$UPDATE_RESPONSE" >"$UPDATE_RESPONSE.tmp"
        mv "$UPDATE_RESPONSE.tmp" "$UPDATE_RESPONSE"
        run updates::check
        [ "$status" -ne 0 ]
        jq -e '.status == "error" and .download_url == "" and .release_url == ""' <<<"$output"
    done
    printf 'not json' >"$UPDATE_RESPONSE"
    run updates::check
    [ "$status" -ne 0 ]
}

@test 'release lookup does not trust alternate asset URLs or duplicate assets' {
    local filter
    for filter in '.assets[0].browser_download_url="https://example.com/root.sh"' '.assets += .assets' '.assets[0].state="new"' '.assets[0].size=0'; do
        release_fixture 1.2.0
        jq "$filter" "$UPDATE_RESPONSE" >"$UPDATE_RESPONSE.tmp"
        mv "$UPDATE_RESPONSE.tmp" "$UPDATE_RESPONSE"
        run updates::check
        [ "$status" -eq 0 ]
        jq -e '.status == "unsupported" and .download_url == "" and .release_url == "https://github.com/octoleo/octoshield/releases/tag/v1.2.0"' <<<"$output"
    done
}

@test 'unsupported systems receive source release page without a wrong architecture download' {
    updates::platform() { return 1; }
    run updates::check
    [ "$status" -eq 0 ]
    jq -e '.status == "unsupported" and .download_url == "" and .platform == ""' <<<"$output"
}

@test 'network failure is reported without leaking server text or implying current protection' {
    curl() {
        printf 'secret hostile network message' >&2
        return 22
    }
    run updates::check
    [ "$status" -ne 0 ]
    [[ $output != *secret* ]]
    jq -e '.status == "error" and .available == false and .download_url == ""' <<<"$output"
}

@test 'oversized response and invalid installed version produce no download' {
    head -c 1048577 /dev/zero >"$UPDATE_RESPONSE"
    run updates::check
    [ "$status" -ne 0 ]
    jq -e '.status == "error" and .download_url == ""' <<<"$output"
    OCTOSHIELD_VERSION='1.1.0;id'
    run updates::check
    [ "$status" -ne 0 ]
    jq -e '.status == "error" and .download_url == ""' <<<"$output"
}

@test 'human output explains the normal package-manager update path' {
    run updates::show
    [ "$status" -eq 0 ]
    [[ $output == *'Installed: 1.1.0'* && $output == *'Latest stable: 1.2.0'* && $output == *'system package installer'* ]]
}
