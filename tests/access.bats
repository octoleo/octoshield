#!/usr/bin/env bats
# SPDX-License-Identifier: Apache-2.0
# shellcheck disable=SC1091,SC2317,SC2329

setup() {
    source "$BATS_TEST_DIRNAME/../src/lib/profiles.sh"
    source "$BATS_TEST_DIRNAME/../src/lib/access.sh"
    source "$BATS_TEST_DIRNAME/../src/lib/office.sh"
    CORE_STATE="$BATS_TEST_TMPDIR/state"
    mkdir -m 0700 "$CORE_STATE"
    CALLS="$BATS_TEST_TMPDIR/calls"
    LIVE="$BATS_TEST_TMPDIR/live"
    SAVED="$BATS_TEST_TMPDIR/saved"
    CLOCK="$BATS_TEST_TMPDIR/clock"
    : >"$CALLS"
    printf '1000\n' >"$CLOCK"
    printf '{"rules":[]}\n' >"$LIVE"
    CONFIRM=yes
    FAIL_APPLY=no
    FAIL_RESTORE=no
    CHANGE_DURING_REVIEW=no
    core::require_root() { :; }
    core::die() {
        printf '%s\n' "$*" >&2
        return 1
    }
    core::log() { printf '%s\n' "$*" >&2; }
    core::record() { printf 'record %s\n' "$*" >>"$CALLS"; }
    controls::local_console() { :; }
    core::confirm() {
        printf 'confirm\n' >>"$CALLS"
        printf '2000\n' >"$CLOCK"
        if [[ $CHANGE_DURING_REVIEW == yes ]]; then printf '{"external":true}\n' >"$LIVE"; fi
        [[ $CONFIRM == yes ]]
    }
    date() { if [[ $* == +%s ]]; then cat "$CLOCK"; else command date "$@"; fi; }
    chown() { :; }
    install() {
        local -a args=()
        while (($#)); do case "$1" in -o | -g) shift 2 ;; *)
            args+=("$1")
            shift
            ;;
        esac done
        command install "${args[@]}"
    }
    profiles::_secure_file() {
        [[ ! -L $1 ]] || return 1
        if [[ ${2-} == directory ]]; then [[ -d $1 && $(stat -c %a "$1") == 700 ]]; else [[ -f $1 && $(stat -c %a "$1") == 600 ]]; fi
    }
    profile_controls::_hash() { sha256sum | cut -d ' ' -f1; }
    profile_controls::_read() { cat "$SAVED"; }
    profile_controls::snapshot() { cat "$LIVE"; }
    profile_controls::preflight() { printf 'preflight %s\n' "$*" >>"$CALLS"; }
    profile_controls::_expiry_ready() { :; }
    profile_controls::apply() {
        local policy desired
        printf 'apply %s\n' "$*" >>"$CALLS"
        policy=$(profiles::get "$2" firewall) || return 1
        printf '%s\n' "$policy" >"$LIVE"
        if [[ $FAIL_APPLY == yes || ($FAIL_APPLY == once && ! -e $BATS_TEST_TMPDIR/failed-once) ]]; then
            : >"$BATS_TEST_TMPDIR/failed-once"
            return 1
        fi
        desired=$(profile_controls::_hash <<<"$policy") || return 1
        jq -cn --arg desired "$desired" '{desired:$desired}' >"$SAVED"
    }
    profile_controls::restore() {
        printf 'restore %s\n' "$*" >>"$CALLS"
        [[ $FAIL_RESTORE != yes ]] || return 1
        printf '{"rules":[]}\n' >"$LIVE"
    }
    profile_controls::verify() {
        local profile desired current
        profile=$(profiles::active firewall) || return 1
        [[ $profile != unmanaged ]] || {
            printf '{"state":"unknown"}\n'
            return
        }
        desired=$(profiles::get "$profile" firewall) || return 1
        current=$(cat "$LIVE") || return 1
        if [[ $desired == "$current" ]]; then
            printf '{"state":"active","summary":"Verified native policy matches."}\n'
        else
            printf '{"state":"partial","summary":"Saved changes are not active."}\n'
        fi
    }
    ufw() { printf 'Existing UFW rule for TCP 9000\n'; }
    profiles::_save "$(profiles::_defaults)"
    profiles::_result firewall applied 'Test policy' home
    profile_controls::apply firewall home
    : >"$CALLS"
}

@test 'access validates bounded ports identifiers sources and actions' {
    run access::validate allow home 80,443 tcp 192.168.1.0/24 wlan0 60
    [ "$status" -eq 0 ]
    run access::validate update home g1-2-3 443 tcp ::1 lo 0
    [ "$status" -eq 0 ]
    for ports in '80,80' '0' '01' '65536' '80,' '80;id' '-p' ''; do
        run access::validate allow home "$ports" tcp any any 60
        [ "$status" -ne 0 ]
    done
    for id in '../rules' 'g1-2-3;id' 'r1-2' 'g1-2-123456'; do
        run access::validate revoke home "$id"
        [ "$status" -ne 0 ]
    done
    run access::validate allow home 80 tcp 192.168.1.999/24 any 60
    [ "$status" -ne 0 ]
}

@test 'web preset becomes one live group and its deadline begins after approval' {
    run access::dispatch allow home 80,443 tcp 192.168.1.0/24 wlan0 60
    [ "$status" -eq 0 ]
    document=$(profiles::state)
    jq -e '.profiles.home.firewall.rules|length==2 and (map(.expires_at)|unique)==[5600] and (map(.group)|unique|length)==1' <<<"$document"
    run access::list
    [ "$status" -eq 0 ]
    jq -e '.profile=="home" and .state=="active" and (.rules|length)==1 and .rules[0].ports=="80,443" and .rules[0].label=="Web server (HTTP + HTTPS)" and .rules[0].state=="active"' <<<"$output"
    [ "$(grep -c '^apply ' "$CALLS")" -eq 1 ]
}

@test 'declining review leaves saved and live policy unchanged' {
    before=$(profiles::state)
    native=$(cat "$LIVE")
    CONFIRM=no
    run access::dispatch allow home 80,443 tcp 192.168.1.0/24 wlan0 60
    [ "$status" -ne 0 ]
    [ "$(profiles::state)" = "$before" ]
    [ "$(cat "$LIVE")" = "$native" ]
    run grep -q '^apply ' "$CALLS"
    [ "$status" -eq 1 ]
}

@test 'revoke closes the complete web permission and retains unrelated grants' {
    access::dispatch allow home 22 tcp 192.168.1.10 wlan0 0
    access::dispatch allow home 80,443 tcp 192.168.1.0/24 wlan0 60
    identifier=$(access::list | jq -r '.rules[]|select(.ports=="80,443")|.id')
    run access::dispatch revoke home "$identifier"
    [ "$status" -eq 0 ]
    jq -e '.rules|length==1 and .[0].port==22' "$LIVE"
    [ "$(profiles::get home firewall.rules | jq length)" -eq 1 ]
}

@test 'editing an existing standalone rule replaces it with one grouped permission' {
    profiles::dispatch rule-add home 80 tcp 192.168.1.0/24 wlan0 0
    profile_controls::apply firewall home
    identifier=$(profiles::get home firewall.rules | jq -r '.[0].id')
    run access::dispatch update home "$identifier" 80,443 tcp 192.168.2.0/24 eth0 30
    [ "$status" -eq 0 ]
    jq -e '.rules|length==2 and all(.[];.source=="192.168.2.0/24" and .interface=="eth0" and .expires_at==3800) and (map(.group)|unique|length)==1' "$LIVE"
}

@test 'failed activation restores previous saved and live rules without false success' {
    access::dispatch allow home 22 tcp 192.168.1.10 wlan0 0
    before=$(profiles::state)
    native=$(cat "$LIVE")
    FAIL_APPLY=once
    run access::dispatch allow home 80,443 tcp any any 0
    [ "$status" -ne 0 ]
    [[ $output == *'previous firewall policy was restored'* ]]
    [ "$(profiles::state)" = "$before" ]
    [ "$(cat "$LIVE")" = "$native" ]
}

@test 'failed restoration leaves an explicit failed result and no active claim' {
    FAIL_APPLY=yes
    run access::dispatch allow home 80,443 tcp any any 0
    [ "$status" -ne 0 ]
    [[ $output == *'Automatic restoration was incomplete'* ]]
    [ "$(profiles::state | jq -r .results.firewall.status)" = failed ]
}

@test 'an unverified successful command restores policy instead of reporting active' {
    before=$(profiles::state)
    native=$(cat "$LIVE")
    profile_controls::verify() { printf '{"state":"partial","summary":"Verification failed"}\n'; }
    run access::dispatch allow home 80,443 tcp any any 0
    [ "$status" -ne 0 ]
    [ "$(profiles::state)" = "$before" ]
    [ "$(cat "$LIVE")" = "$native" ]
}

@test 'failed first adoption restores the original native baseline' {
    profiles::_save "$(profiles::_defaults)"
    before=$(profiles::state)
    FAIL_APPLY=once
    run access::dispatch allow home 80,443 tcp 192.168.1.0/24 eth0 0
    [ "$status" -ne 0 ]
    grep -qx 'restore firewall' "$CALLS"
    [ "$(profiles::state)" = "$before" ]
    [ "$(cat "$LIVE")" = '{"rules":[]}' ]
}

@test 'pending unrelated edits and another selected profile cannot silently activate' {
    profiles::dispatch rule-add home 9000 tcp any any 0
    before=$(profiles::state)
    run access::dispatch allow home 80 tcp 192.168.1.0/24 wlan0 0
    [ "$status" -ne 0 ]
    [[ $output == *'saved changes awaiting Apply'* ]]
    [ "$(profiles::state)" = "$before" ]
    run access::dispatch allow conference 80 tcp any any 0
    [ "$status" -ne 0 ]
    [[ $output == *'Firewall currently uses home'* ]]
    run grep -q '^apply ' "$CALLS"
    [ "$status" -eq 1 ]
}

@test 'a native change during confirmation invalidates the reviewed change' {
    before=$(profiles::state)
    CHANGE_DURING_REVIEW=yes
    run access::dispatch allow home 80 tcp 192.168.1.0/24 wlan0 0
    [ "$status" -ne 0 ]
    [[ $output == *'changed during review'* ]]
    [ "$(profiles::state)" = "$before" ]
    run grep -q '^apply ' "$CALLS"
    [ "$status" -eq 1 ]
}

@test 'first adoption previews native exceptions before consent and keeps cancellation read-only' {
    profiles::_save "$(profiles::_defaults)"
    before=$(profiles::state)
    CONFIRM=no
    run access::dispatch allow home 80,443 tcp 192.168.1.0/24 eth0 0
    [ "$status" -ne 0 ]
    [[ $output == *'Existing UFW rule for TCP 9000'* ]]
    [[ $output == *'replaces its current UFW exceptions'* ]]
    [ "$(profiles::state)" = "$before" ]
    run grep -q '^apply ' "$CALLS"
    [ "$status" -eq 1 ]
}

@test 'expired group is shown expired rather than claimed live' {
    access::dispatch allow home 80,443 tcp 192.168.1.0/24 wlan0 1
    printf '2061\n' >"$CLOCK"
    run access::list
    [ "$status" -eq 0 ]
    jq -e '.rules[0].state=="expired"' <<<"$output"
}

@test 'legacy office firewall uses the effective managed profile path' {
    access::dispatch() { printf 'access %s\n' "$*"; }
    run office::firewall 443 192.168.1.0/24
    [ "$status" -eq 0 ]
    [ "$output" = 'access allow home 443 tcp 192.168.1.0/24 any 0' ]
}

@test 'profile schema accepts bounded groups and refuses unrecognized metadata' {
    access::dispatch allow home 80,443 tcp 192.168.1.0/24 wlan0 0
    document=$(profiles::state)
    run profiles::_validate_document <<<"$(jq '.profiles.home.firewall.rules[0].group="../escape"' <<<"$document")"
    [ "$status" -ne 0 ]
    run profiles::_validate_document <<<"$(jq '.profiles.home.firewall.rules[0].command="anything"' <<<"$document")"
    [ "$status" -ne 0 ]
    run profiles::_validate_document <<<"$(jq '.profiles.home.firewall.rules[0].source="any"' <<<"$document")"
    [ "$status" -ne 0 ]
}

@test 'unmanaged default selection remains usable after deleting the home preset' {
    profiles::_save "$(profiles::_defaults)"
    profiles::dispatch delete home
    run access::list
    [ "$status" -eq 0 ]
    jq -e '.profile=="conference" and .managed==false' <<<"$output"
}

@test 'repeated allow cannot create a second identical permission' {
    access::dispatch allow home 80,443 tcp 192.168.1.0/24 wlan0 0
    before=$(profiles::state)
    run access::dispatch allow home 80,443 tcp 192.168.1.0/24 wlan0 60
    [ "$status" -ne 0 ]
    [[ $output == *'Edit that permission instead'* ]]
    [ "$(profiles::state)" = "$before" ]
}
