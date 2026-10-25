#!/usr/bin/env bats
# SPDX-License-Identifier: Apache-2.0
# shellcheck disable=SC1091,SC2317,SC2329
setup() {
    source "$BATS_TEST_DIRNAME/../src/lib/profiles.sh"
    CORE_STATE="$BATS_TEST_TMPDIR/state"
    mkdir -m 0700 "$CORE_STATE"
    CALLS="$BATS_TEST_TMPDIR/calls"
    : >"$CALLS"
    FAIL=''
    CONFIRM=yes
    core::require_root() { :; }
    core::die() {
        printf '%s\n' "$*" >&2
        return 1
    }
    core::log() { :; }
    core::record() { :; }
    core::confirm() {
        printf 'confirm\n' >>"$CALLS"
        [[ $CONFIRM == yes ]]
    }
    controls::local_console() { :; }
    profile_controls::snapshot() { printf '{"fixture":"unchanged"}\n'; }
    # Ownership syscalls are the privilege boundary; filesystem/data validation
    # remains real, so the suite can run as an ordinary CI account.
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
    profile_controls::preflight() {
        printf 'preflight %s\n' "$1" >>"$CALLS"
        [[ $FAIL != "preflight $1" ]]
    }
    profile_controls::apply() {
        printf 'apply %s\n' "$1" >>"$CALLS"
        [[ $FAIL != "apply $1" ]]
    }
    profile_controls::restore() {
        printf 'restore %s\n' "$1" >>"$CALLS"
        [[ $FAIL != "restore $1" ]]
    }
    usb::profile_preflight() { profile_controls::preflight usb; }
    usb::profile_apply() { profile_controls::apply usb; }
    usb::profile_restore() { profile_controls::restore usb; }
}

@test 'profile defaults are read-only and all presets use independent USB allowlists' {
    run profiles::dispatch list
    [ "$status" -eq 0 ]
    [ "$(jq length <<<"$output")" -eq 4 ]
    jq -e 'all(.[];(.usb|length)==0 and .services.ssh=="disabled")' <<<"$output"
    [ ! -e "$CORE_STATE/profiles" ]
}

@test 'private operation transaction is validated and excluded from public status' {
    CORE_TRANSACTION=20261025T113206Z-1749361
    profiles::_result firewall failed 'Native application failed.'
    profiles::state | jq -e --arg id "$CORE_TRANSACTION" '.results.firewall.transaction==$id'
    profiles::public_status | jq -e '.results.firewall|has("transaction")|not'
    run profiles::_validate_document <<<"$(profiles::state | jq '.results.firewall.transaction="../escape"')"
    [ "$status" -ne 0 ]
    document=$(profiles::state | jq 'del(.results.firewall.transaction)')
    run profiles::_validate_document <<<"$document"
    [ "$status" -eq 0 ]
}
@test 'argument validation rejects option injection malformed addresses and broad unexpected keys' {
    for name in ../oops --profile 'a;id' 'AProfile' unmanaged; do
        run profiles::validate create "$name" home
        [ "$status" -ne 0 ]
    done
    for source in '1.2.3.999/24' '1.2.3.4/33' '::1/129' ':::1' 'a::b::c' '::;id'; do
        run profiles::validate rule-add home 443 tcp "$source" any 0
        [ "$status" -ne 0 ]
    done
    run profiles::validate set home sudo.enabled false
    [ "$status" -ne 0 ]
    run profiles::validate set home services.printing true
    [ "$status" -ne 0 ]
    run profiles::validate rule-add home 443 tcp '2001:db8::/32' eth0 60
    [ "$status" -eq 0 ]
}
@test 'create edit rule and delete use validated private JSON without executing data' {
    profiles::dispatch create workshop office
    profiles::dispatch set workshop services.printing enabled
    id=$(profiles::dispatch rule-add workshop 443 tcp 192.0.2.0/24 wlan0 60)
    result=$(profiles::dispatch show workshop)
    jq -e '.services.printing=="enabled" and .firewall.rules[0].port==443 and .firewall.rules[0].expires_at>0' <<<"$result"
    [ "$(stat -c %a "$CORE_STATE/profiles/state.json")" = 600 ]
    profiles::dispatch rule-remove workshop "$id"
    profiles::dispatch delete workshop
    run profiles::dispatch show workshop
    [ "$status" -ne 0 ]
}
@test 'all selected preflights finish before confirmation or first mutation' {
    profiles::dispatch apply conference
    [ "$(head -n6 "$CALLS")" = $'preflight firewall\npreflight usb\npreflight network\npreflight services\npreflight monitor\nconfirm' ]
    [ "$(profiles::active firewall)" = conference ]
    [ "$(profiles::state | jq -r .global)" = conference ]
}
@test 'failed preflight and declined confirmation make no profile or native changes' {
    FAIL='preflight network'
    run profiles::dispatch apply conference
    [ "$status" -ne 0 ]
    run grep -q '^apply ' "$CALLS"
    [ "$status" -eq 1 ]
    [ ! -e "$CORE_STATE/profiles/state.json" ]
    FAIL=''
    CONFIRM=no
    run profiles::dispatch apply conference
    [ "$status" -ne 0 ]
    run grep -q '^apply ' "$CALLS"
    [ "$status" -eq 1 ]
}
@test 'partial switch reports failure and retains each actually applied assignment' {
    profiles::dispatch apply office
    FAIL='apply network'
    run profiles::dispatch apply conference
    [ "$status" -ne 0 ]
    result=$(profiles::state)
    jq -e '.global=="conference" and .active.firewall=="conference" and .active.usb=="conference" and .active.network=="office" and .active.services=="office" and .results.network.status=="failed"' <<<"$result"
}
@test 'individual override leaves global profile intact and appears in public metadata' {
    profiles::dispatch apply conference
    profiles::dispatch apply office firewall
    result=$(profiles::public_status)
    jq -e '.global=="conference" and .overrides.firewall=="office" and (.catalog|length)==4 and (has("profiles")|not)' <<<"$result"
    run profiles::dispatch delete office
    [ "$status" -ne 0 ]
}
@test 'failed first adoption can restore despite unmanaged assignment' {
    FAIL='apply firewall'
    run profiles::dispatch apply conference firewall
    [ "$status" -ne 0 ]
    [ "$(profiles::active firewall)" = unmanaged ]
    FAIL=''
    profiles::dispatch restore firewall
    grep -qx 'restore firewall' "$CALLS"
    [ "$(profiles::state | jq -r .results.firewall.status)" = unmanaged ]
}
@test 'declining the concrete baseline preview preserves the previous result and assignment' {
    profiles::dispatch apply office firewall
    profiles::_result firewall failed 'Earlier operation remains available.'
    before=$(profiles::state)
    profile_controls::restore() { return 3; }
    run profiles::dispatch restore firewall
    [ "$status" -eq 3 ]
    [ "$(profiles::state)" = "$before" ]
    [ "$(profiles::active firewall)" = office ]
}

@test 'invalid JSON or unsafe state permissions fails closed' {
    profiles::dispatch create custom home
    printf '{"schema":99}\n' >"$CORE_STATE/profiles/state.json"
    run profiles::dispatch list
    [ "$status" -ne 0 ]
    profiles::_defaults >"$CORE_STATE/profiles/state.json"
    chmod 0644 "$CORE_STATE/profiles/state.json"
    run profiles::dispatch list
    [ "$status" -ne 0 ]
}
@test 'state symlinks are rejected and target remains unchanged' {
    mkdir -m700 "$CORE_STATE/profiles"
    printf original >"$BATS_TEST_TMPDIR/target"
    ln -s "$BATS_TEST_TMPDIR/target" "$CORE_STATE/profiles/state.json"
    run profiles::dispatch create custom home
    [ "$status" -ne 0 ]
    [ "$(cat "$BATS_TEST_TMPDIR/target")" = original ]
}
@test 'expired records remain retryable when native expiry removal fails' {
    profiles::dispatch apply conference firewall
    document=$(profiles::state | jq '.profiles.conference.firewall.rules=[{id:"r1-1-1",port:443,protocol:"tcp",source:"any",interface:"any",expires_at:1}]')
    profiles::_save "$document"
    profile_controls::expiry_due() { return 0; }
    profile_controls::expire() { return 1; }
    run profiles::expire
    [ "$status" -ne 0 ]
    [ "$(profiles::get conference firewall.rules | jq length)" -eq 1 ]
    [ "$(profiles::state | jq -r .results.firewall.status)" = failed ]
}
@test 'successful expiry removes only expired entries and retains pending edits' {
    profiles::dispatch apply conference firewall
    document=$(profiles::state | jq '.profiles.conference.firewall.rules=[{id:"r1-1-1",port:443,protocol:"tcp",source:"any",interface:"any",expires_at:1},{id:"r1-1-2",port:88,protocol:"tcp",source:"any",interface:"any",expires_at:0}]')
    profiles::_save "$document"
    profile_controls::expiry_due() { return 0; }
    profile_controls::expire() { printf 'expire %s\n' "$1" >>"$CALLS"; }
    profiles::expire
    [ "$(profiles::get conference firewall.rules | jq '.[0].port')" -eq 88 ]
    grep -qx 'expire conference' "$CALLS"
}
