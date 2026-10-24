#!/usr/bin/env bats
# SPDX-License-Identifier: Apache-2.0
# Exercise the actual helper protocol, private profile documents and public
# status projection together. Native policy operations use isolated fixtures.
# shellcheck disable=SC2317,SC2329,SC2016

setup() {
    bats_require_minimum_version 1.5.0
    [[ $EUID -eq 0 ]] || skip 'Private profile integration requires root-owned fixture files.'
    source "$BATS_TEST_DIRNAME/../src/lib/core.sh"
    source "$BATS_TEST_DIRNAME/../src/lib/controls.sh"
    source "$BATS_TEST_DIRNAME/../src/lib/profiles.sh"
    source "$BATS_TEST_DIRNAME/../src/lib/status.sh"
    source "$BATS_TEST_DIRNAME/../src/lib/api.sh"
    CORE_STATE="$BATS_TEST_TMPDIR/state"
    CORE_PACKAGE_MAINTENANCE="$BATS_TEST_TMPDIR/maintenance"
    STATUS_DIRECTORY="$BATS_TEST_TMPDIR/public"
    TEST_CALLS="$BATS_TEST_TMPDIR/native-calls"
    TEST_NATIVE="$BATS_TEST_TMPDIR/native"
    OCTOSHIELD_VERSION=1.1.0
    install -d -m 0700 "$CORE_STATE" "$TEST_NATIVE"
    : >"$TEST_CALLS"
    core::supported_os() { return 0; }
    # Keep native probes inside this isolated shell fixture. The separate real
    # process/timeout boundary is exercised by tests/locking.bats.
    core::refresh_status() { status::refresh; }
    controls::local_console() { return 0; }
    # Only redirect the transport's /run temporary directory. Private profile
    # and cache atomic writes still exercise the production mktemp behavior.
    mktemp() {
        if [[ ${1-} == -d && ${2-} == /run/octoshield-gui.* ]]; then
            command mktemp -d "$BATS_TEST_TMPDIR/gui.XXXXXXXX"
        else command mktemp "$@"; fi
    }
    profile_controls::preflight() { printf 'review %s %s\n' "$1" "$2" >>"$TEST_CALLS"; }
    profile_controls::apply() {
        printf 'apply %s %s\n' "$1" "$2" >>"$TEST_CALLS"
        printf '%s\n' "$2" >"$TEST_NATIVE/$1"
        [[ ${TEST_FAIL_CONTROL:-} != "$1" ]]
    }
    profile_controls::restore() {
        printf 'restore %s\n' "$1" >>"$TEST_CALLS"
        rm -f -- "$TEST_NATIVE/$1"
    }
    profile_controls::conflict() { return 0; }
    profile_controls::remember_desired() { return 0; }
    profile_controls::expiry_due() { [[ -f "$TEST_NATIVE/expiry-due" ]]; }
    profile_controls::expire() {
        profile_controls::apply firewall "$1" || return 1
        rm -f -- "$TEST_NATIVE/expiry-due"
    }
    profile_controls::verify() { status::result active 'Native fixture policy is active.'; }
    usb::profile_preflight() { profile_controls::preflight usb "$1"; }
    usb::profile_apply() { profile_controls::apply usb "$1"; }
    usb::profile_restore() { profile_controls::restore usb; }
    usb::devices_json() { printf '[]\n'; }
    status::firewall() { status::result active 'Native firewall fixture is active.'; }
    status::usb() { status::result active 'Native USB fixture is active.'; }
    status::network() { status::result active 'Native network fixture is active.'; }
    status::services() { status::result active 'Native service fixture is active.'; }
    status::monitor() { status::result active 'Native monitor fixture is active.'; }
    status::updates() { status::result unknown 'Not inspected in this integration fixture.'; }
    status::apparmor() { status::result unknown 'Not inspected in this integration fixture.'; }
    status::secure_boot() { status::result unsupported 'No firmware fixture.'; }
    status::disk_encryption() { status::result unknown 'No storage fixture.'; }
    status::thunderbolt() { status::result unsupported 'No Thunderbolt fixture.'; }
    status::containers() { status::result unknown 'No container fixture.'; }
    status::forwarding() { status::result unknown 'No forwarding fixture.'; }
    status::network_snapshot() {
        printf '{"fingerprint":"%064d","connected_count":1}\n' 0
    }
}

@test 'global profile and individual override persist and reach the public cache' {
    run api::main profile apply conference <<<'1 yes'
    [ "$status" -eq 0 ]
    jq -e -s '.[-1] == {type:"done",success:true,change_started:true}' <<<"$output"
    jq -e '.global == "conference" and all(.active[]; . == "conference")' "$CORE_STATE/profiles/state.json"
    run api::main profile apply office usb <<<'1 yes'
    [ "$status" -eq 0 ]
    [ "$(stat -c '%u:%a' "$CORE_STATE/profiles/state.json")" = '0:600' ]
    run status::read
    [ "$status" -eq 0 ]
    jq -e '.profiles.available and .profiles.active == "conference" and
        .profiles.assignments.usb == "office" and .profiles.assignments.firewall == "conference" and
        .profiles.overrides == {usb:"office"} and
        ([.profiles.catalog[] | select(.id == "office") | .name] == ["Office"])' <<<"$output"
}

@test 'declining the exact helper confirmation never invokes a native profile change' {
    run api::main profile apply conference <<<'1 no'
    [ "$status" -ne 0 ]
    jq -e -s '([.[] | select(.type == "confirm")] | length) == 1 and .[-1].success == false' <<<"$output"
    [ ! -e "$CORE_STATE/profiles/state.json" ]
    run grep -E '^apply ' "$TEST_CALLS"
    [ "$status" -eq 1 ]
}

@test 'failed global switch publishes a partial result even when a native probe is green' {
    TEST_FAIL_CONTROL=usb
    run api::main profile apply conference <<<'1 yes'
    [ "$status" -ne 0 ]
    jq -e -s '.[-1] == {type:"done",success:false,change_started:true}' <<<"$output"
    jq -e '.global == "conference" and .active.firewall == "conference" and .active.usb == "unmanaged" and .results.usb.status == "failed"' "$CORE_STATE/profiles/state.json"
    run status::read
    [ "$status" -eq 0 ]
    jq -e '.controls.usb.state == "partial" and .profiles.results.usb.status == "failed" and .profiles.overrides.usb == "unmanaged"' <<<"$output"
    run grep -E '^apply (network|services|monitor) ' "$TEST_CALLS"
    [ "$status" -eq 1 ]
}

@test 'the baseline restore remains available after a failed first control application' {
    TEST_FAIL_CONTROL=firewall
    run api::main profile apply conference firewall <<<'1 yes'
    [ "$status" -ne 0 ]
    [ -f "$TEST_NATIVE/firewall" ]
    TEST_FAIL_CONTROL=
    run api::main profile restore firewall <<<'1 yes'
    [ "$status" -eq 0 ]
    [ ! -e "$TEST_NATIVE/firewall" ]
    grep -Fx 'restore firewall' "$TEST_CALLS"
    jq -e '.active.firewall == "unmanaged" and .results.firewall.status == "unmanaged"' "$CORE_STATE/profiles/state.json"
}

@test 'malformed profile state cannot authorize a change or produce a green profile status' {
    install -d -m 0700 "$CORE_STATE/profiles"
    printf '{invalid profile document\n' >"$CORE_STATE/profiles/state.json"
    chmod 0600 "$CORE_STATE/profiles/state.json"
    run api::main profile apply conference <<<'1 yes'
    [ "$status" -ne 0 ]
    [ ! -s "$TEST_CALLS" ]
    run status::read
    [ "$status" -eq 0 ]
    jq -e '.profiles.available == false and
        all(.controls | to_entries[] | select(.key | IN("firewall","usb","network","services","monitor")); .value.state == "unknown")' <<<"$output"
}

@test 'helper rejects profile injection and malformed firewall scope before acquiring state' {
    for name in '../office' '--help' 'office;id' '$(id)' 'Office' 'unmanaged'; do
        run api::main profile apply "$name"
        [ "$status" -eq 2 ]
    done
    run api::main profile rule-add office 443 tcp '192.168.0.1;id' any 0
    [ "$status" -eq 2 ]
    run api::main profile rule-add office 443 tcp any '--help' 0
    [ "$status" -eq 2 ]
    [ ! -e "$CORE_STATE/lock" ]
    [ ! -s "$TEST_CALLS" ]
}

@test 'failed timed exception removal retains a durable expiry retry' {
    local document
    document=$(profiles::_defaults | jq -c '.global="office" | .active.firewall="office" |
        .results.firewall={status:"applied",message:"Previously applied"} |
        .profiles.office.firewall.rules=[{id:"r1-1-1",port:443,protocol:"tcp",source:"any",interface:"any",expires_at:1}]')
    profiles::_save "$document"
    touch "$TEST_NATIVE/expiry-due"
    TEST_FAIL_CONTROL=firewall
    run profiles::expire
    [ "$status" -ne 0 ]
    run profiles::expiry_due
    [ "$status" -eq 0 ]
    jq -e '.results.firewall.status == "failed" and (.profiles.office.firewall.rules | length) == 1' "$CORE_STATE/profiles/state.json"
    TEST_FAIL_CONTROL=
    run profiles::expire
    [ "$status" -eq 0 ]
    run profiles::expiry_due
    [ "$status" -ne 0 ]
    jq -e '.results.firewall.status == "applied" and .profiles.office.firewall.rules == []' "$CORE_STATE/profiles/state.json"
}
