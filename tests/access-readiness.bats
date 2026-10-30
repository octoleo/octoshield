#!/usr/bin/env bats
# SPDX-License-Identifier: Apache-2.0
# shellcheck disable=SC1091,SC2317,SC2329

setup() {
    source "$BATS_TEST_DIRNAME/../src/lib/profiles.sh"
    source "$BATS_TEST_DIRNAME/../src/lib/profile_controls.sh"
    source "$BATS_TEST_DIRNAME/../src/lib/access.sh"
    CORE_STATE="$BATS_TEST_TMPDIR/state"
    PROFILE_ETC="$BATS_TEST_TMPDIR/etc"
    OBSERVED_STATE=active
    PREFLIGHT="$BATS_TEST_TMPDIR/preflight"
    # Only native command observations and ownership are represented here.
    # Tracking, baseline capture, permissions, hashes and assessment use the
    # production implementation and real isolated files, not readiness stubs.
    stat() {
        local value
        value=$(command stat "$@") || return 1
        case "${2-}" in
            '%u:%a' | '%u:%a:%h:%s') value="0:${value#*:}" ;;
            '%u:%g:%a:%F') value="0:0:${value#*:*:}" ;;
        esac
        printf '%s\n' "$value"
    }
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
    core::die() {
        printf '%s\n' "$*" >&2
        return 1
    }
    ufw() {
        [[ $* == 'status verbose' ]] || return 1
        printf 'Status: active\nDefault: deny (incoming), allow (outgoing), deny (routed)\n'
    }
    iptables-save() { printf ':INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n'; }
    ip6tables-save() { iptables-save; }
    profile_controls::firewall_observe() {
        jq -cn --arg state "$OBSERVED_STATE" '{state:$state,summary:"Native Office policy observation."}'
    }
    profile_controls::preflight() {
        profile_controls::conflict "$1" || return 1
        printf '%s\n' "$*" >"$PREFLIGHT"
    }
    install -d -m 0700 "$CORE_STATE"
    install -d -m 0755 "$PROFILE_ETC/ufw" "$PROFILE_ETC/default"
    printf 'IPV6=yes\n' >"$PROFILE_ETC/default/ufw"
    printf '# Retained original rules\n' >"$PROFILE_ETC/ufw/user.rules"
    profiles::_save "$(profiles::_defaults)"
    profiles::_result firewall applied 'Native policy applied; current verification is shown separately.' office
    profile_controls::_capture firewall
    profile_controls::remember_desired firewall office
    profile_controls::_record_actual firewall
    SAVED="$(profile_controls::_directory)/firewall.json"
    BASELINE="$(profile_controls::_directory)/firewall-baseline"
}

@test 'verified Office remains ready when its original restore point is unavailable' {
    profile_controls::firewall_baseline_available
    rm -rf -- "$BASELINE"
    before=$(cat "$SAVED")
    document=$(profiles::state)
    run access::list office
    [ "$status" -eq 0 ]
    jq -e '.ready and .state=="active" and .recovery.reason=="ready" and
        .recovery.last_result=="applied" and .recovery.observed.state=="active" and
        .recovery.can_apply and (.recovery.can_restore|not) and (.recovery.can_reconcile|not)' <<<"$output"
    [[ $(jq -r .summary <<<"$output") == *'original firewall restore point'* ]]
    [ "$(cat "$SAVED")" = "$before" ]
    [ "$(profiles::state)" = "$document" ]
    [ ! -e "$BASELINE" ]
    access::validate allow office 9003 tcp 172.24.0.4 any 0
    run access::_ready office office "$document"
    [ "$status" -eq 0 ]
    [ "$(cat "$PREFLIGHT")" = 'firewall office' ]
}

@test 'a retained restore fingerprint mismatch does not misreport matching live policy' {
    printf '# Changed retained copy\n' >>"$BASELINE/ufw/user.rules"
    run profile_controls::firewall_baseline_available
    [ "$status" -ne 0 ]
    baseline=$(profile_controls::_tree_hash "$BASELINE/ufw" "$BASELINE/default-ufw")
    before=$(cat "$SAVED")
    run access::list office
    [ "$status" -eq 0 ]
    jq -e '.ready and .recovery.reason=="ready" and (.recovery.can_restore|not)' <<<"$output"
    [ "$(cat "$SAVED")" = "$before" ]
    [ "$(profile_controls::_tree_hash "$BASELINE/ufw" "$BASELINE/default-ufw")" = "$baseline" ]
}

@test 'an intact restore point retains all normal ready capabilities' {
    run access::list office
    [ "$status" -eq 0 ]
    jq -e '.ready and .recovery.reason=="ready" and .recovery.can_apply and .recovery.can_restore' <<<"$output"
}

@test 'the restore-point exception never accepts native drift or unreadable tracking' {
    rm -rf -- "$BASELINE"
    printf '# Native change\n' >>"$PROFILE_ETC/ufw/user.rules"
    run access::list office
    [ "$status" -eq 0 ]
    jq -e '(.ready|not) and (.recovery.can_apply|not) and (.recovery.can_restore|not) and (.recovery.can_reconcile|not)' <<<"$output"
    printf '{invalid\n' >"$SAVED"
    run access::list office
    [ "$status" -eq 0 ]
    jq -e '(.ready|not) and .recovery.reason=="unavailable"' <<<"$output"
}

@test 'failed pending and interrupted results cannot use the verified-policy exception' {
    rm -rf -- "$BASELINE"
    for result in failed pending applying; do
        profiles::_result firewall "$result" 'An unresolved operation.'
        run access::list office
        [ "$status" -eq 0 ]
        jq -e '(.ready|not) and (.recovery.can_apply|not) and (.recovery.can_restore|not)' <<<"$output"
        run access::_ready office office "$(profiles::state)"
        [ "$status" -ne 0 ]
    done
    [ ! -e "$PREFLIGHT" ]
}

@test 'saved edits a different selected profile and nonactive observations stay blocked' {
    rm -rf -- "$BASELINE"
    run access::list home
    [ "$status" -eq 0 ]
    jq -e '(.ready|not)' <<<"$output"
    for OBSERVED_STATE in partial unknown inactive unsupported; do
        run access::list office
        [ "$status" -eq 0 ]
        jq -e '(.ready|not)' <<<"$output"
    done
    OBSERVED_STATE=active
    document=$(profiles::state | jq '.profiles.office.firewall.rules=[{id:"r1-2-3",port:9003,protocol:"tcp",source:"172.24.0.4",interface:"any",expires_at:0}]')
    profiles::_save "$document"
    run access::list office
    [ "$status" -eq 0 ]
    jq -e '(.ready|not)' <<<"$output"
}

@test 'a failed current snapshot never enables access from the observation alone' {
    rm -rf -- "$BASELINE"
    profile_controls::snapshot() { return 1; }
    run access::list office
    [ "$status" -eq 0 ]
    jq -e '(.ready|not) and .recovery.observed.state=="active" and (.recovery.can_apply|not)' <<<"$output"
}
