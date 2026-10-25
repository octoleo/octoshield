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
    SAVED="$CORE_STATE/profiles/controls/firewall.json"
    install -d -m 0700 "${SAVED%/*}"
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
    core::backup() { printf 'backup %s\n' "$*" >>"$CALLS"; }
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
    profile_controls::_directory() { printf '%s/profiles/controls\n' "$CORE_STATE"; }
    profile_controls::_read() { cat "$SAVED"; }
    profile_controls::_write() {
        printf '%s\n' "$2" >"$SAVED"
        chmod 0600 "$SAVED"
    }
    profile_controls::firewall_baseline_available() { [[ -f $SAVED ]]; }
    profile_controls::firewall_reconcile_safe() { [[ ${UNSAFE_FIREWALL:-no} == no ]]; }
    profile_controls::_runtime_narrowed() { return 1; }
    profile_controls::snapshot() { cat "$LIVE"; }
    profile_controls::preflight() { printf 'preflight %s\n' "$*" >>"$CALLS"; }
    profile_controls::_expiry_ready() { :; }
    profile_controls::apply() {
        local policy desired before
        printf 'apply %s\n' "$*" >>"$CALLS"
        policy=$(profiles::get "$2" firewall) || return 1
        printf '%s\n' "$policy" >"$LIVE"
        if [[ $FAIL_APPLY == yes || ($FAIL_APPLY == once && ! -e $BATS_TEST_TMPDIR/failed-once) ]]; then
            : >"$BATS_TEST_TMPDIR/failed-once"
            return 1
        fi
        desired=$(profile_controls::_hash <<<"$policy") || return 1
        before='{"rules":[]}'
        if [[ -f $SAVED ]]; then before=$(jq -c .before "$SAVED"); fi
        jq -cn --arg desired "$desired" --argjson before "$before" --argjson policy "$policy" \
            '{schema:1,before:$before,desired:$desired,expected:$desired,observed:$policy,policy:$policy}' >"$SAVED"
        chmod 0600 "$SAVED"
    }
    profile_controls::restore() {
        printf 'restore %s\n' "$1" >>"$CALLS"
        [[ $FAIL_RESTORE != yes ]] || return 1
        printf '{"rules":[]}\n' >"$LIVE"
        rm -f "$SAVED"
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
    profile_controls::firewall_observe() {
        if [[ $(profiles::get "$1" firewall) == "$(cat "$LIVE")" ]]; then
            printf '{"state":"active","summary":"Verified native policy matches."}\n'
        else
            printf '{"state":"partial","summary":"Native rules differ from the selected policy."}\n'
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
    rm -f "$SAVED"
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
    rm -f "$SAVED"
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
    rm -f "$SAVED"
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

@test 'a saved failure remains blocked while actual healthy findings and recovery are visible' {
    profiles::_result firewall failed 'A previous verification failed.'
    before=$(profiles::state)
    run access::list home
    [ "$status" -eq 0 ]
    jq -e '.ready==false and .state=="failed" and .assigned_profile=="home" and
        .recovery.reason=="incomplete" and .recovery.last_result=="failed" and
        .recovery.observed.state=="active" and .recovery.can_apply and .recovery.can_restore' <<<"$output"
    [ "$(profiles::state)" = "$before" ]
    run access::dispatch allow home 80,443 tcp 192.168.1.0/24 wlan0 0
    [ "$status" -ne 0 ]
    [[ $output == *'saved result, not a running operation'* ]]
    [ "$(profiles::state)" = "$before" ]
}

@test 'reviewed recovery reapplies only the selected saved firewall without adding a draft permission' {
    profiles::_result firewall failed 'Failed earlier.'
    before=$(profiles::state)
    run access::dispatch recover home
    [ "$status" -eq 0 ]
    jq -e '.results.firewall.status=="applied" and .profiles.home.firewall.rules==[]' <<<"$(profiles::state)"
    [ "$(jq -c '.profiles' <<<"$(profiles::state)")" = "$(jq -c '.profiles' <<<"$before")" ]
    grep -qx 'apply firewall home' "$CALLS"
    run access::list home
    jq -e '.ready==true and .recovery.reason=="ready"' <<<"$output"
    access::dispatch allow home 80,443 tcp 192.168.1.0/24 wlan0 0
    [ "$(profiles::get home firewall.rules | jq length)" -eq 2 ]
}

@test 'declined recovery preserves the failed result and original tracking evidence' {
    profiles::_result firewall failed 'Failed earlier.'
    before=$(profiles::state)
    saved=$(cat "$SAVED")
    CONFIRM=no
    run access::dispatch recover home
    [ "$status" -ne 0 ]
    [ "$(profiles::state)" = "$before" ]
    [ "$(cat "$SAVED")" = "$saved" ]
    run grep -q '^apply ' "$CALLS"
    [ "$status" -eq 1 ]
}

@test 'a changed firewall during recovery confirmation is preserved before any application' {
    profiles::_result firewall failed 'Failed earlier.'
    before=$(profiles::state)
    CHANGE_DURING_REVIEW=yes
    run access::dispatch recover home
    [ "$status" -ne 0 ]
    [[ $output == *'changed during review'* ]]
    [ "$(profiles::state)" = "$before" ]
    run grep -q '^apply ' "$CALLS"
    [ "$status" -eq 1 ]
}

@test 'failed recovery never clears its outcome or permits the next grant' {
    profiles::_result firewall failed 'Failed earlier.'
    FAIL_APPLY=yes
    run access::dispatch recover home
    [ "$status" -ne 0 ]
    [ "$(profiles::state | jq -r .results.firewall.status)" = failed ]
    run access::list home
    jq -e '.ready==false and .recovery.last_result=="failed"' <<<"$output"
}

@test 'restore is accessible after failure and only resets the firewall assignment' {
    profiles::_result firewall failed 'Failed earlier.'
    profiles::_result network applied 'Network retained.' office
    run access::dispatch restore
    [ "$status" -eq 0 ]
    [ "$(profiles::active firewall)" = unmanaged ]
    [ "$(profiles::active network)" = office ]
    grep -qx 'restore firewall' "$CALLS"
    run access::list home
    jq -e '.ready==true and .recovery.reason=="unmanaged" and .recovery.can_restore==false' <<<"$output"
}

@test 'recovery capabilities do not conceal native drift or missing evidence' {
    printf '{"external":true}\n' >"$LIVE"
    run access::list home
    jq -e '.ready==false and .recovery.reason=="drift" and .recovery.can_apply==false and
        .recovery.can_restore==false and .recovery.can_reconcile==true' <<<"$output"
    run access::dispatch recover home
    [ "$status" -ne 0 ]
    UNSAFE_FIREWALL=yes
    run access::list home
    jq -e '.recovery.can_reconcile==false' <<<"$output"
    profile_controls::firewall_baseline_available() { return 1; }
    run access::list home
    jq -e '.recovery.reason=="unavailable" and .ready==false and .recovery.can_apply==false and .recovery.can_restore==false' <<<"$output"
}

access_reconcile_fixture() {
    [[ $EUID == 0 ]] || skip 'Configuration review uses root-owned fixture files.'
    local original changed desired
    PROFILE_ETC="$BATS_TEST_TMPDIR/etc"
    mkdir -p "$PROFILE_ETC/ufw" "$PROFILE_ETC/default"
    printf 'IPV6=yes\nDEFAULT_INPUT_POLICY="DROP"\n' >"$PROFILE_ETC/default/ufw"
    printf 'ENABLED=yes\n' >"$PROFILE_ETC/ufw/ufw.conf"
    printf '# Current permanent configuration\n' >"$PROFILE_ETC/ufw/user.rules"
    original=$(jq -cn --arg config "$(printf '%064d' 0)" '{config:$config,status:"Status: active",ipv4:"-A ufw-before-input -j ufw-user-input",ipv6:"-A ufw6-before-input -j ufw6-user-input"}')
    changed=$(jq -c '.ipv4+="\n-A ufw-user-input -p tcp --dport 9000 -j ACCEPT"' <<<"$original")
    desired=$(profiles::get home firewall | profile_controls::_hash)
    jq -cn --argjson before "$original" --arg desired "$desired" --arg expected "$(profile_controls::_hash <<<"$original")" \
        '{schema:1,before:$before,observed:$before,expected:$expected,desired:$desired,policy:{rules:[]}}' >"$SAVED"
    printf '%s\n' "$changed" >"$LIVE"
}

@test 'reconciliation reviews real fixture evidence without applying rules or replacing the original baseline' {
    access_reconcile_fixture
    before=$(cat "$SAVED")
    live=$(cat "$LIVE")
    run access::dispatch reconcile home
    [ "$status" -eq 0 ]
    [[ $output == *'--dport 9000'* && $output == *'Current configuration file:'* ]]
    [ "$(cat "$LIVE")" = "$live" ]
    [ "$(jq -c '{before,desired,policy}' "$SAVED")" = "$(jq -c '{before,desired,policy}' <<<"$before")" ]
    [ "$(jq -r .expected "$SAVED")" = "$(profile_controls::_hash <<<"$live")" ]
    [ "$(profiles::state | jq -r .results.firewall.status)" = pending ]
    run access::dispatch allow home 80 tcp any any 0
    [ "$status" -ne 0 ]
    run grep -q '^apply ' "$CALLS"
    [ "$status" -eq 1 ]
}

@test 'cancelled reconciliation leaves the tracking record and failed outcome untouched' {
    access_reconcile_fixture
    profiles::_result firewall failed 'Failed earlier.'
    before=$(cat "$SAVED")
    document=$(profiles::state)
    CONFIRM=no
    run access::dispatch reconcile home
    [ "$status" -ne 0 ]
    [ "$(cat "$SAVED")" = "$before" ]
    [ "$(profiles::state)" = "$document" ]
}

@test 'native edits during reconciliation review or backup are never accepted' {
    access_reconcile_fixture
    before=$(cat "$SAVED")
    CHANGE_DURING_REVIEW=yes
    run access::dispatch reconcile home
    [ "$status" -ne 0 ]
    [[ $output == *'changed during review'* ]]
    [ "$(cat "$SAVED")" = "$before" ]
    access_reconcile_fixture
    CHANGE_DURING_REVIEW=no
    core::backup() { printf '{"late":true}\n' >"$LIVE"; }
    run access::dispatch reconcile home
    [ "$status" -ne 0 ]
    [[ $output == *'changed while preparing'* ]]
    [ "$(cat "$SAVED")" = "$before" ]
}

@test 'reconciliation refuses unsafe hooks malformed observations and unsafe configuration files' {
    access_reconcile_fixture
    before=$(cat "$SAVED")
    UNSAFE_FIREWALL=yes
    run access::dispatch reconcile home
    [ "$status" -ne 0 ]
    UNSAFE_FIREWALL=no
    jq '.observed.ipv4=null' "$SAVED" >"$SAVED.new"
    mv "$SAVED.new" "$SAVED"
    run access::dispatch reconcile home
    [ "$status" -ne 0 ]
    [[ $output == *'cannot be fully previewed safely'* ]]
    printf '%s\n' "$before" >"$SAVED"
    chmod 0666 "$PROFILE_ETC/ufw/user.rules"
    run access::dispatch reconcile home
    [ "$status" -ne 0 ]
    [ "$(cat "$SAVED")" = "$before" ]
    run grep -q '^confirm' "$CALLS"
    [ "$status" -eq 1 ]
}

@test 'failed configuration reads stop reconciliation before confirmation or tracking changes' {
    access_reconcile_fixture
    before=$(cat "$SAVED")
    document=$(profiles::state)
    cat() {
        [[ ${*: -1} != "$PROFILE_ETC/ufw/user.rules" ]] || return 1
        command cat "$@"
    }
    run access::dispatch reconcile home
    [ "$status" -ne 0 ]
    [[ $output == *'cannot be fully previewed safely'* ]]
    [ "$(cat "$SAVED")" = "$before" ]
    [ "$(profiles::state)" = "$document" ]
    run grep -q '^confirm' "$CALLS"
    [ "$status" -eq 1 ]
}

@test 'transaction history is offered only for a valid accessible private action record' {
    CORE_TRANSACTION=20261025T113206Z-1749361
    profiles::_result firewall failed 'Native change failed.'
    run access::list home
    jq -e '.recovery.transaction==""' <<<"$output"
    install -d -m 0700 "$CORE_STATE/backups/$CORE_TRANSACTION"
    printf 'Failure details\n' >"$CORE_STATE/backups/$CORE_TRANSACTION/actions.log"
    chmod 0600 "$CORE_STATE/backups/$CORE_TRANSACTION/actions.log"
    run access::list home
    jq -e --arg id "$CORE_TRANSACTION" '.recovery.transaction==$id' <<<"$output"
    profiles::public_status | jq -e '.results.firewall|has("transaction")|not'
}
