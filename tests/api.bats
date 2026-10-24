#!/usr/bin/env bats
# SPDX-License-Identifier: Apache-2.0
# Bats installs callbacks that the privileged dispatcher invokes indirectly.
# shellcheck disable=SC2317,SC2329

setup() {
    bats_require_minimum_version 1.5.0
    source "$BATS_TEST_DIRNAME/../src/lib/core.sh"
    source "$BATS_TEST_DIRNAME/../src/lib/usb.sh"
    source "$BATS_TEST_DIRNAME/../src/lib/office.sh"
    source "$BATS_TEST_DIRNAME/../src/lib/profiles.sh"
    source "$BATS_TEST_DIRNAME/../src/lib/access.sh"
    source "$BATS_TEST_DIRNAME/../src/lib/connections.sh"
    source "$BATS_TEST_DIRNAME/../src/lib/diagnostics.sh"
    source "$BATS_TEST_DIRNAME/../src/lib/cli.sh"
    source "$BATS_TEST_DIRNAME/../src/lib/api.sh"
    CORE_STATE="$BATS_TEST_TMPDIR/state"
    TEST_CALLS="$BATS_TEST_TMPDIR/calls"
    : >"$TEST_CALLS"
    core::require_root() { return 0; }
    core::supported_os() { return 0; }
    core::begin() {
        CORE_TRANSACTION=20261012T120000Z-123
        printf 'begin %s\n' "$*" >>"$TEST_CALLS"
    }
    core::record() { printf 'record %s\n' "$*" >>"$TEST_CALLS"; }
    core::backup() { printf 'backup %s\n' "$*" >>"$TEST_CALLS"; }
    # Never create helper state in the host's /run directory.
    mktemp() { command mktemp -d "$BATS_TEST_TMPDIR/gui.XXXXXXXX"; }
    cli::status() { printf 'status inspected\n'; }
    api::details() { "${1}::dispatch" "${@:2}"; }
    monitor::status() { printf 'monitor status inspected\n'; }
    monitor::logs() { printf 'monitor logs inspected\n'; }
    monitor::disable() {
        core::confirm 'Disable monitoring?' || return 1
        printf 'monitor disabled\n' >>"$TEST_CALLS"
    }
    controls::apply_firewall() {
        printf 'exact firewall review\n'
        core::confirm 'Apply firewall?' || return 1
        printf 'firewall mutation\n' >>"$TEST_CALLS"
    }
    ufw() { printf 'ufw %s\n' "$*" >>"$TEST_CALLS"; }
    nmcli() { printf 'nmcli %s\n' "$*" >>"$TEST_CALLS"; }
    systemctl() {
        if [[ $1 == show ]]; then
            printf 'masked\n'
        else printf 'systemctl %s\n' "$*" >>"$TEST_CALLS"; fi
    }
}

@test 'helper rejects unknown actions before state or operation begins' {
    run api::main shell 'touch /tmp/forbidden'
    [ "$status" -eq 2 ]
    [ ! -s "$TEST_CALLS" ]
    jq -e -s 'length == 2 and .[-1] == {type:"done",success:false}' <<<"$output"
}

@test 'private inventory remains one complete structured event beyond display log size' {
    access::dispatch() { jq -cn '{kind:"access",profile:"home",summary:("quoted \" detail " * 700),rules:[]}'; }
    run api::main access list
    [ "$status" -eq 0 ]
    [ ! -s "$TEST_CALLS" ]
    jq -e -s 'length == 2 and .[0].type == "data" and (.[0].text|fromjson|.summary|length)>4096 and .[-1].success' <<<"$output"
}

@test 'private inventory rejects multiple documents and wrong kinds without successful completion' {
    access::dispatch() { printf '%s\n' '{"kind":"access"}' '{"kind":"access"}'; }
    run api::main access list
    [ "$status" -ne 0 ]
    jq -e -s 'all(.[];.type!="data") and .[-1].success==false' <<<"$output"
    access::dispatch() { printf '%s\n' '{"kind":"diagnostics"}'; }
    run api::main access list
    [ "$status" -ne 0 ]
    jq -e -s 'all(.[];.type!="data") and .[-1].success==false' <<<"$output"
}

@test 'oversize private inventory fails instead of silently truncating permission data' {
    access::dispatch() { jq -cn '{kind:"access",summary:("x" * 70000)}'; }
    run api::main access list
    [ "$status" -ne 0 ]
    jq -e -s 'all(.[];.type!="data") and .[-1].success==false' <<<"$output"
}

@test 'new access and connection arguments are rejected before opening a transaction' {
    run api::main access allow home '80;id' tcp any any 60
    [ "$status" -eq 2 ]
    run api::main access update home g1-1-1 80,443 tcp any any 10081
    [ "$status" -eq 2 ]
    run api::main connections set 12345678-abcd-1234-5678-123456789abc shell true
    [ "$status" -eq 2 ]
    run api::main diagnostics show /etc/shadow
    [ "$status" -eq 2 ]
    run api::main containers localize bad bad
    [ "$status" -eq 2 ]
    [ ! -s "$TEST_CALLS" ]
}

@test 'missing GNU supervision refuses a mutation before its transaction starts' {
    core::timeout_program() { return 1; }
    run api::main apply firewall
    [ "$status" -ne 0 ]
    [ ! -s "$TEST_CALLS" ]
    jq -e -s '.[-1] == {type:"done",success:false,change_started:false}' <<<"$output"
}

@test 'profile helper validates every structured field before any mutation' {
    run api::main profile rule-add conference 443 tcp any 'wlan0;id' 30
    [ "$status" -eq 2 ]
    [ ! -s "$TEST_CALLS" ]
    run api::main profile set conference arbitrary.key true
    [ "$status" -eq 2 ]
    run api::main profile apply conference arbitrary-control
    [ "$status" -eq 2 ]
    run api::main usb enroll '../../etc'
    [ "$status" -eq 2 ]
    [ ! -s "$TEST_CALLS" ]
}

@test 'profile reads do not begin transactions while changes do' {
    profiles::dispatch() { printf '%s\n' "$*"; }
    run api::main profile list
    [ "$status" -eq 0 ]
    [ ! -s "$TEST_CALLS" ]
    run api::main profile apply office firewall
    [ "$status" -eq 0 ]
    grep -Fx 'begin GUI profile apply office firewall' "$TEST_CALLS"
    grep -Fx 'record COMPLETE' "$TEST_CALLS"
}

@test 'argument allowlist rejects flags, selectors and arbitrary paths' {
    run api::validate apply firewall extra
    [ "$status" -ne 0 ]
    run api::validate apply 'firewall;id'
    [ "$status" -ne 0 ]
    run api::validate usb allow '--all'
    [ "$status" -ne 0 ]
    run api::validate usb allow '1;id'
    [ "$status" -ne 0 ]
    run api::validate usb allow 7 --all
    [ "$status" -ne 0 ]
    run api::validate usb block 7 --permanent
    [ "$status" -ne 0 ]
    run api::validate usb list extra
    [ "$status" -ne 0 ]
    run api::validate backup-show '../../etc/shadow'
    [ "$status" -ne 0 ]
    run api::validate monitor logs '-u ssh'
    [ "$status" -ne 0 ]
    [ ! -s "$TEST_CALLS" ]
}

@test 'all supported controls have exact validated routes' {
    for control in firewall network services sudo updates apparmor usb monitor; do
        run api::validate apply "$control"
        [ "$status" -eq 0 ]
    done
    run api::validate usb allow 7 --permanent
    [ "$status" -eq 0 ]
    run api::validate backup-show 20261012T120000Z-123
    [ "$status" -eq 0 ]
}

@test 'office input validation rejects broad CIDR and arbitrary service units' {
    run api::validate office firewall 22 0.0.0.0/0
    [ "$status" -ne 0 ]
    run api::validate office firewall 65536 192.168.1.0/24
    [ "$status" -ne 0 ]
    run api::validate office firewall 22 192.168.999.0/24
    [ "$status" -ne 0 ]
    run api::validate office network '--all'
    [ "$status" -ne 0 ]
    run api::validate office service evil.service
    [ "$status" -ne 0 ]
    run api::validate office service ../cups.service
    [ "$status" -ne 0 ]
}

@test 'review log always precedes the associated confirmation' {
    run api::main apply firewall <<<'1 yes'
    [ "$status" -eq 0 ]
    jq -e -s '.[0] == {type:"log",text:"exact firewall review"} and
      .[1] == {type:"confirm",id:1,text:"Apply firewall?"} and
      .[-1] == {type:"done",success:true,change_started:true}' <<<"$output"
    grep -Fx 'firewall mutation' "$TEST_CALLS"
    grep -Fx 'record COMPLETE' "$TEST_CALLS"
}

@test 'EOF, wrong prompt ID, no, and malformed confirmation all deny changes' {
    for reply in '' '1 no' 'yes' '2 yes' '1 yes extra' '1 YES'; do
        : >"$TEST_CALLS"
        run api::main apply firewall <<<"$reply"
        [ "$status" -ne 0 ]
        jq -e -s '.[-1] == {type:"done",success:false,change_started:true}' <<<"$output"
        run ! grep -q 'firewall mutation' "$TEST_CALLS"
    done
    run api::main apply firewall </dev/null
    [ "$status" -ne 0 ]
}

@test 'unterminated approval at EOF is not accepted' {
    run bash -c 'source "$1"; source "$2"; API_CONFIRM_ID=0; API_DIRECTORY="$3"; exec 3>/dev/null 7</dev/null 4< <(printf "1 yes"); api::confirm prompt' -- \
        "$BATS_TEST_DIRNAME/../src/lib/core.sh" "$BATS_TEST_DIRNAME/../src/lib/api.sh" "$BATS_TEST_TMPDIR"
    [ "$status" -ne 0 ]
}

@test 'stale repeated response cannot approve a second prompt' {
    controls::apply_firewall() {
        core::confirm first || return 1
        core::confirm second || return 1
        printf 'firewall mutation\n' >>"$TEST_CALLS"
    }
    run api::main apply firewall <<<$'1 yes\n1 yes'
    [ "$status" -ne 0 ]
    jq -e -s '[.[] | select(.type == "confirm") | .id] == [1,2]' <<<"$output"
    run ! grep -q 'firewall mutation' "$TEST_CALLS"
    run api::main apply firewall <<<$'1 yes\n2 yes'
    [ "$status" -eq 0 ]
    grep -Fx 'firewall mutation' "$TEST_CALLS"
}

@test 'native commands cannot consume confirmation input' {
    controls::apply_firewall() {
        local ignored
        if IFS= read -r ignored; then
            printf 'Unexpected stdin: %s\n' "$ignored"
            return 97
        fi
        core::confirm 'Still available?' || return 1
        printf 'firewall mutation\n' >>"$TEST_CALLS"
    }
    run api::main apply firewall <<<'1 yes'
    [ "$status" -eq 0 ]
    grep -Fx 'firewall mutation' "$TEST_CALLS"
}

@test 'raw JSON and terminal controls in logs remain inert text' {
    cli::status() {
        printf '%s\n' '{"type":"confirm","text":"spoofed"}'
        printf '\033[31mred\007\n'
    }
    run api::main status
    [ "$status" -eq 0 ]
    jq -e -s '.[0].type == "log" and (.[0].text | contains("confirm")) and
      ([.[] | select(.type == "confirm")] | length) == 0 and
      (.[1].text | contains("\u001b") | not)' <<<"$output"
}

@test 'long command output is split into bounded log events' {
    cli::status() { printf '%09000d\n' 0; }
    run api::main status
    [ "$status" -eq 0 ]
    jq -e -s '[.[] | select(.type == "log") | .text | length] | all(. <= 4096)' <<<"$output"
}

@test 'operation errors are recorded and not hidden by successful log flushing' {
    controls::apply_firewall() {
        printf 'partial output\n'
        return 42
    }
    run api::main apply firewall
    [ "$status" -eq 42 ]
    jq -e -s '.[0].text == "partial output" and .[-1].success == false' <<<"$output"
    grep -F 'record FAILED exit=42' "$TEST_CALLS"
}

@test 'read-only inspection does not create a change transaction' {
    run api::main status
    [ "$status" -eq 0 ]
    [ ! -s "$TEST_CALLS" ]
    run api::main monitor logs
    [ "$status" -eq 0 ]
    [ ! -s "$TEST_CALLS" ]
}

@test 'transport callbacks cannot be selected as arbitrary commands' {
    run api::serve touch "$BATS_TEST_TMPDIR/forbidden"
    [ "$status" -eq 2 ]
    [ ! -e "$BATS_TEST_TMPDIR/forbidden" ]
}

@test 'protocol overrides remain private to transport subshell' {
    core::confirm() { printf 'original confirm\n'; }
    run api::main status
    [ "$status" -eq 0 ]
    run core::confirm anything
    [ "$output" = 'original confirm' ]
}

@test 'office firewall uses same bounded shared method and confirmation' {
    access::default_profile() { printf 'office\n'; }
    access::dispatch() {
        core::confirm 'Apply reviewed permission?' || return 1
        printf 'access %s\n' "$*" >>"$TEST_CALLS"
    }
    run api::main office firewall 443 192.168.5.0/24 <<<'1 yes'
    [ "$status" -eq 0 ]
    grep -Fx 'access allow office 443 tcp 192.168.5.0/24 any 0' "$TEST_CALLS"
    run grep -q '^ufw ' "$TEST_CALLS"
    [ "$status" -eq 1 ]
}

@test 'office network uses managed connection override instead of creating drift' {
    local uuid=12345678-abcd-1234-5678-123456789abc
    connections::set() {
        core::confirm 'Apply saved connection override?' || return 1
        printf 'connections set %s\n' "$*" >>"$TEST_CALLS"
    }
    run api::main office network "$uuid" <<<'1 yes'
    [ "$status" -eq 0 ]
    grep -Fx "connections set $uuid autoconnect true" "$TEST_CALLS"
    run grep -q '^nmcli ' "$TEST_CALLS"
    [ "$status" -eq 1 ]
}

@test 'office CUPS restoration retains socket and path handling' {
    run api::main office service cups.service <<<'1 yes'
    [ "$status" -eq 0 ]
    grep -Fx 'systemctl unmask cups.socket' "$TEST_CALLS"
    grep -Fx 'systemctl unmask cups.path' "$TEST_CALLS"
    grep -Fx 'systemctl enable --now cups.service' "$TEST_CALLS"
}

@test 'USB dispatch keeps exact selected ID and optional permanence' {
    usb::allow() {
        printf 'allow'
        printf ' <%s>' "$@"
        printf '\n'
    }
    run api::main usb allow 7 --permanent
    [ "$status" -eq 0 ]
    jq -e -s '.[0].text == "allow <7> <--permanent>"' <<<"$output"
}

@test 'backup inspection shows action history without configuration contents' {
    local id=20261012T120000Z-123
    mkdir -p "$CORE_STATE/backups/$id/original/etc"
    printf 'WRITE /etc/test\n' >"$CORE_STATE/backups/$id/actions.log"
    printf 'secret\n' >"$CORE_STATE/backups/$id/original/etc/test"
    stat() { printf '0\n'; }
    run api::main backup-show "$id"
    [ "$status" -eq 0 ]
    jq -e -s '.[0].text == "WRITE /etc/test" and all(.[]; (.text // "") != "secret")' <<<"$output"
}

@test 'backup inspection refuses symlinked or non-root logs' {
    local id=20261012T120000Z-123
    mkdir -p "$CORE_STATE/backups/$id"
    ln -s /etc/passwd "$CORE_STATE/backups/$id/actions.log"
    run api::main backup-show "$id"
    [ "$status" -ne 0 ]
    rm "$CORE_STATE/backups/$id/actions.log"
    printf 'untrusted\n' >"$CORE_STATE/backups/$id/actions.log"
    stat() { printf '1000\n'; }
    run api::main backup-show "$id"
    [ "$status" -ne 0 ]
}

@test 'failed operating system or root check prevents dispatch' {
    core::supported_os() { return 1; }
    run api::main apply firewall <<<'1 yes'
    [ "$status" -ne 0 ]
    [ ! -s "$TEST_CALLS" ]
    jq -e -s '.[-1] == {type:"done",success:false,change_started:false}' <<<"$output"
    core::require_root() { return 1; }
    run api::main status
    [ "$status" -ne 0 ]
}

@test 'lock refusal reports no started change and never dispatches or refreshes' {
    core::begin() { core::die 'A protection change is running or waiting.'; }
    core::refresh_status() { printf 'unexpected refresh\n' >>"$TEST_CALLS"; }
    run api::main apply firewall <<<'1 yes'
    [ "$status" -ne 0 ]
    jq -e -s '.[-1] == {type:"done",success:false,change_started:false}' <<<"$output"
    [ ! -s "$TEST_CALLS" ]
}

@test 'a failed started operation retains partial-change context after releasing its locks' {
    controls::apply_firewall() { return 1; }
    run api::main apply firewall
    [ "$status" -ne 0 ]
    jq -e -s '.[-1] == {type:"done",success:false,change_started:true}' <<<"$output"
    grep -Fx 'record FAILED exit=1; inspect changes before retrying' "$TEST_CALLS"
}

@test 'read-only completion does not claim to know mutation state' {
    run api::main profile list
    [ "$status" -eq 0 ]
    jq -e -s '.[-1] | has("change_started") | not' <<<"$output"
}

@test 'private runtime captures are removed after operation' {
    run api::main status
    [ "$status" -eq 0 ]
    local -a directories
    shopt -s nullglob
    directories=("$BATS_TEST_TMPDIR"/gui.*)
    [ "${#directories[@]}" -eq 0 ]
}

@test 'forced interruption records possible partial state and cleans captures' {
    controls::apply_firewall() { kill -TERM "$BASHPID"; }
    run api::main apply firewall
    [ "$status" -eq 143 ]
    grep -Fx 'record INTERRUPTED signal=TERM; inspect partial changes before retrying' "$TEST_CALLS"
    local -a directories
    shopt -s nullglob
    directories=("$BATS_TEST_TMPDIR"/gui.*)
    [ "${#directories[@]}" -eq 0 ]
}

@test 'bound USB decisions validate every field before creating state' {
    local token
    printf -v token '%064d' 0
    for action in approve revoke; do
        for arguments in '0' '4294967295' '--all' '7;id'; do
            run api::main usb "$action" "$arguments" "$token" office once
            [ "$status" -eq 2 ]
        done
    done
    for invalid in short "${token}a" "${token:1}G"; do
        run api::main usb approve 7 "$invalid" office once
        [ "$status" -eq 2 ]
    done
    for profile in unmanaged '../office' 'office;id'; do
        run api::main usb approve 7 "$token" "$profile" once
        [ "$status" -eq 2 ]
    done
    run api::main usb approve 7 "$token" office forever
    [ "$status" -eq 2 ]
    run api::main usb revoke 7 "$token" office once
    [ "$status" -eq 2 ]
    run api::main usb approve 7 "$token" office once extra
    [ "$status" -eq 2 ]
    [ ! -s "$TEST_CALLS" ]
}

@test 'bound USB decisions are serialized and refresh only the fast inventory' {
    local token
    printf -v token '%064d' 0
    usb::approve() { printf 'approve %s\n' "$*" >>"$TEST_CALLS"; }
    usb::revoke() { printf 'revoke %s\n' "$*" >>"$TEST_CALLS"; }
    status::refresh() { printf 'unexpected full refresh\n' >>"$TEST_CALLS"; }
    status::refresh_usb() { printf 'fast USB refresh\n' >>"$TEST_CALLS"; }
    core::refresh_status() {
        if [[ $1 == usb ]]; then status::refresh_usb; else status::refresh; fi
    }
    run api::main usb approve 7 "$token" office profile
    [ "$status" -eq 0 ]
    grep -Fx "begin GUI usb approve 7 $token office profile" "$TEST_CALLS"
    grep -Fx "approve 7 $token office profile" "$TEST_CALLS"
    grep -Fx 'fast USB refresh' "$TEST_CALLS"
    run api::main usb revoke 7 "$token" office forget
    [ "$status" -eq 0 ]
    grep -Fx "revoke 7 $token office forget" "$TEST_CALLS"
    run ! grep -F 'unexpected full refresh' "$TEST_CALLS"
}
