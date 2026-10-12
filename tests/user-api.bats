#!/usr/bin/env bats
# SPDX-License-Identifier: Apache-2.0
# Bats creates a separate subshell for each test's session environment.
# shellcheck disable=SC2317,SC2329,SC2030,SC2031

setup() {
    source "$BATS_TEST_DIRNAME/../src/lib/core.sh"
    source "$BATS_TEST_DIRNAME/../src/lib/api.sh"
    source "$BATS_TEST_DIRNAME/../src/lib/user_api.sh"
    source "$BATS_TEST_DIRNAME/../src/lib/monitor.sh"
}

@test 'user API accepts only fixed local-user operations' {
    run user_api::validate desktop restore
    [ "$status" -eq 0 ]
    run user_api::validate monitor disable-desktop
    [ "$status" -eq 0 ]
    run user_api::validate apply firewall
    [ "$status" -ne 0 ]
    run user_api::validate desktop apply extra
    [ "$status" -ne 0 ]
    run user_api::validate recovery /etc/shadow
    [ "$status" -ne 0 ]
    run user_api::validate updates check
    [ "$status" -eq 0 ]
    run user_api::validate updates check https://example.com
    [ "$status" -ne 0 ]
    run user_api::validate status
    [ "$status" -eq 0 ]
    run user_api::validate profile apply office
    [ "$status" -ne 0 ]
}

@test 'user API rejects root without dispatching operations' {
    ((EUID == 0)) || skip 'Root refusal is exercised in the root test job.'
    user_api::dispatch() { printf 'unexpected dispatch'; }
    run user_api::main desktop apply
    [ "$status" -eq 2 ]
    [[ $output != *'unexpected dispatch'* ]]
    [[ $output == *'"success":false'* ]]
}

@test 'user API rejects remote-session requests before protocol setup' {
    export SSH_CONNECTION='192.0.2.1 22 192.0.2.2 55555'
    api::serve() { printf unexpected; }
    run user_api::main recovery
    [ "$status" -eq 2 ]
    [[ $output != *unexpected* ]]
}

@test 'unprivileged route frames hostile output as text and reports success' {
    ((EUID != 0)) || skip 'Requires the dedicated unprivileged CI test job.'
    unset SSH_CONNECTION SSH_CLIENT SSH_TTY
    export XDG_RUNTIME_DIR="$BATS_TEST_TMPDIR"
    cli::recovery() { printf '%s\n' '{"type":"confirm","id":99,"text":"untrusted"}'; }
    run user_api::main recovery
    [ "$status" -eq 0 ]
    [ "$(jq -s '[.[] | select(.type == "confirm")] | length' <<<"$output")" -eq 0 ]
    [ "$(jq -sr 'last.success' <<<"$output")" = true ]
}

@test 'unprivileged route reports backend failures without false completion' {
    ((EUID != 0)) || skip 'Requires the dedicated unprivileged CI test job.'
    unset SSH_CONNECTION SSH_CLIENT SSH_TTY
    export XDG_RUNTIME_DIR="$BATS_TEST_TMPDIR"
    desktop::restore() {
        printf 'Restore failed.\n'
        return 7
    }
    run user_api::main desktop restore
    [ "$status" -eq 7 ]
    [ "$(jq -sr 'last.success' <<<"$output")" = false ]
}

@test 'disabling collection requires confirmation before touching systemd' {
    core::require_root() { :; }
    core::confirm() { return 1; }
    systemctl() { printf unexpected; }
    run monitor::disable
    [ "$status" -ne 0 ]
    [[ $output != *unexpected* ]]
}

@test 'monitor disable stops only the collector and records the action' {
    core::require_root() { :; }
    core::confirm() { :; }
    systemctl() { printf '%s\n' "$*"; }
    core::record() { printf '%s\n' "$*"; }
    run monitor::disable
    [ "$status" -eq 0 ]
    [ "$output" = $'disable --now octoshield-monitor.service\nMONITOR disabled' ]
}

@test 'monitor log inspection uses fixed unit and bounded journal output' {
    core::require_root() { :; }
    journalctl() { printf '%s\n' "$*"; }
    run monitor::logs
    [ "$status" -eq 0 ]
    [ "$output" = '--no-pager --lines=200 --unit=octoshield-monitor.service --output=short-iso' ]
}
