#!/usr/bin/env bats
# SPDX-License-Identifier: Apache-2.0
# Bats invokes command mocks through the production dispatch table.
# shellcheck disable=SC2317,SC2329

setup() {
    source "$BATS_TEST_DIRNAME/../src/lib/core.sh"
    source "$BATS_TEST_DIRNAME/../src/lib/cli.sh"
    core::require_local() { :; }
    core::supported_os() { :; }
    cli::system() {
        printf 'SYSTEM'
        printf ' <%s>' "$@"
        printf '\n'
    }
}

@test 'help exposes the full command set' {
    run cli::main --help
    [ "$status" -eq 0 ]
    [[ $output == *'usb allow ID'* && $output == *'monitor status'* && $output == *'office'* ]]
}

@test 'unknown commands and extra arguments are rejected' {
    run cli::main shell 'touch /tmp/bad'
    [ "$status" -eq 2 ]
    run cli::main status extra
    [ "$status" -eq 2 ]
    run cli::main apply
    [ "$status" -eq 2 ]
}

@test 'only registered controls reach privilege boundary' {
    run cli::main apply firewall
    [ "$status" -eq 0 ]
    [ "$output" = 'SYSTEM <apply> <firewall>' ]
    run cli::main apply 'firewall;id'
    [ "$status" -eq 2 ]
    [[ $output != *SYSTEM* ]]
}

@test 'USB approval accepts numeric ID and explicit permanent flag' {
    run cli::main usb allow 17 --permanent
    [ "$status" -eq 0 ]
    [ "$output" = 'SYSTEM <usb> <allow> <17> <--permanent>' ]
    run cli::main usb allow --all
    [ "$status" -eq 2 ]
    run cli::main usb allow 17 --all
    [ "$status" -eq 2 ]
    run cli::main usb block '1;id'
    [ "$status" -eq 2 ]
}

@test 'USB list never accepts a rule or extra argument' {
    run cli::main usb list allow
    [ "$status" -eq 2 ]
}

@test 'monitor status dispatches to read only service inspection' {
    monitor::status() { printf status-ok; }
    run cli::main monitor status
    [ "$status" -eq 0 ]
    [ "$output" = status-ok ]
    run cli::main monitor arbitrary
    [ "$status" -eq 2 ]
}

@test 'desktop restore dispatch preserves normal user session' {
    desktop::restore() { printf restore-ok; }
    run cli::main desktop restore
    [ "$status" -eq 0 ]
    [ "$output" = restore-ok ]
}

@test 'office CIDR parser rejects broad or malformed input' {
    run cli::valid_subnet 192.168.10.0/24
    [ "$status" -eq 0 ]
    run cli::valid_subnet 0.0.0.0/0
    [ "$status" -ne 0 ]
    run cli::valid_subnet 192.168.999.0/24
    [ "$status" -ne 0 ]
    run cli::valid_subnet '192.168.1.0/24;id'
    [ "$status" -ne 0 ]
    run cli::valid_subnet 192.168.1.0/33
    [ "$status" -ne 0 ]
}

@test 'office CUPS restoration unmasks activation units before enabling service' {
    core::confirm() { :; }
    core::backup() { :; }
    core::record() { :; }
    systemctl() {
        if [[ $1 == show ]]; then printf 'masked\n'; else printf '%s\n' "$*" >>"$BATS_TEST_TMPDIR/systemctl"; fi
    }
    cli::office_system <<<'3
cups.service'
    [ "$(cat "$BATS_TEST_TMPDIR/systemctl")" = $'unmask cups.service\nunmask cups.socket\nunmask cups.path\nenable --now cups.service' ]
}
