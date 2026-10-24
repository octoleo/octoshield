#!/usr/bin/env bats
# SPDX-License-Identifier: Apache-2.0
# Exercise the compiled GUI argv model and both Bash frontend dispatchers.
# Every operational handler is a spy; these tests never elevate or change hosts.
# Bats supplies per-test status variables; attack strings must remain literal.
# shellcheck disable=SC1091,SC2317,SC2329,SC2030,SC2031,SC2016

setup_file() {
    local -a compiler_flags
    export OCTOSHIELD_TEST_ROOT="$BATS_TEST_DIRNAME/../.."
    export OCTOSHIELD_CAPABILITY_DRIVER="$BATS_FILE_TMPDIR/capability-driver"
    read -r -a compiler_flags < <(pkg-config --cflags --libs gio-2.0 json-glib-1.0)
    cc -std=c11 -Wall -Wextra -Werror -pedantic \
        -I"$OCTOSHIELD_TEST_ROOT/src/ui" \
        "$BATS_TEST_DIRNAME/capability-driver.c" \
        "$OCTOSHIELD_TEST_ROOT/src/ui/protocol.c" \
        "${compiler_flags[@]}" -o "$OCTOSHIELD_CAPABILITY_DRIVER"
}

setup() {
    bats_require_minimum_version 1.5.0
    source "$OCTOSHIELD_TEST_ROOT/src/lib/core.sh"
    source "$OCTOSHIELD_TEST_ROOT/src/lib/usb.sh"
    source "$OCTOSHIELD_TEST_ROOT/src/lib/office.sh"
    source "$OCTOSHIELD_TEST_ROOT/src/lib/profiles.sh"
    source "$OCTOSHIELD_TEST_ROOT/src/lib/access.sh"
    source "$OCTOSHIELD_TEST_ROOT/src/lib/connections.sh"
    source "$OCTOSHIELD_TEST_ROOT/src/lib/diagnostics.sh"
    source "$OCTOSHIELD_TEST_ROOT/src/lib/containers.sh"
    source "$OCTOSHIELD_TEST_ROOT/src/lib/cli.sh"
    source "$OCTOSHIELD_TEST_ROOT/src/lib/api.sh"
    source "$OCTOSHIELD_TEST_ROOT/src/lib/user_api.sh"
    export OCTOSHIELD_ROOT=$OCTOSHIELD_TEST_ROOT

    test::route() { printf '%s\n' "$@"; }
    core::require_local() { return 0; }
    cli::system() { test::route "$@"; }
    cli::status() { test::route status; }
    cli::recovery() { test::route recovery; }
    core::backups() { test::route backups; }
    api::backup_show() { test::route backup-show "$@"; }
    api::details() { "${1}::dispatch" "${@:2}"; }

    controls::apply_firewall() { test::route apply firewall; }
    controls::apply_network() { test::route apply network; }
    controls::apply_services() { test::route apply services; }
    controls::apply_sudo() { test::route apply sudo; }
    controls::apply_updates() { test::route apply updates; }
    controls::apply_apparmor() { test::route apply apparmor; }
    usb::apply() { test::route apply usb; }
    monitor::apply() { test::route apply monitor; }
    usb::list() { test::route usb list; }
    usb::allow() { test::route usb allow "$@"; }
    usb::block() { test::route usb block "$@"; }
    usb::forget() { test::route usb forget "$@"; }
    usb::profile_enroll() { test::route usb enroll "$@"; }
    usb::devices_json() { test::route usb devices; }
    profiles::dispatch() { test::route profile "$@"; }
    access::dispatch() { test::route access "$@"; }
    connections::dispatch() { test::route connections "$@"; }
    diagnostics::dispatch() { test::route diagnostics "$@"; }
    containers::dispatch() { test::route containers "$@"; }
    updates::check() { test::route updates check; }
    updates::show() { test::route updates check; }
    office::firewall() { test::route office firewall "$@"; }
    office::network() { test::route office network "$@"; }
    office::service() { test::route office service "$@"; }
    monitor::status() { test::route monitor status; }
    monitor::logs() { test::route monitor logs; }
    monitor::disable() { test::route monitor disable; }
    monitor::enable_desktop() { test::route monitor enable-desktop; }
    monitor::disable_desktop() { test::route monitor disable-desktop; }
    desktop::apply() { test::route desktop apply; }
    desktop::restore() { test::route desktop restore; }
    desktop::status() { test::route desktop status; }

    # An unexpected new elevation path must fail the test, never prompt CI.
    sudo() {
        printf 'Unexpected privilege request in a dispatch test.\n' >&2
        return 99
    }
}

test::privileged_parity() {
    local expected
    expected=$(printf '%s\n' "$@")
    run "$OCTOSHIELD_CAPABILITY_DRIVER" privileged "$@"
    [ "$status" -eq 0 ]
    [ "$output" = "$(printf '%s\n' /usr/bin/pkexec /usr/libexec/octoshield-helper "$@")" ]
    run api::validate "$@"
    [ "$status" -eq 0 ]
    run api::dispatch "$@"
    [ "$status" -eq 0 ]
    [ "$output" = "$expected" ]
    run cli::main "$@"
    [ "$status" -eq 0 ]
    [ "$output" = "$expected" ]
}

test::user_parity() {
    local expected
    expected=$(printf '%s\n' "$@")
    run "$OCTOSHIELD_CAPABILITY_DRIVER" user "$@"
    [ "$status" -eq 0 ]
    [ "$output" = "$(printf '%s\n' /usr/bin/octoshield user-api "$@")" ]
    run user_api::validate "$@"
    [ "$status" -eq 0 ]
    run user_api::dispatch "$@"
    [ "$status" -eq 0 ]
    [ "$output" = "$expected" ]
    run cli::main "$@"
    [ "$status" -eq 0 ]
    [ "$output" = "$expected" ]
}

test::reject_privileged() {
    run "$OCTOSHIELD_CAPABILITY_DRIVER" privileged "$@"
    [ "$status" -ne 0 ]
    run api::validate "$@"
    [ "$status" -ne 0 ]
    run cli::main "$@"
    [ "$status" -ne 0 ]
}

@test "all eight security controls share the GUI helper and CLI backend routes" {
    local control
    for control in firewall network services sudo updates apparmor usb monitor; do
        test::privileged_parity apply "$control"
    done
}

@test "USB inspection temporary approval permanent approval and blocking have parity" {
    test::privileged_parity usb list
    test::privileged_parity usb allow 7
    test::privileged_parity usb allow 7 --permanent
    test::privileged_parity usb block 7
    test::privileged_parity usb devices
    test::privileged_parity usb forget 7
    test::privileged_parity usb enroll office
}

@test "named profiles settings restoration and scoped exceptions have GUI CLI parity" {
    test::privileged_parity profile list
    test::privileged_parity profile show office
    test::privileged_parity profile create client-visit conference
    test::privileged_parity profile delete client-visit
    test::privileged_parity profile apply conference
    test::privileged_parity profile apply office usb
    test::privileged_parity profile restore
    test::privileged_parity profile restore firewall
    test::privileged_parity profile set office services.printing baseline
    test::privileged_parity profile set home monitor.enabled true
    test::privileged_parity profile rule-add office 443 tcp 192.168.1.0/24 wlan0 60
    test::privileged_parity profile rule-add home 88 udp 2001:db8::/64 enp3s0 10080
    test::privileged_parity profile rule-add conference 443 tcp any any 0
    test::privileged_parity profile rule-remove office r1791830500-1234-456
}

@test "release checks share the unprivileged GUI and CLI backend" {
    test::user_parity updates check
}

@test "guided access applies grouped ports edits and revokes through the same validated routes" {
    test::privileged_parity access list
    test::privileged_parity access list home
    test::privileged_parity access allow home 80,443 tcp 192.168.1.0/24 wlan0 60
    test::privileged_parity access update home g123-4-56 80,443 tcp 2001:db8::/64 eth0 10080
    test::privileged_parity access update office r123-4-56 22 tcp any any 0
    test::privileged_parity access revoke home g123-4-56
    test::privileged_parity access revoke home r123-4-56
}

@test "connection controls and detail topics have compiled frontend helper CLI parity" {
    local uuid=11111111-2222-3333-4444-555555555555 topic
    test::privileged_parity connections list
    test::privileged_parity connections set "$uuid" autoconnect true
    test::privileged_parity connections set "$uuid" discovery false
    test::privileged_parity connections set "$uuid" mac stable
    test::privileged_parity connections set "$uuid" mac permanent
    test::privileged_parity connections reconnect "$uuid"
    for topic in disk_encryption containers forwarding network; do
        test::privileged_parity diagnostics show "$topic"
    done
}

@test "container plans and reviewed localization remain exclusively user actions" {
    local token=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    test::user_parity containers plan "$token"
    test::user_parity containers localize "$token" "$token"
    run "$OCTOSHIELD_CAPABILITY_DRIVER" privileged containers localize "$token" "$token"
    [ "$status" -ne 0 ]
    run api::validate containers localize "$token" "$token"
    [ "$status" -ne 0 ]
    run "$OCTOSHIELD_CAPABILITY_DRIVER" user access allow home 443 tcp any any 0
    [ "$status" -ne 0 ]
    run user_api::validate access allow home 443 tcp any any 0
    [ "$status" -ne 0 ]
}

@test "guided access validation agrees on CSV boundaries and argument injection" {
    local ports='' index value uuid=11111111-2222-3333-4444-555555555555
    for ((index = 10000; index < 10032; index++)); do
        [[ -z $ports ]] || ports+=,
        ports+=$index
    done
    [ "${#ports}" -eq 191 ]
    test::privileged_parity access update home g1-2-3 "$ports" tcp any any 0
    test::reject_privileged access update home g1-2-3 "$ports," tcp any any 0
    ports=''
    for ((index = 1; index <= 33; index++)); do
        [[ -z $ports ]] || ports+=,
        ports+=$index
    done
    test::reject_privileged access allow home "$ports" tcp any any 0
    for value in '80,80' '80,' ',443' '0' '01' '65536' '80;id' "\$(id)"; do
        test::reject_privileged access allow home "$value" tcp any any 0
    done
    test::reject_privileged access update home g1-2-3 80 tcp any any 0 extra
    test::reject_privileged access revoke home '../rules'
    test::reject_privileged access revoke home g1-2-123456
    test::reject_privileged access allow home 443 tcp 1.2.3.999/24 any 0
    test::reject_privileged access allow home 443 tcp any 'wlan0;id' 0
    test::reject_privileged access allow home 443 tcp any any 10081
    test::reject_privileged connections set "$uuid" discovery yes
    test::reject_privileged connections set "$uuid" mac true
    test::reject_privileged connections reconnect "\$(nmcli)"
    test::reject_privileged diagnostics show '../../etc/shadow'
}

@test "container identity and review tokens reject malformed user input in both adapters" {
    local token=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef value
    for value in '' '--help' "\$(id)" "${token%?}" "${token^^}"; do
        run "$OCTOSHIELD_CAPABILITY_DRIVER" user containers plan "$value"
        [ "$status" -ne 0 ]
        run user_api::validate containers plan "$value"
        [ "$status" -ne 0 ]
        run "$OCTOSHIELD_CAPABILITY_DRIVER" user containers localize "$token" "$value"
        [ "$status" -ne 0 ]
        run user_api::validate containers localize "$token" "$value"
        [ "$status" -ne 0 ]
    done
}

@test "office firewall network and every supported service have parity" {
    local service
    test::privileged_parity office firewall 443 192.168.10.0/24
    test::privileged_parity office network 11111111-2222-3333-4444-555555555555
    for service in ssh.service avahi-daemon.service bluetooth.service cups.service; do
        test::privileged_parity office service "$service"
    done
}

@test "inspection backups and system monitoring controls have parity" {
    test::privileged_parity status
    test::privileged_parity backups
    test::privileged_parity backup-show 20261012T114118Z-1234
    test::privileged_parity monitor status
    test::privileged_parity monitor logs
    test::privileged_parity monitor disable
}

@test "desktop restoration notification preferences and recovery stay unprivileged" {
    test::user_parity desktop apply
    test::user_parity desktop restore
    test::user_parity desktop status
    test::user_parity monitor enable-desktop
    test::user_parity monitor disable-desktop
    test::user_parity monitor status
    test::user_parity recovery
}

@test "GUI cannot route hardening as user actions or user settings as root actions" {
    run "$OCTOSHIELD_CAPABILITY_DRIVER" user apply firewall
    [ "$status" -ne 0 ]
    run user_api::validate apply firewall
    [ "$status" -ne 0 ]
    run "$OCTOSHIELD_CAPABILITY_DRIVER" privileged desktop apply
    [ "$status" -ne 0 ]
    run api::validate desktop apply
    [ "$status" -ne 0 ]
    run "$OCTOSHIELD_CAPABILITY_DRIVER" privileged monitor enable-desktop
    [ "$status" -ne 0 ]
    run api::validate monitor enable-desktop
    [ "$status" -ne 0 ]
}

@test "GUI and helper both reject unrestricted privileged commands and malformed identifiers" {
    local -a words
    local action
    for action in 'apply shell' 'usb allow --permanent' 'usb allow 0' \
        'usb allow 4294967295' 'office service ssh.socket' \
        'office firewall 65536 192.168.1.0/24' \
        'office firewall 443 0.0.0.0/0' 'backup-show ../../etc/shadow' \
        'monitor run'; do
        read -r -a words <<<"$action"
        run "$OCTOSHIELD_CAPABILITY_DRIVER" privileged "${words[@]}"
        [ "$status" -ne 0 ]
        run api::validate "${words[@]}"
        [ "$status" -ne 0 ]
    done
}
