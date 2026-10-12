#!/usr/bin/env bats
# SPDX-License-Identifier: Apache-2.0
# Mocks and files are isolated to BATS_TEST_TMPDIR; no host services are changed.
# shellcheck disable=SC2317,SC2329

setup() {
    bats_require_minimum_version 1.5.0
    source "$BATS_TEST_DIRNAME/../src/lib/monitor.sh"
    OCTOSHIELD_ROOT="$BATS_TEST_DIRNAME/.."
    TEST_UNIT="$BATS_TEST_TMPDIR/override.service"
    TEST_EXPECTED="$BATS_TEST_TMPDIR/packaged.service"
    TEST_CALLS="$BATS_TEST_TMPDIR/calls"
    : >"$TEST_CALLS"
    cat >"$TEST_EXPECTED" <<'UNIT'
[Unit]
Description=OctoShield security-event monitor
[Service]
ExecStart=/usr/bin/octoshield monitor run
UNIT
    core::require_root() { return 0; }
    core::die() {
        printf '%s\n' "$*" >&2
        return 1
    }
    core::backup() {
        printf 'backup %s\n' "$1" >>"$TEST_CALLS"
        cp -- "$1" "$BATS_TEST_TMPDIR/original"
    }
    core::record() { printf 'record %s\n' "$*" >>"$TEST_CALLS"; }
}

@test 'legacy branding and local installation paths migrate after backup' {
    sed -e 's@/usr/@/usr/local/@g' -e 's/OctoShield/Octoshield/g' "$TEST_EXPECTED" >"$TEST_UNIT"
    run monitor::migrate_unit "$TEST_UNIT" "$TEST_EXPECTED"
    [ "$status" -eq 0 ]
    [ ! -e "$TEST_UNIT" ]
    grep -Fx 'Description=Octoshield security-event monitor' "$BATS_TEST_TMPDIR/original"
    grep -Fx 'ExecStart=/usr/local/bin/octoshield monitor run' "$BATS_TEST_TMPDIR/original"
    [ "$(head -n 1 "$TEST_CALLS")" = "backup $TEST_UNIT" ]
    grep -Fx "record MONITOR migrated $TEST_UNIT to the packaged unit" "$TEST_CALLS"
}

@test 'matching current override is safely backed up and removed' {
    cp "$TEST_EXPECTED" "$TEST_UNIT"
    run monitor::migrate_unit "$TEST_UNIT" "$TEST_EXPECTED"
    [ "$status" -eq 0 ]
    [ ! -e "$TEST_UNIT" ]
    cmp "$TEST_EXPECTED" "$BATS_TEST_TMPDIR/original"
}

@test 'administrator edits remain in place and are not recorded as migrated' {
    cp "$TEST_EXPECTED" "$TEST_UNIT"
    printf 'Environment=CUSTOM_SETTING=yes\n' >>"$TEST_UNIT"
    cp "$TEST_UNIT" "$BATS_TEST_TMPDIR/before"
    run monitor::migrate_unit "$TEST_UNIT" "$TEST_EXPECTED"
    [ "$status" -ne 0 ]
    [[ $output == *'administrator-modified unit'* ]]
    cmp "$TEST_UNIT" "$BATS_TEST_TMPDIR/before"
    [ ! -s "$TEST_CALLS" ]
}

@test 'symlinked overrides including a mask are refused' {
    for target in "$TEST_EXPECTED" /dev/null "$BATS_TEST_TMPDIR/missing"; do
        ln -s "$target" "$TEST_UNIT"
        run monitor::migrate_unit "$TEST_UNIT" "$TEST_EXPECTED"
        [ "$status" -ne 0 ]
        [ -L "$TEST_UNIT" ]
        [ "$(readlink "$TEST_UNIT")" = "$target" ]
        [ ! -s "$TEST_CALLS" ]
        rm "$TEST_UNIT"
    done
}

@test 'absent unit is an idempotent no-op without backups' {
    run monitor::migrate_unit "$TEST_UNIT" "$TEST_EXPECTED"
    [ "$status" -eq 0 ]
    [ ! -s "$TEST_CALLS" ]
}

@test 'backup failure preserves the original override' {
    cp "$TEST_EXPECTED" "$TEST_UNIT"
    core::backup() { return 37; }
    run monitor::migrate_unit "$TEST_UNIT" "$TEST_EXPECTED"
    [ "$status" -ne 0 ]
    cmp "$TEST_UNIT" "$TEST_EXPECTED"
    [ ! -s "$TEST_CALLS" ]
}

@test 'missing or symlinked packaged reference cannot remove an override' {
    cp "$TEST_EXPECTED" "$TEST_UNIT"
    run monitor::migrate_unit "$TEST_UNIT" "$BATS_TEST_TMPDIR/missing"
    [ "$status" -ne 0 ]
    [ -f "$TEST_UNIT" ]
    ln -s "$TEST_EXPECTED" "$BATS_TEST_TMPDIR/reference"
    run monitor::migrate_unit "$TEST_UNIT" "$BATS_TEST_TMPDIR/reference"
    [ "$status" -ne 0 ]
    [ -f "$TEST_UNIT" ]
    [ ! -s "$TEST_CALLS" ]
}

@test 'root check prevents backup and removal' {
    cp "$TEST_EXPECTED" "$TEST_UNIT"
    core::require_root() { return 1; }
    run monitor::migrate_unit "$TEST_UNIT" "$TEST_EXPECTED"
    [ "$status" -ne 0 ]
    [ -f "$TEST_UNIT" ]
    [ ! -s "$TEST_CALLS" ]
}

@test 'production migration only selects fixed system and user unit paths' {
    monitor::migrate_unit() { printf '%s|%s\n' "$1" "$2" >>"$TEST_CALLS"; }
    run monitor::migrate_units
    [ "$status" -eq 0 ]
    grep -Fx "/etc/systemd/system/octoshield-monitor.service|$OCTOSHIELD_ROOT/systemd/octoshield-monitor.service" "$TEST_CALLS"
    grep -Fx "/etc/systemd/user/octoshield-notify.service|$OCTOSHIELD_ROOT/systemd/octoshield-notify.service" "$TEST_CALLS"
    [ "$(wc -l <"$TEST_CALLS")" -eq 2 ]
}

@test 'failed system migration stops before touching the user unit' {
    monitor::migrate_unit() {
        printf '%s\n' "$1" >>"$TEST_CALLS"
        return 1
    }
    run monitor::migrate_units
    [ "$status" -ne 0 ]
    [ "$(cat "$TEST_CALLS")" = '/etc/systemd/system/octoshield-monitor.service' ]
}
