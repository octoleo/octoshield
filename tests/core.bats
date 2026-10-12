#!/usr/bin/env bats
# SPDX-License-Identifier: Apache-2.0
# Bats isolates each test and invokes these command mocks indirectly.
# shellcheck disable=SC2030,SC2031,SC2317,SC2329

setup() {
    source "$BATS_TEST_DIRNAME/../src/lib/core.sh"
    CORE_STATE="$BATS_TEST_TMPDIR/state"
    CORE_TRANSACTION=test-transaction
    CORE_PACKAGE_MAINTENANCE="$BATS_TEST_TMPDIR/package-maintenance"
    mkdir -p "$CORE_STATE/backups/$CORE_TRANSACTION/original"
    chmod 0700 "$CORE_STATE" "$CORE_STATE/backups"
    # Ownership changes are privileged in production; all paths here are fixtures.
    chown() { :; }
}

@test 'package maintenance refuses a root operation before creating its transaction' {
    core::require_root() { :; }
    CORE_TRANSACTION=
    : >"$CORE_PACKAGE_MAINTENANCE"
    run core::begin 'must not start'
    [ "$status" -ne 0 ]
    [[ $output == *'package update or removal is in progress'* ]]
    [ ! -e "$CORE_STATE/lock" ]
    [ -z "$CORE_TRANSACTION" ]
}

@test 'maintenance starting between first check and operation lock is refused' {
    core::require_root() { :; }
    install() { mkdir -p "$CORE_STATE" "$CORE_STATE/backups"; }
    flock() {
        command flock "$@" || return 1
        : >"$CORE_PACKAGE_MAINTENANCE"
    }
    CORE_TRANSACTION=
    local result=0
    core::begin 'must not start' || result=$?
    [ "$result" -ne 0 ]
    [ -z "$CORE_TRANSACTION" ]
    # The declined operation must release its lock even in a persistent caller.
    command flock -n "$CORE_STATE/lock" true
}

@test 'package maintenance symlink also fails closed' {
    ln -s "$BATS_TEST_TMPDIR/nonexistent" "$CORE_PACKAGE_MAINTENANCE"
    run core::package_available
    [ "$status" -ne 0 ]
}

@test 'operation refuses linked backup or lock targets before touching their contents' {
    core::require_root() { :; }
    local victim="$BATS_TEST_TMPDIR/victim"
    printf 'keep\n' >"$victim"
    ln -s "$victim" "$CORE_STATE/lock"
    run core::begin unsafe-lock
    [ "$status" -ne 0 ]
    [ "$(cat "$victim")" = keep ]
    rm "$CORE_STATE/lock"
    mv "$CORE_STATE/backups" "$CORE_STATE/original-backups"
    ln -s "$CORE_STATE/original-backups" "$CORE_STATE/backups"
    run core::begin unsafe-backups
    [ "$status" -ne 0 ]
    [ ! -e "$CORE_STATE/lock" ]
}

@test 'operation refuses shared locks and nonprivate state' {
    core::require_root() { :; }
    printf 'keep\n' >"$BATS_TEST_TMPDIR/victim"
    chmod 0600 "$BATS_TEST_TMPDIR/victim"
    ln "$BATS_TEST_TMPDIR/victim" "$CORE_STATE/lock"
    run core::begin shared-lock
    [ "$status" -ne 0 ]
    [ "$(cat "$BATS_TEST_TMPDIR/victim")" = keep ]
    rm "$CORE_STATE/lock"
    chmod 0777 "$CORE_STATE"
    run core::begin unsafe-directory
    [ "$status" -ne 0 ]
    [ ! -e "$CORE_STATE/lock" ]
}

@test 'modules have no side effects when sourced' {
    run bash -c 'source "$1"; [[ -z $CORE_TRANSACTION && $CORE_STATE == /var/lib/octoshield ]]' _ "$BATS_TEST_DIRNAME/../src/lib/core.sh"
    [ "$status" -eq 0 ]
}

@test 'backup preserves the first file value within a transaction' {
    local file="$BATS_TEST_TMPDIR/config"
    printf 'original' >"$file"
    chmod 0640 "$file"
    core::backup "$file"
    printf 'changed' >"$file"
    core::backup "$file"
    [ "$(cat "$CORE_STATE/backups/$CORE_TRANSACTION/original$file")" = original ]
    [ "$(stat -c %a "$CORE_STATE/backups/$CORE_TRANSACTION/original$file")" = 640 ]
}

@test 'backup records absent targets separately from empty files' {
    local file="$BATS_TEST_TMPDIR/absent"
    core::backup "$file"
    [ "$(cat "$CORE_STATE/backups/$CORE_TRANSACTION/saved$file")" = absent ]
    [ ! -e "$CORE_STATE/backups/$CORE_TRANSACTION/original$file" ]
}

@test 'backup copies directory trees and preserves symlinks' {
    mkdir "$BATS_TEST_TMPDIR/configs"
    printf secret >"$BATS_TEST_TMPDIR/configs/key"
    ln -s key "$BATS_TEST_TMPDIR/configs/link"
    core::backup "$BATS_TEST_TMPDIR/configs"
    [ "$(cat "$CORE_STATE/backups/$CORE_TRANSACTION/original$BATS_TEST_TMPDIR/configs/key")" = secret ]
    [ "$(readlink "$CORE_STATE/backups/$CORE_TRANSACTION/original$BATS_TEST_TMPDIR/configs/link")" = key ]
}

@test 'backup refuses traversal and missing transaction' {
    run core::backup /etc/../tmp/path
    [ "$status" -ne 0 ]
    CORE_TRANSACTION=
    run core::backup "$BATS_TEST_TMPDIR/config"
    [ "$status" -ne 0 ]
}

@test 'atomic writes keep previous bytes and specified permissions' {
    local file="$BATS_TEST_TMPDIR/config"
    printf 'old' >"$file"
    printf 'new\n' | core::write_file "$file" 0600
    [ "$(cat "$file")" = new ]
    [ "$(stat -c %a "$file")" = 600 ]
    [ "$(cat "$CORE_STATE/backups/$CORE_TRANSACTION/original$file")" = old ]
}

@test 'atomic writer does not relax existing sensitive directory permissions' {
    mkdir -m 0700 "$BATS_TEST_TMPDIR/private"
    printf secret | core::write_file "$BATS_TEST_TMPDIR/private/config" 0600
    [ "$(stat -c %a "$BATS_TEST_TMPDIR/private")" = 700 ]
}

@test 'failed atomic rename leaves original untouched and cleans staging file' {
    local file="$BATS_TEST_TMPDIR/config"
    printf 'old' >"$file"
    mv() { return 1; }
    run core::write_file "$file" 0600 <<<new
    [ "$status" -ne 0 ]
    [ "$(cat "$file")" = old ]
    [ -z "$(find "$BATS_TEST_TMPDIR" -name '.octoshield.*' -print)" ]
}

@test 'writer refuses symlink targets and never modifies their referent' {
    printf 'old' >"$BATS_TEST_TMPDIR/real"
    ln -s real "$BATS_TEST_TMPDIR/link"
    run core::write_file "$BATS_TEST_TMPDIR/link" 0600 <<<new
    [ "$status" -ne 0 ]
    [ "$(cat "$BATS_TEST_TMPDIR/real")" = old ]
}

@test 'package installer skips installed packages' {
    dpkg-query() { printf 'install ok installed'; }
    apt-get() {
        printf 'unexpected apt'
        return 88
    }
    run core::install_packages ufw
    [ "$status" -eq 0 ]
    [[ $output != *'unexpected apt'* ]]
}

@test 'package installer updates once and passes packages as separate arguments' {
    dpkg-query() { return 1; }
    apt-get() { printf '%s\n' "$*" >>"$BATS_TEST_TMPDIR/apt"; }
    core::install_packages ufw usbguard
    core::install_packages jq
    [ "$(cat "$BATS_TEST_TMPDIR/apt")" = $'update\ninstall --yes --no-install-recommends ufw usbguard\ninstall --yes --no-install-recommends jq' ]
}

@test 'package index failure prevents package install' {
    dpkg-query() { return 1; }
    apt-get() {
        printf '%s\n' "$*" >>"$BATS_TEST_TMPDIR/apt"
        return 1
    }
    run core::install_packages ufw
    [ "$status" -ne 0 ]
    [ "$(cat "$BATS_TEST_TMPDIR/apt")" = update ]
}

@test 'package arguments cannot inject apt options' {
    run core::install_packages --allow-unauthenticated
    [ "$status" -ne 0 ]
}

@test 'local mutation guard rejects SSH and unattended execution' {
    SSH_CONNECTION='192.0.2.1 123 192.0.2.2 22' run core::require_local
    [ "$status" -ne 0 ]
    [[ $output == *'not through SSH'* ]]
    unset SSH_CONNECTION SSH_CLIENT SSH_TTY
    run core::require_local
    [ "$status" -ne 0 ]
}
