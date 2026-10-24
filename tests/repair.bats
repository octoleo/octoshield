#!/usr/bin/env bats
# SPDX-License-Identifier: Apache-2.0
# Native files and recovery snapshots live entirely below BATS_TEST_TMPDIR.
# visudo is substituted here; tests/repair-integration.sh checks native sudo/PAM.
# Bats invokes setup and function substitutions indirectly.
# shellcheck disable=SC2030,SC2031,SC2317,SC2329

setup() {
    ((EUID == 0)) || skip 'repair trust-boundary fixtures require real root ownership'
    source "$BATS_TEST_DIRNAME/../src/lib/core.sh"
    source "$BATS_TEST_DIRNAME/../src/lib/repair.sh"
    umask 077
    REPAIR_ETC="$BATS_TEST_TMPDIR/etc"
    CORE_STATE="$BATS_TEST_TMPDIR/state"
    CORE_TRANSACTION=20261231T235959Z-999
    CORE_PACKAGE_MAINTENANCE="$BATS_TEST_TMPDIR/package-maintenance"
    REPAIR_TEST_FILE="$REPAIR_ETC/sudoers.d/99-octoshield"
    REPAIR_TEST_CALLS="$BATS_TEST_TMPDIR/calls"
    REPAIR_TEST_CONFIRM=yes
    REPAIR_TEST_VISUDO_FAIL=
    install -d -m 0755 "$REPAIR_ETC" "$REPAIR_ETC/sudoers.d"
    install -d -m 0700 "$CORE_STATE" "$CORE_STATE/backups" "$CORE_STATE/backups/$CORE_TRANSACTION/original"
    : >"$REPAIR_TEST_CALLS"
    core::record 'BEGIN repair'
    core::confirm() {
        printf 'confirm %s\n' "$*" >>"$REPAIR_TEST_CALLS"
        [[ $REPAIR_TEST_CONFIRM == yes ]]
    }
    visudo() {
        printf 'visudo %s\n' "$*" >>"$REPAIR_TEST_CALLS"
        case "$REPAIR_TEST_VISUDO_FAIL" in
            before) return 1 ;;
            after-removal) [[ -e $REPAIR_TEST_FILE ]] || return 1 ;;
            invalid-original)
                if [[ -f $REPAIR_TEST_FILE ]] && grep -q 'BROKEN-POLICY' "$REPAIR_TEST_FILE"; then return 1; fi
                local argument
                for argument in "$@"; do
                    [[ -f $argument ]] || continue
                    if grep -q 'BROKEN-POLICY' "$argument"; then return 1; fi
                done
                ;;
        esac
    }
}

repair_test::generated() {
    printf '# Managed by Octoshield; passwordless grants still bypass passwords.\nDefaults timestamp_timeout=0\n'
}

repair_test::install_generated() {
    rm -f "$REPAIR_TEST_FILE"
    repair_test::generated >"$REPAIR_TEST_FILE"
    chmod 0440 "$REPAIR_TEST_FILE"
}

repair_test::snapshot() {
    local id=$1 marker=$2 contents=${3-} directory="$CORE_STATE/backups/$1"
    install -d -m 0700 "$directory/saved${REPAIR_TEST_FILE%/*}" "$directory/original${REPAIR_TEST_FILE%/*}"
    printf '2026-01-01T00:00:00Z BEGIN apply sudo\n' >"$directory/actions.log"
    printf '%s\n' "$marker" >"$directory/saved$REPAIR_TEST_FILE"
    if [[ $marker == existing ]]; then
        printf '%s' "$contents" >"$directory/original$REPAIR_TEST_FILE"
        chmod 0440 "$directory/original$REPAIR_TEST_FILE"
    fi
}

repair_test::state() {
    local observation
    observation=$(repair::status) || return 1
    jq -e --arg expected "$1" '.state == $expected and (.summary | type == "string" and length <= 1024)' <<<"$observation"
}

@test 'sourcing repair discards an inherited path override and performs no system work' {
    # shellcheck disable=SC2016 # The clean child shell must expand its own values.
    run env REPAIR_ETC="$BATS_TEST_TMPDIR/untrusted" bash -c '
        source "$1"
        [[ $REPAIR_ETC == /etc ]]
    ' _ "$BATS_TEST_DIRNAME/../src/lib/repair.sh"
    [ "$status" -eq 0 ]
    [ -z "$output" ]
    [ ! -s "$REPAIR_TEST_CALLS" ]
}

@test 'no legacy policy is an active no-op without consent or a configuration backup' {
    repair_test::state active
    run repair::run
    [ "$status" -eq 0 ]
    [ ! -e "$REPAIR_TEST_FILE" ]
    [ ! -e "$CORE_STATE/backups/$CORE_TRANSACTION/saved$REPAIR_TEST_FILE" ]
    run grep -q '^confirm ' "$REPAIR_TEST_CALLS"
    [ "$status" -eq 1 ]
}

@test 'exact generated policy is reported pending and requires administrator authority' {
    repair_test::install_generated
    repair_test::state partial
    core::require_root() { return 1; }
    run repair::run
    [ "$status" -ne 0 ]
    cmp "$REPAIR_TEST_FILE" <(repair_test::generated)
    [ ! -s "$REPAIR_TEST_CALLS" ]
}

@test 'repair refuses a mutation without an active core transaction' {
    repair_test::install_generated
    CORE_TRANSACTION=
    run repair::run
    [ "$status" -ne 0 ]
    cmp "$REPAIR_TEST_FILE" <(repair_test::generated)
}

@test 'recognized generated policy without an original snapshot can be reviewed and removed' {
    repair_test::install_generated
    run repair::run
    [ "$status" -eq 0 ]
    [ ! -e "$REPAIR_TEST_FILE" ]
    grep -q '^confirm ' "$REPAIR_TEST_CALLS"
    cmp "$CORE_STATE/backups/$CORE_TRANSACTION/original$REPAIR_TEST_FILE" <(repair_test::generated)
    [ "$(cat "$CORE_STATE/backups/$CORE_TRANSACTION/saved$REPAIR_TEST_FILE")" = existing ]
    repair_test::state active
}

@test 'recorded original absence removes only the generated OctoShield drop-in' {
    repair_test::snapshot 20260101T010000Z-101 absent
    repair_test::install_generated
    printf 'Defaults timestamp_timeout=11\n' >"$REPAIR_ETC/sudoers.d/20-independent"
    local original
    original=$(sha256sum "$REPAIR_ETC/sudoers.d/20-independent")
    run repair::run
    [ "$status" -eq 0 ]
    [ ! -e "$REPAIR_TEST_FILE" ]
    [ "$(sha256sum "$REPAIR_ETC/sudoers.d/20-independent")" = "$original" ]
}

@test 'repeated activations are traced through generated snapshots to original absence' {
    repair_test::snapshot 20260101T010000Z-101 absent
    repair_test::snapshot 20260101T020000Z-102 existing "$(repair_test::generated)"$'\n'
    repair_test::snapshot 20260101T030000Z-103 existing "$(repair_test::generated)"$'\n'
    repair_test::install_generated
    run repair::run
    [ "$status" -eq 0 ]
    [ ! -e "$REPAIR_TEST_FILE" ]
    repair_test::state active
}

@test 'repeated activations restore the most recent genuine original policy byte for byte' {
    local original=$'# Existing local policy.\nDefaults timestamp_timeout=7\n'
    repair_test::snapshot 20260101T010000Z-101 absent
    repair_test::snapshot 20260102T010000Z-201 existing "$original"
    repair_test::snapshot 20260102T020000Z-202 existing "$(repair_test::generated)"$'\n'
    repair_test::install_generated
    run repair::run
    [ "$status" -eq 0 ]
    cmp "$REPAIR_TEST_FILE" <(printf '%s' "$original")
    [ "$(stat -c '%u:%a' "$REPAIR_TEST_FILE")" = 0:440 ]
    [ "$(stat -c '%u:%a' "$CORE_STATE/repairs/legacy-sudo-timeout-v1.json")" = 0:600 ]
    repair_test::state active
}

@test 'cancelling the reviewed repair preserves native policy and creates no repair receipt' {
    repair_test::snapshot 20260101T010000Z-101 absent
    repair_test::install_generated
    REPAIR_TEST_CONFIRM=no
    run repair::run
    [ "$status" -ne 0 ]
    cmp "$REPAIR_TEST_FILE" <(repair_test::generated)
    [ ! -e "$CORE_STATE/backups/$CORE_TRANSACTION/saved$REPAIR_TEST_FILE" ]
    [ ! -e "$CORE_STATE/repairs/legacy-sudo-timeout-v1.json" ]
}

@test 'modified drop-in is a conflict and is never overwritten even with consent' {
    repair_test::install_generated
    chmod 0640 "$REPAIR_TEST_FILE"
    printf 'Defaults timestamp_timeout=9\n' >>"$REPAIR_TEST_FILE"
    chmod 0440 "$REPAIR_TEST_FILE"
    local original
    original=$(sha256sum "$REPAIR_TEST_FILE")
    repair_test::state unknown
    run repair::run
    [ "$status" -ne 0 ]
    [ "$(sha256sum "$REPAIR_TEST_FILE")" = "$original" ]
    [ ! -e "$CORE_STATE/backups/$CORE_TRANSACTION/saved$REPAIR_TEST_FILE" ]
}

@test 'symlink hardlink and writable generated policies are conflicts without following them' {
    local kind target="$BATS_TEST_TMPDIR/external"
    repair_test::generated >"$target"
    chmod 0440 "$target"
    for kind in symlink hardlink writable; do
        case "$kind" in
            symlink) ln -s "$target" "$REPAIR_TEST_FILE" ;;
            hardlink) ln "$target" "$REPAIR_TEST_FILE" ;;
            writable)
                repair_test::install_generated
                chmod 0666 "$REPAIR_TEST_FILE"
                ;;
        esac
        repair_test::state unknown
        run repair::run
        [ "$status" -ne 0 ]
        cmp "$target" <(repair_test::generated)
        rm "$REPAIR_TEST_FILE"
    done
}

@test 'a linked sudoers directory cannot redirect a repair outside its fixed path' {
    rmdir "$REPAIR_ETC/sudoers.d"
    mkdir "$BATS_TEST_TMPDIR/external"
    ln -s "$BATS_TEST_TMPDIR/external" "$REPAIR_ETC/sudoers.d"
    repair_test::install_generated
    repair_test::state unknown
    run repair::run
    [ "$status" -ne 0 ]
    cmp "$BATS_TEST_TMPDIR/external/99-octoshield" <(repair_test::generated)
}

@test 'an existing marker without its saved original refuses repair instead of assuming absence' {
    repair_test::snapshot 20260101T010000Z-101 existing 'lost original'
    rm "$CORE_STATE/backups/20260101T010000Z-101/original$REPAIR_TEST_FILE"
    repair_test::install_generated
    repair_test::state partial
    run repair::run
    [ "$status" -ne 0 ]
    cmp "$REPAIR_TEST_FILE" <(repair_test::generated)
}

@test 'a malformed snapshot marker refuses repair without destroying current policy' {
    repair_test::snapshot 20260101T010000Z-101 'not-a-backup-marker'
    repair_test::install_generated
    repair_test::state partial
    run repair::run
    [ "$status" -ne 0 ]
    cmp "$REPAIR_TEST_FILE" <(repair_test::generated)
}

@test 'unsafe saved originals are never installed by repair' {
    local original=$'Defaults timestamp_timeout=7\n'
    repair_test::snapshot 20260101T010000Z-101 existing "$original"
    local saved="$CORE_STATE/backups/20260101T010000Z-101/original$REPAIR_TEST_FILE"
    chmod 0666 "$saved"
    repair_test::install_generated
    repair_test::state partial
    run repair::run
    [ "$status" -ne 0 ]
    cmp "$REPAIR_TEST_FILE" <(repair_test::generated)
}

@test 'a linked historical marker is refused even when its text says absent' {
    repair_test::snapshot 20260101T010000Z-101 absent
    local marker="$CORE_STATE/backups/20260101T010000Z-101/saved$REPAIR_TEST_FILE"
    mv "$marker" "$BATS_TEST_TMPDIR/external-marker"
    ln -s "$BATS_TEST_TMPDIR/external-marker" "$marker"
    repair_test::install_generated
    repair_test::state partial
    run repair::run
    [ "$status" -ne 0 ]
    cmp "$REPAIR_TEST_FILE" <(repair_test::generated)
}

@test 'native validation failure before repair does not mutate or record success' {
    repair_test::install_generated
    REPAIR_TEST_VISUDO_FAIL=before
    run repair::run
    [ "$status" -ne 0 ]
    cmp "$REPAIR_TEST_FILE" <(repair_test::generated)
    [ ! -e "$CORE_STATE/repairs/legacy-sudo-timeout-v1.json" ]
}

@test 'invalid saved policy is refused before consent or installation into the live path' {
    repair_test::snapshot 20260101T010000Z-101 existing $'BROKEN-POLICY\n'
    repair_test::install_generated
    REPAIR_TEST_VISUDO_FAIL=invalid-original
    run repair::run
    [ "$status" -ne 0 ]
    cmp "$REPAIR_TEST_FILE" <(repair_test::generated)
    [ ! -e "$CORE_STATE/backups/$CORE_TRANSACTION/saved$REPAIR_TEST_FILE" ]
    [ ! -e "$CORE_STATE/repairs/legacy-sudo-timeout-v1.json" ]
    run grep -q '^confirm ' "$REPAIR_TEST_CALLS"
    [ "$status" -eq 1 ]
}

@test 'failed native validation after removal restores the generated policy and reports failure' {
    repair_test::snapshot 20260101T010000Z-101 absent
    repair_test::install_generated
    REPAIR_TEST_VISUDO_FAIL=after-removal
    run repair::run
    [ "$status" -ne 0 ]
    cmp "$REPAIR_TEST_FILE" <(repair_test::generated)
    [ ! -e "$CORE_STATE/repairs/legacy-sudo-timeout-v1.json" ]
}

@test 'a matching restored original is re-inspected as active and repeated repair does not rewrite it' {
    local original=$'# Retain this policy.\nDefaults timestamp_timeout=7\n'
    repair_test::snapshot 20260101T010000Z-101 existing "$original"
    repair_test::install_generated
    repair::run
    local inode
    inode=$(stat -c '%i' "$REPAIR_TEST_FILE")
    : >"$REPAIR_TEST_CALLS"
    run repair::run
    [ "$status" -eq 0 ]
    [ "$(stat -c '%i' "$REPAIR_TEST_FILE")" = "$inode" ]
    cmp "$REPAIR_TEST_FILE" <(printf '%s' "$original")
    run grep -q '^confirm ' "$REPAIR_TEST_CALLS"
    [ "$status" -eq 1 ]
    repair_test::state active
}

@test 'a changed restored original invalidates the receipt and is preserved for review' {
    repair_test::snapshot 20260101T010000Z-101 existing $'Defaults timestamp_timeout=7\n'
    repair_test::install_generated
    repair::run
    chmod 0640 "$REPAIR_TEST_FILE"
    printf 'Defaults timestamp_timeout=8\n' >"$REPAIR_TEST_FILE"
    chmod 0440 "$REPAIR_TEST_FILE"
    repair_test::state unknown
    run repair::run
    [ "$status" -ne 0 ]
    [ "$(cat "$REPAIR_TEST_FILE")" = 'Defaults timestamp_timeout=8' ]
}

@test 'reintroduced generated policy is detected even after a successful repair receipt' {
    repair_test::snapshot 20260101T010000Z-101 existing $'Defaults timestamp_timeout=7\n'
    repair_test::install_generated
    repair::run
    repair_test::install_generated
    repair_test::state partial
    run repair::run
    [ "$status" -eq 0 ]
    [ "$(cat "$REPAIR_TEST_FILE")" = 'Defaults timestamp_timeout=7' ]
    repair_test::state active
}

@test 'a writable receipt cannot authorize a custom current policy as repaired' {
    repair_test::snapshot 20260101T010000Z-101 existing $'Defaults timestamp_timeout=7\n'
    repair_test::install_generated
    repair::run
    chmod 0666 "$CORE_STATE/repairs/legacy-sudo-timeout-v1.json"
    repair_test::state unknown
    run repair::run
    [ "$status" -ne 0 ]
    [ "$(cat "$REPAIR_TEST_FILE")" = 'Defaults timestamp_timeout=7' ]
}

@test 'repair runs under an actual core transaction and releases its native lock afterward' {
    repair_test::snapshot 20260101T010000Z-101 absent
    repair_test::install_generated
    core::end
    core::begin 'Repair integration fixture'
    run command flock --nonblock "$CORE_STATE/lock" true
    [ "$status" -ne 0 ]
    repair::run
    [ ! -e "$REPAIR_TEST_FILE" ]
    core::end
    command flock --nonblock "$CORE_STATE/lock" true
}

@test 'native policy changed during consent is preserved and stops the repair' {
    repair_test::snapshot 20260101T010000Z-101 absent
    repair_test::install_generated
    core::confirm() {
        chmod 0640 "$REPAIR_TEST_FILE"
        printf 'Defaults timestamp_timeout=9\n' >"$REPAIR_TEST_FILE"
        chmod 0440 "$REPAIR_TEST_FILE"
    }
    run repair::run
    [ "$status" -ne 0 ]
    [ "$(cat "$REPAIR_TEST_FILE")" = 'Defaults timestamp_timeout=9' ]
    [ ! -e "$CORE_STATE/backups/$CORE_TRANSACTION/saved$REPAIR_TEST_FILE" ]
}

@test 'original recovery evidence changed during consent stops the repair' {
    repair_test::snapshot 20260101T010000Z-101 existing $'Defaults timestamp_timeout=7\n'
    repair_test::install_generated
    core::confirm() {
        local saved="$CORE_STATE/backups/20260101T010000Z-101/original$REPAIR_TEST_FILE"
        chmod 0640 "$saved"
        printf 'Defaults timestamp_timeout=8\n' >"$saved"
        chmod 0440 "$saved"
    }
    run repair::run
    [ "$status" -ne 0 ]
    cmp "$REPAIR_TEST_FILE" <(repair_test::generated)
    [ ! -e "$CORE_STATE/backups/$CORE_TRANSACTION/saved$REPAIR_TEST_FILE" ]
}

@test 'failed repair receipt persistence rolls the native policy back and does not report success' {
    repair_test::snapshot 20260101T010000Z-101 absent
    repair_test::install_generated
    mv() {
        [[ ${!#} != "$CORE_STATE/repairs/legacy-sudo-timeout-v1.json" ]] || return 1
        command mv "$@"
    }
    run repair::run
    [ "$status" -ne 0 ]
    cmp "$REPAIR_TEST_FILE" <(repair_test::generated)
    [ ! -e "$CORE_STATE/repairs/legacy-sudo-timeout-v1.json" ]
}

@test 'live policy edited after the repair begin record is preserved before native mutation' {
    repair_test::snapshot 20260101T010000Z-101 absent
    repair_test::install_generated
    core::record() {
        printf 'record %s\n' "$*" >>"$REPAIR_TEST_CALLS"
        if [[ $* == 'REPAIR legacy-sudo-timeout-v1 begin '* ]]; then
            chmod 0640 "$REPAIR_TEST_FILE"
            printf 'Defaults timestamp_timeout=9\n' >"$REPAIR_TEST_FILE"
            chmod 0440 "$REPAIR_TEST_FILE"
        fi
    }
    run repair::run
    [ "$status" -ne 0 ]
    grep -q '^record REPAIR legacy-sudo-timeout-v1 begin ' "$REPAIR_TEST_CALLS"
    [ "$(cat "$REPAIR_TEST_FILE")" = 'Defaults timestamp_timeout=9' ]
    cmp "$CORE_STATE/backups/$CORE_TRANSACTION/original$REPAIR_TEST_FILE" <(repair_test::generated)
    [ ! -e "$CORE_STATE/repairs/legacy-sudo-timeout-v1.json" ]
}

@test 'original policy changed during candidate copying is refused before consent or live backup' {
    repair_test::snapshot 20260101T010000Z-101 existing $'Defaults timestamp_timeout=7\n'
    repair_test::install_generated
    local original="$CORE_STATE/backups/20260101T010000Z-101/original$REPAIR_TEST_FILE"
    cp() {
        if [[ ${1-} == -p && ${2-} == -- && ${3-} == "$original" ]]; then
            chmod 0640 "$original"
            printf 'Defaults timestamp_timeout=8\n' >"$original"
            chmod 0440 "$original"
        fi
        command cp "$@"
    }
    run repair::run
    [ "$status" -ne 0 ]
    [ "$(cat "$original")" = 'Defaults timestamp_timeout=8' ]
    cmp "$REPAIR_TEST_FILE" <(repair_test::generated)
    [ ! -e "$CORE_STATE/backups/$CORE_TRANSACTION/saved$REPAIR_TEST_FILE" ]
    [ ! -e "$CORE_STATE/repairs/legacy-sudo-timeout-v1.json" ]
    run grep -q '^confirm ' "$REPAIR_TEST_CALLS"
    [ "$status" -eq 1 ]
}

@test 'different original policies from the same second and PIDs 9 and 10 refuse recovery' {
    repair_test::snapshot 20260101T010000Z-9 existing $'Defaults timestamp_timeout=7\n'
    repair_test::snapshot 20260101T010000Z-10 existing $'Defaults timestamp_timeout=8\n'
    repair_test::install_generated
    run repair::run
    [ "$status" -ne 0 ]
    cmp "$REPAIR_TEST_FILE" <(repair_test::generated)
    [ ! -e "$CORE_STATE/backups/$CORE_TRANSACTION/saved$REPAIR_TEST_FILE" ]
    run grep -q '^confirm ' "$REPAIR_TEST_CALLS"
    [ "$status" -eq 1 ]
}

@test 'same-second original absence with PID 9 and a custom original with PID 10 are ambiguous' {
    repair_test::snapshot 20260101T010000Z-9 absent
    repair_test::snapshot 20260101T010000Z-10 existing $'Defaults timestamp_timeout=7\n'
    repair_test::install_generated
    run repair::run
    [ "$status" -ne 0 ]
    cmp "$REPAIR_TEST_FILE" <(repair_test::generated)
    [ ! -e "$CORE_STATE/backups/$CORE_TRANSACTION/saved$REPAIR_TEST_FILE" ]
}

@test 'same-second custom original with PID 9 and original absence with PID 10 are ambiguous' {
    repair_test::snapshot 20260101T010000Z-9 existing $'Defaults timestamp_timeout=7\n'
    repair_test::snapshot 20260101T010000Z-10 absent
    repair_test::install_generated
    run repair::run
    [ "$status" -ne 0 ]
    cmp "$REPAIR_TEST_FILE" <(repair_test::generated)
    [ ! -e "$CORE_STATE/backups/$CORE_TRANSACTION/saved$REPAIR_TEST_FILE" ]
}

@test 'identical same-second originals select numeric PID 10 ahead of PID 9' {
    local original=$'Defaults timestamp_timeout=7\n'
    repair_test::snapshot 20260101T010000Z-9 existing "$original"
    repair_test::snapshot 20260101T010000Z-10 existing "$original"
    repair_test::install_generated
    repair::sudo_plan
    [ "$REPAIR_PLAN_BASELINE" = 20260101T010000Z-10 ]
    run repair::run
    [ "$status" -eq 0 ]
    cmp "$REPAIR_TEST_FILE" <(printf '%s' "$original")
    repair_test::state active
}

@test 'multiple JSON documents cannot make a receipt valid through its last object' {
    repair_test::snapshot 20260101T010000Z-101 existing $'Defaults timestamp_timeout=7\n'
    repair_test::install_generated
    repair::run
    local receipt="$CORE_STATE/repairs/legacy-sudo-timeout-v1.json" valid
    valid=$(cat "$receipt")
    printf 'null\n%s\n' "$valid" >"$receipt"
    repair_test::state unknown
    run repair::run
    [ "$status" -ne 0 ]
    [ "$(cat "$REPAIR_TEST_FILE")" = 'Defaults timestamp_timeout=7' ]
    cmp "$receipt" <(printf 'null\n%s\n' "$valid")
}

@test 'a linked activation transaction is rejected instead of treated as missing recovery history' {
    repair_test::snapshot 20260101T010000Z-101 existing $'Defaults timestamp_timeout=7\n'
    local transaction="$CORE_STATE/backups/20260101T010000Z-101"
    mv "$transaction" "$BATS_TEST_TMPDIR/external-transaction"
    ln -s "$BATS_TEST_TMPDIR/external-transaction" "$transaction"
    repair_test::install_generated
    run repair::run
    [ "$status" -ne 0 ]
    cmp "$REPAIR_TEST_FILE" <(repair_test::generated)
    [ ! -e "$CORE_STATE/backups/$CORE_TRANSACTION/saved$REPAIR_TEST_FILE" ]
    run grep -q '^confirm ' "$REPAIR_TEST_CALLS"
    [ "$status" -eq 1 ]
}
