#!/usr/bin/env bats
# SPDX-License-Identifier: Apache-2.0
# Real kernel locks and independent processes exercise admission and recovery.
# Only administrator identity is substituted for unprivileged test runners.
# shellcheck disable=SC2030,SC2031,SC2317,SC2329

setup() {
    source "$BATS_TEST_DIRNAME/../src/lib/core.sh"
    CORE_STATE="$BATS_TEST_TMPDIR/state"
    CORE_PACKAGE_MAINTENANCE="$BATS_TEST_TMPDIR/package-maintenance"
    CORE_TRANSACTION=
    mkdir -m 0700 "$CORE_STATE" "$CORE_STATE/backups"
    LOCKING_PIDS=()
    core::require_root() { :; }
    stat() {
        local metadata
        metadata=$(command stat "$@") || return 1
        case "${2:-}" in
            '%u:%a' | '%u:%a:%h') metadata="0:${metadata#*:}" ;;
        esac
        printf '%s\n' "$metadata"
    }
}

teardown() {
    core::read_end
    core::end
    local pid
    for pid in "${LOCKING_PIDS[@]}"; do
        [[ -n $pid ]] || continue
        kill "$pid" 2>/dev/null || :
        wait "$pid" 2>/dev/null || :
    done
}

locking::wait_for_file() {
    local attempt
    for ((attempt = 0; attempt < 200; attempt++)); do
        [[ -e $1 ]] && return 0
        sleep 0.02
    done
    printf 'Timed out waiting for fixture: %s\n' "$1" >&2
    return 1
}

locking::wait_for_writer() {
    local attempt
    for ((attempt = 0; attempt < 200; attempt++)); do
        if [[ -f $CORE_STATE/lock-admission ]] && ! command flock -n "$CORE_STATE/lock-admission" true; then
            return 0
        fi
        sleep 0.02
    done
    printf 'Writer never acquired the admission gate.\n' >&2
    return 1
}

locking::reap() {
    local pid=$1 result=0 index
    wait "$pid" || result=$?
    for index in "${!LOCKING_PIDS[@]}"; do
        [[ ${LOCKING_PIDS[$index]} != "$pid" ]] || LOCKING_PIDS[index]=
    done
    return "$result"
}

locking::start_reader() {
    mkfifo "$BATS_TEST_TMPDIR/reader-release"
    (
        core::read_begin || exit "$?"
        : >"$BATS_TEST_TMPDIR/reader-ready"
        IFS= read -r _ <"$BATS_TEST_TMPDIR/reader-release"
        core::read_end
    ) >"$BATS_TEST_TMPDIR/reader-output" 2>&1 &
    LOCKING_READER_PID=$!
    LOCKING_PIDS+=("$LOCKING_READER_PID")
    locking::wait_for_file "$BATS_TEST_TMPDIR/reader-ready"
}

locking::release_reader() {
    printf 'finish\n' >"$BATS_TEST_TMPDIR/reader-release"
    locking::reap "$LOCKING_READER_PID"
}

locking::start_writer() {
    (
        local result=0
        core::begin 'Apply fixture profile' || result=$?
        if ((result == 0)); then
            printf 'changed\n' >"$BATS_TEST_TMPDIR/mutation"
            core::end
        fi
        printf '%s\n' "$result" >"$BATS_TEST_TMPDIR/writer-result"
    ) >"$BATS_TEST_TMPDIR/writer-output" 2>&1 &
    LOCKING_WRITER_PID=$!
    LOCKING_PIDS+=("$LOCKING_WRITER_PID")
    locking::wait_for_writer
}

locking::assert_no_transaction() {
    [[ -z $CORE_TRANSACTION ]]
    [[ -z $(find "$CORE_STATE/backups" -mindepth 1 -print -quit) ]]
    [[ ! -e $BATS_TEST_TMPDIR/mutation ]]
}

locking::assert_writer_descriptors_closed() {
    locking::assert_descriptor_closed 6
    locking::assert_descriptor_closed 9
}

locking::assert_descriptor_closed() {
    # Test the descriptor itself, including in containers with a virtual /proc.
    if { : >&"$1"; } 2>/dev/null; then
        printf 'Descriptor %s is unexpectedly open.\n' "$1" >&2
        return 1
    fi
}

@test 'interactive writer automatically proceeds after the current status reader finishes' {
    locking::start_reader
    locking::start_writer
    [[ ! -e $BATS_TEST_TMPDIR/mutation ]]
    [[ ! -e $BATS_TEST_TMPDIR/writer-result ]]
    locking::release_reader
    locking::wait_for_file "$BATS_TEST_TMPDIR/writer-result"
    locking::reap "$LOCKING_WRITER_PID"
    [[ $(cat "$BATS_TEST_TMPDIR/writer-result") == 0 ]]
    [[ $(cat "$BATS_TEST_TMPDIR/mutation") == changed ]]
    command flock -n "$CORE_STATE/lock" true
    command flock -n "$CORE_STATE/lock-admission" true
}

@test 'new readers skip a waiting writer instead of starving the user action' {
    locking::start_reader
    locking::start_writer
    local result=0
    core::read_begin || result=$?
    [[ $result -eq 75 ]]
    locking::assert_descriptor_closed 6
    locking::assert_descriptor_closed 8
    locking::release_reader
    locking::wait_for_file "$BATS_TEST_TMPDIR/writer-result"
    locking::reap "$LOCKING_WRITER_PID"
    [[ $(cat "$BATS_TEST_TMPDIR/writer-result") == 0 ]]
}

@test 'a second writer is declined while the first waits without creating a transaction' {
    locking::start_reader
    locking::start_writer
    local result=0
    core::_begin 0 0.2 'Second change' || result=$?
    [[ $result -eq 75 ]]
    locking::assert_no_transaction
    locking::assert_writer_descriptors_closed
    locking::release_reader
    locking::wait_for_file "$BATS_TEST_TMPDIR/writer-result"
    locking::reap "$LOCKING_WRITER_PID"
    [[ $(cat "$BATS_TEST_TMPDIR/writer-result") == 0 ]]
}

@test 'bounded reader wait expires without mutation or transaction and releases admission' {
    locking::start_reader
    local result=0
    core::_begin 0 0.1 'Timed out change' || result=$?
    [[ $result -eq 75 ]]
    locking::assert_no_transaction
    locking::assert_writer_descriptors_closed
    command flock -n "$CORE_STATE/lock-admission" true
    # The original reader still owns its real kernel lock; it was not killed.
    kill -0 "$LOCKING_READER_PID"
    run command flock -n "$CORE_STATE/lock" true
    [[ $status -eq 1 ]]
    locking::release_reader
    core::begin 'Next change'
    core::end
}

@test 'background transaction acquisition skips busy status without retaining locks' {
    locking::start_reader
    local result=0
    core::try_begin 'Expiry bookkeeping' || result=$?
    [[ $result -eq 75 ]]
    locking::assert_no_transaction
    locking::assert_writer_descriptors_closed
    command flock -n "$CORE_STATE/lock-admission" true
    locking::release_reader
    core::try_begin 'Expiry bookkeeping'
    [[ -n $CORE_TRANSACTION ]]
    core::end
}

@test 'foreground change waits behind active expiry bookkeeping and prevents new background work' {
    mkfifo "$BATS_TEST_TMPDIR/expiry-release"
    (
        core::try_begin 'Reconcile expiry metadata' || exit "$?"
        : >"$BATS_TEST_TMPDIR/expiry-ready"
        IFS= read -r _ <"$BATS_TEST_TMPDIR/expiry-release"
        core::end
    ) >"$BATS_TEST_TMPDIR/expiry-output" 2>&1 &
    local expiry_pid=$! result=0
    LOCKING_PIDS+=("$expiry_pid")
    locking::wait_for_file "$BATS_TEST_TMPDIR/expiry-ready"
    # Bookkeeping excludes mutations through the main lock but leaves the
    # admission gate available for a foreground operation to claim priority.
    command flock -n "$CORE_STATE/lock-admission" true
    run command flock -n "$CORE_STATE/lock" true
    [[ $status -eq 1 ]]
    locking::start_writer
    [[ ! -e $BATS_TEST_TMPDIR/mutation ]]
    [[ ! -e $BATS_TEST_TMPDIR/writer-result ]]
    core::read_begin || result=$?
    [[ $result -eq 75 ]]
    locking::assert_descriptor_closed 8
    result=0
    core::try_begin 'Another background pass' || result=$?
    [[ $result -eq 75 ]]
    [[ -z $CORE_TRANSACTION ]]
    locking::assert_writer_descriptors_closed
    printf 'finish\n' >"$BATS_TEST_TMPDIR/expiry-release"
    locking::reap "$expiry_pid"
    locking::wait_for_file "$BATS_TEST_TMPDIR/writer-result"
    locking::reap "$LOCKING_WRITER_PID"
    [[ $(cat "$BATS_TEST_TMPDIR/writer-result") == 0 ]]
    [[ $(cat "$BATS_TEST_TMPDIR/mutation") == changed ]]
    command flock -n "$CORE_STATE/lock-admission" flock -n "$CORE_STATE/lock" true
}

@test 'package maintenance appearing during the wait prevents the pending change' {
    locking::start_reader
    locking::start_writer
    : >"$CORE_PACKAGE_MAINTENANCE"
    locking::release_reader
    locking::wait_for_file "$BATS_TEST_TMPDIR/writer-result"
    locking::reap "$LOCKING_WRITER_PID"
    [[ $(cat "$BATS_TEST_TMPDIR/writer-result") == 1 ]]
    locking::assert_no_transaction
    command flock -n "$CORE_STATE/lock" true
    command flock -n "$CORE_STATE/lock-admission" true
}

@test 'a crashed reader releases its kernel lock so a queued writer recovers automatically' {
    locking::start_reader
    local inode
    inode=$(command stat -c %i "$CORE_STATE/lock")
    locking::start_writer
    # Only this test's disposable child is terminated, never a system process.
    kill -KILL "$LOCKING_READER_PID"
    locking::reap "$LOCKING_READER_PID" || :
    locking::wait_for_file "$BATS_TEST_TMPDIR/writer-result"
    locking::reap "$LOCKING_WRITER_PID"
    [[ $(cat "$BATS_TEST_TMPDIR/writer-result") == 0 ]]
    [[ $(cat "$BATS_TEST_TMPDIR/mutation") == changed ]]
    [[ $(command stat -c %i "$CORE_STATE/lock") == "$inode" ]]
}

@test 'readers hold only the observation lock and release it explicitly' {
    core::read_begin
    : >&8
    locking::assert_descriptor_closed 6
    command flock -n "$CORE_STATE/lock-admission" true
    run command flock -n "$CORE_STATE/lock" true
    [[ $status -eq 1 ]]
    core::read_end
    locking::assert_descriptor_closed 8
    command flock -n "$CORE_STATE/lock" true
}

@test 'ending a transaction releases both locks and permits another operation in the same process' {
    core::begin 'First change'
    [[ -n $CORE_TRANSACTION ]]
    : >&6
    : >&9
    core::end
    [[ -z $CORE_TRANSACTION ]]
    locking::assert_writer_descriptors_closed
    command flock -n "$CORE_STATE/lock" true
    command flock -n "$CORE_STATE/lock-admission" true
    core::begin 'Second change'
    core::end
}

@test 'transaction directory failure releases both locks in a persistent caller' {
    install() { return 1; }
    local result=0
    core::begin 'Cannot create snapshot' || result=$?
    [[ $result -ne 0 ]]
    locking::assert_no_transaction
    locking::assert_writer_descriptors_closed
    command flock -n "$CORE_STATE/lock" true
    command flock -n "$CORE_STATE/lock-admission" true
    unset -f install
    core::begin 'Recovered change'
    core::end
}

@test 'transaction journal failure releases both locks without leaving an active transaction' {
    core::record() { return 1; }
    local result=0
    core::begin 'Cannot journal change' || result=$?
    [[ $result -ne 0 ]]
    [[ -z $CORE_TRANSACTION ]]
    locking::assert_writer_descriptors_closed
    command flock -n "$CORE_STATE/lock" true
    command flock -n "$CORE_STATE/lock-admission" true
}

@test 'unsafe admission gates are refused by readers and writers without touching referents' {
    local kind result
    printf 'preserved\n' >"$BATS_TEST_TMPDIR/victim"
    chmod 0600 "$BATS_TEST_TMPDIR/victim"
    for kind in symlink hardlink public directory; do
        case "$kind" in
            symlink) ln -s "$BATS_TEST_TMPDIR/victim" "$CORE_STATE/lock-admission" ;;
            hardlink) ln "$BATS_TEST_TMPDIR/victim" "$CORE_STATE/lock-admission" ;;
            public)
                : >"$CORE_STATE/lock-admission"
                chmod 0666 "$CORE_STATE/lock-admission"
                ;;
            directory) mkdir "$CORE_STATE/lock-admission" ;;
        esac
        result=0
        core::read_begin || result=$?
        [[ $result -eq 1 ]]
        result=0
        core::begin 'Unsafe gate' || result=$?
        [[ $result -eq 1 ]]
        [[ $(cat "$BATS_TEST_TMPDIR/victim") == preserved ]]
        locking::assert_no_transaction
        locking::assert_writer_descriptors_closed
        locking::assert_descriptor_closed 8
        if [[ $kind == directory ]]; then rmdir "$CORE_STATE/lock-admission"; else rm "$CORE_STATE/lock-admission"; fi
    done
}

@test 'unsafe main lock is refused by readers and writers without retaining admission' {
    printf 'preserved\n' >"$BATS_TEST_TMPDIR/victim"
    ln -s "$BATS_TEST_TMPDIR/victim" "$CORE_STATE/lock"
    local result=0
    core::read_begin || result=$?
    [[ $result -eq 1 ]]
    result=0
    core::begin 'Unsafe observation lock' || result=$?
    [[ $result -eq 1 ]]
    locking::assert_no_transaction
    locking::assert_writer_descriptors_closed
    locking::assert_descriptor_closed 8
    [[ $(cat "$BATS_TEST_TMPDIR/victim") == preserved ]]
}

@test 'readers skip a legacy exclusive writer and close failed acquisition descriptors' {
    mkfifo "$BATS_TEST_TMPDIR/legacy-release"
    (
        exec 9>"$CORE_STATE/lock"
        chmod 0600 "$CORE_STATE/lock"
        command flock -x 9
        : >"$BATS_TEST_TMPDIR/legacy-ready"
        IFS= read -r _ <"$BATS_TEST_TMPDIR/legacy-release"
    ) >"$BATS_TEST_TMPDIR/legacy-output" 2>&1 &
    local pid=$! result=0
    LOCKING_PIDS+=("$pid")
    locking::wait_for_file "$BATS_TEST_TMPDIR/legacy-ready"
    core::read_begin || result=$?
    [[ $result -eq 75 ]]
    locking::assert_descriptor_closed 6
    locking::assert_descriptor_closed 8
    command flock -n "$CORE_STATE/lock-admission" true
    kill -0 "$pid"
    printf 'finish\n' >"$BATS_TEST_TMPDIR/legacy-release"
    locking::reap "$pid"
}

@test 'supervised inspection kills a stalled TERM-resistant descendant and unblocks the waiting change' {
    ((EUID == 0)) || skip 'the production status daemon requires administrator identity'
    source "$BATS_TEST_DIRNAME/../src/lib/api.sh"
    OCTOSHIELD_ROOT="$BATS_TEST_TMPDIR/collector"
    mkdir -p "$OCTOSHIELD_ROOT/src/lib"
    cp "$BATS_TEST_DIRNAME/../src/status-daemon" "$OCTOSHIELD_ROOT/src/status-daemon"
    cp "$BATS_TEST_DIRNAME/../src/lib/core.sh" "$OCTOSHIELD_ROOT/src/lib/core.sh"
    # Keep the production lock and supervision code. Only the native status
    # probes and absolute installation paths are replaced by private fixtures.
    printf '\nCORE_STATE=%q\nCORE_PACKAGE_MAINTENANCE=%q\n' \
        "$CORE_STATE" "$CORE_PACKAGE_MAINTENANCE" >>"$OCTOSHIELD_ROOT/src/lib/core.sh"
    local module
    for module in controls usb monitor office profiles profile_firewall_verify profile_controls; do
        : >"$OCTOSHIELD_ROOT/src/lib/$module.sh"
    done
    cat >"$OCTOSHIELD_ROOT/src/lib/status.sh" <<'STATUS'
status::refresh() {
    (
        trap '' TERM
        : >"$CORE_STATE/collector-ready"
        IFS= read -r _ <"$CORE_STATE/collector-release"
    ) &
    wait "$!"
}
STATUS
    mkfifo "$CORE_STATE/collector-release"
    printf 'previous verified snapshot\n' >"$CORE_STATE/previous-cache"
    status::refresh() { return 99; }
    cli::status() { : >"$BATS_TEST_TMPDIR/displayed-status"; }
    timeout() {
        # Assert the real caller's production limits, then shorten only this
        # test's deadline. GNU timeout still owns and signals the whole group.
        [[ $1 == --kill-after=3s && $2 == 60s ]] || return 99
        shift 2
        local result=0
        command timeout --kill-after=0.2s 3s "$@" || result=$?
        printf '%s\n' "$result" >"$BATS_TEST_TMPDIR/timeout-result"
        return "$result"
    }
    (
        result=0
        api::inspect || result=$?
        printf '%s\n' "$result" >"$BATS_TEST_TMPDIR/inspection-result"
    ) >"$BATS_TEST_TMPDIR/inspection-output" 2>&1 &
    local inspection_pid=$! inode
    LOCKING_PIDS+=("$inspection_pid")
    locking::wait_for_file "$CORE_STATE/collector-ready"
    inode=$(command stat -c %i "$CORE_STATE/lock")
    locking::start_writer
    [[ ! -e $BATS_TEST_TMPDIR/mutation ]]
    locking::wait_for_file "$BATS_TEST_TMPDIR/writer-result"
    locking::wait_for_file "$BATS_TEST_TMPDIR/inspection-result"
    locking::reap "$LOCKING_WRITER_PID"
    locking::reap "$inspection_pid"
    # TERM alone cannot release the descendant's inherited SH lock. Exit 137
    # proves the real supervisor escalated to KILL before the writer continued.
    [[ $(cat "$BATS_TEST_TMPDIR/timeout-result") == 137 ]]
    [[ $(cat "$BATS_TEST_TMPDIR/inspection-result") == 1 ]]
    [[ $(cat "$BATS_TEST_TMPDIR/writer-result") == 0 ]]
    [[ $(cat "$BATS_TEST_TMPDIR/mutation") == changed ]]
    [[ $(cat "$CORE_STATE/previous-cache") == 'previous verified snapshot' ]]
    [[ ! -e $BATS_TEST_TMPDIR/displayed-status ]]
    [[ $(command stat -c %i "$CORE_STATE/lock") == "$inode" ]]
    command flock -n "$CORE_STATE/lock" true
    command flock -n "$CORE_STATE/lock-admission" true
}

@test 'persistent root CLI releases transaction locks after successful and failed actions' {
    ((EUID == 0)) || skip 'the persistent administrator menu runs as root'
    source "$BATS_TEST_DIRNAME/../src/lib/cli.sh"
    source "$BATS_TEST_DIRNAME/../src/lib/api.sh"
    core::require_local() { :; }
    core::supported_os() { :; }
    api::dispatch() {
        [[ -n $CORE_TRANSACTION ]] || return 99
        : >&6
        : >&9
        return "$LOCKING_DISPATCH_RESULT"
    }
    local expected result
    for expected in 0 23; do
        LOCKING_DISPATCH_RESULT=$expected
        result=0
        # Call directly, without Bats run or a subshell: the menu process must
        # remain alive, with no lock retained, after either dispatch outcome.
        cli::system apply firewall || result=$?
        [[ $result -eq $expected ]]
        [[ -z $CORE_TRANSACTION ]]
        locking::assert_writer_descriptors_closed
        command flock -n "$CORE_STATE/lock-admission" flock -n "$CORE_STATE/lock" true
        core::read_begin
        core::read_end
    done
}

locking::stage_after_change_collector() {
    OCTOSHIELD_ROOT="$BATS_TEST_TMPDIR/after-change-collector"
    mkdir -p "$OCTOSHIELD_ROOT/src/lib"
    cp "$BATS_TEST_DIRNAME/../src/status-daemon" "$OCTOSHIELD_ROOT/src/status-daemon"
    cp "$BATS_TEST_DIRNAME/../src/lib/core.sh" "$OCTOSHIELD_ROOT/src/lib/core.sh"
    printf '\nCORE_STATE=%q\nCORE_PACKAGE_MAINTENANCE=%q\n' \
        "$CORE_STATE" "$CORE_PACKAGE_MAINTENANCE" >>"$OCTOSHIELD_ROOT/src/lib/core.sh"
    local module
    for module in controls usb monitor office profiles profile_firewall_verify profile_controls; do
        : >"$OCTOSHIELD_ROOT/src/lib/$module.sh"
    done
    # Keep the real worker, descriptor validation and timeout invocation. Only
    # system observations are replaced; no host policy or cache is inspected.
    cat >"$OCTOSHIELD_ROOT/src/lib/status.sh" <<'STATUS'
status::_fixture_observe() {
    # Reopening either inode must conflict with the inherited exclusive lock.
    if flock --exclusive --nonblock "$CORE_STATE/lock-admission" true ||
        flock --exclusive --nonblock "$CORE_STATE/lock" true; then return 99; fi
    printf '%s\n' "$1" >>"$CORE_STATE/observations"
}
status::refresh() { status::_fixture_observe full; }
status::refresh_usb() { status::_fixture_observe usb; }
STATUS
}

@test 'after-change full and USB workers validate inherited locks without releasing the parent transaction' {
    ((EUID == 0)) || skip 'the production status daemon requires administrator identity'
    locking::stage_after_change_collector
    core::begin 'Observe completed change'
    local transaction=$CORE_TRANSACTION mode
    for mode in full usb; do
        run core::refresh_status "$mode"
        [[ $status -eq 0 ]]
        [[ $CORE_TRANSACTION == "$transaction" ]]
        : >&6
        : >&9
        run command flock -n "$CORE_STATE/lock-admission" true
        [[ $status -eq 1 ]]
        run command flock -n "$CORE_STATE/lock" true
        [[ $status -eq 1 ]]
    done
    [[ $(cat "$CORE_STATE/observations") == $'full\nusb' ]]
    core::end
    command flock -n "$CORE_STATE/lock-admission" flock -n "$CORE_STATE/lock" true
}

@test 'after-change workers refuse missing or unrelated inherited descriptors before observation' {
    ((EUID == 0)) || skip 'the production status daemon requires administrator identity'
    locking::stage_after_change_collector
    run /bin/bash -c 'exec 6>&- 9>&-; exec /bin/bash -p "$1" --after-change full' _ "$OCTOSHIELD_ROOT/src/status-daemon"
    [[ $status -ne 0 ]]
    [[ ! -e $CORE_STATE/observations ]]
    core::begin 'Validate completed change observation'
    local descriptor
    for descriptor in 6 9; do
        run /bin/bash -c '
            case "$2" in
                6) exec 6>>"$3/unrelated" ;;
                9) exec 9>>"$3/unrelated" ;;
            esac
            exec /bin/bash -p "$1" --after-change usb
        ' _ "$OCTOSHIELD_ROOT/src/status-daemon" "$descriptor" "$CORE_STATE"
        [[ $status -ne 0 ]]
        [[ ! -e $CORE_STATE/observations ]]
        run command flock -n "$CORE_STATE/lock-admission" true
        [[ $status -eq 1 ]]
        run command flock -n "$CORE_STATE/lock" true
        [[ $status -eq 1 ]]
    done
    core::end
    command flock -n "$CORE_STATE/lock-admission" flock -n "$CORE_STATE/lock" true
}
