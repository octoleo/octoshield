#!/usr/bin/env bats

# Bats invokes these test-local stubs indirectly and deliberately isolates tests.
# shellcheck disable=SC2317,SC2030,SC2031
setup() {
    # The fake backend is isolated from the user's actual dconf database.
    export XDG_STATE_HOME="$BATS_TEST_TMPDIR/state"
    export DESKTOP_FIXTURE="$BATS_TEST_TMPDIR/gsettings"
    mkdir -p "$DESKTOP_FIXTURE"
    printf '%s\n' 'uint32 600' >"$DESKTOP_FIXTURE/idle-delay"
    printf '%s\n' false >"$DESKTOP_FIXTURE/lock-enabled"
    printf '%s\n' 'uint32 10' >"$DESKTOP_FIXTURE/lock-delay"
    printf '%s\n' true >"$DESKTOP_FIXTURE/disable-lock-screen"
    printf '%s\n' true >"$DESKTOP_FIXTURE/automount"
    printf '%s\n' true >"$DESKTOP_FIXTURE/automount-open"
    printf '%s\n' false >"$DESKTOP_FIXTURE/autorun-never"
    printf '%s\n' true >"$DESKTOP_FIXTURE/rdp-enable"
    printf '%s\n' true >"$DESKTOP_FIXTURE/vnc-enable"
    : >"$DESKTOP_FIXTURE/writes"
    # shellcheck source=../src/lib/desktop.sh
    source "$BATS_TEST_DIRNAME/../src/lib/desktop.sh"
    # Functional tests cover policy and recovery without requiring a real desktop.
    desktop::require_session() { return 0; }
    gsettings() {
        local operation=$1 schema=${2:-} key=${3:-} value=${4:-}
        local fixture_key=$key
        if [[ $schema == org.gnome.desktop.remote-desktop.* ]]; then
            fixture_key="${schema##*.}-$key"
        fi
        case $operation in
            list-schemas)
                printf '%s\n' org.gnome.desktop.session org.gnome.desktop.screensaver org.gnome.desktop.lockdown
                [[ ${MISSING_SCHEMA:-false} == true ]] || printf '%s\n' org.gnome.desktop.media-handling
                if [[ ${OPTIONAL_SHARING:-false} == true ]]; then
                    printf '%s\n' org.gnome.desktop.remote-desktop.rdp org.gnome.desktop.remote-desktop.vnc
                fi
                ;;
            list-keys)
                case $schema in
                    org.gnome.desktop.session) printf '%s\n' idle-delay ;;
                    org.gnome.desktop.screensaver) printf '%s\n' lock-enabled lock-delay ;;
                    org.gnome.desktop.lockdown) printf '%s\n' disable-lock-screen ;;
                    org.gnome.desktop.media-handling)
                        printf '%s\n' automount automount-open
                        [[ ${MISSING_KEY:-false} == true ]] || printf '%s\n' autorun-never
                        ;;
                    org.gnome.desktop.remote-desktop.*)
                        if [[ ${MISSING_SHARING_KEY:-false} != true ]]; then printf '%s\n' enable; fi
                        ;;
                    *) return 1 ;;
                esac
                ;;
            writable)
                if [[ $key == "${LOCKED_KEY:-}" ]]; then printf '%s\n' false; else printf '%s\n' true; fi
                ;;
            get)
                if [[ $key == "${BAD_VALUE_KEY:-}" ]]; then
                    printf '%s\n' "'unexpected string'"
                else
                    cat "$DESKTOP_FIXTURE/$fixture_key"
                fi
                ;;
            set)
                printf '%s\t%s\n' "$key" "$value" >>"$DESKTOP_FIXTURE/writes"
                if [[ $key == "${FAIL_ONCE_KEY:-}" && ! -e $DESKTOP_FIXTURE/failed ]]; then
                    : >"$DESKTOP_FIXTURE/failed"
                    return 1
                fi
                if [[ $key == "${IGNORE_ONCE_KEY:-}" && ! -e $DESKTOP_FIXTURE/ignored ]]; then
                    : >"$DESKTOP_FIXTURE/ignored"
                    return 0
                fi
                printf '%s\n' "$value" >"$DESKTOP_FIXTURE/$fixture_key"
                ;;
            *) return 1 ;;
        esac
    }
}

@test "desktop applies all seven controls and stores a private baseline" {
    run desktop::apply
    [ "$status" -eq 0 ]
    [ "$(cat "$DESKTOP_FIXTURE/idle-delay")" = 'uint32 300' ]
    [ "$(cat "$DESKTOP_FIXTURE/lock-enabled")" = true ]
    [ "$(cat "$DESKTOP_FIXTURE/lock-delay")" = 'uint32 0' ]
    [ "$(cat "$DESKTOP_FIXTURE/disable-lock-screen")" = false ]
    [ "$(cat "$DESKTOP_FIXTURE/automount")" = false ]
    [ "$(cat "$DESKTOP_FIXTURE/automount-open")" = false ]
    [ "$(cat "$DESKTOP_FIXTURE/autorun-never")" = true ]
    [ "$(stat -c %a "$XDG_STATE_HOME/octoshield")" = 700 ]
    [ "$(stat -c %a "$XDG_STATE_HOME/octoshield/desktop.tsv")" = 600 ]
    [ "$(wc -l <"$XDG_STATE_HOME/octoshield/desktop.tsv")" -eq 7 ]
}

@test "desktop repeat apply preserves the first baseline and skips matching writes" {
    desktop::apply
    cp "$XDG_STATE_HOME/octoshield/desktop.tsv" "$BATS_TEST_TMPDIR/baseline"
    : >"$DESKTOP_FIXTURE/writes"
    run desktop::apply
    [ "$status" -eq 0 ]
    [ ! -s "$DESKTOP_FIXTURE/writes" ]
    cmp "$BATS_TEST_TMPDIR/baseline" "$XDG_STATE_HOME/octoshield/desktop.tsv"
    printf '%s\n' 'uint32 900' >"$DESKTOP_FIXTURE/idle-delay"
    desktop::apply
    cmp "$BATS_TEST_TMPDIR/baseline" "$XDG_STATE_HOME/octoshield/desktop.tsv"
}

@test "desktop restores original values and retains the baseline" {
    desktop::apply
    run desktop::restore
    [ "$status" -eq 0 ]
    [ "$(cat "$DESKTOP_FIXTURE/idle-delay")" = 'uint32 600' ]
    [ "$(cat "$DESKTOP_FIXTURE/lock-enabled")" = false ]
    [ "$(cat "$DESKTOP_FIXTURE/lock-delay")" = 'uint32 10' ]
    [ "$(cat "$DESKTOP_FIXTURE/disable-lock-screen")" = true ]
    [ "$(cat "$DESKTOP_FIXTURE/automount")" = true ]
    [ "$(cat "$DESKTOP_FIXTURE/automount-open")" = true ]
    [ "$(cat "$DESKTOP_FIXTURE/autorun-never")" = false ]
    [ -f "$XDG_STATE_HOME/octoshield/desktop.tsv" ]
}

@test "desktop checks writability of every key before writing anything" {
    export LOCKED_KEY=autorun-never
    run desktop::apply
    [ "$status" -ne 0 ]
    [[ $output == *'locked by administrator policy'* ]]
    [ ! -s "$DESKTOP_FIXTURE/writes" ]
    [ ! -e "$XDG_STATE_HOME/octoshield/desktop.tsv" ]
}

@test "desktop refuses missing schemas before any mutation" {
    export MISSING_SCHEMA=true
    run desktop::apply
    [ "$status" -ne 0 ]
    [ ! -s "$DESKTOP_FIXTURE/writes" ]
}

@test "desktop refuses missing keys before any mutation" {
    export MISSING_KEY=true
    run desktop::apply
    [ "$status" -ne 0 ]
    [ ! -s "$DESKTOP_FIXTURE/writes" ]
}

@test "desktop refuses values with unexpected types" {
    export BAD_VALUE_KEY=autorun-never
    run desktop::apply
    [ "$status" -ne 0 ]
    [[ $output == *'Unexpected value type'* ]]
    [ ! -s "$DESKTOP_FIXTURE/writes" ]
}

@test "desktop rolls back earlier settings when a write fails" {
    export FAIL_ONCE_KEY=lock-delay
    run desktop::apply
    [ "$status" -ne 0 ]
    [[ $output == *'before this operation have been restored'* ]]
    [ "$(cat "$DESKTOP_FIXTURE/idle-delay")" = 'uint32 600' ]
    [ "$(cat "$DESKTOP_FIXTURE/lock-enabled")" = false ]
    [ -f "$XDG_STATE_HOME/octoshield/desktop.tsv" ]
}

@test "desktop verifies writes and rolls back silently ignored writes" {
    export IGNORE_ONCE_KEY=lock-delay
    run desktop::apply
    [ "$status" -ne 0 ]
    [ "$(cat "$DESKTOP_FIXTURE/idle-delay")" = 'uint32 600' ]
    [ "$(cat "$DESKTOP_FIXTURE/lock-enabled")" = false ]
}

@test "desktop rejects symlink state paths without changing settings" {
    mkdir -p "$BATS_TEST_TMPDIR/elsewhere"
    ln -s "$BATS_TEST_TMPDIR/elsewhere" "$XDG_STATE_HOME"
    run desktop::apply
    [ "$status" -ne 0 ]
    [[ $output == *'symlink'* ]]
    [ ! -s "$DESKTOP_FIXTURE/writes" ]
}

@test "desktop rejects a symlink baseline" {
    (
        umask 077
        mkdir -p "$XDG_STATE_HOME/octoshield"
    )
    touch "$BATS_TEST_TMPDIR/elsewhere"
    ln -s "$BATS_TEST_TMPDIR/elsewhere" "$XDG_STATE_HOME/octoshield/desktop.tsv"
    run desktop::apply
    [ "$status" -ne 0 ]
    [ ! -s "$DESKTOP_FIXTURE/writes" ]
}

@test "desktop rejects a baseline readable by other users" {
    desktop::apply
    chmod 644 "$XDG_STATE_HOME/octoshield/desktop.tsv"
    : >"$DESKTOP_FIXTURE/writes"
    run desktop::restore
    [ "$status" -ne 0 ]
    [ ! -s "$DESKTOP_FIXTURE/writes" ]
}

@test "desktop rejects duplicate baseline entries before restore" {
    desktop::apply
    local first_entry
    first_entry=$(head -n 1 "$XDG_STATE_HOME/octoshield/desktop.tsv")
    printf '%s\n' "$first_entry" >>"$XDG_STATE_HOME/octoshield/desktop.tsv"
    : >"$DESKTOP_FIXTURE/writes"
    run desktop::restore
    [ "$status" -ne 0 ]
    [[ $output == *Duplicate* ]]
    [ ! -s "$DESKTOP_FIXTURE/writes" ]
}

@test "desktop rejects unknown keys and never evaluates baseline text" {
    desktop::apply
    printf '%s\t%s\t%s\n' org.gnome.desktop.session unknown "\$(touch $BATS_TEST_TMPDIR/executed)" >>"$XDG_STATE_HOME/octoshield/desktop.tsv"
    : >"$DESKTOP_FIXTURE/writes"
    run desktop::restore
    [ "$status" -ne 0 ]
    [ ! -e "$BATS_TEST_TMPDIR/executed" ]
    [ ! -s "$DESKTOP_FIXTURE/writes" ]
}

@test "desktop rejects an incomplete baseline" {
    desktop::apply
    sed -i '$d' "$XDG_STATE_HOME/octoshield/desktop.tsv"
    : >"$DESKTOP_FIXTURE/writes"
    run desktop::restore
    [ "$status" -ne 0 ]
    [[ $output == *Incomplete* ]]
    [ ! -s "$DESKTOP_FIXTURE/writes" ]
}

@test "desktop rejects an invalid saved GVariant value" {
    desktop::apply
    sed -i 's/uint32 600/uint32 4294967296/' "$XDG_STATE_HOME/octoshield/desktop.tsv"
    : >"$DESKTOP_FIXTURE/writes"
    run desktop::restore
    [ "$status" -ne 0 ]
    [[ $output == *'Invalid value'* ]]
    [ ! -s "$DESKTOP_FIXTURE/writes" ]
}

@test "desktop status reports locked settings without writing" {
    export LOCKED_KEY=autorun-never
    run desktop::status
    [ "$status" -eq 0 ]
    [[ $output == *'idle-delay = uint32 600 [custom]'* ]]
    [ ! -s "$DESKTOP_FIXTURE/writes" ]
    [ ! -e "$XDG_STATE_HOME" ]
}

@test "desktop refuses a restore when no baseline exists" {
    run desktop::restore
    [ "$status" -ne 0 ]
    [[ $output == *'No saved desktop baseline'* ]]
    [ ! -s "$DESKTOP_FIXTURE/writes" ]
}

@test "desktop session guard refuses root" {
    ((EUID == 0)) || skip 'This root-specific check only applies when tests run as root.'
    source "$BATS_TEST_DIRNAME/../src/lib/desktop.sh"
    run desktop::require_session
    [ "$status" -ne 0 ]
    [[ $output == *'without sudo'* ]]
}

@test "desktop session guard reports unsupported desktops" {
    if ((EUID == 0)); then
        command -v setpriv >/dev/null || skip 'setpriv is required to exercise the unprivileged guard.'
        setpriv --reuid=65534 --regid=65534 --clear-groups true 2>/dev/null || skip 'This container cannot switch to an unprivileged UID.'
        run setpriv --reuid=65534 --regid=65534 --clear-groups bash -c 'source /dev/stdin; export XDG_CURRENT_DESKTOP=KDE; desktop::require_session' <"$BATS_TEST_DIRNAME/../src/lib/desktop.sh"
    else
        source "$BATS_TEST_DIRNAME/../src/lib/desktop.sh"
        export XDG_CURRENT_DESKTOP=KDE
        run desktop::require_session
    fi
    [ "$status" -ne 0 ]
    [[ $output == *'Unsupported session'* ]]
}

@test "desktop session guard requires the logged-in user bus" {
    if ((EUID == 0)); then
        command -v setpriv >/dev/null || skip 'setpriv is required to exercise the unprivileged guard.'
        setpriv --reuid=65534 --regid=65534 --clear-groups true 2>/dev/null || skip 'This container cannot switch to an unprivileged UID.'
        run setpriv --reuid=65534 --regid=65534 --clear-groups bash -c 'source /dev/stdin; export XDG_CURRENT_DESKTOP=GNOME; unset DBUS_SESSION_BUS_ADDRESS; desktop::require_session' <"$BATS_TEST_DIRNAME/../src/lib/desktop.sh"
    else
        source "$BATS_TEST_DIRNAME/../src/lib/desktop.sh"
        export XDG_CURRENT_DESKTOP=GNOME
        unset DBUS_SESSION_BUS_ADDRESS
        run desktop::require_session
    fi
    [ "$status" -ne 0 ]
    [[ $output == *'No user session D-Bus'* ]]
}

@test "desktop disables supported per-user remote desktop backends and restores them" {
    export OPTIONAL_SHARING=true
    run desktop::apply
    [ "$status" -eq 0 ]
    [ "$(cat "$DESKTOP_FIXTURE/rdp-enable")" = false ]
    [ "$(cat "$DESKTOP_FIXTURE/vnc-enable")" = false ]
    [ "$(wc -l <"$XDG_STATE_HOME/octoshield/desktop.tsv")" -eq 9 ]
    run desktop::restore
    [ "$status" -eq 0 ]
    [ "$(cat "$DESKTOP_FIXTURE/rdp-enable")" = true ]
    [ "$(cat "$DESKTOP_FIXTURE/vnc-enable")" = true ]
}

@test "desktop reports missing optional sharing controls without skipping core protection" {
    export OPTIONAL_SHARING=true MISSING_SHARING_KEY=true
    run desktop::apply
    [ "$status" -eq 0 ]
    [[ $output == *'enable key is unavailable'* ]]
    [ "$(cat "$DESKTOP_FIXTURE/idle-delay")" = 'uint32 300' ]
    [ "$(cat "$DESKTOP_FIXTURE/rdp-enable")" = true ]
    [ "$(wc -l <"$XDG_STATE_HOME/octoshield/desktop.tsv")" -eq 7 ]
}

@test "desktop checks optional sharing writability before any settings change" {
    export OPTIONAL_SHARING=true LOCKED_KEY=enable
    run desktop::apply
    [ "$status" -ne 0 ]
    [ ! -s "$DESKTOP_FIXTURE/writes" ]
}

@test "desktop rejects simultaneous mutation while the state directory is locked" {
    desktop::state_path true
    local lock_fd
    exec {lock_fd}<"$XDG_STATE_HOME/octoshield"
    flock -n "$lock_fd"
    run desktop::apply
    [ "$status" -ne 0 ]
    [[ $output == *'Another desktop policy operation'* ]]
    [ ! -s "$DESKTOP_FIXTURE/writes" ]
    exec {lock_fd}<&-
}

@test "desktop adds first-seen sharing controls without overwriting existing baselines" {
    desktop::apply
    cp "$XDG_STATE_HOME/octoshield/desktop.tsv" "$BATS_TEST_TMPDIR/original"
    export OPTIONAL_SHARING=true
    desktop::apply
    head -n 7 "$XDG_STATE_HOME/octoshield/desktop.tsv" >"$BATS_TEST_TMPDIR/preserved"
    cmp "$BATS_TEST_TMPDIR/original" "$BATS_TEST_TMPDIR/preserved"
    [ "$(wc -l <"$XDG_STATE_HOME/octoshield/desktop.tsv")" -eq 9 ]
    desktop::restore
    [ "$(cat "$DESKTOP_FIXTURE/rdp-enable")" = true ]
    [ "$(cat "$DESKTOP_FIXTURE/idle-delay")" = 'uint32 600' ]
}

@test "desktop restores core settings after an optional sharing backend is removed" {
    export OPTIONAL_SHARING=true
    desktop::apply
    export OPTIONAL_SHARING=false
    run desktop::restore
    [ "$status" -eq 0 ]
    [[ $output == *'currently unavailable and will be retained'* ]]
    [ "$(cat "$DESKTOP_FIXTURE/idle-delay")" = 'uint32 600' ]
    [ "$(wc -l <"$XDG_STATE_HOME/octoshield/desktop.tsv")" -eq 9 ]
}
