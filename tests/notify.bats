#!/usr/bin/env bats
# SPDX-License-Identifier: Apache-2.0
# shellcheck disable=SC2030,SC2031,SC2317,SC2329
setup() {
    source "$BATS_TEST_DIRNAME/../src/notify.sh"
    NOTIFY_LOG="$BATS_TEST_TMPDIR/notifications"
    notify::message() { printf '%s\n' "$1" >>"$NOTIFY_LOG"; }
    notify::open_message() { printf '%s\n' "$1" >>"$NOTIFY_LOG"; }
    CURRENT='{"controls":{"firewall":{"state":"active"}},"network":{"fingerprint":"same"},"usb":{"pending":1,"devices":[{"id":1,"state":"blocked"}]}}'
}

@test 'pending USB is announced when notifier first starts' {
    notify::status_changes '' "$CURRENT"
    wait
    [ "$(cat "$NOTIFY_LOG")" = 'USB approval required' ]
}

@test 'unchanged status does not repeat notifications' {
    notify::status_changes "$CURRENT" "$CURRENT"
    wait
    [ ! -e "$NOTIFY_LOG" ]
}

@test 'replacement blocked USB with unchanged count produces a fresh notice' {
    local next
    next=$(jq '.usb.devices[0].id = 2' <<<"$CURRENT")
    notify::status_changes "$CURRENT" "$next"
    wait
    [ "$(cat "$NOTIFY_LOG")" = 'USB approval required' ]
}

@test 'network change is announced without exposing identifiers' {
    local next
    next=$(jq '.network.fingerprint = "other"' <<<"$CURRENT")
    notify::status_changes "$CURRENT" "$next"
    [ "$(cat "$NOTIFY_LOG")" = 'Network connection changed' ]
}

@test 'effective protection change produces a review notice' {
    local next
    next=$(jq '.controls.firewall.state = "partial"' <<<"$CURRENT")
    notify::status_changes "$CURRENT" "$next"
    [ "$(cat "$NOTIFY_LOG")" = 'Protection status changed' ]
}

@test 'only an unlocked active local session permits approval navigation' {
    XDG_SESSION_ID=c2
    timeout() { printf 'User=%s\nActive=yes\nRemote=no\nLockedHint=no\n' "$UID"; }
    run notify::unlocked
    [ "$status" -eq 0 ]
    timeout() { printf 'User=%s\nActive=yes\nRemote=no\nLockedHint=yes\n' "$UID"; }
    run notify::unlocked
    [ "$status" -ne 0 ]
    timeout() { printf 'User=%s\nActive=yes\nRemote=yes\nLockedHint=no\n' "$UID"; }
    run notify::unlocked
    [ "$status" -ne 0 ]
    timeout() { return 1; }
    run notify::unlocked
    [ "$status" -ne 0 ]
}

@test 'another user session is refused even when locally active' {
    XDG_SESSION_ID=c2
    timeout() { printf 'User=%s\nActive=yes\nRemote=no\nLockedHint=no\n' "$((UID + 1))"; }
    run notify::unlocked
    [ "$status" -ne 0 ]
}
