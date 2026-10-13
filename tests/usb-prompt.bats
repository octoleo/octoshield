#!/usr/bin/env bats
# SPDX-License-Identifier: Apache-2.0
# shellcheck disable=SC2030,SC2031,SC2317,SC2329

setup() {
    # shellcheck source=src/usb-prompt.sh
    source "$BATS_TEST_DIRNAME/../src/usb-prompt.sh"
    export XDG_RUNTIME_DIR="$BATS_TEST_TMPDIR/runtime" XDG_CONFIG_HOME="$BATS_TEST_TMPDIR/config"
    mkdir -m 0700 "$XDG_RUNTIME_DIR" "$XDG_CONFIG_HOME"
    usb_prompt::prepare
    PROMPT_LOG="$BATS_TEST_TMPDIR/prompts"
    TOKEN=$(printf '%064d' 1)
    OTHER_TOKEN=$(printf '%064d' 2)
    CURRENT=$(jq -cn --arg token "$TOKEN" '{usb:{available:true,state:"active",devices:[{id:1,token:$token,profile:"conference",state:"blocked"}]}}')
    status::read_usb() { printf '%s\n' "$CURRENT"; }
    usb_prompt::unlocked() { return 0; }
    usb_prompt::available() { return 0; }
    usb_prompt::launch() { printf 'review\n' >>"$PROMPT_LOG"; }
}

@test 'new blocked attachment opens review exactly once across polling and restart' {
    usb_prompt::poll
    usb_prompt::poll
    # A fresh process reads the same private state instead of prompting again.
    (usb_prompt::poll)
    [ "$(cat "$PROMPT_LOG")" = review ]
    [ "$(stat -c '%a' "$USB_PROMPT_DIRECTORY/seen.json")" = 600 ]
}

@test 'rejected devices prompt but already authorized devices do not' {
    CURRENT=$(jq '.usb.devices[0].state = "allowed"' <<<"$CURRENT")
    usb_prompt::poll
    [ ! -e "$PROMPT_LOG" ]
    CURRENT=$(jq '.usb.devices[0].state = "rejected"' <<<"$CURRENT")
    usb_prompt::poll
    [ "$(cat "$PROMPT_LOG")" = review ]
}

@test 'new attachment token and changed USB profile each offer fresh review' {
    usb_prompt::poll
    CURRENT=$(jq --arg token "$OTHER_TOKEN" '.usb.devices[0].token = $token' <<<"$CURRENT")
    usb_prompt::poll
    CURRENT=$(jq '.usb.devices[0].profile = "office"' <<<"$CURRENT")
    usb_prompt::poll
    [ "$(wc -l <"$PROMPT_LOG")" -eq 3 ]
    [ "$(jq length "$USB_PROMPT_DIRECTORY/seen.json")" -eq 1 ]
}

@test 'multiple pending devices are batched into one review activation' {
    CURRENT=$(jq --arg token "$OTHER_TOKEN" '.usb.devices += [{id:2,token:$token,profile:"conference",state:"blocked"}]' <<<"$CURRENT")
    usb_prompt::poll
    [ "$(cat "$PROMPT_LOG")" = review ]
    [ "$(jq length "$USB_PROMPT_DIRECTORY/seen.json")" -eq 2 ]
}

@test 'cancelled or failed GUI launch is not retried for the same attachment' {
    usb_prompt::launch() {
        printf 'cancel\n' >>"$PROMPT_LOG"
        return 1
    }
    run usb_prompt::poll
    [ "$status" -eq 1 ]
    usb_prompt::poll
    [ "$(cat "$PROMPT_LOG")" = cancel ]
}

@test 'allowed then blocked state preserves dismissal for the same attachment' {
    usb_prompt::poll
    CURRENT=$(jq '.usb.devices[0].state = "allowed"' <<<"$CURRENT")
    usb_prompt::poll
    CURRENT=$(jq '.usb.devices[0].state = "blocked"' <<<"$CURRENT")
    usb_prompt::poll
    [ "$(cat "$PROMPT_LOG")" = review ]
}

@test 'unavailable or malformed cache does not erase remembered dismissals' {
    usb_prompt::poll
    status::read_usb() { return 1; }
    run usb_prompt::poll
    [ "$status" -eq 1 ]
    [ "$(jq length "$USB_PROMPT_DIRECTORY/seen.json")" -eq 1 ]
    status::read_usb() { printf '{"usb":{"available":true,"state":"active","devices":[{"token":"bad","profile":"../escape","state":"blocked"}]}}\n'; }
    run usb_prompt::poll
    [ "$status" -eq 1 ]
    [ "$(jq length "$USB_PROMPT_DIRECTORY/seen.json")" -eq 1 ]
}

@test 'unavailable USB inventory does not clear dismissed devices or open review' {
    usb_prompt::poll
    CURRENT=$(jq '.usb.available = false | .usb.state = "unknown" | .usb.devices = []' <<<"$CURRENT")
    run usb_prompt::poll
    [ "$status" -ne 0 ]
    [ "$(jq length "$USB_PROMPT_DIRECTORY/seen.json")" -eq 1 ]
    [ "$(cat "$PROMPT_LOG")" = review ]
}

@test 'a confirmed disconnect prunes previous attachments from the bounded state' {
    usb_prompt::poll
    CURRENT=$(jq '.usb.devices = []' <<<"$CURRENT")
    usb_prompt::poll
    [ "$(usb_prompt::read_seen)" = '[]' ]
    CURRENT=$(jq -cn --arg token "$OTHER_TOKEN" '{usb:{available:true,state:"partial",devices:[{id:2,token:$token,profile:"conference",state:"blocked"}]}}')
    usb_prompt::poll
    [ "$(wc -l <"$PROMPT_LOG")" -eq 2 ]
    [ "$(jq length "$USB_PROMPT_DIRECTORY/seen.json")" -eq 1 ]
}

@test 'corrupted or unsafe private dedupe state prevents popup storms' {
    printf 'broken\n' >"$USB_PROMPT_DIRECTORY/seen.json"
    chmod 0600 "$USB_PROMPT_DIRECTORY/seen.json"
    run usb_prompt::poll
    [ "$status" -ne 0 ]
    [ ! -e "$PROMPT_LOG" ]
    rm "$USB_PROMPT_DIRECTORY/seen.json"
    ln -s "$BATS_TEST_TMPDIR/elsewhere" "$USB_PROMPT_DIRECTORY/seen.json"
    run usb_prompt::poll
    [ "$status" -ne 0 ]
    [ ! -e "$BATS_TEST_TMPDIR/elsewhere" ]
}

@test 'locked desktop defers a new prompt until the session is unlocked' {
    usb_prompt::unlocked() { return 1; }
    usb_prompt::poll
    [ ! -e "$PROMPT_LOG" ]
    [ "$(usb_prompt::read_seen)" = '[]' ]
    usb_prompt::unlocked() { return 0; }
    usb_prompt::poll
    [ "$(cat "$PROMPT_LOG")" = review ]
}

@test 'automatic prompt preference is live and defaults to enabled' {
    usb_prompt::enabled
    mkdir -m 0700 "$XDG_CONFIG_HOME/octoshield"
    printf '[USB]\nautomatic-prompts=false\n' >"$XDG_CONFIG_HOME/octoshield/preferences.ini"
    chmod 0600 "$XDG_CONFIG_HOME/octoshield/preferences.ini"
    usb_prompt::poll
    [ ! -e "$PROMPT_LOG" ]
    printf '[USB]\nautomatic-prompts=true\n' >"$XDG_CONFIG_HOME/octoshield/preferences.ini"
    usb_prompt::poll
    [ "$(cat "$PROMPT_LOG")" = review ]
}

@test 'malformed preference and symlinked preference fail closed' {
    mkdir -m 0700 "$XDG_CONFIG_HOME/octoshield"
    printf '[USB]\nautomatic-prompts=maybe\n' >"$XDG_CONFIG_HOME/octoshield/preferences.ini"
    chmod 0600 "$XDG_CONFIG_HOME/octoshield/preferences.ini"
    run usb_prompt::enabled
    [ "$status" -ne 0 ]
    rm "$XDG_CONFIG_HOME/octoshield/preferences.ini"
    ln -s "$BATS_TEST_TMPDIR/missing" "$XDG_CONFIG_HOME/octoshield/preferences.ini"
    run usb_prompt::enabled
    [ "$status" -ne 0 ]
}

@test 'runtime directory must be private and not a symlink' {
    chmod 0755 "$XDG_RUNTIME_DIR"
    run usb_prompt::prepare
    [ "$status" -ne 0 ]
    chmod 0700 "$XDG_RUNTIME_DIR"
    mv "$XDG_RUNTIME_DIR/octoshield" "$XDG_RUNTIME_DIR/replaced"
    ln -s "$XDG_RUNTIME_DIR/replaced" "$XDG_RUNTIME_DIR/octoshield"
    run usb_prompt::prepare
    [ "$status" -ne 0 ]
}

@test 'only one agent may hold a desktop user lock' {
    usb_prompt::lock
    run usb_prompt::lock
    [ "$status" -ne 0 ]
    exec {USB_PROMPT_LOCK}<&-
}

@test 'another user, remote, inactive and locked sessions cannot open review' {
    # shellcheck source=src/usb-prompt.sh
    source "$BATS_TEST_DIRNAME/../src/usb-prompt.sh"
    export XDG_SESSION_ID=c2
    timeout() { printf 'User=%s\nActive=yes\nRemote=no\nLockedHint=no\nType=wayland\n' "$UID"; }
    usb_prompt::unlocked
    timeout() { printf 'User=%s\nActive=yes\nRemote=no\nLockedHint=no\nType=wayland\n' "$((UID + 1))"; }
    run usb_prompt::unlocked
    [ "$status" -ne 0 ]
    timeout() { printf 'User=%s\nActive=yes\nRemote=yes\nLockedHint=no\nType=wayland\n' "$UID"; }
    run usb_prompt::unlocked
    [ "$status" -ne 0 ]
    timeout() { printf 'User=%s\nActive=no\nRemote=no\nLockedHint=no\nType=wayland\n' "$UID"; }
    run usb_prompt::unlocked
    [ "$status" -ne 0 ]
    timeout() { printf 'User=%s\nActive=yes\nRemote=no\nLockedHint=yes\nType=wayland\n' "$UID"; }
    run usb_prompt::unlocked
    [ "$status" -ne 0 ]
    timeout() { printf 'User=%s\nActive=yes\nRemote=no\nLockedHint=no\nType=tty\n' "$UID"; }
    run usb_prompt::unlocked
    [ "$status" -ne 0 ]
    timeout() { return 1; }
    run usb_prompt::unlocked
    [ "$status" -ne 0 ]
}

@test 'GUI launch contains a fixed unprivileged command and no device strings' {
    # shellcheck source=src/usb-prompt.sh
    source "$BATS_TEST_DIRNAME/../src/usb-prompt.sh"
    timeout() { printf '%s\n' "$@"; }
    run usb_prompt::launch
    [ "$status" -eq 0 ]
    [[ "$output" == *$'/usr/bin/systemd-run\n--user\n--collect\n--quiet\n--service-type=exec\n--\n/usr/bin/octoshield-gtk\n--usb-review' ]]
}

@test 'the desktop agent refuses to run as root' {
    if ((EUID != 0)); then skip 'Root-only entrypoint refusal'; fi
    run usb_prompt::run
    [ "$status" -eq 1 ]
    [[ "$output" == *'desktop user'* ]]
}
