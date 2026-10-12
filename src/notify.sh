#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Runs only as the desktop user. Never consumes raw root logs or evaluates state.

notify::message() {
    notify-send --app-name=Octoshield --icon=security-high --urgency=normal \
        --expire-time=15000 "Octoshield: $1" "$2"
}

notify::snapshot() {
    local file=/run/octoshield/events metadata modified now state
    [[ -f $file && ! -L $file && ! -L /run/octoshield ]] || return 1
    metadata=$(stat -c '%u:%a' /run/octoshield) || return 1
    [[ $metadata == 0:755 ]] || return 1
    metadata=$(stat -c '%u:%a:%s:%Y' "$file") || return 1
    [[ $metadata =~ ^0:644:([0-9]{1,3}):([0-9]+)$ ]] || return 1
    ((BASH_REMATCH[1] <= 255)) || return 1
    modified=${BASH_REMATCH[2]}
    now=$(date +%s) || return 1
    # Modest wall-clock adjustments are allowed; a stopped service goes stale.
    ((now - modified <= 45 && modified - now <= 45)) || return 1
    IFS= read -r state <"$file" || return 1
    [[ $state =~ ^v1\ [0-9]+-[0-9]+-[0-9]+\ [0-9]{1,20}\ [0-9]{1,20}\ [0-9]{1,20}$ ]] || return 1
    printf '%s\n' "$state"
}

notify::changes() {
    local previous=$1 current=$2 _version old_instance new_instance old_fw old_usb old_auth fw usb auth
    read -r _version old_instance old_fw old_usb old_auth <<<"$previous"
    read -r _version new_instance fw usb auth <<<"$current"
    # A restarted collector has new counters. Its first alert may arrive before
    # our next poll; compare against zero instead of dropping that alert.
    if [[ $old_instance != "$new_instance" ]]; then
        old_fw=0
        old_usb=0
        old_auth=0
    fi
    if [[ $fw != "$old_fw" ]]; then
        notify::message 'Repeated firewall blocks' \
            'At least 5 firewall block log events occurred within 60 seconds. This is not proof of compromise. Review your network; disconnect Wi-Fi or Ethernet if concerned.' || :
    fi
    if [[ $usb != "$old_usb" ]]; then
        notify::message 'USB device blocked' \
            'USBGuard blocked or rejected a device. Leave unfamiliar devices blocked. Run octoshield usb list to inspect and octoshield usb allow for administrator-authenticated approval.' || :
    fi
    if [[ $auth != "$old_auth" ]]; then
        notify::message 'Repeated authentication failures' \
            'At least 5 sudo or SSH failure log events occurred within 60 seconds. Review recent activity and lock the laptop. This alone does not show a successful intrusion.' || :
    fi
}

notify::run() {
    [[ $EUID -ne 0 ]] || {
        printf 'Run the notifier as your desktop user.\n' >&2
        return 1
    }
    local previous='' current='' unavailable=0
    while :; do
        if current=$(notify::snapshot 2>/dev/null); then
            if ((unavailable)); then notify::message 'Monitoring resumed' 'The security event monitor is reporting again.' || :; fi
            if [[ -n $previous ]]; then notify::changes "$previous" "$current"; fi
            previous=$current
            unavailable=0
        elif ((unavailable == 0)); then
            notify::message 'Monitoring unavailable' 'Octoshield is not reporting security events. Run octoshield monitor status. Existing firewall and USB policies are independent of this monitor.' || :
            unavailable=1
        fi
        sleep 3
    done
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    set -u
    export PATH=/usr/sbin:/usr/bin:/sbin:/bin
    notify::run
fi
