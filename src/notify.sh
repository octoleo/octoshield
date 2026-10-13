#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Runs only as the desktop user. Never consumes raw root logs or evaluates state.

notify::message() {
    notify-send --app-name=OctoShield --icon=security-high --urgency=normal \
        --expire-time=15000 "OctoShield: $1" "$2"
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

# Only an unlocked, active, local session may offer a path to approval. The
# notification never contains an approve action and never invokes pkexec.
notify::unlocked() {
    local session=${XDG_SESSION_ID:-} report key value user='' active='' remote='' locked=''
    if [[ -z $session ]]; then
        session=$(timeout 3s loginctl show-user "$UID" --property=Display --value 2>/dev/null) || return 1
    fi
    [[ $session =~ ^[a-zA-Z0-9_-]{1,64}$ ]] || return 1
    report=$(timeout 3s loginctl show-session "$session" --property=User --property=Active --property=Remote --property=LockedHint 2>/dev/null) || return 1
    while IFS='=' read -r key value; do
        case "$key" in User) user=$value ;; Active) active=$value ;; Remote) remote=$value ;; LockedHint) locked=$value ;; esac
    done <<<"$report"
    [[ $user == "$UID" && $active == yes && $remote == no && $locked == no ]]
}

notify::open_message() (
    local action
    if [[ ! -x /usr/bin/octoshield-gtk ]]; then
        notify::message "$1" "$2 Open OctoShield, or run octoshield usb list in a local terminal."
        return
    fi
    action=$(timeout --kill-after=1s 20s notify-send --app-name=OctoShield --icon=security-high --urgency=normal \
        --expire-time=15000 --action='open=Open OctoShield' --wait "OctoShield: $1" "$2") || return 0
    if [[ $action == open ]] && notify::unlocked; then /usr/bin/octoshield-gtk >/dev/null 2>&1 & fi
)

notify::automatic_usb_prompts() {
    # The CLI-only installation may not include the graphical companion. Keep
    # its existing notification fallback, and respect the desktop preference.
    declare -F usb_prompt::enabled >/dev/null || return 1
    usb_prompt::enabled || return 1
    timeout 3s systemctl --user is-active --quiet octoshield-usb-agent.service 2>/dev/null
}

notify::status_changes() {
    local previous=$1 current=$2 pending old_pending signature old_signature fingerprint old_fingerprint previous_json
    previous_json=$previous
    [[ -n $previous_json ]] || previous_json='{}'
    pending=$(jq -er .usb.pending <<<"$current") || return 1
    old_pending=$(jq -er '.usb.pending // 0' <<<"$previous_json") || old_pending=0
    signature=$(jq -c '.usb.devices | map(select(.state == "blocked" or .state == "rejected") | {id,state})' <<<"$current") || return 1
    old_signature=$(jq -c '.usb.devices // [] | map(select(.state == "blocked" or .state == "rejected") | {id,state})' <<<"$previous_json") || old_signature='[]'
    if ((pending > 0)) && { [[ $pending != "$old_pending" || $signature != "$old_signature" || -z $previous ]]; } && ! notify::automatic_usb_prompts; then
        notify::open_message 'USB approval required' \
            'A USB device remains blocked. Review it in OctoShield and choose a temporary or profile-specific approval only if you recognize it.' &
    fi
    if [[ -n $previous ]]; then
        fingerprint=$(jq -er .network.fingerprint <<<"$current") || return 1
        old_fingerprint=$(jq -er .network.fingerprint <<<"$previous") || return 1
        if [[ $fingerprint != "$old_fingerprint" ]]; then
            notify::message 'Network connection changed' \
                'A network adapter or active connection changed. Your selected profile stays in effect; review it before allowing incoming access.' || :
        fi
        if [[ $(jq -c '.controls | map_values(.state)' <<<"$previous") != "$(jq -c '.controls | map_values(.state)' <<<"$current")" ]]; then
            notify::message 'Protection status changed' \
                'OctoShield detected a change in effective protection. Open the dashboard to review verified status and any incomplete profile changes.' || :
        fi
    fi
}

notify::run() {
    [[ $EUID -ne 0 ]] || {
        printf 'Run the notifier as your desktop user.\n' >&2
        return 1
    }
    local previous='' current='' unavailable=0 status_previous='' status_current='' status_unavailable=0
    while :; do
        if current=$(notify::snapshot 2>/dev/null); then
            if ((unavailable)); then notify::message 'Monitoring resumed' 'The security event monitor is reporting again.' || :; fi
            if [[ -n $previous ]]; then notify::changes "$previous" "$current"; fi
            previous=$current
            unavailable=0
        elif ((unavailable == 0)); then
            notify::message 'Monitoring unavailable' 'OctoShield is not reporting security events. Run octoshield monitor status. Existing firewall and USB policies are independent of this monitor.' || :
            unavailable=1
        fi
        if status_current=$(status::read 2>/dev/null); then
            if notify::unlocked; then
                if ((status_unavailable)); then notify::message 'Live status resumed' 'OctoShield can verify protection status again.' || :; fi
                notify::status_changes "$status_previous" "$status_current" || :
                status_previous=$status_current
                status_unavailable=0
            fi
        elif ((status_unavailable == 0)) && notify::unlocked; then
            notify::message 'Live status unavailable' 'OctoShield cannot verify current protection. Existing firewall and USB enforcement are independent of the status collector.' || :
            status_unavailable=1
        fi
        sleep 3
    done
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    set -u
    export PATH=/usr/sbin:/usr/bin:/sbin:/bin
    notify_source=$(readlink -f -- "${BASH_SOURCE[0]}") || exit 1
    # shellcheck source=src/lib/status.sh
    source "${notify_source%/*}/lib/status.sh"
    if [[ -f ${notify_source%/*}/usb-prompt.sh ]]; then
        # shellcheck source=src/usb-prompt.sh
        source "${notify_source%/*}/usb-prompt.sh"
    fi
    unset notify_source
    notify::run
fi
