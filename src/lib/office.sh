#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Shared, narrowly scoped office adjustments for both frontends.

office::valid_port() {
    [[ ${1-} =~ ^[1-9][0-9]{0,4}$ ]] && ((10#$1 <= 65535))
}

office::valid_subnet() {
    local subnet=${1-} octet prefix
    local -a octets
    [[ $subnet =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[12][0-9]|3[0-2])$ ]] || return 1
    prefix=${subnet##*/}
    ((10#$prefix > 0)) || return 1
    IFS='.' read -r -a octets <<<"${subnet%/*}"
    for octet in "${octets[@]}"; do
        ((10#$octet <= 255)) || return 1
    done
}

office::valid_uuid() {
    [[ ${1-} =~ ^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$ ]]
}

office::valid_service() {
    case "${1-}" in
        ssh.service | avahi-daemon.service | bluetooth.service | cups.service) return 0 ;;
        *) return 1 ;;
    esac
}

office::firewall() {
    local profile
    core::require_root || return 1
    [[ $# -eq 2 ]] && office::valid_port "$1" && office::valid_subnet "$2" || return 1
    profile=$(access::default_profile) || return 1
    access::dispatch allow "$profile" "$1" tcp "$2" any 0
}

office::network() {
    core::require_root || return 1
    [[ $# -eq 1 ]] && office::valid_uuid "$1" || return 1
    connections::set "$1" autoconnect true
}

office::service() {
    local unit load_state
    local -a units=()
    core::require_root || return 1
    [[ $# -eq 1 ]] && office::valid_service "$1" || return 1
    core::confirm "Unmask and start $1? Firewall exceptions must be configured separately." || return 1
    case "$1" in
        ssh.service) units=(ssh.service ssh.socket) ;;
        avahi-daemon.service) units=(avahi-daemon.service avahi-daemon.socket) ;;
        bluetooth.service) units=(bluetooth.service) ;;
        cups.service) units=(cups.service cups.socket cups.path) ;;
    esac
    for unit in "${units[@]}"; do
        load_state=$(systemctl show --property=LoadState --value "$unit") || return 1
        [[ $load_state != not-found ]] || continue
        core::backup "/etc/systemd/system/$unit" || return 1
        systemctl unmask "$unit" || return 1
    done
    systemctl enable --now "$1" || return 1
    core::record "OFFICE service $1"
}
