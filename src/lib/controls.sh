#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Native host controls. Mutations are explicit, confirmed, and return failures.
# This module is sourced by octoshield; it performs no work when sourced.

controls::local_console() {
    if [[ -n ${SSH_CONNECTION:-} || -n ${SSH_CLIENT:-} || -n ${SSH_TTY:-} ]]; then
        core::die 'Run this control from the laptop console; it can disconnect remote access.'
        return 1
    fi
}

# Emit a complete UFW defaults file while preserving unrelated package settings.
controls::ufw_defaults() {
    local file=${1:-/etc/default/ufw}
    if [[ ! -f $file ]]; then
        core::die "Missing UFW defaults: $file"
        return 1
    fi
    awk '
        /^[[:space:]]*IPV6[[:space:]]*=/ { if (!seen++) print "IPV6=yes"; next }
        { print }
        END { if (!seen) print "IPV6=yes" }
    ' "$file"
}

controls::apply_firewall() {
    local defaults
    core::require_root || return 1
    controls::local_console || return 1
    core::confirm 'Prepare the conference firewall? Any missing UFW package will be installed before the network-disconnection step.' || return 1
    core::install_packages ufw || return 1
    core::log 'The conference firewall removes existing UFW exceptions, denies unsolicited incoming and forwarded traffic, permits outgoing traffic, and filters IPv4/IPv6.'
    core::log 'Reset briefly disables UFW. Disconnect Wi-Fi/Ethernet first. Docker/container published ports and other firewall managers require separate review.'
    if command -v ufw >/dev/null 2>&1; then
        ufw status numbered || return 1
    fi
    core::confirm 'Back up and RESET all UFW rules, then enable the conference firewall?' || return 1
    core::backup /etc/ufw || return 1
    core::backup /etc/default/ufw || return 1
    defaults=$(controls::ufw_defaults /etc/default/ufw) || return 1
    ufw --force reset || return 1
    core::write_file /etc/default/ufw 0644 <<<"$defaults" || return 1
    ufw default deny incoming || return 1
    ufw default allow outgoing || return 1
    ufw default deny routed || return 1
    ufw logging low || return 1
    ufw --force enable || return 1
    ufw status verbose || return 1
    core::record 'firewall: reset UFW; IPv4/IPv6 inbound/forward deny, outbound allow, low logging' || return 1
}

controls::apply_network() {
    local profiles uuid type
    core::require_root || return 1
    controls::local_console || return 1
    if ! command -v nmcli >/dev/null 2>&1; then
        core::die 'NetworkManager is required; Octoshield will not replace your network stack.'
        return 1
    fi
    # UUIDs and types avoid parsing profile names, which can contain colons/newlines.
    profiles=$(nmcli --terse --fields UUID,TYPE connection show) || return 1
    core::log 'Disable autoconnect for existing Wi-Fi profiles, use stable private Wi-Fi MACs, randomize scanning, and disable LLMNR/mDNS for existing profiles.'
    core::log 'Reconnect manually afterward to apply profile changes. Local .local discovery may stop working; MAC-registered networks may require office adjustments.'
    core::confirm 'Apply network privacy settings and back up existing connection profiles (including their secrets)?' || return 1
    core::backup /etc/NetworkManager/system-connections || return 1
    core::backup /run/NetworkManager/system-connections || return 1
    core::write_file /etc/NetworkManager/conf.d/90-octoshield.conf 0644 <<'CONFIG' || return 1
# Managed by Octoshield. Explicit profile settings take precedence over defaults.
[device]
wifi.scan-rand-mac-address=yes
wifi.iwd.autoconnect=false

[connection]
wifi.cloned-mac-address=stable
connection.llmnr=0
connection.mdns=0
CONFIG
    while IFS=: read -r uuid type; do
        [[ -n $uuid ]] || continue
        if [[ ! $uuid =~ ^[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}$ ]]; then
            core::die 'NetworkManager returned an invalid connection UUID; stopped.'
            return 1
        fi
        nmcli connection modify uuid "$uuid" connection.llmnr 0 connection.mdns 0 || return 1
        case "$type" in
            802-11-wireless | wifi)
                nmcli connection modify uuid "$uuid" connection.autoconnect no \
                    802-11-wireless.cloned-mac-address stable || return 1
                ;;
        esac
    done <<<"$profiles"
    nmcli general reload conf || return 1
    core::record 'network: existing Wi-Fi autoconnect disabled; private MAC defaults; LLMNR/mDNS profiles disabled; reconnect required' || return 1
    core::log 'Reconnect Wi-Fi/Ethernet manually before relying on the new profile settings. Disable autoconnect when adding new conference networks; these defaults cannot enforce that choice.'
}

controls::apply_services() {
    local unit load_state unit_state active_state
    local -a units=(
        ssh.service ssh.socket avahi-daemon.service avahi-daemon.socket
        cups.service cups.socket cups.path cups-browsed.service
        bluetooth.service smbd.service nmbd.service gnome-remote-desktop.service
    )
    core::require_root || return 1
    controls::local_console || return 1
    core::log 'Stop and persistently mask installed SSH, Avahi, CUPS printing, Bluetooth, Samba, and system GNOME remote-desktop services/sockets.'
    core::log 'Bluetooth keyboards/mice will disconnect. Use the built-in or a trusted wired keyboard. Per-user sharing is managed separately in Desktop settings.'
    core::confirm 'Disable these local services? Printing, Bluetooth and inbound SSH will stop.' || return 1
    for unit in "${units[@]}"; do
        load_state=$(systemctl show --property=LoadState --value "$unit") || return 1
        [[ $load_state == not-found ]] && continue
        unit_state=$(systemctl show --property=UnitFileState --value "$unit") || return 1
        active_state=$(systemctl show --property=ActiveState --value "$unit") || return 1
        core::record "service-before: $unit enabled=$unit_state active=$active_state" || return 1
        core::backup "/etc/systemd/system/$unit" || return 1
        systemctl mask --now "$unit" || return 1
    done
    core::record 'services: installed conference sharing services masked; see service-before entries for recovery' || return 1
}

controls::apply_sudo() {
    local temporary
    core::require_root || return 1
    core::confirm 'Require authentication for every sudo command by setting timestamp_timeout=0? Existing NOPASSWD rules are not removed.' || return 1
    core::install_packages sudo || return 1
    visudo --check || return 1
    temporary=$(mktemp) || return 1
    if ! printf '%s\n' '# Managed by Octoshield; passwordless grants still bypass passwords.' 'Defaults timestamp_timeout=0' >"$temporary"; then
        rm -f -- "$temporary"
        return 1
    fi
    if ! visudo --check --file "$temporary"; then
        rm -f -- "$temporary"
        return 1
    fi
    if ! core::write_file /etc/sudoers.d/99-octoshield 0440 <"$temporary"; then
        rm -f -- "$temporary"
        return 1
    fi
    rm -f -- "$temporary" || return 1
    visudo --check || return 1
    core::record 'sudo: timestamp_timeout=0; existing NOPASSWD/per-user overrides require manual review' || return 1
    core::log 'The global sudo timeout is zero. Existing NOPASSWD or more specific Defaults rules may override authentication; review sudo -l for your account.'
}

controls::apply_updates() {
    core::require_root || return 1
    core::confirm 'Enable daily unattended security updates without automatic reboot? Existing additional update origins will be preserved.' || return 1
    core::install_packages unattended-upgrades || return 1
    # APT list entries append to the distribution policy; never clear its origins.
    # Keep substitutions literal: unattended-upgrades resolves distro variables.
    core::write_file /etc/apt/apt.conf.d/90-octoshield 0644 <<'CONFIG' || return 1
// Managed by Octoshield. Retain upstream and administrator origin policies.
APT::Periodic::Enable "1";
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
Unattended-Upgrade::Allowed-Origins:: "${distro_id}:${distro_codename}-security";
Unattended-Upgrade::Allowed-Origins:: "${distro_id}ESMApps:${distro_codename}-apps-security";
Unattended-Upgrade::Allowed-Origins:: "${distro_id}ESM:${distro_codename}-infra-security";
Unattended-Upgrade::Automatic-Reboot "false";
CONFIG
    apt-config dump >/dev/null || return 1
    systemctl enable --now apt-daily.timer apt-daily-upgrade.timer || return 1
    core::record 'updates: daily unattended security upgrades enabled; existing origins preserved; no automatic reboot' || return 1
    core::log 'Install pending updates on a trusted connection before travel. Reboot when Ubuntu requests it; enabling a timer does not mean the laptop is already patched.'
}

controls::apply_apparmor() {
    core::require_root || return 1
    core::confirm 'Enable AppArmor and reload installed profiles in their existing modes? Complain/disabled profiles remain unchanged.' || return 1
    core::install_packages apparmor apparmor-utils || return 1
    if ! aa-enabled --quiet; then
        core::die 'AppArmor is unavailable in the running kernel. Check boot configuration and reboot; no profiles were forced into enforcement.'
        return 1
    fi
    systemctl enable --now apparmor.service || return 1
    systemctl reload apparmor.service || return 1
    aa-status || return 1
    core::record 'apparmor: service enabled and installed policy reloaded; existing profile modes preserved' || return 1
}
