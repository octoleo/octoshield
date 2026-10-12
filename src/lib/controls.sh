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

# Backwards-compatible entry points use the same profile engine as both UIs.
controls::apply_firewall() {
    core::require_root || return 1
    controls::local_console || return 1
    profiles::apply conference firewall
}

controls::apply_network() {
    core::require_root || return 1
    controls::local_console || return 1
    profiles::apply conference network
}

controls::apply_services() {
    core::require_root || return 1
    controls::local_console || return 1
    profiles::apply conference services
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
