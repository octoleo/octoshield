#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Namespaced modules encapsulate behavior; this registry is the dispatch table.

declare -gAr CLI_CONTROLS=(
    [firewall]=controls::apply_firewall [network]=controls::apply_network
    [services]=controls::apply_services [sudo]=controls::apply_sudo
    [updates]=controls::apply_updates [apparmor]=controls::apply_apparmor
    [usb]=usb::apply [monitor]=monitor::apply
)

cli::usage() {
    cat <<'USAGE'
OctoShield 1.2.0 — Ubuntu laptop protection, part of the OctoLeo suite

Usage: octoshield [COMMAND]
  setup                     Guided setup and later adjustments (default)
  install                   Install this checkout and open guided setup
  status                    Inspect protections and listening services
  status --json             Read the verified, freshness-checked status snapshot
  inspect                   Refresh the verified status with administrator access
  profile                   Open the guided profile manager (Whiptail)
  profile list|show NAME    List profiles or inspect one profile
  profile create NAME BASE Copy a profile into a new editable profile
  profile delete NAME      Delete an unused custom profile
  profile apply NAME [CONTROL] Switch all protections, or override one
  profile restore [CONTROL] Restore saved original settings
  profile set NAME KEY VALUE Change a profile setting
  profile rule-add NAME PORT PROTO SOURCE INTERFACE MINUTES
                            Save an incoming exception (any source/interface allowed)
  profile rule-remove NAME ID Remove a saved firewall exception
  updates check             Check official releases and show upgrade instructions
  apply CONTROL             firewall|network|services|sudo|updates|apparmor|usb|monitor
  desktop apply|restore     Configure or restore this user's GNOME settings
  usb list                  List USB devices and authorization state
  usb allow ID [--permanent] Allow once, or remember for the current USB profile
  usb block ID              Block a device
  usb forget ID             Forget this device in the current USB profile and block it
  usb enroll NAME           Physically review trusted devices for a profile
  monitor enable-desktop    Enable security notifications for this user
  monitor disable-desktop   Disable this user's notifications
  monitor status            Inspect monitor and desktop notification services
  monitor logs|disable      Read collector logs or disable collection
  office                    Guided, narrowly scoped office access changes
  office firewall PORT CIDR Allow one TCP port from a trusted IPv4 subnet
  office network UUID       Enable autoconnect for one saved network
  office service UNIT       Restore one supported service
  password                  Change your password using the system passwd tool
  backups                   List private system configuration snapshots
  backup-show ID            Read a private transaction's action history
  recovery                  Show recovery instructions
  --help | --version

Run from your normal GNOME terminal. System changes request sudo; desktop
settings and notifications remain in your own user session. No automatic
weakening occurs when you return to the office. Review each selected change.
USAGE
}

cli::installed_command() {
    case "$OCTOSHIELD_ROOT" in
        /usr/lib/octoshield) printf '/usr/bin/octoshield\n' ;;
        /usr/local/lib/octoshield) printf '/usr/local/bin/octoshield\n' ;;
        *)
            core::die 'Install first: bash src/octoshield install'
            return 1
            ;;
    esac
}

cli::system() {
    core::require_local || return 1
    if ((EUID != 0)); then
        local launcher
        launcher=$(cli::installed_command) || return 1
        [[ -x $launcher ]] || {
            core::die 'Install first: bash src/octoshield install'
            return 1
        }
        # Expire the caller's cached timestamp for device authorization.
        if [[ ${1:-} == usb && ${2:-} == allow ]]; then
            sudo -k -- "$launcher" "$@"
        else
            sudo -- "$launcher" "$@"
        fi
        return $?
    fi
    core::supported_os || return 1
    if [[ $1 != office-system ]]; then api::validate "$@" || return 2; fi
    if [[ $1 == office-system ]] || api::mutates "$@"; then core::begin "$*" || return 1; fi
    local result=0
    case "$1" in
        office-system) cli::office_system || result=$? ;;
        *) api::dispatch "$@" || result=$? ;;
    esac
    if [[ $1 == office-system ]] || api::mutates "$@"; then
        if declare -F status::refresh >/dev/null; then
            status::refresh >/dev/null 2>&1 || core::log 'Live status refresh failed; the background collector will retry.'
        fi
    fi
    if [[ $1 != office-system ]] && ! api::mutates "$@"; then return "$result"; fi
    if ((result == 0)); then
        core::record 'COMPLETE'
        core::log "Saved change record: $CORE_STATE/backups/$CORE_TRANSACTION"
    else
        core::record "FAILED exit=$result; inspect changes before retrying"
        core::log "Operation failed; inspect $CORE_STATE/backups/$CORE_TRANSACTION and run octoshield recovery."
    fi
    return "$result"
}

cli::status() {
    local snapshot
    if declare -F status::read >/dev/null && snapshot=$(status::read 2>/dev/null); then
        jq -r '
          "OctoShield — verified system status", "",
          ("Profile: " + (.profiles.active // .profiles.global // "unmanaged")),
          ("Checked: " + (.checked_at | todateiso8601)), "",
          ((.profiles.overrides // {}) | to_entries[] | "Override: \(.key) uses \(.value)"),
          (.controls | to_entries[] | "\(.key): \(.value.state) — \(.value.summary)"), "",
          (.exposures | to_entries[] | "\(.key): \(.value.state) — \(.value.summary)")
        ' <<<"$snapshot"
        return $?
    fi
    printf 'Live status is unavailable or stale. Showing a limited direct inspection.\n\n'
    printf 'OctoShield 1.2.0 — inspection (unknown means not verified)\n\n'
    printf 'Operating system: '
    sed -n 's/^PRETTY_NAME=//p' /etc/os-release
    if command -v ufw >/dev/null; then
        if ((EUID == 0)); then
            ufw status verbose || true
        else printf 'Firewall: run sudo ufw status verbose for effective IPv4/IPv6 policy.\n'; fi
    else printf 'Firewall: UFW is not installed.\n'; fi
    printf '\nSystem services:\n'
    local unit state
    for unit in ufw usbguard apparmor octoshield-monitor apt-daily-upgrade.timer ssh.socket ssh avahi-daemon bluetooth cups; do
        state=$(systemctl is-active "$unit" 2>/dev/null) || true
        printf '  %-26s %s\n' "$unit" "${state:-unknown}"
    done
    printf '\nAppArmor kernel enforcement: '
    if [[ -r /sys/module/apparmor/parameters/enabled ]]; then
        cat /sys/module/apparmor/parameters/enabled
    else printf 'unknown\n'; fi
    printf 'Secure Boot: '
    if command -v mokutil >/dev/null; then mokutil --sb-state 2>&1 || true; else printf 'unknown (mokutil is not installed)\n'; fi
    printf '\nBlock-device encryption topology (verify every sensitive filesystem):\n'
    lsblk -o NAME,TYPE,FSTYPE,MOUNTPOINTS 2>/dev/null || true
    printf '\nListening TCP/UDP sockets (review container-published ports too):\n'
    ss -lntu 2>/dev/null || true
    printf '\nNetwork connections:\n'
    if command -v nmcli >/dev/null; then nmcli -f NAME,UUID,TYPE,AUTOCONNECT connection show || true; fi
    printf '\n'
    if ((EUID != 0)); then desktop::status || true; fi
    printf '\nA service being active is not proof of complete protection. See README limits.\n'
}

cli::install() {
    core::require_local || return 1
    if [[ $OCTOSHIELD_ROOT == /usr/lib/octoshield ]]; then
        core::log 'This copy is managed by Debian. Upgrade it with sudo apt install ./octoshield_VERSION_ARCH.deb.'
        return 0
    fi
    if ((EUID == 0)); then
        core::supported_os || return 1
        install::run || return 1
        core::log 'Installed. Run octoshield from your normal GNOME terminal to configure protections.'
    else
        sudo -- bash "$OCTOSHIELD_ROOT/src/octoshield" install --system || return 1
        /usr/local/bin/octoshield setup
    fi
}

cli::setup() {
    core::require_local || return 1
    if [[ $OCTOSHIELD_ROOT != /usr/local/lib/octoshield && $OCTOSHIELD_ROOT != /usr/lib/octoshield ]]; then
        cli::install
        return $?
    fi
    local choice result
    while :; do
        if command -v whiptail >/dev/null; then
            choice=$(whiptail --title 'OctoShield — laptop security' --menu \
                'Select a protection or adjustment. Each system change is reviewed before applying.' 24 88 15 \
                status 'Inspect current security and listening ports' \
                profiles 'Switch and configure Conference, Office, Home or custom profiles' \
                updates-check 'Check for a new OctoShield release' \
                firewall 'Block unsolicited inbound Wi-Fi/Ethernet traffic' \
                usb 'Enroll trusted USB devices and block unknown devices' \
                network 'Limit automatic connections and network discovery' \
                services 'Disable selected listening and Bluetooth services' \
                desktop 'Lock GNOME promptly and disable media automount' \
                desktop-restore 'Restore your saved GNOME settings' \
                sudo 'Require fresh sudo authentication' \
                updates 'Enable automatic security updates' \
                apparmor 'Activate installed AppArmor confinement profiles' \
                monitor 'Enable system security-event monitoring' \
                notifications 'Enable GNOME security notifications' \
                notifications-off 'Disable GNOME security notifications' \
                monitor-status 'Inspect monitoring and notifications' \
                monitor-logs 'Read the collector log' \
                monitor-off 'Disable the system event collector' \
                devices 'Review/authorize a blocked USB device' \
                backups 'List saved transactions and read action history' \
                office 'Allow selected office access without a global reset' \
                password 'Change your user password' \
                recovery 'Read recovery and backup instructions' 3>&1 1>&2 2>&3) || return 0
        else
            printf '\nChoices: status profiles updates-check firewall usb network services desktop desktop-restore sudo updates apparmor\nmonitor monitor-status monitor-logs monitor-off notifications notifications-off devices backups office password recovery quit\n> '
            IFS= read -r choice || return 0
        fi
        result=0
        case "$choice" in
            quit | '') return 0 ;;
            status) cli::status || result=$? ;;
            profiles) profile_cli::menu || result=$? ;;
            updates-check) updates::show || result=$? ;;
            desktop) desktop::apply || result=$? ;;
            desktop-restore) desktop::restore || result=$? ;;
            notifications) monitor::enable_desktop || result=$? ;;
            notifications-off) monitor::disable_desktop || result=$? ;;
            monitor-status) monitor::status || result=$? ;;
            monitor-logs) cli::system monitor logs || result=$? ;;
            monitor-off) cli::system monitor disable || result=$? ;;
            backups) cli::backup_menu || result=$? ;;
            devices) cli::devices || result=$? ;;
            office) cli::system office-system || result=$? ;;
            password) cli::password || result=$? ;;
            recovery) cli::recovery || result=$? ;;
            *)
                if [[ -n ${CLI_CONTROLS[$choice]+set} ]]; then
                    cli::system apply "$choice" || result=$?
                else core::log 'Unknown choice.'; fi
                ;;
        esac
        ((result == 0)) || core::log 'The selected operation was cancelled or failed. Review the message above.'
        printf '\nPress Enter to return to the menu. '
        IFS= read -r _ || return 0
    done
}

cli::devices() {
    cli::system usb list || return 1
    local id action
    printf '\nReview the device above. Enter its numeric ID (empty cancels): '
    IFS= read -r id || return 1
    [[ -n $id ]] || return 0
    [[ $id =~ ^[0-9]+$ ]] || {
        core::die 'Use a numeric device ID.'
        return 1
    }
    printf 'Action: 1) Allow until unplug/restart/profile switch  2) Remember for current USB profile  3) Block  4) Forget and block\n> '
    IFS= read -r action || return 1
    case "$action" in
        1) cli::system usb allow "$id" ;;
        2) cli::system usb allow "$id" --permanent ;;
        3) cli::system usb block "$id" ;;
        4) cli::system usb forget "$id" ;;
        *) return 1 ;;
    esac
}

cli::backup_menu() {
    local identifier
    cli::system backups || return 1
    printf '\nTransaction ID to inspect (empty returns): '
    IFS= read -r identifier || return 1
    [[ -n $identifier ]] || return 0
    api::valid_backup_id "$identifier" || return 2
    cli::system backup-show "$identifier"
}

cli::password() {
    ((EUID != 0)) || {
        core::die 'Run password changes from your normal user session.'
        return 1
    }
    core::require_local || return 1
    passwd
}

cli::office_system() {
    local choice port subnet uuid
    printf '\n1) Allow one TCP port from an office IPv4 subnet\n2) Enable autoconnect for a trusted saved network\n3) Restore selected disabled service\nChoice: '
    IFS= read -r choice || return 1
    case "$choice" in
        1)
            printf 'TCP port (1–65535): '
            IFS= read -r port || return 1
            printf 'Trusted IPv4 subnet in CIDR notation (example 192.168.1.0/24): '
            IFS= read -r subnet || return 1
            office::firewall "$port" "$subnet"
            ;;
        2)
            nmcli -f NAME,UUID,TYPE,AUTOCONNECT connection show || return 1
            printf 'Trusted connection UUID: '
            IFS= read -r uuid || return 1
            office::network "$uuid"
            ;;
        3)
            printf 'Service (ssh.service, avahi-daemon.service, bluetooth.service, cups.service): '
            IFS= read -r choice || return 1
            office::service "$choice"
            ;;
        *) return 1 ;;
    esac
}

cli::valid_subnet() {
    office::valid_subnet "$@"
}

cli::recovery() {
    cat "$OCTOSHIELD_ROOT/docs/recovery.md"
}

cli::main() {
    local command=${1:-setup}
    (($# == 0)) || shift
    case "$command" in
        --help | -h | help)
            (($# == 0)) || return 2
            cli::usage
            ;;
        --version)
            (($# == 0)) || return 2
            printf 'OctoShield 1.2.0\n'
            ;;
        status)
            if [[ $# -eq 1 && $1 == --json ]]; then
                status::read
            elif (($# == 0)); then
                cli::status
            else return 2; fi
            ;;
        profile)
            if (($# == 0)); then
                profile_cli::menu
            else
                profiles::validate "$@" || return 2
                cli::system profile "$@"
            fi
            ;;
        inspect)
            (($# == 0)) || return 2
            cli::system inspect
            ;;
        updates)
            [[ $# -eq 1 && $1 == check ]] || return 2
            updates::show
            ;;
        setup | password | recovery)
            (($# == 0)) || return 2
            "cli::$command"
            ;;
        install)
            [[ $# -eq 0 || ($# -eq 1 && $1 == --system && $EUID -eq 0) ]] || return 2
            cli::install
            ;;
        apply)
            [[ $# -eq 1 && -n ${CLI_CONTROLS[$1]+set} ]] || {
                cli::usage
                return 2
            }
            cli::system apply "$1"
            ;;
        desktop)
            [[ $# -eq 1 && ($1 == apply || $1 == restore || $1 == status) ]] || return 2
            core::require_local || return 1
            "desktop::$1"
            ;;
        usb)
            case "${1:-}" in
                list | devices) [[ $# -eq 1 ]] || return 2 ;;
                enroll) [[ $# -eq 2 ]] && profiles::valid_name "$2" || return 2 ;;
                allow) [[ ($# -eq 2 || ($# -eq 3 && $3 == --permanent)) && $2 =~ ^[0-9]+$ ]] || return 2 ;;
                block | forget) [[ $# -eq 2 && $2 =~ ^[0-9]+$ ]] || return 2 ;;
                *) return 2 ;;
            esac
            cli::system usb "$@"
            ;;
        monitor)
            [[ $# -eq 1 ]] || return 2
            case "$1" in
                enable-desktop) monitor::enable_desktop ;;
                disable-desktop) monitor::disable_desktop ;;
                status) monitor::status ;;
                logs | disable) cli::system monitor "$1" ;;
                run)
                    core::require_root || return 1
                    monitor::run
                    ;;
                *) return 2 ;;
            esac
            ;;
        office)
            if (($# == 0)); then
                cli::system office-system
            else
                api::validate office "$@" || return 2
                cli::system office "$@"
            fi
            ;;
        office-system)
            (($# == 0 && EUID == 0)) || return 2
            cli::system office-system
            ;;
        backups | backup-show)
            api::validate "$command" "$@" || return 2
            cli::system "$command" "$@"
            ;;
        user-api) user_api::main "$@" ;;
        *)
            core::die "Unknown command: $command (use --help)"
            return 2
            ;;
    esac
}
