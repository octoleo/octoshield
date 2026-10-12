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
Octoshield 0.1.0 — Ubuntu laptop protection, part of the OctoLeo suite

Usage: octoshield [COMMAND]
  setup                     Guided setup and later adjustments (default)
  install                   Install this checkout and open guided setup
  status                    Inspect protections and listening services
  apply CONTROL             firewall|network|services|sudo|updates|apparmor|usb|monitor
  desktop apply|restore     Configure or restore this user's GNOME settings
  usb list                  List USB devices and authorization state
  usb allow ID [--permanent] Authorize a reviewed device (temporary by default)
  usb block ID              Block a device
  monitor enable-desktop    Enable security notifications for this user
  monitor disable-desktop   Disable this user's notifications
  monitor status            Inspect monitor and desktop notification services
  office                    Guided, narrowly scoped office access changes
  password                  Change your password using the system passwd tool
  backups                   List private system configuration snapshots
  recovery                  Show recovery instructions
  --help | --version

Run from your normal GNOME terminal. System changes request sudo; desktop
settings and notifications remain in your own user session. No automatic
weakening occurs when you return to the office. Review each selected change.
USAGE
}

cli::system() {
    core::require_local || return 1
    if ((EUID != 0)); then
        [[ -x /usr/local/bin/octoshield ]] || {
            core::die 'Install first: bash src/octoshield install'
            return 1
        }
        # Expire the caller's cached timestamp for device authorization.
        if [[ ${1:-} == usb && ${2:-} == allow ]]; then
            sudo -k -- /usr/local/bin/octoshield "$@"
        else
            sudo -- /usr/local/bin/octoshield "$@"
        fi
        return $?
    fi
    core::supported_os || return 1
    core::begin "$*" || return 1
    local result=0
    case "$1" in
        apply) "${CLI_CONTROLS[$2]}" || result=$? ;;
        usb)
            case "$2" in
                list) usb::list || result=$? ;;
                allow) usb::allow "${@:3}" || result=$? ;;
                block) usb::block "$3" || result=$? ;;
            esac
            ;;
        office-system) cli::office_system || result=$? ;;
    esac
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
    printf 'Octoshield 0.1.0 — inspection (unknown means not verified)\n\n'
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
    if command -v nmcli >/dev/null; then nmcli -f NAME,TYPE,AUTOCONNECT connection show || true; fi
    printf '\n'
    if ((EUID != 0)); then desktop::status || true; fi
    printf '\nA service being active is not proof of complete protection. See README limits.\n'
}

cli::install() {
    core::require_local || return 1
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
    if [[ $OCTOSHIELD_ROOT != /usr/local/lib/octoshield ]]; then
        cli::install
        return $?
    fi
    local choice result
    while :; do
        if command -v whiptail >/dev/null; then
            choice=$(whiptail --title 'Octoshield — laptop security' --menu \
                'Select a protection or adjustment. Each system change is reviewed before applying.' 24 88 15 \
                status 'Inspect current security and listening ports' \
                firewall 'Block unsolicited inbound Wi-Fi/Ethernet traffic' \
                usb 'Enroll trusted USB devices and block unknown devices' \
                network 'Limit automatic connections and network discovery' \
                services 'Disable selected listening and Bluetooth services' \
                desktop 'Lock GNOME promptly and disable media automount' \
                sudo 'Require fresh sudo authentication' \
                updates 'Enable automatic security updates' \
                apparmor 'Activate installed AppArmor confinement profiles' \
                monitor 'Enable system security-event monitoring' \
                notifications 'Enable GNOME security notifications' \
                devices 'Review/authorize a blocked USB device' \
                office 'Allow selected office access without a global reset' \
                password 'Change your user password' \
                recovery 'Read recovery and backup instructions' 3>&1 1>&2 2>&3) || return 0
        else
            printf '\nChoices: status firewall usb network services desktop sudo updates apparmor\nmonitor notifications devices office password recovery quit\n> '
            IFS= read -r choice || return 0
        fi
        result=0
        case "$choice" in
            quit | '') return 0 ;;
            status) cli::status || result=$? ;;
            desktop) desktop::apply || result=$? ;;
            notifications) monitor::enable_desktop || result=$? ;;
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
    local id
    printf '\nReview the device above. Enter its numeric ID to allow until unplug/restart (empty cancels): '
    IFS= read -r id || return 1
    [[ -n $id ]] || return 0
    [[ $id =~ ^[0-9]+$ ]] || {
        core::die 'Use a numeric device ID.'
        return 1
    }
    cli::system usb allow "$id"
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
    local choice port subnet uuid unit load_state
    local -a units=()
    printf '\n1) Allow one TCP port from an office IPv4 subnet\n2) Enable autoconnect for a trusted saved network\n3) Restore selected disabled service\nChoice: '
    IFS= read -r choice || return 1
    case "$choice" in
        1)
            printf 'TCP port (1–65535): '
            IFS= read -r port || return 1
            [[ $port =~ ^[1-9][0-9]{0,4}$ ]] && ((10#$port <= 65535)) || return 1
            printf 'Trusted IPv4 subnet in CIDR notation (example 192.168.1.0/24): '
            IFS= read -r subnet || return 1
            cli::valid_subnet "$subnet" || {
                core::die 'Invalid subnet; /0 is intentionally refused.'
                return 1
            }
            core::confirm "Allow TCP $port only from $subnet?" || return 1
            core::backup /etc/ufw || return 1
            ufw allow from "$subnet" to any port "$port" proto tcp || return 1
            core::record "OFFICE firewall tcp/$port from $subnet"
            ;;
        2)
            nmcli -f NAME,UUID,TYPE,AUTOCONNECT connection show || return 1
            printf 'Trusted connection UUID: '
            IFS= read -r uuid || return 1
            [[ $uuid =~ ^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$ ]] || return 1
            core::confirm "Enable autoconnect for $uuid?" || return 1
            core::backup /etc/NetworkManager/system-connections || return 1
            nmcli connection modify uuid "$uuid" connection.autoconnect yes || return 1
            core::record "OFFICE autoconnect $uuid"
            ;;
        3)
            printf 'Service (ssh.service, avahi-daemon.service, bluetooth.service, cups.service): '
            IFS= read -r choice || return 1
            case "$choice" in ssh.service | avahi-daemon.service | bluetooth.service | cups.service) ;; *) return 1 ;; esac
            core::confirm "Unmask and start $choice? Firewall exceptions must be configured separately." || return 1
            case "$choice" in
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
            systemctl enable --now "$choice" || return 1
            core::record "OFFICE service $choice"
            ;;
        *) return 1 ;;
    esac
}

cli::valid_subnet() {
    local subnet=$1 octet prefix
    local -a octets
    [[ $subnet =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[12][0-9]|3[0-2])$ ]] || return 1
    prefix=${subnet##*/}
    ((10#$prefix > 0)) || return 1
    IFS='.' read -r -a octets <<<"${subnet%/*}"
    for octet in "${octets[@]}"; do
        ((10#$octet <= 255)) || return 1
    done
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
            printf 'Octoshield 0.1.0\n'
            ;;
        setup | status | password | recovery)
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
                list) [[ $# -eq 1 ]] || return 2 ;;
                allow) [[ ($# -eq 2 || ($# -eq 3 && $3 == --permanent)) && $2 =~ ^[0-9]+$ ]] || return 2 ;;
                block) [[ $# -eq 2 && $2 =~ ^[0-9]+$ ]] || return 2 ;;
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
                run)
                    core::require_root || return 1
                    monitor::run
                    ;;
                *) return 2 ;;
            esac
            ;;
        office)
            (($# == 0)) || return 2
            cli::system office-system
            ;;
        office-system)
            (($# == 0 && EUID == 0)) || return 2
            cli::system office-system
            ;;
        backups)
            (($# == 0)) || return 2
            if ((EUID == 0)); then core::backups; else sudo -- /usr/local/bin/octoshield backups; fi
            ;;
        *)
            core::die "Unknown command: $command (use --help)"
            return 2
            ;;
    esac
}
