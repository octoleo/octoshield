#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Namespaced modules encapsulate behavior; this registry is the dispatch table.

declare -gAr CLI_CONTROLS=(
    [firewall]=controls::apply_firewall [network]=controls::apply_network
    [services]=controls::apply_services
    [updates]=controls::apply_updates [apparmor]=controls::apply_apparmor
    [usb]=usb::apply [monitor]=monitor::apply
)

cli::usage() {
    cat <<'USAGE'
OctoShield 1.3.4 — Ubuntu laptop protection, part of the OctoLeo suite

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
  access                    Guided service access, edit and revoke permissions
  access list [PROFILE]     Inspect grouped firewall permissions as JSON
  access allow PROFILE PORTS PROTO SOURCE INTERFACE MINUTES
                            Review, apply and verify a permission immediately
  access update PROFILE ID PORTS PROTO SOURCE INTERFACE MINUTES
                            Review and replace one permission
  access revoke PROFILE ID  Revoke a permission immediately
  access recover PROFILE    Review and reapply only this saved firewall profile
  access restore            Review and restore the original firewall settings
  access reconcile PROFILE  Review external firewall changes before recovery
  connections               Select a named connection and adjust privacy
  connections list          Inspect saved and active connection details as JSON
  connections set UUID KEY VALUE
                            Change autoconnect, discovery or MAC choice
  connections reconnect UUID Reconnect after reviewing the interruption
  connections reconcile     Review and accept external saved network changes
  diagnostics               Explain encryption, Docker, forwarding or privacy
  diagnostics show TOPIC    Return private diagnostic details as JSON
  containers                Review localhost port bindings for a Compose service
  containers plan ID        Inspect a localhost binding plan as JSON
  containers localize ID TOKEN Apply a reviewed plan as your normal user
  updates check             Check official releases and show upgrade instructions
  apply CONTROL             firewall|network|services|updates|apparmor|usb|monitor
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
  repair                    Review and repair known retired OctoShield settings
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
    # Compatibility route: menus choose actions before acquiring their locks.
    if [[ $1 == office-system ]]; then
        cli::office_system
        return
    fi
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
    if [[ $1 == office-system ]] || api::mutates "$@"; then
        core::timeout_program >/dev/null || return 1
        core::begin "$*" || return 1
    fi
    local result=0
    case "$1" in
        office-system) cli::office_system || result=$? ;;
        *) api::dispatch "$@" || result=$? ;;
    esac
    if [[ $1 == office-system ]] || api::mutates "$@"; then
        if declare -F status::refresh >/dev/null; then
            core::refresh_status full >/dev/null 2>&1 || core::log 'Live status refresh failed or timed out; the background collector will retry.'
        fi
    fi
    if [[ $1 != office-system ]] && ! api::mutates "$@"; then return "$result"; fi
    if ((result == 0)); then
        core::record 'COMPLETE' || result=1
        core::log "Saved change record: $CORE_STATE/backups/$CORE_TRANSACTION"
    else
        core::record "FAILED exit=$result; inspect changes before retrying" || :
        core::log "Operation failed; inspect $CORE_STATE/backups/$CORE_TRANSACTION and run octoshield recovery."
    fi
    # A root-owned Whiptail menu can outlive one action. Release its locks when
    # that action completes instead of blocking every other app while idle.
    core::end
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
    printf 'OctoShield 1.3.4 — inspection (unknown means not verified)\n\n'
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
                access 'Allow web/SSH access, edit or revoke permissions' \
                connections 'Manage named network connections and privacy' \
                diagnostics 'Explain findings and show their configuration sources' \
                containers 'Bind Docker Compose service ports to localhost' \
                updates-check 'Check for a new OctoShield release' \
                firewall 'Block unsolicited inbound Wi-Fi/Ethernet traffic' \
                usb 'Enroll trusted USB devices and block unknown devices' \
                network 'Limit automatic connections and network discovery' \
                services 'Disable selected listening and Bluetooth services' \
                desktop 'Lock GNOME promptly and disable media automount' \
                desktop-restore 'Restore your saved GNOME settings' \
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
                repair 'Review and repair known retired OctoShield settings' \
                office 'Allow selected office access without a global reset' \
                password 'Change your user password' \
                recovery 'Read recovery and backup instructions' 3>&1 1>&2 2>&3) || return 0
        else
            printf '\nChoices: status profiles access connections diagnostics containers updates-check firewall usb network services desktop desktop-restore updates apparmor\nmonitor monitor-status monitor-logs monitor-off notifications notifications-off devices backups repair office password recovery quit\n> '
            IFS= read -r choice || return 0
        fi
        result=0
        case "$choice" in
            quit | '') return 0 ;;
            status) cli::status || result=$? ;;
            profiles) profile_cli::menu || result=$? ;;
            access) cli::access_menu || result=$? ;;
            connections) cli::connections_menu || result=$? ;;
            diagnostics) cli::diagnostics_menu || result=$? ;;
            containers) cli::containers_menu || result=$? ;;
            updates-check) updates::show || result=$? ;;
            desktop) desktop::apply || result=$? ;;
            desktop-restore) desktop::restore || result=$? ;;
            notifications) monitor::enable_desktop || result=$? ;;
            notifications-off) monitor::disable_desktop || result=$? ;;
            monitor-status) monitor::status || result=$? ;;
            monitor-logs) cli::system monitor logs || result=$? ;;
            monitor-off) cli::system monitor disable || result=$? ;;
            backups) cli::backup_menu || result=$? ;;
            repair) cli::system repair || result=$? ;;
            devices) cli::devices || result=$? ;;
            office) cli::office_system || result=$? ;;
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
    local choice
    printf '\n1) Manage firewall access\n2) Manage connection privacy\n3) Restore selected disabled service\nChoice: '
    IFS= read -r choice || return 1
    case "$choice" in
        1) cli::access_menu ;;
        2) cli::connections_menu ;;
        3)
            printf 'Service (ssh.service, avahi-daemon.service, bluetooth.service, cups.service): '
            IFS= read -r choice || return 1
            office::valid_service "$choice" || return 2
            cli::system office service "$choice"
            ;;
        *) return 1 ;;
    esac
}

# Menus use short numeric choices. Device-provided labels are display text,
# never shell input, and control/formatting characters are removed for terminals.
cli::safe_text() {
    jq -r 'gsub("[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u2028-\u202e\u2060-\u206f]"; " ")'
}
cli::select_item() {
    local prompt=$1 items=$2 count choice
    count=$(jq -er 'select(type=="array")|length' <<<"$items") || return 1
    ((count > 0 && count <= 512)) || {
        core::log 'No selectable items were found.' >&2
        return 1
    }
    jq -r 'to_entries[] | "\(.key+1)) " + (.value.label|gsub("[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u2028-\u202e\u2060-\u206f]";" "))' <<<"$items" >&2 || return 1
    printf '%s (empty cancels): ' "$prompt" >&2
    IFS= read -r choice || return 1
    [[ -n $choice ]] || return 1
    if [[ ! $choice =~ ^[1-9][0-9]{0,2}$ ]] || ((10#$choice > count)); then
        core::log 'Choose a number from the list.' >&2
        return 1
    fi
    jq -c --argjson index "$((10#$choice - 1))" '.[$index]' <<<"$items"
}

cli::access_menu() {
    local document profile action selected identifier='' ports protocol=tcp source interface minutes networks choices scope transaction
    core::require_local || return 1
    document=$(cli::system access list) || return 1
    profile=$(jq -er '.profile' <<<"$document") || return 1
    printf '\nFirewall profile: %s\n' "$profile"
    jq '.summary' <<<"$document" | cli::safe_text || return 1
    jq '.recovery.observed.summary//"Native inspection unavailable."' <<<"$document" | cli::safe_text || return 1
    jq '.recovery.message//"No earlier operation details are available."' <<<"$document" | cli::safe_text || return 1
    jq -r '.rules[]|"  \(.label) — \(.state), from \(.source), interface \(.interface)"' <<<"$document"
    printf '\n1) Allow a service\n2) Edit a permission\n3) Revoke a permission\n4) Inspect current firewall\n5) Review and apply selected firewall profile\n6) Restore original firewall settings\n7) Review external firewall changes\n8) Inspect last firewall change\nChoice (empty returns): '
    IFS= read -r action || return 1
    [[ -n $action ]] || return 0
    case "$action" in
        1 | 2 | 3)
            jq -e '.ready==true' <<<"$document" >/dev/null || {
                core::die 'Firewall recovery is required before editing permissions. Use the recovery choices in this menu.'
                return 1
            }
            ;;
        4)
            cli::system access list "$profile"
            return
            ;;
        5)
            cli::system access recover "$profile"
            return
            ;;
        6)
            cli::system access restore
            return
            ;;
        7)
            cli::system access reconcile "$profile"
            return
            ;;
        8)
            transaction=$(jq -r '.recovery.transaction//""' <<<"$document") || return 1
            profiles::valid_transaction "$transaction" || {
                core::die 'No verified transaction reference is available for this older result. Inspect Recovery and the saved change records.'
                return 1
            }
            cli::system backup-show "$transaction"
            return
            ;;
    esac
    case "$action" in
        1) action=allow ;;
        2 | 3)
            choices=$(jq -c '[.rules[]|.label += (" — "+.state+", "+.source+", "+.interface)]' <<<"$document") || return 1
            selected=$(cli::select_item 'Permission' "$choices") || return 0
            identifier=$(jq -er .id <<<"$selected") || return 1
            if [[ $action == 3 ]]; then
                cli::system access revoke "$profile" "$identifier"
                return
            fi
            action=update
            ;;
        *) return 2 ;;
    esac
    printf '\n1) Web server — HTTP + HTTPS (TCP 80,443)\n2) Incoming SSH (TCP 22)\n3) Custom ports\nService: '
    IFS= read -r selected || return 1
    case "$selected" in
        1) ports=80,443 ;;
        2) ports=22 ;;
        3)
            printf 'Ports separated by commas: '
            IFS= read -r ports || return 1
            printf 'Protocol (tcp or udp): '
            IFS= read -r protocol || return 1
            ;;
        *) return 2 ;;
    esac
    printf '\nWho may connect?\n1) Devices on a selected local network\n2) A specific address or subnet\n3) Any source (all reachable networks)\nScope: '
    IFS= read -r scope || return 1
    case "$scope" in
        1)
            networks=$(cli::system connections list) || return 1
            choices=$(jq -c '[.connections[]|select(.active and .lan_candidate) as $c|.subnets[]|{source:.,interface:$c.interface,label:($c.name+" · "+$c.interface+" · "+.)}]' <<<"$networks") || return 1
            selected=$(cli::select_item 'Network and address family' "$choices") || return 0
            source=$(jq -er .source <<<"$selected") interface=$(jq -er .interface <<<"$selected") || return 1
            ;;
        2)
            printf 'Source IPv4/IPv6 address or CIDR: '
            IFS= read -r source || return 1
            printf 'Incoming interface (or any): '
            IFS= read -r interface || return 1
            ;;
        3) source=any interface=any ;;
        *) return 2 ;;
    esac
    printf 'Duration in minutes (Enter = 60, 0 = permanent): '
    IFS= read -r minutes || return 1
    minutes=${minutes:-60}
    if [[ $action == update ]]; then
        access::validate update "$profile" "$identifier" "$ports" "$protocol" "$source" "$interface" "$minutes" || return 2
        cli::system access update "$profile" "$identifier" "$ports" "$protocol" "$source" "$interface" "$minutes"
    else
        access::validate allow "$profile" "$ports" "$protocol" "$source" "$interface" "$minutes" || return 2
        cli::system access allow "$profile" "$ports" "$protocol" "$source" "$interface" "$minutes"
    fi
}

cli::connections_menu() {
    local document choices selected uuid action value
    core::require_local || return 1
    document=$(cli::system connections list) || return 1
    choices=$(jq -c '[.connections[]|. + {label:(.name+" · "+.type+" · "+(if .active then .interface else "disconnected" end))}]' <<<"$document") || return 1
    selected=$(cli::select_item 'Connection' "$choices") || return 0
    uuid=$(jq -er .uuid <<<"$selected") || return 1
    jq -r '["Automatic connection: "+.autoconnect,"Discovery: mDNS "+.mdns+", LLMNR "+.llmnr,"MAC choice: "+.mac,.runtime.summary][]|gsub("[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u2028-\u202e\u2060-\u206f]";" ")' <<<"$selected" || return 1
    printf '\n1) Automatic connection\n2) Local discovery\n3) Wi-Fi MAC choice\n4) Reconnect now\n5) Review external network changes\nChoice (empty returns): '
    IFS= read -r action || return 1
    case "$action" in
        '') return 0 ;;
        1 | 2)
            printf '1) Enabled\n2) Disabled\nChoice: '
            IFS= read -r value || return 1
            case "$value" in 1) value=true ;; 2) value=false ;; *) return 2 ;; esac
            if [[ $action == 1 ]]; then action=autoconnect; else action=discovery; fi
            cli::system connections set "$uuid" "$action" "$value"
            ;;
        3)
            printf '1) Stable private address\n2) Hardware address (registered networks)\nChoice: '
            IFS= read -r value || return 1
            case "$value" in 1) value=stable ;; 2) value=permanent ;; *) return 2 ;; esac
            cli::system connections set "$uuid" mac "$value"
            ;;
        4) cli::system connections reconnect "$uuid" ;;
        5) cli::system connections reconcile ;;
        *) return 2 ;;
    esac
}

cli::diagnostics_menu() {
    local topic document
    core::require_local || return 1
    printf '\n1) Disk encryption\n2) Docker published ports\n3) Network forwarding\n4) Connection privacy\nTopic (empty returns): '
    IFS= read -r topic || return 1
    case "$topic" in '') return 0 ;; 1) topic=disk_encryption ;; 2) topic=containers ;; 3) topic=forwarding ;; 4) topic=network ;; *) return 2 ;; esac
    document=$(cli::system diagnostics show "$topic") || return 1
    jq -r '[.title,.summary, (.findings[]|"\n"+.title+" ["+.state+"]",.detail,(if .source!="" then "Source: "+.source else empty end),(if .action!="" then "Next step: "+.action else empty end))][]|gsub("[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u200b-\u200f\u2028-\u202e\u2060-\u206f]";" ")' <<<"$document"
}

cli::containers_menu() {
    local document choices selected identifier plan token
    core::require_local || return 1
    ((EUID != 0)) || {
        core::die 'Run container repairs as your normal desktop user, without sudo.'
        return 1
    }
    document=$(cli::system diagnostics show containers) || return 1
    choices=$(jq -c '[.findings[]|select(.fix=="localize")|select((.container_id//"")|test("^[a-f0-9]{64}$"))|{id:.container_id,label:.title}]|unique_by(.id)' <<<"$document") || return 1
    selected=$(cli::select_item 'Service to review for localhost port bindings' "$choices") || return 0
    identifier=$(jq -er .id <<<"$selected") || return 1
    plan=$(containers::dispatch plan "$identifier") || return 1
    # The shared localize operation repeats its concrete review and confirmation.
    # No token or configuration path needs to be copied into a terminal command.
    token=$(jq -er '.token' <<<"$plan") || return 1
    containers::dispatch localize "$identifier" "$token"
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
            printf 'OctoShield 1.3.4\n'
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
        access | connections | diagnostics)
            if (($# == 0)); then
                "cli::${command}_menu"
            else
                "${command}::validate" "$@" || return 2
                cli::system "$command" "$@"
            fi
            ;;
        containers)
            core::require_local || return 1
            if (($# == 0)); then
                cli::containers_menu
            else
                containers::validate "$@" || return 2
                containers::dispatch "$@"
            fi
            ;;
        inspect | repair)
            (($# == 0)) || return 2
            cli::system "$command"
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
                cli::office_system
            else
                api::validate office "$@" || return 2
                cli::system office "$@"
            fi
            ;;
        office-system)
            (($# == 0 && EUID == 0)) || return 2
            cli::office_system
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
