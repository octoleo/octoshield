#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Terminal presentation only; all validation and mutation use the shared API.

profile_cli::input() {
    local prompt=$1 initial=${2-} answer
    if command -v whiptail >/dev/null; then
        whiptail --title OctoShield --inputbox "$prompt" 12 82 "$initial" 3>&1 1>&2 2>&3
    else
        printf '%s [%s]: ' "$prompt" "$initial" >/dev/tty || return 1
        IFS= read -r answer </dev/tty || return 1
        printf '%s\n' "${answer:-$initial}"
    fi
}

profile_cli::choice() {
    local title=$1 answer
    shift
    if command -v whiptail >/dev/null; then
        whiptail --title OctoShield --menu "$title" 24 90 15 "$@" 3>&1 1>&2 2>&3
    else
        printf '\n%s\n' "$title" >/dev/tty || return 1
        while (($#)); do
            printf '  %s: %s\n' "$1" "$2" >/dev/tty || return 1
            shift 2
        done
        printf '> ' >/dev/tty || return 1
        IFS= read -r answer </dev/tty || return 1
        [[ -n $answer ]] || return 1
        printf '%s\n' "$answer"
    fi
}

profile_cli::control() {
    profile_cli::choice 'Choose the protection to change' \
        firewall 'Network firewall' usb 'USB device authorization' \
        network 'Network privacy and discovery' services 'Sharing, printing and Bluetooth' \
        monitor 'Security event monitoring'
}

profile_cli::setting() {
    local name=$1 key value
    key=$(profile_cli::choice 'Choose a setting to save in this profile' \
        network.autoconnect 'Saved Wi-Fi autoconnect: false disables, true restores original choices' \
        network.discovery 'Local discovery: false disables, true permits discovery' \
        services.printing 'Printing service policy' services.bluetooth 'Bluetooth service policy' \
        services.ssh 'Incoming SSH service policy' services.discovery 'Local discovery service policy' \
        services.samba 'Samba file sharing service policy' services.remote_desktop 'System remote desktop service policy' \
        monitor.enabled 'Security event monitoring') || return 0
    case "$key" in
        services.*)
            value=$(profile_cli::choice 'Choose the service behavior' \
                baseline 'Restore the original service state' enabled 'Enable the installed service' \
                disabled 'Stop and mask the installed service') || return 0
            ;;
        *) value=$(profile_cli::choice 'Choose the setting value' true 'Enabled / restore original autoconnect choices' false 'Disabled') || return 0 ;;
    esac
    cli::system profile set "$name" "$key" "$value"
}

profile_cli::rule_add() {
    local name=$1 port protocol source interface minutes
    port=$(profile_cli::input 'Incoming destination port (1-65535)' 443) || return 0
    protocol=$(profile_cli::choice 'Network protocol' tcp TCP udp UDP) || return 0
    source=$(profile_cli::input 'Allowed source: an IPv4/IPv6 address or CIDR, or any' any) || return 0
    interface=$(profile_cli::input 'Incoming interface name, or any' any) || return 0
    minutes=$(profile_cli::input 'Expire after minutes (0 means no automatic expiry)' 0) || return 0
    cli::system profile rule-add "$name" "$port" "$protocol" "$source" "$interface" "$minutes"
}

profile_cli::menu() {
    core::require_local || return 1
    local action name base control id result
    while :; do
        action=$(profile_cli::choice 'Profiles: inspect, configure and switch protections' \
            status 'Show verified current status' list 'List all profiles' show 'Show a profile and its rules' \
            apply 'Switch every protection to a profile' override 'Switch one protection to a profile' \
            create 'Create a profile by copying another' setting 'Edit a profile setting' \
            rule-add 'Add a scoped firewall exception' rule-remove 'Remove a firewall exception' \
            enroll 'Review trusted USB devices for a profile' delete 'Delete an unused custom profile' \
            restore 'Restore original settings for one or all protections' back 'Return') || return 0
        result=0
        case "$action" in
            back) return 0 ;;
            status) cli::status || result=$? ;;
            list) cli::system profile list || result=$? ;;
            restore)
                control=$(profile_cli::choice 'Restore the saved pre-profile baseline' \
                    all 'All protections with a saved baseline' firewall Firewall usb USB network Network services Services monitor Monitoring) || continue
                if [[ $control == all ]]; then
                    cli::system profile restore || result=$?
                else cli::system profile restore "$control" || result=$?; fi
                ;;
            apply | override | create | setting | rule-add | rule-remove | enroll | delete | show)
                name=$(profile_cli::input 'Profile identifier: conference, public, office, home, or a custom name' conference) || continue
                case "$action" in
                    apply) cli::system profile apply "$name" || result=$? ;;
                    override)
                        control=$(profile_cli::control) || continue
                        cli::system profile apply "$name" "$control" || result=$?
                        ;;
                    create)
                        base=$(profile_cli::input 'Copy settings from profile' conference) || continue
                        cli::system profile create "$name" "$base" || result=$?
                        ;;
                    setting) profile_cli::setting "$name" || result=$? ;;
                    rule-add) profile_cli::rule_add "$name" || result=$? ;;
                    rule-remove)
                        cli::system profile show "$name" || continue
                        id=$(profile_cli::input 'Firewall rule identifier to remove') || continue
                        cli::system profile rule-remove "$name" "$id" || result=$?
                        ;;
                    enroll) cli::system usb enroll "$name" || result=$? ;;
                    show | delete) cli::system profile "$action" "$name" || result=$? ;;
                esac
                ;;
            *)
                core::log 'Unknown profile action.'
                result=2
                ;;
        esac
        ((result == 0)) || core::log 'The operation was cancelled or failed. Review the result above.'
        printf '\nPress Enter to return to profiles. ' >/dev/tty || return 1
        IFS= read -r _ </dev/tty || return 0
    done
}
