#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Private, unprivileged GUI route. Never invokes sudo or sources user settings.

user_api::validate() {
    case "${1-}" in
        desktop)
            [[ $# -eq 2 ]] || return 1
            case "$2" in apply | restore | status) return 0 ;; esac
            ;;
        monitor)
            [[ $# -eq 2 ]] || return 1
            case "$2" in enable-desktop | disable-desktop | status) return 0 ;; esac
            ;;
        recovery) [[ $# -eq 1 ]] && return 0 ;;
        status) [[ $# -eq 1 ]] && return 0 ;;
        updates) [[ $# -eq 2 && $2 == check ]] && return 0 ;;
    esac
    return 1
}

user_api::dispatch() {
    case "$1 ${2-}" in
        'desktop apply') desktop::apply ;;
        'desktop restore') desktop::restore ;;
        'desktop status') desktop::status ;;
        'monitor enable-desktop') monitor::enable_desktop ;;
        'monitor disable-desktop') monitor::disable_desktop ;;
        'monitor status') monitor::status ;;
        'recovery ') cli::recovery ;;
        'status ') status::read ;;
        'updates check') updates::check ;;
        *) return 2 ;;
    esac
}

user_api::main() (
    if ((EUID == 0)) || [[ -n ${SSH_CONNECTION:-}${SSH_CLIENT:-}${SSH_TTY:-} ]] || ! user_api::validate "$@"; then
        printf '%s\n' '{"type":"log","text":"Invalid user action or session. Open OctoShield as your local desktop user."}' '{"type":"done","success":false}'
        return 2
    fi
    # GNOME mutations enforce their own schema/session checks. Monitoring and
    # recovery also work from other local desktops without borrowing root's bus.
    api::serve user_api::dispatch "$@"
)
