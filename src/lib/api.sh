#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Private GUI adapter. All actions use the same modules as the terminal frontend.

api::valid_backup_id() {
    [[ ${#1} -le 40 && $1 =~ ^[0-9]{8}T[0-9]{6}Z-[1-9][0-9]*$ ]]
}

api::validate() {
    case "${1-}" in
        apply)
            [[ $# -eq 2 ]] || return 1
            case "$2" in firewall | network | services | sudo | updates | apparmor | usb | monitor) return 0 ;; esac
            ;;
        usb)
            case "${2-}" in
                list | devices) [[ $# -eq 2 ]] && return 0 ;;
                enroll) [[ $# -eq 3 ]] && profiles::valid_name "$3" && return 0 ;;
                approve | revoke)
                    [[ $# -eq 6 && $4 =~ ^[a-f0-9]{64}$ ]] || return 1
                    usb::_validate_id "$3" >/dev/null 2>&1 && profiles::valid_name "$5" || return 1
                    case "$2:$6" in approve:once | approve:profile | revoke:block | revoke:forget) return 0 ;; esac
                    ;;
                allow)
                    [[ $# -eq 3 || ($# -eq 4 && $4 == --permanent) ]] || return 1
                    usb::_validate_id "$3" >/dev/null 2>&1 && return 0
                    ;;
                block | forget) [[ $# -eq 3 ]] && usb::_validate_id "$3" >/dev/null 2>&1 && return 0 ;;
            esac
            ;;
        profile) profiles::validate "${@:2}" && return 0 ;;
        office)
            case "${2-}" in
                firewall) [[ $# -eq 4 ]] && office::valid_port "$3" && office::valid_subnet "$4" && return 0 ;;
                network) [[ $# -eq 3 ]] && office::valid_uuid "$3" && return 0 ;;
                service) [[ $# -eq 3 ]] && office::valid_service "$3" && return 0 ;;
            esac
            ;;
        backups | status | inspect) [[ $# -eq 1 ]] && return 0 ;;
        backup-show) [[ $# -eq 2 ]] && api::valid_backup_id "$2" && return 0 ;;
        monitor)
            [[ $# -eq 2 ]] || return 1
            case "$2" in status | logs | disable) return 0 ;; esac
            ;;
    esac
    return 1
}

api::mutates() {
    case "$1 ${2-}" in
        'profile '*) profiles::mutates "${@:2}" ;;
        'apply '* | 'office '* | 'usb allow' | 'usb block' | 'usb forget' | 'usb enroll' | 'usb approve' | 'usb revoke' | 'monitor disable') return 0 ;;
        *) return 1 ;;
    esac
}

# FD3 is the sole protocol output. Every JSON record is serialized under a lock
# opened afresh, including records produced by synchronous pipeline children.
api::event() {
    local type=$1 text=${2-} prompt=${3:-0}
    {
        flock -x 8 || return 1
        jq -cn --arg type "$type" --arg text "$text" --argjson prompt "$prompt" '
            if $type == "done" then {type:$type,success:($text == "true")}
            else {type:$type,text:($text | gsub("[\u0000-\u0008\u000b-\u001f\u007f]"; "") | .[0:4096])}
                | if $type == "confirm" then . + {id:$prompt} else . end
            end' >&3
    } 8>"$API_DIRECTORY/events.lock"
}

# Native command output is captured in a private file. Flush it synchronously
# before every prompt, so the GUI sees the exact USB review before its question.
# FD7 retains its read offset as commands append; no concurrent output pump is
# needed and raw device strings can never become protocol records.
api::flush() {
    local line
    while IFS= read -r -n 4096 line <&7 || [[ -n $line ]]; do
        api::event log "$line" || return 1
    done
}

api::confirm() {
    local answer
    api::flush || return 1
    ((API_CONFIRM_ID < 2147483647)) || return 1
    API_CONFIRM_ID=$((API_CONFIRM_ID + 1))
    api::event confirm "$*" "$API_CONFIRM_ID" || return 1
    # The dedicated descriptor cannot be consumed by apt, ufw, or other commands.
    # Limit reads so malformed input cannot allocate an unbounded shell string.
    IFS= read -r -n 32 answer <&4 || return 1
    [[ $answer == "$API_CONFIRM_ID yes" ]]
}

api::backup_show() {
    local directory="$CORE_STATE/backups/$1" file="$CORE_STATE/backups/$1/actions.log" owner
    api::valid_backup_id "$1" || return 1
    [[ -d $directory && ! -L $directory && -f $file && ! -L $file ]] || {
        core::die 'That backup action log does not exist or is not a regular file.'
        return 1
    }
    owner=$(stat -c %u -- "$file") || return 1
    [[ $owner -eq 0 ]] || {
        core::die 'The backup action log is not root-owned.'
        return 1
    }
    # Configuration snapshots may contain secrets. Only action history is shown.
    head -c 262144 -- "$file" || return 1
}

api::inspect() (
    if declare -F status::refresh >/dev/null; then
        core::package_available || return 1
        if [[ -e $CORE_STATE/lock || -L $CORE_STATE/lock ]]; then
            core::private_directory "$CORE_STATE" && core::safe_lock "$CORE_STATE/lock" || return 1
            exec 8<"$CORE_STATE/lock" || return 1
            flock --shared --nonblock 8 || {
                core::die 'Another OctoShield operation is still running.'
                return 1
            }
        fi
        status::refresh || return 1
    fi
    cli::status
)

api::dispatch() {
    case "$1" in
        apply) "${CLI_CONTROLS[$2]}" ;;
        profile) profiles::dispatch "${@:2}" ;;
        usb)
            case "$2" in
                list) usb::list ;;
                devices) usb::devices_json ;;
                enroll) usb::profile_enroll "$3" ;;
                approve) usb::approve "${@:3}" ;;
                revoke) usb::revoke "${@:3}" ;;
                allow) usb::allow "${@:3}" ;;
                block) usb::block "$3" ;;
                forget) usb::forget "$3" ;;
            esac
            ;;
        office)
            case "$2" in
                firewall) office::firewall "$3" "$4" ;;
                network) office::network "$3" ;;
                service) office::service "$3" ;;
            esac
            ;;
        backups) core::backups ;;
        backup-show) api::backup_show "$2" ;;
        status | inspect) api::inspect ;;
        monitor)
            case "$2" in
                status) monitor::status ;;
                logs) monitor::logs ;;
                disable) monitor::disable ;;
            esac
            ;;
        *) return 2 ;;
    esac
}

api::operation() {
    local result=0
    core::require_root || return 1
    core::supported_os || return 1
    if api::mutates "$@"; then
        core::begin "GUI $*" || return 1
    fi
    api::dispatch "$@" || result=$?
    # The background reader cannot take a coherent snapshot during a mutation.
    # Refresh synchronously under our existing operation lock before completion.
    if api::mutates "$@" && declare -F status::refresh >/dev/null; then
        if [[ $1 == usb ]] && declare -F status::refresh_usb >/dev/null; then
            status::refresh_usb >/dev/null 2>&1 || core::log 'USB status refresh failed; the background collector will retry.'
        else
            status::refresh >/dev/null 2>&1 || core::log 'Live status refresh failed; the background collector will retry.'
        fi
    fi
    if api::mutates "$@"; then
        if ((result == 0)); then
            core::record 'COMPLETE' || result=1
        else
            core::record "FAILED exit=$result; inspect changes before retrying" || :
        fi
        core::log "Saved change record: $CORE_STATE/backups/$CORE_TRANSACTION" || result=1
    fi
    return "$result"
}

api::interrupted() {
    # Best effort only: native package/service commands may already have changed
    # state. A disconnected GUI must not make signal handling block on a pipe.
    if [[ -n ${CORE_TRANSACTION:-} ]]; then
        core::record "INTERRUPTED signal=$1; inspect partial changes before retrying" || :
    fi
    exit "$2"
}

# Shared transport for the two fixed, trusted adapters. Run in a subshell so
# protocol overrides never leak into the terminal CLI or caller's environment.
# Callbacks below are invoked indirectly by the shared control modules.
# shellcheck disable=SC2317,SC2329
api::serve() (
    local callback=${1-} result=0 base=/run API_DIRECTORY API_CONFIRM_ID=0
    case "$callback" in api::operation | user_api::dispatch) ;; *) return 2 ;; esac
    shift
    exec 3>&1 4<&0
    if ((EUID != 0)); then base=${XDG_RUNTIME_DIR:-/tmp}; fi
    [[ $base == /* && -d $base ]] || return 1
    API_DIRECTORY=$(mktemp -d "$base/octoshield-gui.XXXXXXXX") || return 1
    trap 'rm -rf -- "$API_DIRECTORY"' EXIT
    chmod 0700 "$API_DIRECTORY" || return 1
    trap 'api::interrupted INT 130' INT
    trap 'api::interrupted TERM 143' TERM
    trap 'api::interrupted HUP 129' HUP
    : >"$API_DIRECTORY/output" || return 1
    exec 7<"$API_DIRECTORY/output" || return 1
    core::confirm() { api::confirm "$@"; }
    core::log() {
        api::flush || return 1
        api::event log "OctoShield: $*"
    }
    if [[ $callback == api::operation ]]; then
        # Preserve conffiles and keep package prompts off the GUI protocol.
        apt-get() {
            DEBIAN_FRONTEND=noninteractive command apt-get -o Dpkg::Options::=--force-confold "$@" </dev/null
        }
    fi
    "$callback" "$@" >>"$API_DIRECTORY/output" 2>&1 </dev/null || result=$?
    api::flush || result=1
    if ((result == 0)); then
        api::event 'done' true || return 1
    else api::event 'done' false || return 1; fi
    return "$result"
)

api::main() {
    # Validate before creating state, acquiring locks, or running any action.
    if ! api::validate "$@"; then
        printf '%s\n' '{"type":"log","text":"Invalid helper action or arguments."}' '{"type":"done","success":false}'
        return 2
    fi
    core::require_root || return 1
    api::serve api::operation "$@"
}
