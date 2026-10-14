#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Shared infrastructure. Files in this directory are sourced, never executed.

CORE_STATE=/var/lib/octoshield
CORE_TRANSACTION=
CORE_APT_UPDATED=0
CORE_PACKAGE_MAINTENANCE=/run/octoshield-package-maintenance

core::log() { printf 'OctoShield: %s\n' "$*" >&2; }
core::die() {
    core::log "ERROR: $*"
    return 1
}

core::require_root() {
    [[ $EUID -eq 0 ]] || {
        core::die 'Administrator privileges are required.'
        return 1
    }
}

core::require_local() {
    [[ -z ${SSH_CONNECTION:-}${SSH_CLIENT:-}${SSH_TTY:-} ]] || {
        core::die 'Run security changes at the laptop console, not through SSH.'
        return 1
    }
    [[ -t 0 && -t 1 ]] || {
        core::die 'An interactive local terminal is required.'
        return 1
    }
}

core::confirm() {
    local answer
    printf '\n%s\nType yes to continue: ' "$*" >/dev/tty || return 1
    IFS= read -r answer </dev/tty || return 1
    [[ $answer == yes ]]
}

core::supported_os() {
    local key value distro='' version=''
    while IFS='=' read -r key value; do
        value=${value#\"}
        value=${value%\"}
        case "$key" in ID) distro=$value ;; VERSION_ID) version=$value ;; esac
    done </etc/os-release
    [[ $distro == ubuntu && ($version == 24.04 || $version == 26.04) ]] || {
        core::die "Supported targets: Ubuntu 24.04 and 26.04; found $distro $version."
        return 1
    }
    [[ -d /run/systemd/system ]] || {
        core::die 'A booted systemd host is required for installation and hardening.'
        return 1
    }
}

# One process owns all system mutations. User settings use their own user lock.
core::package_available() {
    [[ ! -e $CORE_PACKAGE_MAINTENANCE && ! -L $CORE_PACKAGE_MAINTENANCE ]] || {
        core::die 'An OctoShield package update or removal is in progress. Finish or repair the APT operation before changing protections; see the recovery guide if it was interrupted.'
        return 1
    }
}

core::private_directory() {
    local directory=$1 metadata
    if [[ -e $directory || -L $directory ]]; then
        [[ -d $directory && ! -L $directory ]] || return 1
        metadata=$(stat -c '%u:%a' -- "$directory") || return 1
        [[ $metadata =~ ^0:([0-7]{3,4})$ ]] || return 1
        (((8#${BASH_REMATCH[1]} & 077) == 0)) || return 1
    else
        install -d -m 0700 -o root -g root -- "$directory" || return 1
    fi
}

core::safe_lock() {
    local file=$1 metadata
    [[ ! -L $file ]] || return 1
    if [[ -e $file ]]; then
        [[ -f $file ]] || return 1
        metadata=$(stat -c '%u:%a:%h' -- "$file") || return 1
        [[ $metadata =~ ^0:([0-7]{3,4}):1$ ]] || return 1
        (((8#${BASH_REMATCH[1]} & 077) == 0)) || return 1
    fi
}

# Readers hold the admission lock only while acquiring their shared operation
# lock. A writer keeps admission exclusive while existing readers drain and
# throughout its transaction, so repeated background refreshes cannot starve it.
# Descriptors 6, 8 and 9 are reserved for admission, reading and writing here.
core::read_end() { exec 8>&-; }

core::end() {
    exec 9>&- 6>&-
    CORE_TRANSACTION=
}

core::read_begin() {
    local result=0
    core::require_root || return 1
    core::package_available || return 1
    umask 077
    if ! core::private_directory "$CORE_STATE" || ! core::safe_lock "$CORE_STATE/lock" ||
        ! core::safe_lock "$CORE_STATE/lock-admission"; then
        core::die 'State and locks must be private root-owned paths without symlinks or shared links.'
        return 1
    fi
    exec 6>>"$CORE_STATE/lock-admission" || return 1
    flock --shared --nonblock --conflict-exit-code 75 6 || result=$?
    if ((result != 0)); then
        exec 6>&-
        if ((result == 75)); then return 75; fi
        core::die 'Cannot acquire the status admission lock.'
        return 1
    fi
    if ! exec 8>>"$CORE_STATE/lock"; then
        exec 6>&-
        return 1
    fi
    flock --shared --nonblock --conflict-exit-code 75 8 || result=$?
    # Do not retain shared admission while inspecting: the next writer must be
    # able to close admission to new readers immediately.
    exec 6>&-
    if ((result != 0)); then
        core::read_end
        if ((result == 75)); then return 75; fi
        core::die 'Cannot acquire the status operation lock.'
        return 1
    fi
    if ! core::package_available; then
        core::read_end
        return 1
    fi
}

core::_begin() {
    local admission_wait=$1 reader_wait=$2 result=0
    shift 2
    core::require_root || return 1
    core::package_available || return 1
    umask 077
    if ! core::private_directory "$CORE_STATE" || ! core::private_directory "$CORE_STATE/backups" ||
        ! core::safe_lock "$CORE_STATE/lock" || ! core::safe_lock "$CORE_STATE/lock-admission"; then
        core::die 'State, backups and locks must be private root-owned paths without symlinks or shared links.'
        return 1
    fi
    exec 6>>"$CORE_STATE/lock-admission" || return 1
    flock --exclusive --wait "$admission_wait" --conflict-exit-code 75 6 || result=$?
    if ((result != 0)); then
        exec 6>&-
        if ((result == 75)); then
            if [[ $admission_wait != 0 ]]; then
                core::die 'Another OctoShield protection change is running or waiting. No changes were started.'
            fi
            return 75
        fi
        core::die 'Cannot acquire the protection admission lock.'
        return 1
    fi
    if ! core::package_available || ! exec 9>>"$CORE_STATE/lock"; then
        core::end
        return 1
    fi
    flock --exclusive --nonblock --conflict-exit-code 75 9 || result=$?
    if ((result == 75)) && [[ $reader_wait != 0 ]]; then
        core::log 'Waiting for the current system inspection to finish. New background inspections are paused; no changes have started.' || {
            core::end
            return 1
        }
        result=0
        flock --exclusive --wait "$reader_wait" --conflict-exit-code 75 9 || result=$?
    fi
    if ((result != 0)); then
        core::end
        if ((result == 75)); then
            if [[ $reader_wait != 0 ]]; then
                core::die 'System state is still in use after waiting. No changes were started; the current operation has been left intact.'
            fi
            return 75
        fi
        core::die 'Cannot acquire the protection operation lock.'
        return 1
    fi
    # A package operation may have acquired the same lock after our first check.
    # Its marker outlives the maintainer script while dpkg replaces program files.
    if ! core::package_available; then
        core::end
        return 1
    fi
    CORE_TRANSACTION="$(date -u +%Y%m%dT%H%M%SZ)-$$"
    if ! install -d -m 0700 "$CORE_STATE/backups/$CORE_TRANSACTION/original" || ! core::record "BEGIN $*"; then
        core::end
        return 1
    fi
}

# Full background inspections are supervised for at most 60 seconds, with a
# three-second kill grace. Leave time for their descriptors to drain normally.
core::begin() { core::_begin 1 70 "$@"; }

# Background expiry bookkeeping is opportunistic. It never queues for a lock,
# and releases admission once it owns the exclusive operation lock. This lets
# an administrator claim admission and wait for bounded bookkeeping to finish;
# that administrator then excludes further background readers and bookkeeping.
# Only background callers may use this entry point. FD9 still protects every
# metadata change until core::end or process exit releases the operation lock.
core::try_begin() {
    core::_begin 0 0 "$@" || return "$?"
    exec 6>&-
}

# A completed change must not keep the writer lock indefinitely merely because
# its final status query stalls. The trusted child validates the inherited
# locks and only observes state; the parent retains both locks until it returns.
core::refresh_status() {
    local deadline grace
    case "${1-}" in
        full) deadline=60s grace=3s ;;
        usb) deadline=8s grace=1s ;;
        *) return 2 ;;
    esac
    timeout --kill-after="$grace" "$deadline" /bin/bash -p "$OCTOSHIELD_ROOT/src/status-daemon" --after-change "$1"
}

core::record() {
    [[ -n $CORE_TRANSACTION ]] || return 0
    printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" >>"$CORE_STATE/backups/$CORE_TRANSACTION/actions.log"
}

core::valid_path() {
    [[ $1 == /* && $1 != / && $1 != *'/../'* && $1 != */.. && $1 != *$'\n'* && $1 != *$'\t'* ]]
}

core::backup() {
    local path=$1 dest marker
    core::valid_path "$path" || {
        core::die 'Invalid backup path.'
        return 1
    }
    [[ -n $CORE_TRANSACTION ]] || {
        core::die 'No active change transaction.'
        return 1
    }
    dest="$CORE_STATE/backups/$CORE_TRANSACTION/original$path"
    marker="$CORE_STATE/backups/$CORE_TRANSACTION/saved$path"
    [[ ! -e $marker ]] || return 0
    mkdir -p -- "${dest%/*}" "${marker%/*}" || return 1
    if [[ -e $path || -L $path ]]; then
        cp -a -- "$path" "$dest" || return 1
        printf 'existing\n' >"$marker" || return 1
    else
        printf 'absent\n' >"$marker" || return 1
    fi
    core::record "BACKUP $path"
}

# Stdin is configuration data. Never eval or source persisted configuration.
core::write_file() {
    local path=$1 mode=${2:-0644} temp
    core::valid_path "$path" || return 1
    [[ ! -L $path ]] || {
        core::die "Refusing to replace symlink: $path"
        return 1
    }
    core::backup "$path" || return 1
    [[ -d ${path%/*} ]] || install -d -m 0755 -- "${path%/*}" || return 1
    temp=$(mktemp "${path%/*}/.octoshield.XXXXXX") || return 1
    if ! cat >"$temp" || ! chmod "$mode" "$temp" || ! chown root:root "$temp" || ! mv -fT -- "$temp" "$path"; then
        rm -f -- "$temp"
        return 1
    fi
    core::record "WRITE $path"
}

core::install_packages() {
    local package status
    local -a missing=()
    for package in "$@"; do
        [[ $package =~ ^[a-z0-9][a-z0-9+.-]*$ ]] || return 1
        status=$(dpkg-query -W -f='${Status}' "$package" 2>/dev/null) || status=
        [[ $status == 'install ok installed' ]] || missing+=("$package")
    done
    ((${#missing[@]})) || return 0
    core::log "Installing Ubuntu packages: ${missing[*]}"
    if ((CORE_APT_UPDATED == 0)); then
        apt-get update || return 1
        CORE_APT_UPDATED=1
    fi
    apt-get install --yes --no-install-recommends "${missing[@]}" || return 1
    core::record "PACKAGES ${missing[*]}"
}

core::backups() {
    core::require_root || return 1
    if [[ ! -d $CORE_STATE/backups ]]; then
        core::log 'No saved changes.'
        return 0
    fi
    find "$CORE_STATE/backups" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort
    core::log "Private snapshots and action logs: $CORE_STATE/backups. See docs/recovery.md before restoring."
}
