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

core::begin() {
    core::require_root || return 1
    core::package_available || return 1
    umask 077
    if ! core::private_directory "$CORE_STATE" || ! core::private_directory "$CORE_STATE/backups" ||
        ! core::safe_lock "$CORE_STATE/lock"; then
        core::die 'State, backups and lock must be private root-owned paths without symlinks or shared links.'
        return 1
    fi
    exec 9>"$CORE_STATE/lock" || return 1
    flock -n 9 || {
        core::die 'Another OctoShield operation is running.'
        return 1
    }
    # A package operation may have acquired the same lock after our first check.
    # Its marker outlives the maintainer script while dpkg replaces program files.
    if ! core::package_available; then
        exec 9>&-
        return 1
    fi
    CORE_TRANSACTION="$(date -u +%Y%m%dT%H%M%SZ)-$$"
    install -d -m 0700 "$CORE_STATE/backups/$CORE_TRANSACTION/original" || return 1
    core::record "BEGIN $*"
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
