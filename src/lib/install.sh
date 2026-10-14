#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Fixed system destinations are deliberately not configurable through the environment.
INSTALL_LIBRARY=/usr/local/lib
INSTALL_EXECUTABLES=/usr/local/bin
INSTALL_SYSTEM_UNITS=/etc/systemd/system
INSTALL_USER_UNITS=/etc/systemd/user

install::files() {
    printf '%s\n' \
        src/octoshield src/lib/core.sh src/lib/controls.sh src/lib/usb.sh \
        src/lib/desktop.sh src/lib/monitor.sh src/lib/install.sh src/lib/cli.sh \
        src/lib/office.sh src/lib/api.sh src/lib/user_api.sh \
        src/lib/profiles.sh src/lib/profile_controls.sh src/lib/profile_cli.sh src/lib/status.sh src/lib/updates.sh \
        src/lib/profile_firewall_verify.sh \
        src/status-daemon systemd/octoshield-status.service \
        src/monitor.c src/notify.sh systemd/octoshield-monitor.service \
        systemd/octoshield-notify.service README.md LICENSE docs/recovery.md
}

install::safe_directory() {
    local directory=$1 ownership permissions
    [[ -d $directory && ! -L $directory ]] || {
        core::die "Expected a real directory: $directory"
        return 1
    }
    ownership=$(stat -c '%u' -- "$directory") || return 1
    permissions=$(stat -c '%a' -- "$directory") || return 1
    if [[ $ownership != 0 ]] || (((8#$permissions & 022) != 0)); then
        core::die "Directory must be owned by root and not writable by others: $directory"
        return 1
    fi
}

install::validate_source() {
    local source_root=$1 relative component parent
    [[ -d $source_root && ! -L $source_root ]] || {
        core::die 'Installation source must be a real directory.'
        return 1
    }
    while IFS= read -r relative; do
        [[ -f $source_root/$relative && ! -L $source_root/$relative ]] || {
            core::die "Missing or linked source file: $relative"
            return 1
        }
        parent=$source_root
        # Check each ancestor inside the source tree, not only the final file.
        while [[ $relative == */* ]]; do
            component=${relative%%/*}
            relative=${relative#*/}
            parent+=/$component
            [[ -d $parent && ! -L $parent ]] || {
                core::die "Linked source directory: $parent"
                return 1
            }
        done
    done < <(install::files)
}

install::stage() {
    local source_root=$1 stage=$2 relative
    while IFS= read -r relative; do
        install -D -o root -g root -m 0644 -- "$source_root/$relative" "$stage/$relative" || return 1
    done < <(install::files)
    install -d -o root -g root -m 0755 "$stage/bin" || return 1
    # Never execute a checkout Makefile as root or honor CC/CFLAGS/CPATH overrides.
    env -i PATH=/usr/bin:/bin LC_ALL=C /usr/bin/gcc \
        -std=c11 -O2 -Wall -Wextra -Werror -pedantic \
        -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -pie \
        -Wl,-z,relro,-z,now \
        "$stage/src/monitor.c" -o "$stage/bin/octoshield-monitor" || return 1
    chmod 0755 "$stage" "$stage/src/octoshield" "$stage/src/notify.sh" "$stage/src/status-daemon" "$stage/bin/octoshield-monitor" || return 1
}

install::safe_file() {
    local metadata
    [[ -f $1 && ! -L $1 ]] || return 1
    metadata=$(stat -c '%u:%a:%h' -- "$1") || return 1
    [[ $metadata =~ ^0:([0-7]{3,4}):1$ ]] || return 1
    (((8#${BASH_REMATCH[1]} & 022) == 0))
}

install::unit_target() {
    case "$1" in
        octoshield-status.service | octoshield-monitor.service) printf '%s/%s\n' "$INSTALL_SYSTEM_UNITS" "$1" ;;
        octoshield-notify.service) printf '%s/%s\n' "$INSTALL_USER_UNITS" "$1" ;;
        *) return 1 ;;
    esac
}

# Compare every target before changing any program file or unit. Existing units
# can match either the new distribution or the previous installed distribution;
# an upgrade must not mistake an unchanged older vendor unit for an admin edit.
install::preflight_units() {
    local source_root=$1 previous_root=${2-} unit target source_file previous_file directory
    for directory in "$INSTALL_SYSTEM_UNITS" "$INSTALL_USER_UNITS"; do
        if [[ -e $directory || -L $directory ]]; then
            install::safe_directory "$directory" || return 1
        else
            install -d -o root -g root -m 0755 "$directory" || return 1
        fi
    done
    for unit in octoshield-status.service octoshield-monitor.service octoshield-notify.service; do
        source_file="$source_root/systemd/$unit"
        target=$(install::unit_target "$unit") || return 1
        install::safe_file "$source_file" || {
            core::die "The distributed service file is unsafe: $unit"
            return 1
        }
        [[ -e $target || -L $target ]] || continue
        if install::safe_file "$target"; then
            cmp -s -- "$source_file" "$target" && continue
            previous_file="$previous_root/systemd/$unit"
            if [[ -n $previous_root ]] && install::safe_directory "$previous_root/systemd" &&
                install::safe_file "$previous_file" && cmp -s -- "$previous_file" "$target"; then continue; fi
        fi
        core::die "An administrator-modified or linked service exists: $target. Review it before updating the standalone installation; it has been preserved."
        return 1
    done
}

# Deploy all three unit definitions so profile preflight works on a first source
# install. Only the passive status observer is enabled automatically. Previously
# active monitoring is restarted after upgrade, but an inactive collector and
# every desktop notification session remain under the user's control.
install::services() {
    local source_root=$1 previous_root=${2-} unit target new=0
    install::preflight_units "$source_root" "$previous_root" || return 1
    [[ -e $INSTALL_SYSTEM_UNITS/octoshield-status.service ]] || new=1
    for unit in octoshield-status.service octoshield-monitor.service octoshield-notify.service; do
        target=$(install::unit_target "$unit") || return 1
        cmp -s -- "$source_root/systemd/$unit" "$target" && continue
        core::write_file "$target" 0644 <"$source_root/systemd/$unit" || return 1
    done
    systemctl daemon-reload || return 1
    if ((new)); then
        systemctl enable --now octoshield-status.service || return 1
    elif systemctl is-active --quiet octoshield-status.service; then
        systemctl restart octoshield-status.service || return 1
    fi
    if systemctl is-active --quiet octoshield-monitor.service; then systemctl restart octoshield-monitor.service || return 1; fi
    return 0
}

install::ensure_timeout() {
    core::timeout_program >/dev/null 2>&1 && return 0
    core::install_packages gnu-coreutils || return 1
    core::timeout_program >/dev/null
}

install::run() (
    local stage='' previous='' launcher='' destination directory published=0 succeeded=0
    core::require_root || return 1
    [[ -n ${CORE_TRANSACTION:-} ]] || core::begin installation || return 1
    install::validate_source "$OCTOSHIELD_ROOT" || return 1
    install::safe_directory /usr || return 1
    install::safe_directory /usr/local || return 1
    for directory in "$INSTALL_LIBRARY" "$INSTALL_EXECUTABLES"; do
        if [[ -e $directory || -L $directory ]]; then
            install::safe_directory "$directory" || return 1
        else
            install -d -o root -g root -m 0755 "$directory" || return 1
        fi
    done
    destination=$INSTALL_LIBRARY/octoshield
    [[ ! -L $destination && ! -L $INSTALL_EXECUTABLES/octoshield ]] || {
        core::die 'Refusing to replace a linked OctoShield installation.'
        return 1
    }
    if [[ -e $destination ]]; then
        install::safe_directory "$destination" || return 1
    fi
    core::install_packages gcc libc6-dev curl ca-certificates whiptail jq || return 1
    install::ensure_timeout || return 1
    stage=$(mktemp -d "$INSTALL_LIBRARY/.octoshield-install.XXXXXXXX") || return 1
    previous=$stage.previous
    launcher=$(mktemp "$INSTALL_EXECUTABLES/.octoshield-launcher.XXXXXXXX") || {
        rm -rf -- "$stage"
        return 1
    }
    # Roll back the old program if either promotion fails or installation is interrupted.
    # shellcheck disable=SC2317,SC2329 # Invoked indirectly by the EXIT trap below.
    install::cleanup() {
        if ((succeeded == 0)); then
            if [[ -d $previous ]]; then
                rm -rf -- "$destination"
                mv -T -- "$previous" "$destination" || core::log "Restore $previous to $destination manually."
            elif ((published == 1)) || [[ ! -d $stage ]]; then
                rm -rf -- "$destination"
            fi
        fi
        [[ -z $stage ]] || rm -rf -- "$stage"
        [[ -z $launcher ]] || rm -f -- "$launcher"
    }
    trap install::cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    install::stage "$OCTOSHIELD_ROOT" "$stage" || return 1
    install::preflight_units "$stage" "$destination" || return 1
    cat >"$launcher" <<'LAUNCHER' || return 1
#!/bin/bash
exec /usr/bin/bash /usr/local/lib/octoshield/src/octoshield "$@"
LAUNCHER
    chmod 0755 "$launcher" || return 1
    chown root:root "$launcher" || return 1
    if [[ -d $destination ]]; then
        mv -T -- "$destination" "$previous" || return 1
    fi
    mv -T -- "$stage" "$destination" || return 1
    published=1
    stage=
    mv -fT -- "$launcher" "$INSTALL_EXECUTABLES/octoshield" || return 1
    launcher=
    succeeded=1
    # The previous tree is still available when recognizing/upgrading vendor
    # service definitions. If deployment fails, preserve it for manual recovery.
    install::services "$destination" "$previous" || return 1
    if [[ -e $previous ]]; then rm -rf -- "$previous" || return 1; fi
    core::record "INSTALL $destination" || return 1
    core::log 'Installed. Run octoshield to configure protections, or octoshield status to inspect them.'
)
