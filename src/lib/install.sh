#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Fixed system destinations are deliberately not configurable through the environment.
INSTALL_LIBRARY=/usr/local/lib
INSTALL_EXECUTABLES=/usr/local/bin

install::files() {
    printf '%s\n' \
        src/octoshield src/lib/core.sh src/lib/controls.sh src/lib/usb.sh \
        src/lib/desktop.sh src/lib/monitor.sh src/lib/install.sh src/lib/cli.sh \
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
    chmod 0755 "$stage" "$stage/src/octoshield" "$stage/src/notify.sh" "$stage/bin/octoshield-monitor" || return 1
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
        core::die 'Refusing to replace a linked Octoshield installation.'
        return 1
    }
    if [[ -e $destination ]]; then
        install::safe_directory "$destination" || return 1
    fi
    core::install_packages gcc libc6-dev curl ca-certificates whiptail jq libnotify-bin || return 1
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
    if [[ -e $previous ]]; then rm -rf -- "$previous" || return 1; fi
    core::record "INSTALL $destination" || return 1
    core::log 'Installed. Run octoshield to configure protections, or octoshield status to inspect them.'
)
