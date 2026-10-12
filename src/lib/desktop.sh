#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# GNOME desktop policy. Source this module; call desktop::{apply,restore,status}
# from the logged-in, unprivileged user's session (never from sudo/root).
# The first apply records a private, non-executable TSV baseline. Every saved
# entry is checked against the built-in schema/key/type catalog before use.

# Parallel arrays form the policy object; callers should use the public methods.
declare -a DESKTOP_SCHEMA=() DESKTOP_KEY=() DESKTOP_TYPE=() DESKTOP_TARGET=() DESKTOP_CURRENT=()

# Avoid requiring the launcher's logging implementation when testing this module.
desktop::error() {
    printf 'OctoShield desktop: %s\n' "$*" >&2
    return 1
}

desktop::catalog() {
    DESKTOP_SCHEMA=() DESKTOP_KEY=() DESKTOP_TYPE=() DESKTOP_TARGET=()
    local schema key type target
    while IFS='|' read -r schema key type target; do
        DESKTOP_SCHEMA+=("$schema")
        DESKTOP_KEY+=("$key")
        DESKTOP_TYPE+=("$type")
        DESKTOP_TARGET+=("$target")
    done <<'POLICY'
org.gnome.desktop.session|idle-delay|uint32|uint32 300
org.gnome.desktop.screensaver|lock-enabled|boolean|true
org.gnome.desktop.screensaver|lock-delay|uint32|uint32 0
org.gnome.desktop.lockdown|disable-lock-screen|boolean|false
org.gnome.desktop.media-handling|automount|boolean|false
org.gnome.desktop.media-handling|automount-open|boolean|false
org.gnome.desktop.media-handling|autorun-never|boolean|true
POLICY
    DESKTOP_REQUIRED_COUNT=${#DESKTOP_SCHEMA[@]}
}

# Remote Desktop is optional on GNOME installations. Manage only a schema/key
# pair exposed by the installed version; never assume absence means all sharing
# is disabled (system remote login and other sharing products are separate).
desktop::optional_catalog() {
    local schemas=$1 protocol schema keys
    for protocol in rdp vnc; do
        schema="org.gnome.desktop.remote-desktop.$protocol"
        if [[ $'\n'"$schemas"$'\n' != *$'\n'"$schema"$'\n'* ]]; then
            printf 'GNOME per-user %s control is unavailable; no claim is made about that sharing backend.\n' "$protocol" >&2
            continue
        fi
        keys=$(gsettings list-keys "$schema") || return 1
        if [[ $'\n'"$keys"$'\n' != *$'\n'enable$'\n'* ]]; then
            printf 'GNOME per-user %s enable key is unavailable; no sharing setting was changed.\n' "$protocol" >&2
            continue
        fi
        DESKTOP_SCHEMA+=("$schema")
        DESKTOP_KEY+=(enable)
        DESKTOP_TYPE+=(boolean)
        DESKTOP_TARGET+=(false)
    done
}

desktop::require_session() {
    ((EUID != 0)) || {
        desktop::error 'Run this command as your normal logged-in desktop user, without sudo.'
        return 1
    }
    case ${XDG_CURRENT_DESKTOP:-} in
        *GNOME* | *gnome*) ;;
        *)
            desktop::error 'Unsupported session: these settings require a logged-in GNOME desktop.'
            return 1
            ;;
    esac
    [[ -n ${DBUS_SESSION_BUS_ADDRESS:-} ]] || {
        desktop::error 'No user session D-Bus address; run this command in a GNOME terminal.'
        return 1
    }
    command -v gsettings >/dev/null 2>&1 || {
        desktop::error 'gsettings is unavailable; install the Ubuntu libglib2.0-bin package.'
        return 1
    }
}

desktop::valid_value() {
    case $1 in
        boolean) [[ $2 == true || $2 == false ]] ;;
        uint32)
            [[ $2 =~ ^uint32\ ([0-9]{1,10})$ ]] || return 1
            ((10#${BASH_REMATCH[1]} <= 4294967295))
            ;;
        *) return 1 ;;
    esac
}

# Read and validate every setting before allowing any mutation. Status does not
# require writability, so administrator-locked settings can still be inspected.
desktop::preflight() {
    local mode=${1:-write} schemas keys value writable i schema key
    desktop::catalog
    DESKTOP_CURRENT=()
    schemas=$(gsettings list-schemas) || {
        desktop::error 'Unable to list GSettings schemas.'
        return 1
    }
    desktop::optional_catalog "$schemas" || return 1
    for i in "${!DESKTOP_SCHEMA[@]}"; do
        schema=${DESKTOP_SCHEMA[i]} key=${DESKTOP_KEY[i]}
        [[ $'\n'"$schemas"$'\n' == *$'\n'"$schema"$'\n'* ]] || {
            desktop::error "Missing GNOME schema: $schema"
            return 1
        }
        keys=$(gsettings list-keys "$schema") || {
            desktop::error "Unable to inspect $schema"
            return 1
        }
        [[ $'\n'"$keys"$'\n' == *$'\n'"$key"$'\n'* ]] || {
            desktop::error "Missing GNOME setting: $schema $key"
            return 1
        }
        if [[ $mode == write ]]; then
            writable=$(gsettings writable "$schema" "$key") || {
                desktop::error "Unable to check writability: $schema $key"
                return 1
            }
            [[ $writable == true ]] || {
                desktop::error "Setting is locked by administrator policy: $schema $key"
                return 1
            }
        fi
        value=$(gsettings get "$schema" "$key") || {
            desktop::error "Unable to read: $schema $key"
            return 1
        }
        desktop::valid_value "${DESKTOP_TYPE[i]}" "$value" || {
            desktop::error "Unexpected value type: $schema $key"
            return 1
        }
        DESKTOP_CURRENT+=("$value")
    done
}

# The process is unprivileged, but still reject symlinks, foreign-owned state,
# and readable-by-others backups. Never source or evaluate stored values.
desktop::state_path() {
    local create=${1:-false} state_home component path='' uid
    state_home=${XDG_STATE_HOME:-${HOME:?HOME is required}/.local/state}
    [[ $state_home == /* && $state_home != *$'\n'* && $state_home != *$'\t'* ]] || {
        desktop::error 'XDG_STATE_HOME must be an absolute, ordinary directory path.'
        return 1
    }
    local -a components=()
    IFS='/' read -r -a components <<<"$state_home/octoshield"
    for component in "${components[@]}"; do
        [[ -n $component ]] || continue
        [[ $component != . && $component != .. ]] || {
            desktop::error 'Dot path components are not permitted in the state path.'
            return 1
        }
        path+="/$component"
        [[ ! -L $path ]] || {
            desktop::error "Refusing a symlink in the desktop state path: $path"
            return 1
        }
        [[ ! -e $path || -d $path ]] || {
            desktop::error "State path is not a directory: $path"
            return 1
        }
    done
    DESKTOP_STATE_DIR=$state_home/octoshield
    DESKTOP_STATE_FILE=$DESKTOP_STATE_DIR/desktop.tsv
    if [[ $create == true ]]; then
        (
            umask 077
            mkdir -p -- "$DESKTOP_STATE_DIR"
        ) || {
            desktop::error 'Unable to create the desktop state directory.'
            return 1
        }
    fi
    [[ -d $DESKTOP_STATE_DIR ]] || {
        desktop::error 'No saved desktop baseline exists.'
        return 1
    }
    uid=$(id -u) || return 1
    [[ $(stat -c '%u' -- "$state_home") == "$uid" && $(stat -c '%u' -- "$DESKTOP_STATE_DIR") == "$uid" ]] || {
        desktop::error 'The desktop state directory must belong to the current user.'
        return 1
    }
    [[ $(stat -c '%a' -- "$DESKTOP_STATE_DIR") == 700 ]] || {
        desktop::error 'The octoshield state directory must have permission mode 700.'
        return 1
    }
    if [[ -e $DESKTOP_STATE_FILE || -L $DESKTOP_STATE_FILE ]]; then
        [[ -f $DESKTOP_STATE_FILE && ! -L $DESKTOP_STATE_FILE ]] || {
            desktop::error 'The saved desktop baseline must be a regular file, not a symlink.'
            return 1
        }
        [[ $(stat -c '%u:%a:%h' -- "$DESKTOP_STATE_FILE") == "$uid:600:1" ]] || {
            desktop::error 'The saved desktop baseline must be privately owned (mode 600), without extra hard links.'
            return 1
        }
    fi
}

desktop::lock() {
    command -v flock >/dev/null 2>&1 || {
        desktop::error 'flock is unavailable; install the Ubuntu util-linux package.'
        return 1
    }
    # Lock the validated private directory itself, avoiding a separate lock file
    # that could be replaced. The public operation's subshell closes the FD.
    exec {DESKTOP_LOCK_FD}<"$DESKTOP_STATE_DIR" || return 1
    flock -n "$DESKTOP_LOCK_FD" || {
        desktop::error 'Another desktop policy operation is in progress.'
        return 1
    }
}

desktop::read_baseline() {
    local -n baseline_values=$1
    baseline_values=()
    [[ -f $DESKTOP_STATE_FILE ]] || {
        desktop::error 'No saved desktop baseline exists.'
        return 1
    }
    local mode=${2:-restore} line schema key value extra i found identity
    local -A seen=()
    while IFS= read -r line || [[ -n $line ]]; do
        IFS=$'\t' read -r schema key value extra <<<"$line"
        [[ $line == "$schema"$'\t'"$key"$'\t'"$value" && -z $extra ]] || {
            desktop::error 'Malformed desktop baseline; no settings changed.'
            return 1
        }
        identity="$schema/$key"
        [[ ! ${seen[$identity]:-} ]] || {
            desktop::error 'Duplicate entry in desktop baseline.'
            return 1
        }
        seen[$identity]=true
        found=false
        for i in "${!DESKTOP_SCHEMA[@]}"; do
            if [[ $schema == "${DESKTOP_SCHEMA[i]}" && $key == "${DESKTOP_KEY[i]}" ]]; then
                desktop::valid_value "${DESKTOP_TYPE[i]}" "$value" || {
                    desktop::error 'Invalid value in desktop baseline.'
                    return 1
                }
                # shellcheck disable=SC2034 # Filled through the caller-provided nameref.
                baseline_values[i]=$value
                found=true
                break
            fi
        done
        # Preserve a validated optional backend's original value even after its
        # package is removed. It cannot be restored until that schema returns.
        if [[ $found == false && $key == enable ]]; then
            case $schema in
                org.gnome.desktop.remote-desktop.rdp | org.gnome.desktop.remote-desktop.vnc)
                    desktop::valid_value boolean "$value" || {
                        desktop::error 'Invalid saved value for an unavailable optional backend.'
                        return 1
                    }
                    printf 'Saved %s setting is currently unavailable and will be retained.\n' "$schema" >&2
                    found=true
                    ;;
            esac
        fi
        [[ $found == true ]] || {
            desktop::error 'Unknown setting in desktop baseline; no settings changed.'
            return 1
        }
    done <"$DESKTOP_STATE_FILE"
    for i in "${!DESKTOP_SCHEMA[@]}"; do
        [[ ! ${baseline_values[i]+present} ]] || continue
        if ((i < DESKTOP_REQUIRED_COUNT)); then
            desktop::error 'Incomplete desktop baseline; no settings changed.'
            return 1
        fi
        if [[ $mode == restore ]]; then
            printf 'No baseline for newly available %s; leaving it unchanged.\n' "${DESKTOP_SCHEMA[i]}" >&2
            baseline_values[i]=${DESKTOP_CURRENT[i]}
        fi
    done
}

desktop::save_baseline() {
    local temporary i update=false missing=false
    local -a existing=()
    if [[ -e $DESKTOP_STATE_FILE ]]; then
        desktop::read_baseline existing extend || return 1
        for i in "${!DESKTOP_SCHEMA[@]}"; do
            [[ ${existing[i]+present} ]] || missing=true
        done
        [[ $missing == true ]] || return 0
        update=true
    fi
    temporary=$(mktemp "$DESKTOP_STATE_DIR/.desktop.XXXXXXXX") || return 1
    if [[ $update == true ]] && ! cat -- "$DESKTOP_STATE_FILE" >"$temporary"; then
        rm -f -- "$temporary"
        return 1
    fi
    for i in "${!DESKTOP_SCHEMA[@]}"; do
        [[ ! ${existing[i]+present} ]] || continue
        if ! printf '%s\t%s\t%s\n' "${DESKTOP_SCHEMA[i]}" "${DESKTOP_KEY[i]}" "${DESKTOP_CURRENT[i]}" >>"$temporary"; then
            rm -f -- "$temporary"
            desktop::error 'Unable to write the desktop baseline.'
            return 1
        fi
    done
    if [[ $update == true ]]; then
        # Only append first-seen optional controls; previous values are copied
        # byte-for-byte and never replaced. The directory lock serializes this.
        mv -f -- "$temporary" "$DESKTOP_STATE_FILE" || {
            rm -f -- "$temporary"
            return 1
        }
        return 0
    fi
    # Linking is atomic and fails if another process already created the file.
    if ! ln -- "$temporary" "$DESKTOP_STATE_FILE"; then
        rm -f -- "$temporary"
        desktop::error 'Unable to save the desktop baseline; no settings changed.'
        return 1
    fi
    rm -f -- "$temporary"
}

# Verify each mutation. On failure, restore the values from this invocation,
# including the setting whose write failed, and retain the original baseline.
desktop::write_values() {
    local -n requested_values=$1
    local i j actual failed=false rollback_failed=false
    for i in "${!DESKTOP_SCHEMA[@]}"; do
        [[ ${DESKTOP_CURRENT[i]} != "${requested_values[i]}" ]] || continue
        if ! gsettings set "${DESKTOP_SCHEMA[i]}" "${DESKTOP_KEY[i]}" "${requested_values[i]}"; then
            failed=true
        elif ! actual=$(gsettings get "${DESKTOP_SCHEMA[i]}" "${DESKTOP_KEY[i]}"); then
            failed=true
        elif [[ $actual != "${requested_values[i]}" ]]; then
            failed=true
        fi
        if [[ $failed == true ]]; then
            for ((j = i; j >= 0; j--)); do
                if ! gsettings set "${DESKTOP_SCHEMA[j]}" "${DESKTOP_KEY[j]}" "${DESKTOP_CURRENT[j]}"; then
                    rollback_failed=true
                elif ! actual=$(gsettings get "${DESKTOP_SCHEMA[j]}" "${DESKTOP_KEY[j]}") || [[ $actual != "${DESKTOP_CURRENT[j]}" ]]; then
                    rollback_failed=true
                fi
            done
            if [[ $rollback_failed == true ]]; then
                desktop::error 'A setting failed and rollback was incomplete. Inspect desktop status and restore the saved baseline.'
            else
                desktop::error 'A setting failed; the settings from before this operation have been restored.'
            fi
            return 1
        fi
    done
}

desktop::apply() (
    desktop::require_session || return 1
    desktop::state_path true || return 1
    desktop::lock || return 1
    desktop::preflight write || return 1
    desktop::save_baseline || return 1
    desktop::write_values DESKTOP_TARGET || return 1
    printf '%s\n' 'GNOME protection applied: lock after 5 minutes idle, immediate lock on blanking, and removable-media automount/autorun disabled.'
    printf '%s\n' 'Available GNOME per-user RDP/VNC controls are disabled. System remote login and other sharing software require separate controls.'
    printf '%s\n' 'USB device authorization is a separate system policy; disabling automount does not block USB keyboards or network adapters.'
)

desktop::restore() (
    desktop::require_session || return 1
    desktop::state_path false || return 1
    desktop::lock || return 1
    desktop::preflight write || return 1
    # shellcheck disable=SC2034 # Shared with reader/writer through namerefs.
    local -a baseline=()
    desktop::read_baseline baseline || return 1
    desktop::write_values baseline || return 1
    printf '%s\n' 'The original GNOME settings have been restored. The private baseline is retained for repeatable recovery.'
)

desktop::status() {
    desktop::require_session || return 1
    desktop::preflight read || return 1
    local i label
    for i in "${!DESKTOP_SCHEMA[@]}"; do
        label='custom'
        [[ ${DESKTOP_CURRENT[i]} != "${DESKTOP_TARGET[i]}" ]] || label='protected'
        printf '%s %s = %s [%s]\n' "${DESKTOP_SCHEMA[i]}" "${DESKTOP_KEY[i]}" "${DESKTOP_CURRENT[i]}" "$label"
    done
}
