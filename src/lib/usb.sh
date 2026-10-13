#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# USBGuard enrollment and explicit administrator device authorization.
# These locations are deliberately assigned, never inherited from the environment.
USB_CONFIG_DIR=/etc/usbguard
USB_STATE_DIR=/var/lib/octoshield/usb
USB_LOG_DIR=/var/log/usbguard
USB_UNIT_DIR=/etc/systemd/system
USB_SYS_DIR=/sys
USB_PROC_DIR=/proc

# Profile files are data, never shell programs. The root helper serializes every
# mutation with the application's operation lock before entering this module.
usb::_profile_name() {
    [[ ${1-} =~ ^[a-z][a-z0-9-]{0,31}$ ]]
}

usb::_private_path() {
    local path=$1 current=/ part owner mode
    [[ $path == /* && $path != *'/../'* && $path != */.. ]] || return 1
    local -a parts=()
    IFS=/ read -r -a parts <<<"${path#/}"
    for part in "${parts[@]}"; do
        current="${current%/}/$part"
        [[ ! -L $current ]] || return 1
    done
    if [[ -e $path ]]; then
        owner=$(stat -c %u -- "$path") && mode=$(stat -c %a -- "$path") || return 1
        [[ $owner == 0 && $mode =~ ^[0-7]{3,4}$ ]] && (((8#$mode & 0022) == 0)) || return 1
    fi
}

usb::_paths() {
    local path
    for path in "$USB_STATE_DIR" "$USB_STATE_DIR/profiles" "$USB_CONFIG_DIR" \
        "$USB_CONFIG_DIR/rules.conf" "$USB_CONFIG_DIR/usbguard-daemon.conf" \
        "$USB_STATE_DIR/active-profile" "$USB_STATE_DIR/legacy.rules" \
        "$USB_STATE_DIR/enrolled" "$USB_STATE_DIR/profile-pending"; do
        usb::_private_path "$path" || {
            core::die 'USB policy paths must be root-owned, not writable by other users, and must not contain symlinks.'
            return 1
        }
    done
}

usb::active_profile() {
    local name=legacy
    usb::_paths || return
    if [[ -f "$USB_STATE_DIR/active-profile" ]]; then
        [[ $(stat -c %s -- "$USB_STATE_DIR/active-profile") -le 33 ]] || return 1
        IFS= read -r name <"$USB_STATE_DIR/active-profile" || return 1
        usb::_profile_name "$name" || return 1
    fi
    printf '%s\n' "$name"
}

# Tokenize USBGuard's serialized rule language without evaluating it. In
# particular a device name containing text such as `hash` cannot impersonate
# an attribute. Only the bounded identity attributes below become policy data.
usb::_identity() {
    local text=$1 token key value quoted='^"(([^"\\]|\\.)*)"([[:space:]]|$)' bare='^([^[:space:]"{}]+)' space='^[[:space:]]+'
    local -a tokens=()
    [[ $text =~ ^[1-9][0-9]*:\ (.*)$ ]] && text=${BASH_REMATCH[1]}
    while [[ -n $text ]]; do
        if [[ $text =~ $space ]]; then
            text=${text:${#BASH_REMATCH[0]}}
        elif [[ $text =~ $quoted ]]; then
            token="\"${BASH_REMATCH[1]}\""
            tokens+=("$token")
            text=${text:${#token}}
        elif [[ $text == '{'* || $text == '}'* ]]; then
            tokens+=("${text:0:1}")
            text=${text:1}
        elif [[ $text =~ $bare ]]; then
            token=${BASH_REMATCH[1]}
            tokens+=("$token")
            text=${text:${#token}}
        else
            return 1
        fi
        ((${#tokens[@]} <= 256)) || return 1
    done
    [[ ${tokens[0]-} == allow || ${tokens[0]-} == block || ${tokens[0]-} == reject ]] || return 1
    USB_DEVICE_TARGET=${tokens[0]}
    USB_DEVICE_VID='' USB_DEVICE_HASH='' USB_DEVICE_PORT='' USB_DEVICE_NAME='' USB_DEVICE_INTERFACES=''
    local i=1 count=${#tokens[@]}
    while ((i < count)); do
        key=${tokens[i]}
        ((i += 1))
        ((i < count)) || return 1
        value=${tokens[i]}
        case "$key" in
            id)
                [[ -z $USB_DEVICE_VID && $value =~ ^[[:xdigit:]]{4}:[[:xdigit:]]{4}$ ]] || return 1
                USB_DEVICE_VID=$value
                ;;
            hash)
                [[ -z $USB_DEVICE_HASH && $value =~ ^\"[A-Za-z0-9+/=_-]{1,128}\"$ ]] || return 1
                USB_DEVICE_HASH=${value:1:${#value}-2}
                ;;
            via-port)
                [[ -z $USB_DEVICE_PORT && $value =~ ^\"(usb[0-9]+|[0-9]+-[0-9]+(\.[0-9]+)*)\"$ ]] || return 1
                USB_DEVICE_PORT=${value:1:${#value}-2}
                ;;
            name | serial | parent-hash | with-connect-type | label)
                [[ $value == \"*\" ]] || return 1
                [[ $key != name ]] || USB_DEVICE_NAME=${value:1:${#value}-2}
                ;;
            with-interface)
                [[ $value != equals && $value != equals-ordered ]] || {
                    ((i += 1))
                    value=${tokens[i]-}
                }
                if [[ $value == '{' ]]; then
                    ((i += 1))
                    while ((i < count)) && [[ ${tokens[i]} != '}' ]]; do
                        [[ ${tokens[i]} =~ ^[[:xdigit:]]{2}:[[:xdigit:]]{2}:[[:xdigit:]]{2}$ ]] || return 1
                        USB_DEVICE_INTERFACES+=" ${tokens[i]}"
                        ((i += 1))
                    done
                    [[ ${tokens[i]-} == '}' ]] || return 1
                else
                    [[ $value =~ ^[[:xdigit:]]{2}:[[:xdigit:]]{2}:[[:xdigit:]]{2}$ ]] || return 1
                    USB_DEVICE_INTERFACES+=" $value"
                fi
                ;;
            *) return 1 ;;
        esac
        ((i += 1))
    done
    [[ -n $USB_DEVICE_VID && -n $USB_DEVICE_HASH && -n $USB_DEVICE_PORT ]]
}

usb::_canonical() {
    usb::_identity "$1" || return
    printf 'allow id %s hash "%s" via-port "%s"\n' "$USB_DEVICE_VID" "$USB_DEVICE_HASH" "$USB_DEVICE_PORT"
}

usb::_policy_valid() {
    local line canonical
    while IFS= read -r line || [[ -n $line ]]; do
        [[ -n $line && $line != '#'* ]] || continue
        canonical=$(usb::_canonical "$line") || return 1
        [[ $line == "$canonical" ]] || return 1
    done
}

usb::_profile_policy() {
    local name=$1 path="$USB_STATE_DIR/profiles/$1.rules"
    usb::_profile_name "$name" && usb::_paths && usb::_private_path "$path" || return 1
    if [[ $name == legacy && -f "$USB_STATE_DIR/legacy.rules" ]]; then
        [[ $(stat -c %s -- "$USB_STATE_DIR/legacy.rules") -le 1048576 ]] || return 1
        cat -- "$USB_STATE_DIR/legacy.rules"
    elif [[ -f $path ]]; then
        [[ $(stat -c %s -- "$path") -le 1048576 ]] || return 1
        usb::_policy_valid <"$path" || {
            core::die 'The USB profile contains unsupported or unsafe rules.'
            return 1
        }
        cat -- "$path"
    elif [[ $name == legacy && -f "$USB_CONFIG_DIR/rules.conf" ]]; then
        [[ $(stat -c %s -- "$USB_CONFIG_DIR/rules.conf") -le 1048576 ]] || return 1
        cat -- "$USB_CONFIG_DIR/rules.conf"
    fi
}

usb::_adopt() {
    usb::_paths || return
    install -d -m 0700 -o root -g root "$USB_STATE_DIR" "$USB_STATE_DIR/profiles" || return
    if [[ ! -e "$USB_STATE_DIR/legacy.rules" ]]; then
        cat -- "$USB_CONFIG_DIR/rules.conf" | core::write_file "$USB_STATE_DIR/legacy.rules" 0600 || return
    fi
    if [[ ! -e "$USB_STATE_DIR/active-profile" ]]; then
        printf 'legacy\n' | core::write_file "$USB_STATE_DIR/active-profile" 0600 || return
    fi
}

usb::_managed() {
    usb::_paths || return
    if ! { [[ -f "$USB_STATE_DIR/enrolled" && -f "$USB_CONFIG_DIR/rules.conf" ]] &&
        cmp -s "$USB_CONFIG_DIR/usbguard-daemon.conf" <(usb::_config) &&
        usb::_masked_by_us usbguard-dbus.service; }; then
        core::die 'USBGuard must first be explicitly enrolled with OctoShield, with its root-only configuration intact.'
        return 1
    fi
}

usb::_policy_lines() {
    sed -E '/^[[:space:]]*(#|$)/d; s/^[0-9]+: //'
}

usb::_verified_policy() {
    local policy=$1 runtime
    systemctl is-active --quiet usbguard.service || return 1
    [[ $(usbguard get-parameter ImplicitPolicyTarget) == block &&
    $(usbguard get-parameter InsertedDevicePolicy) == apply-policy ]] || return 1
    runtime=$(usbguard list-rules) || return 1
    [[ $(usb::_policy_lines <<<"$runtime") == "$(usb::_policy_lines <<<"$policy")" ]]
}

usb::_device_deviations() {
    local policy=$1 devices line canonical allowed_rules='' count=0 matches
    while IFS= read -r line; do
        [[ -n $line && $line != '#'* ]] || continue
        [[ $line == 'allow '* ]] || return 1
        canonical=$(usb::_canonical "$line") || return 1
        allowed_rules+="$canonical"$'\n'
    done <<<"$policy"
    devices=$(usbguard list-devices) || return
    while IFS= read -r line; do
        [[ -n $line ]] || continue
        usb::_identity "$line" || return
        [[ $USB_DEVICE_PORT != usb* ]] || continue
        canonical=$(usb::_canonical "$line") || return
        matches=no
        grep -Fxq -- "$canonical" <<<"$allowed_rules" && matches=yes
        if [[ ($USB_DEVICE_TARGET == allow && $matches == no) ||
            ($USB_DEVICE_TARGET != allow && $matches == yes) ]]; then
            ((count += 1))
        fi
    done <<<"$devices"
    printf '%s\n' "$count"
}

# Follow stacked block devices (dm-crypt, LVM, MD) back to their USB transport.
# The caller compares a physical port, so removing a hub also checks its disks.
usb::_block_uses_port() {
    local path=$1 port=$2 depth=${3:-0} resolved child result
    ((depth < 32)) || return 2
    resolved=$(readlink -f -- "$path") || return 2
    [[ -d $resolved ]] || return 2
    [[ $resolved != *"/$port/"* && $resolved != */"$port" ]] || return 0
    for child in "$resolved"/slaves/*; do
        [[ -e $child || -L $child ]] || continue
        if usb::_block_uses_port "$child" "$port" "$((depth + 1))"; then
            return 0
        else
            result=$?
            [[ $result == 1 ]] || return 2
        fi
    done
    return 1
}

usb::_safe_to_block() {
    local port=$1 devices numbers number result=0
    # MOUNTPOINTS includes [SWAP] and child mappings; the tree includes USB
    # filesystems even when an encrypted mapper rather than the disk is mounted.
    devices=$(lsblk --json --output MAJ:MIN,MOUNTPOINTS) || {
        core::die 'Cannot check mounted USB storage; no devices will be disconnected.'
        return 1
    }
    numbers=$(jq -er '[.blockdevices[] | recurse(.children[]?) |
        select(any(.mountpoints[]?; . != null and . != "")) | .["maj:min"]] | unique | .[]' <<<"$devices") || result=$?
    [[ $result -eq 0 || $result -eq 4 ]] || return 1
    while IFS= read -r number; do
        [[ -n $number ]] || continue
        [[ $number =~ ^[0-9]+:[0-9]+$ ]] || return 1
        if usb::_block_uses_port "$USB_SYS_DIR/dev/block/$number" "$port"; then
            core::die "USB port $port supplies mounted storage or swap. Unmount/eject it safely before this change. Nothing was disconnected."
            return 1
        else
            result=$?
            [[ $result == 1 ]] || {
                core::die 'Cannot resolve mounted storage; USB change stopped safely.'
                return 1
            }
        fi
    done <<<"$numbers"
}

usb::_affected() {
    local devices=$1 policy=$2 line canonical port
    while IFS= read -r line; do
        [[ -n $line ]] || continue
        usb::_identity "$line" || {
            core::die 'Cannot safely interpret a connected USB device; no profile was applied.'
            return 1
        }
        [[ $USB_DEVICE_TARGET == allow && $USB_DEVICE_PORT != usb* ]] || continue
        canonical=$(usb::_canonical "$line") || return
        # Modern profile rules have exactly these three identity attributes.
        # Legacy rules may be more restrictive: treat them conservatively.
        if ! grep -Fxq -- "$canonical" <<<"$policy"; then
            port=$USB_DEVICE_PORT
            core::log 'This currently allowed device may be disconnected by the profile (input, hubs, networking and storage can be affected):'
            printf '%s\n' "$line" | LC_ALL=C sed -n l
            usb::_safe_to_block "$port" || return
        fi
    done <<<"$devices"
}

usb::profile_preflight() {
    local name=${1-} policy devices current line selected='' after current_policy
    core::require_root && usb::_profile_name "$name" && usb::_paths || return 1
    if [[ ! -f "$USB_STATE_DIR/enrolled" ]]; then
        core::log 'USB protection needs initial enrollment. Its installation masks remain in place until you physically review connected devices.'
        usb::apply || return
        core::log 'Initial USB protection is now active with your physically reviewed policy. Canceling the upcoming profile switch keeps that protection active; no additional devices will be trusted.'
    fi
    usb::_managed || return
    systemctl is-active --quiet usbguard.service || {
        core::die 'Activate the enrolled USB protection before switching its profile.'
        return 1
    }
    current=$(usb::active_profile) && policy=$(usb::_profile_policy "$name") && devices=$(usbguard list-devices) || return
    if [[ -f "$USB_STATE_DIR/active-profile" && ! -e "$USB_STATE_DIR/profile-pending" ]]; then
        current_policy=$(usb::_profile_policy "$current") || return
        if ! cmp -s "$USB_CONFIG_DIR/rules.conf" <(printf '%s\n' "$current_policy") || ! usb::_verified_policy "$current_policy"; then
            core::die 'USB rules changed outside the active profile. Inspect the changed native policy before replacing it.'
            return 1
        fi
    fi
    USB_PROFILE_PREVIEW_SOURCE=$(sha256sum "$USB_CONFIG_DIR/rules.conf") || return
    USB_PROFILE_PREVIEW_RUNTIME=$(usbguard list-rules) || return
    USB_PROFILE_PREVIEW_DESTINATION=$(usb::_profile_policy "$name") || return
    if [[ ! -e "$USB_STATE_DIR/profiles/$name.rules" && $name != legacy ]]; then
        core::log "USB profile $name has no enrolled devices. Review the currently allowed devices below; blocked devices will stay blocked."
        while IFS= read -r line; do
            [[ -n $line ]] || continue
            usb::_identity "$line" || return 1
            [[ $USB_DEVICE_TARGET == allow && $USB_DEVICE_PORT != usb* ]] || continue
            printf '%s\n' "$line" | LC_ALL=C sed -n l
            selected+="$(usb::_canonical "$line")"$'\n'
        done <<<"$devices"
        if [[ -n $selected ]]; then
            core::confirm "I physically recognize ALL listed devices and want to remember this exact set ONLY for USB profile $name. Continue?" || return 1
            policy=${selected%$'\n'}
        fi
    fi
    usb::_affected "$devices" "$policy" || return
    after=$(usbguard list-devices) || return
    [[ $devices == "$after" ]] || {
        core::die 'USB devices changed during profile review. Review the destination profile again.'
        return 1
    }
    USB_PROFILE_PREVIEW_NAME=$name
    USB_PROFILE_PREVIEW_POLICY=$policy
    USB_PROFILE_PREVIEW_DEVICES=$devices
    USB_PROFILE_PREVIEW_CURRENT=$current
    core::log "USB profile $name: existing devices will be reevaluated, permissions from $current will not carry over, and temporary approvals will expire."
}

usb::profile_apply() {
    local name=${1-} devices policy
    core::require_root && usb::_profile_name "$name" && usb::_paths || return 1
    if [[ ${USB_PROFILE_PREVIEW_NAME-} != "$name" ]]; then usb::profile_preflight "$name" || return; fi
    usb::_managed || return
    devices=$(usbguard list-devices) || return
    [[ $devices == "$USB_PROFILE_PREVIEW_DEVICES" && $(usb::active_profile) == "$USB_PROFILE_PREVIEW_CURRENT" ]] || {
        core::die 'USB devices or the active profile changed after review. No USB profile was applied; review again.'
        return 1
    }
    [[ $(sha256sum "$USB_CONFIG_DIR/rules.conf") == "$USB_PROFILE_PREVIEW_SOURCE" &&
    $(usbguard list-rules) == "$USB_PROFILE_PREVIEW_RUNTIME" &&
    $(usb::_profile_policy "$name") == "$USB_PROFILE_PREVIEW_DESTINATION" ]] || {
        core::die 'USB policy changed after review. No USB profile was applied; inspect the changed rules and review again.'
        return 1
    }
    policy=$USB_PROFILE_PREVIEW_POLICY
    # Check mounts again immediately before deauthorization; they may have been
    # mounted while the administrator reviewed another control's changes.
    usb::_affected "$devices" "$policy" || return
    usb::_adopt || return
    printf '%s\n' "$name" | core::write_file "$USB_STATE_DIR/profile-pending" 0600 || return
    if [[ $name != legacy ]]; then
        printf '%s\n' "$policy" | core::write_file "$USB_STATE_DIR/profiles/$name.rules" 0600 || return
    fi
    printf '%s\n' "$policy" | core::write_file "$USB_CONFIG_DIR/rules.conf" 0600 || return
    # USBGuard reapplies policy to all present devices on restart, including
    # previously allowed devices. Unknown insertion remains kernel-default deny.
    if ! systemctl restart usbguard.service || ! usb::_verified_policy "$policy" || [[ $(usb::_device_deviations "$policy") != 0 ]]; then
        core::die 'USB profile application could not be verified. The profile is incomplete; inspect USBGuard before relying on protection.'
        return 1
    fi
    printf '%s\n' "$name" | core::write_file "$USB_STATE_DIR/active-profile" 0600 || return
    rm -f -- "$USB_STATE_DIR/profile-pending" || return
    USB_PROFILE_PREVIEW_NAME=
    core::record "USB profile $name applied and runtime policy verified; temporary approvals expired."
}

usb::profile_restore() {
    core::require_root && usb::_managed || return 1
    [[ -f "$USB_STATE_DIR/legacy.rules" ]] || {
        core::die 'No pre-profile USB policy is available to restore.'
        return 1
    }
    usb::profile_preflight legacy && usb::profile_apply legacy
}

usb::profile_clone() {
    local name=${1-} base=${2-} policy
    core::require_root && usb::_profile_name "$name" && usb::_profile_name "$base" && usb::_paths || return 1
    [[ $name != legacy && ! -e "$USB_STATE_DIR/profiles/$name.rules" && ! -L "$USB_STATE_DIR/profiles/$name.rules" ]] || return 1
    # No implicit copying of legacy/global approvals into a fresh profile.
    [[ -f "$USB_STATE_DIR/profiles/$base.rules" ]] || return 0
    policy=$(usb::_profile_policy "$base") || return
    install -d -m 0700 -o root -g root "$USB_STATE_DIR" "$USB_STATE_DIR/profiles" || return
    printf '%s\n' "$policy" | core::write_file "$USB_STATE_DIR/profiles/$name.rules" 0600
}

usb::profile_delete() {
    local name=${1-}
    core::require_root && usb::_profile_name "$name" && usb::_paths || return 1
    [[ $name != legacy && $(usb::active_profile) != "$name" ]] || {
        core::die 'Cannot delete the active or recovery USB policy.'
        return 1
    }
    usb::_private_path "$USB_STATE_DIR/profiles/$name.rules" || return
    rm -f -- "$USB_STATE_DIR/profiles/$name.rules"
}

usb::profile_enroll() {
    local name=${1-} devices after policy='' line
    [[ $# == 1 ]] && core::require_root && usb::_profile_name "$name" && usb::_managed || return 1
    if declare -F profiles::get >/dev/null; then
        profiles::get "$name" >/dev/null || {
            core::die 'Create the named profile before enrolling USB devices for it.'
            return 1
        }
    fi
    [[ $name != legacy && $(usb::active_profile) != "$name" ]] || {
        core::die 'Use allow/forget for the active USB profile; enrollment prepares an inactive profile.'
        return 1
    }
    devices=$(usbguard list-devices) || return
    core::log "Physically review EVERY connected device below. This replaces the remembered device set ONLY for inactive USB profile $name; it does not switch the current profile. Disconnect untrusted devices first."
    while IFS= read -r line; do
        [[ -n $line ]] || continue
        usb::_identity "$line" || return 1
        [[ $USB_DEVICE_PORT != usb* ]] || continue
        printf '%s\n' "$line" | LC_ALL=C sed -n l
        policy+="$(usb::_canonical "$line")"$'\n'
    done <<<"$devices"
    core::confirm "I physically recognize ALL listed devices and want this exact device set remembered only for USB profile $name. Save it?" || return 1
    after=$(usbguard list-devices) || return
    [[ $devices == "$after" ]] || {
        core::die 'USB devices changed during review. No profile was enrolled.'
        return 1
    }
    usb::_adopt || return
    usb::_private_path "$USB_STATE_DIR/profiles/$name.rules" || return
    printf '%s\n' "${policy%$'\n'}" | core::write_file "$USB_STATE_DIR/profiles/$name.rules" 0600 || return
    core::record "Physically reviewed USB device set enrolled only for inactive profile $name."
}

# Device IDs are allocated again when USBGuard restarts. Bind every interactive
# decision to this daemon invocation and boot as well as its private identity.
# This digest is a stale-selection guard, not a credential or device attestation.
usb::_attachment_context() {
    local boot invocation
    IFS= read -r boot <"$USB_PROC_DIR/sys/kernel/random/boot_id" || return 1
    invocation=$(systemctl show --property=InvocationID --value usbguard.service) || return 1
    [[ $boot =~ ^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$ && $invocation =~ ^[a-f0-9]{32}$ ]] || return 1
    printf '%s:%s\n' "$boot" "$invocation"
}

usb::_attachment_token() {
    local id=$1 device=$2 context=${3-} identity digest
    usb::_validate_id "$id" && [[ $device == "$id: "* ]] || return 1
    [[ -n $context ]] || context=$(usb::_attachment_context) || return 1
    usb::_identity "$device" || return 1
    identity=${device#"$id: "}
    identity=${identity#* }
    # Include every validated descriptor, excluding only the allow/block state.
    digest=$(printf '%s\n%s\n%s\n' "$context" "$id" "$identity" | sha256sum) || return 1
    printf '%s\n' "${digest%% *}"
}

usb::_approval_matches() {
    local id=$1 device=$2 token=$3 profile=$4 current
    [[ $token =~ ^[a-f0-9]{64}$ ]] && usb::_profile_name "$profile" || return 1
    current=$(usb::active_profile) || return 1
    if [[ $current != "$profile" || $(usb::_attachment_token "$id" "$device") != "$token" ]]; then
        core::die 'The USB device or active profile changed. Refresh connected devices and choose again; no new approval was granted.'
        return 1
    fi
}

usb::devices_json() {
    core::require_root || return
    local devices profile policy line id state canonical remembered category context token remembered_rules='' rows='' count=0
    profile=$(usb::active_profile) && policy=$(usb::_profile_policy "$profile") && context=$(usb::_attachment_context) && devices=$(usbguard list-devices) || return
    # Older enrolled policies retain USBGuard's extra name/serial/interface
    # fields. Compare their safely parsed, exact VID/hash/port identity rather
    # than mistaking a remembered device for a temporary allowance. This is a
    # display projection only: no saved/native authorization rule is rewritten.
    while IFS= read -r line; do
        [[ $line == 'allow '* ]] || continue
        if canonical=$(usb::_canonical "$line"); then remembered_rules+="$canonical"$'\n'; fi
    done <<<"$policy"
    while IFS= read -r line; do
        [[ -n $line ]] || continue
        ((count += 1))
        ((count <= 256 && ${#line} <= 16384)) || return 1
        [[ $line =~ ^([1-9][0-9]*):\  ]] || return 1
        id=${BASH_REMATCH[1]}
        usb::_validate_id "$id" && usb::_identity "$line" || return 1
        [[ $USB_DEVICE_PORT != usb* ]] || continue
        case "$USB_DEVICE_TARGET" in allow) state=allowed ;; block) state=blocked ;; reject) state=rejected ;; esac
        category=other
        case " $USB_DEVICE_INTERFACES " in
            *' 03:'*) category=input ;;
            *' 08:'*) category=storage ;;
            *' 02:'* | *' 0a:'* | *' e0:'*) category=network ;;
            *' 09:'*) category=hub ;;
        esac
        canonical=$(usb::_canonical "$line") || return
        token=$(usb::_attachment_token "$id" "$line" "$context") || return
        remembered=false
        grep -Fxq -- "$canonical" <<<"$remembered_rules" && remembered=true
        rows+=$(jq -cn --argjson id "$id" --arg token "$token" --arg state "$state" --arg category "$category" \
            --arg name "$USB_DEVICE_NAME" --arg vendor_product "$USB_DEVICE_VID" \
            --arg port "$USB_DEVICE_PORT" --arg profile "$profile" --argjson remembered "$remembered" \
            '($name | gsub("[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]";"") | .[0:128]) as $safe_name |
             {id:$id,token:$token,state:$state,category:$category,name:$safe_name,label:(if $safe_name == "" then "USB device" else $safe_name end),vendor_product:$vendor_product,port:$port,profile:$profile,remembered:$remembered}') || return
        rows+=$'\n'
    done <<<"$devices"
    # A restart during collection could otherwise associate new numeric IDs
    # with the old daemon invocation. Never publish an inconsistent inventory.
    [[ $(usb::_attachment_context) == "$context" && $(usb::active_profile) == "$profile" ]] || return 1
    jq -s '.' <<<"$rows"
}

usb::profile_status() {
    local state=unknown summary='USB protection cannot be verified.' profile=legacy policy devices pending=0 remembered=0 verified=false deviations
    if ! usb::_managed >/dev/null 2>&1; then
        summary='USB protection requires explicit enrollment or its managed configuration has changed.'
    elif ! systemctl is-active --quiet usbguard.service; then
        state=inactive
        summary='USBGuard is not running; USB protection is not active.'
    elif profile=$(usb::active_profile) && policy=$(usb::_profile_policy "$profile"); then
        remembered=$(usb::_policy_lines <<<"$policy" | wc -l)
        [[ -n $(usb::_policy_lines <<<"$policy") ]] || remembered=0
        if [[ -e "$USB_STATE_DIR/profile-pending" ]] || ! cmp -s "$USB_CONFIG_DIR/rules.conf" <(printf '%s\n' "$policy") || ! usb::_verified_policy "$policy"; then
            state=partial
            summary='USB profile differs from the running policy or a profile change is incomplete.'
        elif devices=$(usb::devices_json); then
            pending=$(jq '[.[] | select(.state == "blocked" or .state == "rejected")] | length' <<<"$devices") || return
            deviations=$(usb::_device_deviations "$policy") || deviations=unknown
            if [[ $deviations == 0 ]]; then
                state=active
                verified=true
                summary="USB profile $profile is active; unknown devices stay blocked pending approval."
            else
                state=partial
                summary="USB profile $profile has temporary or external device exceptions; inspect connected devices."
            fi
        fi
    fi
    jq -cn --arg state "$state" --arg summary "$summary" --arg profile "$profile" \
        --argjson pending "$pending" --argjson remembered "$remembered" --argjson verified "$verified" \
        '{state:$state,summary:$summary,profile:$profile,pending:$pending,remembered:$remembered,verified:$verified}'
}

usb::_config() {
    cat <<CONFIG
# Managed by Octoshield. Device rules are enrolled separately and retained.
RuleFile=$USB_CONFIG_DIR/rules.conf
ImplicitPolicyTarget=block
PresentDevicePolicy=apply-policy
PresentControllerPolicy=keep
InsertedDevicePolicy=apply-policy
AuthorizedDefault=none
RestoreControllerDeviceState=false
DeviceManagerBackend=uevent
IPCAllowedUsers=root
DeviceRulesWithPort=true
AuditBackend=FileAudit
AuditFilePath=$USB_LOG_DIR/usbguard-audit.log
HidePII=true
CONFIG
}

usb::_masked_by_us() {
    local unit=$1
    [[ -f "$USB_STATE_DIR/masked-$unit" && -L "$USB_UNIT_DIR/$unit" ]] &&
        [[ $(readlink "$USB_UNIT_DIR/$unit") == /dev/null ]]
}

usb::_mask() {
    local unit=$1
    if usb::_masked_by_us "$unit"; then
        return 0
    fi
    if [[ -e "$USB_UNIT_DIR/$unit" || -L "$USB_UNIT_DIR/$unit" ]] ||
        [[ $(systemctl is-enabled "$unit" 2>/dev/null) == masked* ]]; then
        core::die "Existing mask or override for $unit; inspect it manually before USB enrollment."
        return 1
    fi
    systemctl mask "$unit" || return
    printf '%s\n' 'Octoshield installation mask' |
        core::write_file "$USB_STATE_DIR/masked-$unit" 0600 || return
}

usb::_unmask_daemon() {
    if [[ -f "$USB_STATE_DIR/masked-usbguard.service" ]]; then
        usb::_masked_by_us usbguard.service || {
            core::die 'The USBGuard installation mask has changed; inspect it manually.'
            return 1
        }
        systemctl unmask usbguard.service || return
        rm -f -- "$USB_STATE_DIR/masked-usbguard.service" || return
    fi
}

usb::_pending_message() {
    core::log 'USB enrollment is incomplete. Octoshield keeps its installation masks in place to protect input devices from an unreviewed policy. Rerun octoshield apply usb to resume; see README recovery instructions. USB protection is NOT active yet.'
}

usb::_start() {
    usb::_unmask_daemon || return
    systemctl enable --now usbguard.service || {
        core::die 'USBGuard did not start. Inspect: sudo journalctl -u usbguard.service. Do not assume USB protection is active.'
        return 1
    }
    systemctl is-active --quiet usbguard.service || {
        core::die 'USBGuard is not active after startup.'
        return 1
    }
}

usb::_unmanaged() {
    [[ -e "$USB_CONFIG_DIR" || -L "$USB_CONFIG_DIR" ]] ||
        command -v usbguard >/dev/null 2>&1 ||
        systemctl is-active --quiet usbguard.service
}

usb::_valid_policy() {
    local line count=0
    while IFS= read -r line || [[ -n $line ]]; do
        [[ -z $line || $line == '#'* ]] && continue
        # Reject empty or broad policies, but leave full rule parsing to USBGuard.
        [[ $line =~ ^allow\ id\ [[:xdigit:]]{4}:[[:xdigit:]]{4}\  &&
            $line == *' hash "'* && $line == *' via-port "'* ]] || return 1
        ((count += 1))
    done
    ((count > 0))
}

usb::apply() {
    core::require_root || return
    if [[ -f "$USB_STATE_DIR/enrolled" ]]; then
        if [[ ! -s "$USB_CONFIG_DIR/rules.conf" ]] ||
            ! cmp -s "$USB_CONFIG_DIR/usbguard-daemon.conf" <(usb::_config); then
            core::die 'Managed USBGuard configuration is missing or changed. Inspect it manually; Octoshield will not overwrite policy or enroll current devices again.'
            return 1
        fi
        usb::_masked_by_us usbguard-dbus.service || {
            core::die 'The USBGuard D-Bus bridge mask has changed; inspect it before enabling USB protection.'
            return 1
        }
        usb::_start || return
        rm -f -- "$USB_STATE_DIR/pending" || return
        core::log 'USBGuard is active. Existing trusted-device rules were retained; no devices were enrolled.'
        return 0
    fi

    if [[ ! -f "$USB_STATE_DIR/pending" ]] && usb::_unmanaged; then
        core::die 'An existing USBGuard installation was found. Octoshield will not replace it. Review its policy and administrator access manually; see README.'
        return 1
    fi
    core::confirm 'USB enrollment: disconnect ALL untrusted USB devices. Keep only your trusted keyboard, mouse, required hubs/dock and built-in devices connected. Stay at the laptop throughout setup. Have a recovery login/boot plan. Continue?' || return 1
    install -d -m 0700 -o root -g root "$USB_STATE_DIR" || return
    printf '%s\n' 'USB enrollment pending' | core::write_file "$USB_STATE_DIR/pending" 0600 || return
    # Persistent masks also protect a reboot following an interrupted apt install.
    # The D-Bus bridge remains masked: only the root-owned CLI may change policy.
    if ! usb::_mask usbguard.service || ! usb::_mask usbguard-dbus.service; then
        usb::_pending_message
        return 1
    fi
    core::install_packages usbguard || {
        usb::_pending_message
        return 1
    }
    usb::_enroll || {
        usb::_pending_message
        return 1
    }
}

usb::_enroll() {
    local policy current
    policy=$(usbguard generate-policy --with-ports) || return
    if ! usb::_valid_policy <<<"$policy"; then
        core::die 'USBGuard did not produce a nonempty, device-specific policy. Enrollment stopped.'
        return 1
    fi
    core::log 'Review EVERY proposed trusted device below, including built-in devices and hubs. Device names/descriptors can be spoofed. These are the exact rules that will be installed:'
    # Render any control characters inert, including device-supplied names.
    printf '%s\n' "$policy" | LC_ALL=C sed -n l || return
    core::confirm 'I physically recognize ALL listed devices, have removed untrusted devices, and want to trust this exact set. Enable USBGuard now?' || return 1
    current=$(usbguard generate-policy --with-ports) || return
    if [[ $current != "$policy" ]]; then
        core::die 'The USB device set changed during review. No policy was enrolled. Rerun setup and review again.'
        return 1
    fi
    install -d -m 0700 -o root -g root "$USB_CONFIG_DIR" "$USB_LOG_DIR" || return
    printf '%s\n' "$policy" | core::write_file "$USB_CONFIG_DIR/rules.conf" 0600 || return
    usb::_config | core::write_file "$USB_CONFIG_DIR/usbguard-daemon.conf" 0600 || return
    # Mark enrollment before startup: a retry must never trust newly attached devices.
    printf '%s\n' 'Reviewed device policy installed' |
        core::write_file "$USB_STATE_DIR/enrolled" 0600 || return
    usb::_start || return
    rm -f -- "$USB_STATE_DIR/pending" || return
    core::record 'USBGuard enabled with reviewed port-bound device rules, unknown devices blocked, root-only IPC, and D-Bus bridge masked.' || return
    core::log 'USBGuard is active. An unknown device stays blocked until approved with octoshield usb allow ID. Moving trusted devices to another port may require approval.'
}

usb::_validate_id() {
    if [[ ! ${1-} =~ ^[1-9][0-9]{0,9}$ ]] || ((10#$1 > 4294967294)); then
        core::die 'Use one positive numeric device ID from octoshield usb list; rules and wildcard selectors are not accepted.'
        return 1
    fi
}

usb::_device() {
    local id=$1 devices line
    devices=$(usbguard list-devices) || return
    while IFS= read -r line; do
        if [[ $line == "$id: "* ]]; then
            printf '%s\n' "$line"
            return 0
        fi
    done <<<"$devices"
    core::die "USB device ID $id is no longer present. Run octoshield usb list again."
    return 1
}

usb::_change() {
    local operation=$1 id=$2 permanent=$3 token=${4-} expected_profile=${5-} before after profile canonical policy path
    core::require_root || return
    usb::_validate_id "$id" || return
    systemctl is-active --quiet usbguard.service || {
        core::die 'USBGuard is not active. Run octoshield apply usb first.'
        return 1
    }
    before=$(usb::_device "$id") || return
    if [[ -n $token ]]; then
        usb::_managed && usb::_approval_matches "$id" "$before" "$token" "$expected_profile" || return 1
    fi
    printf '%s\n' "$before" | LC_ALL=C sed -n l || return
    if [[ $operation == block ]]; then
        core::confirm 'Block this device until it is reconnected or policy is reapplied? Blocking your keyboard, input hub or network adapter may interrupt access.' || return 1
        usb::_identity "$before" && usb::_safe_to_block "$USB_DEVICE_PORT" || return 1
    elif [[ $permanent == yes ]]; then
        usb::_managed || return
        profile=$(usb::active_profile) && policy=$(usb::_profile_policy "$profile") && canonical=$(usb::_canonical "$before") || return
        usb::_verified_policy "$policy" || {
            core::die 'USB runtime policy differs from the active profile. Reapply the profile before remembering a device.'
            return 1
        }
        [[ -n $token ]] || core::confirm "Remember this physically verified device on this port ONLY in USB profile $profile? Other profiles will still block it. Device descriptors are not cryptographic identity." || return 1
    else
        [[ -n $token ]] || core::confirm 'Allow this physically verified device this time? Approval ends on reconnection, daemon restart or profile switch unless the destination profile already remembers it.' || return 1
    fi
    after=$(usb::_device "$id") || return
    [[ $before == "$after" ]] || {
        core::die 'Device identity/state changed during review. List devices and retry.'
        return 1
    }
    [[ -z $token ]] || usb::_approval_matches "$id" "$after" "$token" "$expected_profile" || return 1
    if [[ $permanent == yes ]]; then
        usb::_adopt || return
        path="$USB_STATE_DIR/profiles/$profile.rules"
        [[ $profile != legacy ]] || path="$USB_STATE_DIR/legacy.rules"
        if ! grep -Fxq -- "$canonical" <<<"$policy"; then
            policy="${policy:+$policy$'\n'}$canonical"
            printf '%s\n' "$profile" | core::write_file "$USB_STATE_DIR/profile-pending" 0600 || return
            printf '%s\n' "$policy" | core::write_file "$path" 0600 || return
            core::backup "$USB_CONFIG_DIR/rules.conf" || return
            usbguard append-rule "$canonical" || return
        fi
        after=$(usb::_device "$id") || return
        [[ $after == "$before" ]] || {
            core::die 'Device changed while saving approval. No temporary authorization was granted; inspect the saved rule.'
            return 1
        }
        [[ -z $token ]] || usb::_approval_matches "$id" "$after" "$token" "$expected_profile" || return 1
        usbguard allow-device "$id" && usb::_verified_policy "$policy" &&
            cmp -s "$USB_CONFIG_DIR/rules.conf" <(printf '%s\n' "$policy") || return 1
        rm -f -- "$USB_STATE_DIR/profile-pending" || return
    else
        usbguard "$operation-device" "$id" || return
    fi
    core::record "USB device $id: $operation (permanent=$permanent)."
}

usb::_forget() {
    local id=$1 token=${2-} expected_profile=${3-} before after profile policy line canonical retained='' path
    core::require_root && usb::_validate_id "$id" && usb::_managed || return 1
    before=$(usb::_device "$id") && canonical=$(usb::_canonical "$before") && profile=$(usb::active_profile) && policy=$(usb::_profile_policy "$profile") || return
    [[ -z $token ]] || usb::_approval_matches "$id" "$before" "$token" "$expected_profile" || return 1
    usb::_verified_policy "$policy" || return 1
    printf '%s\n' "$before" | LC_ALL=C sed -n l
    core::confirm "Forget this device ONLY in USB profile $profile and block it now? Other profiles are unchanged; input devices and docks can interrupt access." || return 1
    usb::_identity "$before" && usb::_safe_to_block "$USB_DEVICE_PORT" || return 1
    while IFS= read -r line; do
        [[ -n $line && $line != '#'* ]] || continue
        [[ $(usb::_canonical "$line") == "$canonical" ]] && continue
        retained+="$line"$'\n'
    done <<<"$policy"
    after=$(usb::_device "$id") || return
    [[ $after == "$before" ]] || return 1
    [[ -z $token ]] || usb::_approval_matches "$id" "$after" "$token" "$expected_profile" || return 1
    usb::_adopt || return
    path="$USB_STATE_DIR/profiles/$profile.rules"
    [[ $profile != legacy ]] || path="$USB_STATE_DIR/legacy.rules"
    printf '%s\n' "$profile" | core::write_file "$USB_STATE_DIR/profile-pending" 0600 || return
    printf '%s\n' "${retained%$'\n'}" | core::write_file "$path" 0600 || return
    # Reapply the complete policy so cached runtime authorizations cannot survive
    # removing a remembered rule. This also expires other temporary approvals.
    USB_PROFILE_PREVIEW_NAME=
    usb::profile_preflight "$profile" && usb::profile_apply "$profile"
}

usb::forget() {
    [[ $# == 1 ]] || return 1
    usb::_forget "$1"
}

# The desktop displays the exact bounded inventory before sending this explicit
# decision over its administrator-authorized broker. Approval omits its duplicate
# textual review; revocation retains warnings about disrupting input/storage.
# Native identity, profile, storage and policy checks remain. The token conveys
# no authority and cannot replace root access.
usb::approve() {
    [[ $# == 4 && $2 =~ ^[a-f0-9]{64}$ ]] && usb::_validate_id "$1" && usb::_profile_name "$3" || return 1
    case "$4" in
        once) usb::_change allow "$1" no "$2" "$3" ;;
        profile) usb::_change allow "$1" yes "$2" "$3" ;;
        *) return 1 ;;
    esac
}

usb::revoke() {
    [[ $# == 4 && $2 =~ ^[a-f0-9]{64}$ ]] && usb::_validate_id "$1" && usb::_profile_name "$3" || return 1
    case "$4" in
        block) usb::_change block "$1" no "$2" "$3" ;;
        forget) usb::_forget "$1" "$2" "$3" ;;
        *) return 1 ;;
    esac
}

usb::allow() {
    if (($# < 1 || $# > 2)) || [[ ${2-} != '' && ${2-} != --permanent ]]; then
        core::die 'Usage: octoshield usb allow ID [--permanent]'
        return 1
    fi
    local permanent=no
    [[ ${2-} == --permanent ]] && permanent=yes
    usb::_change allow "$1" "$permanent"
}

usb::block() {
    if (($# != 1)); then
        core::die 'Usage: octoshield usb block ID'
        return 1
    fi
    usb::_change block "$1" no
}

usb::list() {
    core::require_root || return
    command -v usbguard >/dev/null 2>&1 || {
        core::die 'USBGuard is not installed.'
        return 1
    }
    local devices
    devices=$(usbguard list-devices) || return
    printf '%s\n' "$devices" | LC_ALL=C sed -n l
}

usb::status() {
    if systemctl is-active --quiet usbguard.service; then
        core::log 'USBGuard: active (inspect rules with sudo usbguard list-rules).'
    elif [[ -f "$USB_STATE_DIR/pending" ]]; then
        core::log 'USBGuard: enrollment incomplete; USB protection is NOT active.'
    else
        core::log 'USBGuard: inactive.'
    fi
}
