#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# USBGuard enrollment and explicit administrator device authorization.
# These locations are deliberately assigned, never inherited from the environment.
USB_CONFIG_DIR=/etc/usbguard
USB_STATE_DIR=/var/lib/octoshield/usb
USB_LOG_DIR=/var/log/usbguard
USB_UNIT_DIR=/etc/systemd/system

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
    local operation=$1 id=$2 permanent=$3 before after
    core::require_root || return
    usb::_validate_id "$id" || return
    systemctl is-active --quiet usbguard.service || {
        core::die 'USBGuard is not active. Run octoshield apply usb first.'
        return 1
    }
    before=$(usb::_device "$id") || return
    printf '%s\n' "$before" | LC_ALL=C sed -n l || return
    if [[ $operation == block ]]; then
        core::confirm 'Block this device until it is reconnected or policy is reapplied? Blocking your keyboard, input hub or network adapter may interrupt access.' || return 1
    elif [[ $permanent == yes ]]; then
        core::confirm 'Trust this physically verified device permanently on this port? Device descriptors are not cryptographic identity.' || return 1
        core::backup "$USB_CONFIG_DIR/rules.conf" || return
    else
        core::confirm 'Allow this physically verified device temporarily? It will need approval after reconnection or daemon restart unless an existing policy allows it.' || return 1
    fi
    after=$(usb::_device "$id") || return
    [[ $before == "$after" ]] || {
        core::die 'Device identity/state changed during review. List devices and retry.'
        return 1
    }
    if [[ $permanent == yes ]]; then
        usbguard "$operation-device" --permanent "$id" || return
    else
        usbguard "$operation-device" "$id" || return
    fi
    core::record "USB device $id: $operation (permanent=$permanent)."
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
