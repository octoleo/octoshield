#!/usr/bin/env bats
# SPDX-License-Identifier: Apache-2.0
# Mock all USB/system changes; tests never inspect or modify host USB devices.
# shellcheck disable=SC2317,SC2329

setup() {
    bats_require_minimum_version 1.5.0
    # shellcheck source=src/lib/usb.sh
    source "$BATS_TEST_DIRNAME/../src/lib/usb.sh"
    USB_CONFIG_DIR="$BATS_TEST_TMPDIR/etc"
    USB_STATE_DIR="$BATS_TEST_TMPDIR/state"
    USB_UNIT_DIR="$BATS_TEST_TMPDIR/units"
    USB_SYS_DIR="$BATS_TEST_TMPDIR/sys"
    TEST_CALLS="$BATS_TEST_TMPDIR/calls"
    TEST_DEVICES="$BATS_TEST_TMPDIR/devices"
    TEST_RULE='allow id 1234:abcd hash "keyboardhash" via-port "1-1"'
    TEST_SECOND='allow id 5678:ef01 hash "storagehash" via-port "1-2"'
    mkdir -p "$USB_CONFIG_DIR" "$USB_STATE_DIR/profiles" "$USB_UNIT_DIR" "$USB_SYS_DIR/dev/block"
    chmod 700 "$USB_CONFIG_DIR" "$USB_STATE_DIR" "$USB_STATE_DIR/profiles"
    printf '%s\n' "$TEST_RULE" >"$USB_CONFIG_DIR/rules.conf"
    usb::_config >"$USB_CONFIG_DIR/usbguard-daemon.conf"
    touch "$USB_STATE_DIR/enrolled" "$USB_STATE_DIR/masked-usbguard-dbus.service"
    ln -s /dev/null "$USB_UNIT_DIR/usbguard-dbus.service"
    printf '7: %s\n8: block id 5678:ef01 hash "storagehash" via-port "1-2"\n' "$TEST_RULE" >"$TEST_DEVICES"
    : >"$TEST_CALLS"
    core::require_root() { return 0; }
    core::log() { printf '%s\n' "$*"; }
    core::die() {
        printf '%s\n' "$*" >&2
        return 1
    }
    core::confirm() {
        printf 'confirm %s\n' "$*" >>"$TEST_CALLS"
        [[ ${TEST_DECLINE:-no} != yes ]]
    }
    core::record() { printf 'record %s\n' "$*" >>"$TEST_CALLS"; }
    core::backup() { printf 'backup %s\n' "$*" >>"$TEST_CALLS"; }
    core::write_file() {
        [[ ${TEST_WRITE_FAIL:-} != "$1" ]] || return 1
        mkdir -p "${1%/*}"
        cat >"$1"
        chmod "$2" "$1"
    }
    install() {
        local -a args=()
        while (($#)); do case "$1" in -o | -g) shift 2 ;; *)
            args+=("$1")
            shift
            ;;
        esac done
        command install "${args[@]}"
    }
    lsblk() {
        local blocks=${TEST_BLOCKS-}
        [[ -n $blocks ]] || blocks='{"blockdevices":[]}'
        printf '%s\n' "$blocks"
    }
    systemctl() {
        printf 'systemctl %s\n' "$*" >>"$TEST_CALLS"
        case "$1" in
            is-active) [[ ${TEST_ACTIVE:-yes} == yes ]] ;;
            restart)
                [[ ${TEST_RESTART_FAIL:-no} != yes ]] || return 1
                [[ ${TEST_SKIP_REEVALUATE:-no} != yes ]] || return 0
                local device identity rule rules='' result=''
                while IFS= read -r rule; do
                    [[ -n $rule && $rule != '#'* ]] || continue
                    rules+="$(usb::_canonical "$rule")"$'\n'
                done <"$USB_CONFIG_DIR/rules.conf"
                while IFS= read -r device; do
                    identity=$(usb::_canonical "$device") || return
                    if grep -Fxq -- "$identity" <<<"$rules"; then
                        result+="${device%%: *}: $identity"$'\n'
                    else
                        result+="${device%%: *}: block ${identity#allow }"$'\n'
                    fi
                done <"$TEST_DEVICES"
                printf '%s' "$result" >"$TEST_DEVICES"
                ;;
            *) return 1 ;;
        esac
    }
    usbguard() {
        printf 'usbguard %s\n' "$*" >>"$TEST_CALLS"
        case "$1" in
            list-devices) cat "$TEST_DEVICES" ;;
            list-rules)
                if [[ ${TEST_RUNTIME_DRIFT:-no} == yes ]]; then printf 'allow\n'; else cat "$USB_CONFIG_DIR/rules.conf"; fi
                ;;
            get-parameter)
                case "$2" in ImplicitPolicyTarget) printf 'block\n' ;; InsertedDevicePolicy) printf 'apply-policy\n' ;; esac
                ;;
            append-rule) printf '%s\n' "$2" >>"$USB_CONFIG_DIR/rules.conf" ;;
            allow-device | block-device) [[ ${TEST_COMMAND_FAIL:-no} != yes ]] ;;
            *) return 1 ;;
        esac
    }
}

@test "first profile explicitly reviews currently allowed devices without trusting blocked devices" {
    run usb::profile_apply conference
    [ "$status" -eq 0 ]
    [ "$(cat "$USB_STATE_DIR/active-profile")" = conference ]
    [ "$(cat "$USB_STATE_DIR/legacy.rules")" = "$TEST_RULE" ]
    [ "$(cat "$USB_STATE_DIR/profiles/conference.rules")" = "$TEST_RULE" ]
    grep -q 'physically recognize ALL listed devices' "$TEST_CALLS"
    run ! grep -q storagehash "$USB_STATE_DIR/profiles/conference.rules"
    grep -Fx 'systemctl restart usbguard.service' "$TEST_CALLS"
    [ ! -e "$USB_STATE_DIR/profile-pending" ]
}

@test "declining new-profile physical review preserves legacy configuration byte for byte" {
    TEST_DECLINE=yes
    run usb::profile_apply conference
    [ "$status" -ne 0 ]
    [ "$(cat "$USB_CONFIG_DIR/rules.conf")" = "$TEST_RULE" ]
    [ ! -f "$USB_STATE_DIR/active-profile" ]
    run ! grep -q restart "$TEST_CALLS"
}

@test "switch replaces entire policy and forces reevaluation of already allowed devices" {
    printf '%s\n' "$TEST_SECOND" >"$USB_STATE_DIR/profiles/home.rules"
    run usb::profile_apply home
    [ "$status" -eq 0 ]
    [ "$(cat "$USB_CONFIG_DIR/rules.conf")" = "$TEST_SECOND" ]
    [[ $output == *'currently allowed device may be disconnected'* ]]
    grep -Fx 'systemctl restart usbguard.service' "$TEST_CALLS"
    run ! grep -q 'usbguard allow-device' "$TEST_CALLS"
}

@test "a deliberately empty profile stays empty and is not automatically enrolled" {
    : >"$USB_STATE_DIR/profiles/conference.rules"
    run usb::profile_apply conference
    [ "$status" -eq 0 ]
    [ -z "$(cat "$USB_CONFIG_DIR/rules.conf")" ]
    run ! grep -q 'physically recognize' "$TEST_CALLS"
}

@test "device topology race after preflight refuses profile changes" {
    usb::profile_preflight conference
    printf '9: %s\n' "$TEST_SECOND" >>"$TEST_DEVICES"
    run usb::profile_apply conference
    [ "$status" -ne 0 ]
    [[ $output == *'changed after review'* ]]
    [ ! -f "$USB_STATE_DIR/active-profile" ]
    run ! grep -q restart "$TEST_CALLS"
}

@test "mounted USB storage prevents profile activation before changing files" {
    printf '8: %s\n' "$TEST_SECOND" >"$TEST_DEVICES"
    : >"$USB_STATE_DIR/profiles/conference.rules"
    mkdir -p "$USB_SYS_DIR/devices/usb1/1-2/block/sda"
    ln -s "$USB_SYS_DIR/devices/usb1/1-2/block/sda" "$USB_SYS_DIR/dev/block/8:0"
    TEST_BLOCKS='{"blockdevices":[{"maj:min":"8:0","mountpoints":["/media/data"]}]}'
    run usb::profile_apply conference
    [ "$status" -ne 0 ]
    [[ $output == *'mounted storage or swap'* ]]
    [ ! -f "$USB_STATE_DIR/active-profile" ]
    run ! grep -q restart "$TEST_CALLS"
}

@test "encrypted USB storage is checked through mapped block device slaves" {
    mkdir -p "$USB_SYS_DIR/devices/usb1/1-2/block/sda" "$USB_SYS_DIR/devices/virtual/dm-0/slaves"
    ln -s "$USB_SYS_DIR/devices/usb1/1-2/block/sda" "$USB_SYS_DIR/devices/virtual/dm-0/slaves/sda"
    ln -s "$USB_SYS_DIR/devices/virtual/dm-0" "$USB_SYS_DIR/dev/block/253:0"
    TEST_BLOCKS='{"blockdevices":[{"maj:min":"253:0","mountpoints":["[SWAP]"]}]}'
    run usb::_safe_to_block 1-2
    [ "$status" -ne 0 ]
    [[ $output == *'mounted storage or swap'* ]]
}

@test "unresolvable mounted storage fails closed" {
    TEST_BLOCKS='{"blockdevices":[{"maj:min":"8:0","mountpoints":["/media/data"]}]}'
    run usb::_safe_to_block 1-2
    [ "$status" -ne 0 ]
    [[ $output == *'Cannot resolve mounted storage'* ]]
}

@test "restart failure keeps pending marker and never reports destination active" {
    : >"$USB_STATE_DIR/profiles/home.rules"
    TEST_RESTART_FAIL=yes
    run usb::profile_apply home
    [ "$status" -ne 0 ]
    [ "$(cat "$USB_STATE_DIR/active-profile")" = legacy ]
    [ "$(cat "$USB_STATE_DIR/profile-pending")" = home ]
    run usb::profile_status
    [ "$status" -eq 0 ]
    [[ $output == *'"state":"partial"'* ]]
}

@test "a runtime mismatch cannot be reported as successful application" {
    TEST_RUNTIME_DRIFT=yes
    run usb::profile_apply conference
    [ "$status" -ne 0 ]
    [ "$(cat "$USB_STATE_DIR/active-profile")" = legacy ]
    [ -e "$USB_STATE_DIR/profile-pending" ]
}

@test "remember only modifies active profile and leaves other profiles unchanged" {
    usb::profile_apply office
    printf '%s\n' "$TEST_RULE" >"$USB_STATE_DIR/profiles/conference.rules"
    : >"$TEST_CALLS"
    run usb::allow 8 --permanent
    [ "$status" -eq 0 ]
    grep -Fx "$TEST_SECOND" "$USB_STATE_DIR/profiles/office.rules"
    [ "$(cat "$USB_STATE_DIR/profiles/conference.rules")" = "$TEST_RULE" ]
    [ "$(cat "$USB_STATE_DIR/legacy.rules")" = "$TEST_RULE" ]
    grep -q 'ONLY in USB profile office' "$TEST_CALLS"
}

@test "temporary approval never writes a remembered rule" {
    usb::profile_apply office
    : >"$TEST_CALLS"
    run usb::allow 8
    [ "$status" -eq 0 ]
    [ "$(cat "$USB_STATE_DIR/profiles/office.rules")" = "$TEST_RULE" ]
    run ! grep -q append-rule "$TEST_CALLS"
    grep -Fx 'usbguard allow-device 8' "$TEST_CALLS"
}

@test "restore reinstates original legacy policy and reevaluates attached devices" {
    usb::profile_apply office
    usb::allow 8 --permanent
    run usb::profile_restore
    [ "$status" -eq 0 ]
    [ "$(cat "$USB_STATE_DIR/active-profile")" = legacy ]
    [ "$(cat "$USB_CONFIG_DIR/rules.conf")" = "$TEST_RULE" ]
}

@test "explicit profile clone copies only named profile permissions" {
    usb::profile_apply office
    run usb::profile_clone work office
    [ "$status" -eq 0 ]
    [ "$(cat "$USB_STATE_DIR/profiles/work.rules")" = "$TEST_RULE" ]
    run usb::profile_clone conference legacy
    [ "$status" -eq 0 ]
    [ ! -e "$USB_STATE_DIR/profiles/conference.rules" ]
}

@test "active and recovery policies cannot be deleted" {
    usb::profile_apply office
    run usb::profile_delete office
    [ "$status" -ne 0 ]
    run usb::profile_delete legacy
    [ "$status" -ne 0 ]
    printf '%s\n' "$TEST_RULE" >"$USB_STATE_DIR/profiles/work.rules"
    run usb::profile_delete work
    [ "$status" -eq 0 ]
    [ ! -e "$USB_STATE_DIR/profiles/work.rules" ]
}

@test "symlinked policy and unsafe profile IDs are rejected" {
    ln -s "$USB_CONFIG_DIR/rules.conf" "$USB_STATE_DIR/profiles/home.rules"
    run usb::profile_apply home
    [ "$status" -ne 0 ]
    for name in '../bad' 'Home' '-option' 'office/x' ''; do
        run usb::profile_apply "$name"
        [ "$status" -ne 0 ]
    done
    run ! grep -q restart "$TEST_CALLS"
}

@test "device-supplied attribute-looking name cannot alter canonical identity" {
    local device='7: allow id 1234:abcd name "fake hash \"evil\" via-port \"1-9\"" hash "good" via-port "1-1"'
    run usb::_canonical "$device"
    [ "$status" -eq 0 ]
    [ "$output" = 'allow id 1234:abcd hash "good" via-port "1-1"' ]
}

@test "broad duplicate and conditional device rules are rejected" {
    for rule in 'allow' 'allow id *:* hash "h" via-port "1-1"' 'allow id 1234:abcd hash "h" hash "x" via-port "1-1"' 'allow id 1234:abcd hash "h" via-port "1-1" if true'; do
        run usb::_canonical "$rule"
        [ "$status" -ne 0 ]
    done
}

@test "public device data omits serials and hashes and identifies blocked devices" {
    printf '8: block id 5678:ef01 serial "private-serial" name "USB disk" hash "storagehash" via-port "1-2" with-interface 08:06:50\n' >"$TEST_DEVICES"
    run usb::devices_json
    [ "$status" -eq 0 ]
    [[ $output == *'"category": "storage"'* ]]
    [[ $output == *'"state": "blocked"'* ]]
    [[ $output != *private-serial* && $output != *storagehash* ]]
}

@test "enrolling inactive profile requires physical review and never changes active policy" {
    run usb::profile_enroll conference
    [ "$status" -eq 0 ]
    grep -Fx "$TEST_SECOND" "$USB_STATE_DIR/profiles/conference.rules"
    [ "$(cat "$USB_CONFIG_DIR/rules.conf")" = "$TEST_RULE" ]
    run ! grep -q restart "$TEST_CALLS"
}

@test "forget removes current profile permission and expires runtime approvals" {
    usb::profile_apply office
    run usb::forget 7
    [ "$status" -eq 0 ]
    [ -z "$(cat "$USB_STATE_DIR/profiles/office.rules")" ]
    [ "$(cat "$USB_STATE_DIR/legacy.rules")" = "$TEST_RULE" ]
    grep -Fx 'systemctl restart usbguard.service' "$TEST_CALLS"
}

@test "native policy modification after review aborts rather than overwriting external rules" {
    usb::profile_preflight office
    printf '# changed by another administrator\n' >>"$USB_CONFIG_DIR/rules.conf"
    run usb::profile_apply office
    [ "$status" -ne 0 ]
    [[ $output == *'policy changed after review'* ]]
    run ! grep -q restart "$TEST_CALLS"
}

@test "unsafe storage check errors through stacked slaves are propagated" {
    mkdir -p "$USB_SYS_DIR/devices/virtual/dm-0/slaves"
    ln -s "$USB_SYS_DIR/disappeared" "$USB_SYS_DIR/devices/virtual/dm-0/slaves/sda"
    ln -s "$USB_SYS_DIR/devices/virtual/dm-0" "$USB_SYS_DIR/dev/block/253:0"
    TEST_BLOCKS='{"blockdevices":[{"maj:min":"253:0","mountpoints":["/media/data"]}]}'
    run usb::_safe_to_block 1-2
    [ "$status" -ne 0 ]
    [[ $output == *'Cannot resolve mounted storage'* ]]
}

@test "device display strips control characters without corrupting ordinary names" {
    printf '8: block id 5678:ef01 name "Office USB disk\033" hash "storagehash" via-port "1-2"\n' >"$TEST_DEVICES"
    run usb::devices_json
    [ "$status" -eq 0 ]
    [[ $output == *'"name": "Office USB disk"'* ]]
    [[ $output != *'\\u001b'* ]]
}

@test "fresh profile activation invokes guarded explicit initial enrollment" {
    rm "$USB_STATE_DIR/enrolled"
    usb::apply() {
        printf 'physical-enrollment\n' >>"$TEST_CALLS"
        touch "$USB_STATE_DIR/enrolled"
    }
    run usb::profile_apply conference
    [ "$status" -eq 0 ]
    [[ $output == *'Canceling the upcoming profile switch keeps that protection active'* ]]
    grep -Fx physical-enrollment "$TEST_CALLS"
    grep -q 'physically recognize ALL listed devices' "$TEST_CALLS"
}

@test "USB enrollment cannot create permissions for an unknown named profile" {
    profiles::get() { [[ $1 == office ]]; }
    run usb::profile_enroll missing-profile
    [ "$status" -ne 0 ]
    [[ $output == *'Create the named profile'* ]]
    [ ! -e "$USB_STATE_DIR/profiles/missing-profile.rules" ]
    run ! grep -q '^confirm' "$TEST_CALLS"
    run ! grep -q 'usbguard list-devices' "$TEST_CALLS"
}

@test "successful daemon restart without revoking old approvals is incomplete" {
    : >"$USB_STATE_DIR/profiles/conference.rules"
    TEST_SKIP_REEVALUATE=yes
    run usb::profile_apply conference
    [ "$status" -ne 0 ]
    [ "$(cat "$USB_STATE_DIR/active-profile")" = legacy ]
    [ -f "$USB_STATE_DIR/profile-pending" ]
}

@test "temporary or external device authorizations make live profile status partial" {
    usb::profile_apply office
    printf '8: %s\n' "$TEST_SECOND" >>"$TEST_DEVICES"
    run usb::profile_status
    [ "$status" -eq 0 ]
    [[ $output == *'"state":"partial"'* ]]
    [[ $output == *'temporary or external device exceptions'* ]]
}
