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
    USB_PROC_DIR="$BATS_TEST_TMPDIR/proc"
    TEST_CALLS="$BATS_TEST_TMPDIR/calls"
    TEST_DEVICES="$BATS_TEST_TMPDIR/devices"
    TEST_RULE='allow id 1234:abcd hash "keyboardhash" via-port "1-1"'
    TEST_SECOND='allow id 5678:ef01 hash "storagehash" via-port "1-2"'
    mkdir -p "$USB_CONFIG_DIR" "$USB_STATE_DIR/profiles" "$USB_UNIT_DIR" "$USB_SYS_DIR/dev/block" "$USB_PROC_DIR/sys/kernel/random"
    printf '11111111-2222-3333-4444-555555555555\n' >"$USB_PROC_DIR/sys/kernel/random/boot_id"
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
            show) printf '%s\n' "${TEST_INVOCATION:-0123456789abcdef0123456789abcdef}" ;;
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

@test "attachment tokens are stable across authorization changes and omit private identities" {
    local token changed
    token=$(usb::_attachment_token 8 "$(usb::_device 8)")
    [[ $token =~ ^[a-f0-9]{64}$ ]]
    changed=$(usb::_attachment_token 8 "8: $TEST_SECOND")
    [ "$changed" = "$token" ]
    run usb::devices_json
    [ "$status" -eq 0 ]
    jq -e --arg token "$token" '.[] | select(.id == 8) | .token == $token and .label == "USB device" and .profile == "legacy"' <<<"$output"
    [[ $output != *storagehash* && $output != *keyboardhash* ]]
}

@test "attachment token changes for reused IDs, descriptor changes, restarts and reboots" {
    local device token
    device=$(usb::_device 8)
    token=$(usb::_attachment_token 8 "$device")
    [ "$(usb::_attachment_token 9 "9: ${device#8: }")" != "$token" ]
    [ "$(usb::_attachment_token 8 "$device name \"Different device\"")" != "$token" ]
    TEST_INVOCATION=abcdef0123456789abcdef0123456789
    [ "$(usb::_attachment_token 8 "$device")" != "$token" ]
    unset TEST_INVOCATION
    printf '22222222-2222-3333-4444-555555555555\n' >"$USB_PROC_DIR/sys/kernel/random/boot_id"
    [ "$(usb::_attachment_token 8 "$device")" != "$token" ]
}

@test "missing daemon invocation refuses an actionable inventory" {
    TEST_INVOCATION=unavailable
    run usb::devices_json
    [ "$status" -ne 0 ]
}

@test "bound once approval keeps current profile unchanged without duplicate review" {
    local token
    token=$(usb::_attachment_token 8 "$(usb::_device 8)")
    run usb::approve 8 "$token" legacy once
    [ "$status" -eq 0 ]
    grep -Fx 'usbguard allow-device 8' "$TEST_CALLS"
    run ! grep -q '^confirm\|^backup\|append-rule' "$TEST_CALLS"
    [ ! -f "$USB_STATE_DIR/active-profile" ]
}

@test "bound remembered approval is written only to the effective USB profile" {
    usb::profile_apply office
    local token
    token=$(usb::_attachment_token 8 "$(usb::_device 8)")
    : >"$TEST_CALLS"
    run usb::approve 8 "$token" office profile
    [ "$status" -eq 0 ]
    grep -Fx "$TEST_SECOND" "$USB_STATE_DIR/profiles/office.rules"
    [ "$(cat "$USB_STATE_DIR/legacy.rules")" = "$TEST_RULE" ]
    run ! grep -q '^confirm' "$TEST_CALLS"
}

@test "bound approval rejects stale profile before any device or policy mutation" {
    local token
    token=$(usb::_attachment_token 8 "$(usb::_device 8)")
    run usb::approve 8 "$token" office profile
    [ "$status" -ne 0 ]
    [[ $output == *'device or active profile changed'* ]]
    run ! grep -q 'allow-device\|append-rule\|^backup' "$TEST_CALLS"
}

@test "bound approval rejects replaced identity and restarted daemon before mutation" {
    local token
    token=$(usb::_attachment_token 8 "$(usb::_device 8)")
    sed -i 's/storagehash/replacedhash/' "$TEST_DEVICES"
    run usb::approve 8 "$token" legacy once
    [ "$status" -ne 0 ]
    sed -i 's/replacedhash/storagehash/' "$TEST_DEVICES"
    TEST_INVOCATION=abcdef0123456789abcdef0123456789
    run usb::approve 8 "$token" legacy once
    [ "$status" -ne 0 ]
    run ! grep -q 'allow-device' "$TEST_CALLS"
}

@test "bound approval rejects invalid tokens and scopes before native operations" {
    run usb::approve 8 invalid legacy once
    [ "$status" -ne 0 ]
    run usb::approve 8 "$(printf '%064d' 0)" legacy remember-all
    [ "$status" -ne 0 ]
    [ ! -s "$TEST_CALLS" ]
}

@test "bound approval rechecks daemon invocation immediately before authorizing" {
    local token
    token=$(usb::_attachment_token 8 "$(usb::_device 8)")
    usb::_attachment_context() {
        if [[ -f "$BATS_TEST_TMPDIR/context-read" ]]; then
            printf 'new-invocation\n'
        else
            touch "$BATS_TEST_TMPDIR/context-read"
            printf '11111111-2222-3333-4444-555555555555:0123456789abcdef0123456789abcdef\n'
        fi
    }
    run usb::approve 8 "$token" legacy once
    [ "$status" -ne 0 ]
    run ! grep -q 'allow-device' "$TEST_CALLS"
}

@test "bound revocation keeps disruption confirmation and respects cancellation" {
    local token
    token=$(usb::_attachment_token 7 "$(usb::_device 7)")
    TEST_DECLINE=yes
    run usb::revoke 7 "$token" legacy block
    [ "$status" -ne 0 ]
    grep -q '^confirm Block this device' "$TEST_CALLS"
    run ! grep -q 'block-device' "$TEST_CALLS"
}

@test "bound revocation rechecks profile after disruption confirmation" {
    local token
    token=$(usb::_attachment_token 7 "$(usb::_device 7)")
    core::confirm() { printf 'office\n' >"$USB_STATE_DIR/active-profile"; }
    run usb::revoke 7 "$token" legacy block
    [ "$status" -ne 0 ]
    run ! grep -q 'block-device' "$TEST_CALLS"
}

@test "device display strips bidi overrides and C1 controls from human labels" {
    # UTF-8 byte escapes also exercise real Unicode when the test locale is C.
    printf '8: block id 5678:ef01 name "Office\342\200\256 USB\302\205 disk" hash "storagehash" via-port "1-2"\n' >"$TEST_DEVICES"
    run usb::devices_json
    [ "$status" -eq 0 ]
    jq -e '.[0].name == "Office USB disk" and .[0].label == "Office USB disk"' <<<"$output"
}

@test "legacy enrollment descriptors remain remembered without rewriting native policy" {
    local legacy='allow id 5678:ef01 serial "private-serial" name "USB disk" hash "storagehash" via-port "1-2" with-interface 08:06:50'
    printf '%s\n' "$legacy" >"$USB_CONFIG_DIR/rules.conf"
    printf '8: %s\n' "$legacy" >"$TEST_DEVICES"
    run usb::devices_json
    [ "$status" -eq 0 ]
    jq -e '.[0].state == "allowed" and .[0].remembered and .[0].profile == "legacy"' <<<"$output"
    [[ $output != *private-serial* && $output != *storagehash* ]]
    [ "$(cat "$USB_CONFIG_DIR/rules.conf")" = "$legacy" ]
    run ! grep -q 'append-rule\|allow-device\|block-device\|^backup' "$TEST_CALLS"
}

@test "legacy remembered display requires an exact vendor hash and port identity" {
    local original='allow id 5678:ef01 name "USB disk" hash "storagehash" via-port "1-2"'
    printf '8: %s\n' "$original" >"$TEST_DEVICES"
    local different
    for different in "${original/5678:ef01/1234:abcd}" "${original/storagehash/otherhash}" "${original/1-2/1-20}"; do
        printf '%s\n' "$different" >"$USB_CONFIG_DIR/rules.conf"
        run usb::devices_json
        [ "$status" -eq 0 ]
        jq -e '.[0].remembered == false' <<<"$output"
    done
}

@test "legacy broad conditional and blocking rules cannot impersonate remembered approvals" {
    printf 'allow\nallow id *:*\nallow id 5678:ef01 hash "storagehash" via-port "1-2" if true\nblock id 5678:ef01 hash "storagehash" via-port "1-2"\n' >"$USB_CONFIG_DIR/rules.conf"
    run usb::devices_json
    [ "$status" -eq 0 ]
    jq -e 'all(.[]; .remembered == false)' <<<"$output"
}
