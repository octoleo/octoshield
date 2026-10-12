#!/usr/bin/env bats
# SPDX-License-Identifier: Apache-2.0
# All privileged operations are mocks. Files are confined to BATS_TEST_TMPDIR.
# ShellCheck cannot follow functions installed as mocks by Bats setup.
# shellcheck disable=SC2317

setup() {
    bats_require_minimum_version 1.5.0
    # shellcheck source=src/lib/usb.sh
    source "$BATS_TEST_DIRNAME/../src/lib/usb.sh"
    USB_CONFIG_DIR="$BATS_TEST_TMPDIR/etc/usbguard"
    USB_STATE_DIR="$BATS_TEST_TMPDIR/state"
    USB_LOG_DIR="$BATS_TEST_TMPDIR/log"
    USB_UNIT_DIR="$BATS_TEST_TMPDIR/units"
    TEST_CALLS="$BATS_TEST_TMPDIR/calls"
    TEST_POLICY='allow id 1234:abcd serial "trusted" name "Keyboard" hash "abcd" via-port "1-1" with-interface 03:01:01'
    TEST_DEVICE="7: $TEST_POLICY"
    mkdir -p "$USB_UNIT_DIR"
    : >"$TEST_CALLS"
    core::log() { printf '%s\n' "$*"; }
    core::die() {
        printf '%s\n' "$*" >&2
        return 1
    }
    core::require_root() { return 0; }
    core::confirm() {
        printf 'confirm\n' >>"$TEST_CALLS"
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
    core::install_packages() {
        printf 'packages %s\n' "$*" >>"$TEST_CALLS"
        usb::_masked_by_us usbguard.service || return 1
        usb::_masked_by_us usbguard-dbus.service || return 1
        [[ ${TEST_APT_FAIL:-no} != yes ]]
    }
    usb::_unmanaged() { [[ ${TEST_UNMANAGED:-no} == yes ]]; }
    install() {
        local -a args=()
        while (($#)); do
            case "$1" in
                -o | -g) shift 2 ;;
                *)
                    args+=("$1")
                    shift
                    ;;
            esac
        done
        command install "${args[@]}"
    }
    systemctl() {
        printf 'systemctl %s\n' "$*" >>"$TEST_CALLS"
        case "$1" in
            mask) ln -s /dev/null "$USB_UNIT_DIR/$2" ;;
            unmask) rm "$USB_UNIT_DIR/$2" ;;
            is-enabled) return 1 ;;
            is-active) [[ ${TEST_ACTIVE:-yes} == yes ]] ;;
            enable) [[ ${TEST_START_FAIL:-no} != yes ]] ;;
            *) return 1 ;;
        esac
    }
    usbguard() {
        printf 'usbguard %s\n' "$*" >>"$TEST_CALLS"
        case "$1" in
            generate-policy)
                [[ ${TEST_GENERATE_FAIL:-no} != yes ]] || return 1
                if [[ ${TEST_POLICY_CHANGE:-no} == yes && -f "$BATS_TEST_TMPDIR/generated" ]]; then
                    printf '%s changed\n' "$TEST_POLICY"
                else
                    printf '%s\n' "$TEST_POLICY"
                fi
                touch "$BATS_TEST_TMPDIR/generated"
                ;;
            list-devices) printf '%s\n' "$TEST_DEVICE" ;;
            allow-device | block-device) [[ ${TEST_DEVICE_FAIL:-no} != yes ]] ;;
            *) return 1 ;;
        esac
    }
}

@test "fresh enrollment masks services before installation and keeps only bridge masked" {
    run usb::apply
    [ "$status" -eq 0 ]
    [ -f "$USB_STATE_DIR/enrolled" ]
    [ ! -e "$USB_STATE_DIR/pending" ]
    [ ! -L "$USB_UNIT_DIR/usbguard.service" ]
    [ -L "$USB_UNIT_DIR/usbguard-dbus.service" ]
    [ "$(cat "$USB_CONFIG_DIR/rules.conf")" = "$TEST_POLICY" ]
    [ "$(stat -c %a "$USB_CONFIG_DIR/rules.conf")" = 600 ]
    [ "$(stat -c %a "$USB_LOG_DIR")" = 700 ]
    grep -Fx 'IPCAllowedUsers=root' "$USB_CONFIG_DIR/usbguard-daemon.conf"
    grep -Fx 'AuthorizedDefault=none' "$USB_CONFIG_DIR/usbguard-daemon.conf"
    run ! grep -Eq '^(IPCAllowedGroups|IPCAccessControlFiles)=' "$USB_CONFIG_DIR/usbguard-daemon.conf"
}

@test "repeat setup preserves trusted rules and never enrolls newly present devices" {
    usb::apply
    : >"$TEST_CALLS"
    TEST_POLICY='allow id ffff:ffff name "untrusted" hash "new" via-port "2-1"'
    run usb::apply
    [ "$status" -eq 0 ]
    run ! grep -q generate-policy "$TEST_CALLS"
    run ! grep -q untrusted "$USB_CONFIG_DIR/rules.conf"
}

@test "existing unmanaged deployment is left unchanged" {
    TEST_UNMANAGED=yes
    run usb::apply
    [ "$status" -ne 0 ]
    [[ $output == *'existing USBGuard installation'* ]]
    [ ! -d "$USB_STATE_DIR" ]
    [ ! -s "$TEST_CALLS" ]
}

@test "declining initial enrollment makes no system changes" {
    TEST_DECLINE=yes
    run usb::apply
    [ "$status" -ne 0 ]
    [ ! -d "$USB_STATE_DIR" ]
    run ! grep -q 'systemctl\|packages' "$TEST_CALLS"
}

@test "apt failure leaves persistent mask and resumable state" {
    TEST_APT_FAIL=yes
    run usb::apply
    [ "$status" -ne 0 ]
    [ -f "$USB_STATE_DIR/pending" ]
    [ -L "$USB_UNIT_DIR/usbguard.service" ]
    [ ! -f "$USB_STATE_DIR/enrolled" ]
    TEST_APT_FAIL=no
    run usb::apply
    [ "$status" -eq 0 ]
}

@test "preexisting service mask is not removed or adopted" {
    ln -s /dev/null "$USB_UNIT_DIR/usbguard.service"
    run usb::apply
    [ "$status" -ne 0 ]
    [ -L "$USB_UNIT_DIR/usbguard.service" ]
    [ ! -f "$USB_STATE_DIR/masked-usbguard.service" ]
    run ! grep -q '^packages' "$TEST_CALLS"
}

@test "changing USB topology during review aborts without enrollment" {
    TEST_POLICY_CHANGE=yes
    run usb::apply
    [ "$status" -ne 0 ]
    [[ $output == *'device set changed'* ]]
    [ ! -f "$USB_STATE_DIR/enrolled" ]
    [ -L "$USB_UNIT_DIR/usbguard.service" ]
    run ! grep -q 'systemctl enable' "$TEST_CALLS"
}

@test "policy generator failure cannot enable service" {
    TEST_GENERATE_FAIL=yes
    run usb::apply
    [ "$status" -ne 0 ]
    run ! grep -q 'systemctl enable' "$TEST_CALLS"
}

@test "empty or broad generated policy is refused" {
    for TEST_POLICY in '' 'allow' 'allow id *:*'; do
        run usb::_valid_policy <<<"$TEST_POLICY"
        [ "$status" -ne 0 ]
    done
}

@test "config write failure propagates and cannot enable service" {
    TEST_WRITE_FAIL="$USB_CONFIG_DIR/usbguard-daemon.conf"
    run usb::apply
    [ "$status" -ne 0 ]
    [ ! -f "$USB_STATE_DIR/enrolled" ]
    run ! grep -q 'systemctl enable' "$TEST_CALLS"
}

@test "failed startup retains reviewed enrollment for safe retry" {
    TEST_START_FAIL=yes
    run usb::apply
    [ "$status" -ne 0 ]
    [ -f "$USB_STATE_DIR/enrolled" ]
    : >"$TEST_CALLS"
    TEST_START_FAIL=no
    run usb::apply
    [ "$status" -eq 0 ]
    run ! grep -q generate-policy "$TEST_CALLS"
    [ ! -e "$USB_STATE_DIR/pending" ]
}

@test "changed managed configuration is never silently replaced" {
    usb::apply
    printf 'ImplicitPolicyTarget=allow\n' >>"$USB_CONFIG_DIR/usbguard-daemon.conf"
    : >"$TEST_CALLS"
    run usb::apply
    [ "$status" -ne 0 ]
    [[ $output == *'missing or changed'* ]]
    run ! grep -q 'systemctl enable' "$TEST_CALLS"
}

@test "device selectors accept only bounded positive numeric IDs" {
    for id in '' 0 -1 007 4294967295 10000000000 'allow id *:*' '--permanent' '1;touch /tmp/no' '1+2'; do
        run usb::allow "$id"
        [ "$status" -ne 0 ]
    done
    run ! grep -q 'usbguard allow-device' "$TEST_CALLS"
}

@test "allow is temporary by default and requires physical review" {
    run usb::allow 7
    [ "$status" -eq 0 ]
    grep -Fx 'usbguard allow-device 7' "$TEST_CALLS"
    grep -Fx confirm "$TEST_CALLS"
    run ! grep -q '^backup' "$TEST_CALLS"
}

@test "permanent authorization explicitly requested and backed up" {
    run usb::allow 7 --permanent
    [ "$status" -eq 0 ]
    grep -Fx 'usbguard allow-device --permanent 7' "$TEST_CALLS"
    grep -Fx "backup $USB_CONFIG_DIR/rules.conf" "$TEST_CALLS"
}

@test "unrecognized allow options and extra block arguments are refused" {
    run usb::allow 7 --all
    [ "$status" -ne 0 ]
    run usb::block 7 --permanent
    [ "$status" -ne 0 ]
    [ ! -s "$TEST_CALLS" ]
}

@test "missing or changed device cannot be authorized" {
    run usb::allow 8
    [ "$status" -ne 0 ]
    run ! grep -q 'usbguard allow-device' "$TEST_CALLS"
    core::confirm() { TEST_DEVICE='7: allow id ffff:ffff name "changed"'; }
    run usb::allow 7
    [ "$status" -ne 0 ]
    [[ $output == *'identity/state changed'* ]]
    run ! grep -q 'usbguard allow-device' "$TEST_CALLS"
}

@test "authorization cancellation and backend failure propagate" {
    TEST_DECLINE=yes
    run usb::allow 7
    [ "$status" -ne 0 ]
    run ! grep -q 'usbguard allow-device' "$TEST_CALLS"
    TEST_DECLINE=no
    TEST_DEVICE_FAIL=yes
    run usb::allow 7
    [ "$status" -ne 0 ]
    run ! grep -q '^record' "$TEST_CALLS"
}

@test "blocking is confirmed and temporary" {
    run usb::block 7
    [ "$status" -eq 0 ]
    grep -Fx 'usbguard block-device 7' "$TEST_CALLS"
    grep -Fx confirm "$TEST_CALLS"
}

@test "no device modification occurs without administrator privileges" {
    core::require_root() { return 1; }
    run usb::allow 7
    [ "$status" -ne 0 ]
    run usb::apply
    [ "$status" -ne 0 ]
    [ ! -s "$TEST_CALLS" ]
}

@test "device listing renders terminal control characters harmless" {
    TEST_DEVICE=$'7: allow name "\e[31mspoof"'
    run usb::list
    [ "$status" -eq 0 ]
    [[ $output != *$'\e'* ]]
    [[ $output == *'\\033[31m'* || $output == *'\033[31m'* ]]
}

@test "inactive daemon refuses device approval and reports incomplete setup" {
    TEST_ACTIVE=no
    mkdir -p "$USB_STATE_DIR"
    touch "$USB_STATE_DIR/pending"
    run usb::allow 7
    [ "$status" -ne 0 ]
    run ! grep -q 'usbguard allow-device' "$TEST_CALLS"
    run usb::status
    [ "$status" -eq 0 ]
    [[ $output == *'NOT active'* ]]
}
