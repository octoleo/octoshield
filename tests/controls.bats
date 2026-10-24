#!/usr/bin/env bats
# Tests never call host firewall, service, package, or network operations.
# SPDX-License-Identifier: Apache-2.0
# Bats invokes setup and mocked commands indirectly; source path is relative to this test.
# shellcheck disable=SC1091,SC2317,SC2329,SC2030,SC2031

setup() {
    source "$BATS_TEST_DIRNAME/../src/lib/controls.sh"
    export CALLS="$BATS_TEST_TMPDIR/calls"
    export WRITES="$BATS_TEST_TMPDIR/writes"
    mkdir -p "$WRITES"
    : >"$CALLS"
    unset SSH_CLIENT SSH_CONNECTION SSH_TTY
    export FAIL=''
    export SERVICE_UNITS='ssh.service'
    export PROFILES=$'11111111-1111-1111-1111-111111111111:802-11-wireless\n22222222-2222-2222-2222-222222222222:802-3-ethernet'

    fake() {
        printf '%s\n' "$*" >>"$CALLS"
        [[ $* != "$FAIL" ]]
    }
    core::require_root() { fake root; }
    core::log() { printf '%s\n' "$*"; }
    core::die() {
        printf '%s\n' "$*" >&2
        return 1
    }
    core::confirm() { fake confirm; }
    core::install_packages() { fake install "$@"; }
    core::backup() { fake backup "$@"; }
    core::record() { fake record "$@"; }
    core::write_file() {
        fake write "$@" || return 1
        mkdir -p "$WRITES$(dirname -- "$1")" || return 1
        cat >"$WRITES$1"
    }
    ufw() { fake ufw "$@"; }
    controls::ufw_defaults() { printf 'IPV6=yes\nMANAGE_BUILTINS=no\n'; }
    nmcli() {
        fake nmcli "$@" || return 1
        if [[ $* == '--terse --fields UUID,TYPE connection show' ]]; then
            printf '%s\n' "$PROFILES"
        fi
    }
    systemctl() {
        fake systemctl "$@" || return 1
        case "$*" in
            'show --property=LoadState --value '*)
                if [[ " $SERVICE_UNITS " == *" $4 "* ]]; then
                    printf 'loaded\n'
                else
                    printf 'not-found\n'
                fi
                ;;
            'show --property=UnitFileState --value '*) printf 'enabled\n' ;;
            'show --property=ActiveState --value '*) printf 'active\n' ;;
        esac
    }
    apt-config() { fake apt-config "$@"; }
    aa-enabled() { fake aa-enabled "$@"; }
    aa-status() { fake aa-status; }
}

@test 'sourcing controls has no side effects' {
    run source "$BATS_TEST_DIRNAME/../src/lib/controls.sh"
    [ "$status" -eq 0 ]
    [ ! -s "$CALLS" ]
}

@test 'all security controls reject insufficient privilege before mutation' {
    FAIL=root
    for control in firewall network services updates apparmor; do
        run "controls::apply_$control"
        [ "$status" -ne 0 ]
    done
    [ "$(sort -u "$CALLS")" = root ]
}

@test 'firewall cannot change the host from an SSH session' {
    export SSH_CONNECTION='192.0.2.1 12345 192.0.2.2 22'
    run controls::apply_firewall
    [ "$status" -ne 0 ]
    [ "$(cat "$CALLS")" = root ]
}

@test 'UFW defaults transform preserves unrelated settings and removes duplicate IPv6 assignments' {
    source "$BATS_TEST_DIRNAME/../src/lib/controls.sh"
    printf '%s\n' '# test' 'IPV6=no' 'MANAGE_BUILTINS=no' '  IPV6 =no' >"$BATS_TEST_TMPDIR/ufw"
    run controls::ufw_defaults "$BATS_TEST_TMPDIR/ufw"
    [ "$status" -eq 0 ]
    [ "$output" = $'# test\nIPV6=yes\nMANAGE_BUILTINS=no' ]
}

@test 'UFW defaults adds IPv6 when absent and rejects a missing file' {
    source "$BATS_TEST_DIRNAME/../src/lib/controls.sh"
    printf 'MANAGE_BUILTINS=no\n' >"$BATS_TEST_TMPDIR/ufw"
    run controls::ufw_defaults "$BATS_TEST_TMPDIR/ufw"
    [ "$status" -eq 0 ]
    [ "$output" = $'MANAGE_BUILTINS=no\nIPV6=yes' ]
    run controls::ufw_defaults "$BATS_TEST_TMPDIR/missing"
    [ "$status" -ne 0 ]
}

@test 'updates append security origins without clearing existing policies or automatic reboot' {
    run controls::apply_updates
    [ "$status" -eq 0 ]
    # shellcheck disable=SC2016 # Assert the literal unattended-upgrades substitutions.
    grep -F 'Unattended-Upgrade::Allowed-Origins:: "${distro_id}:${distro_codename}-security";' "$WRITES/etc/apt/apt.conf.d/90-octoshield"
    grep -F 'Unattended-Upgrade::Automatic-Reboot "false";' "$WRITES/etc/apt/apt.conf.d/90-octoshield"
    run grep -q '#clear' "$WRITES/etc/apt/apt.conf.d/90-octoshield"
    [ "$status" -eq 1 ]
    grep -Fx 'systemctl enable --now apt-daily.timer apt-daily-upgrade.timer' "$CALLS"
}

@test 'invalid APT configuration prevents timer activation and success' {
    FAIL='apt-config dump'
    run controls::apply_updates
    [ "$status" -ne 0 ]
    run grep -Eq '^(systemctl enable|record updates)' "$CALLS"
    [ "$status" -eq 1 ]
}

@test 'AppArmor reloads existing policy without forcing profile enforcement' {
    run controls::apply_apparmor
    [ "$status" -eq 0 ]
    grep -Fx 'aa-enabled --quiet' "$CALLS"
    grep -Fx 'systemctl reload apparmor.service' "$CALLS"
    run grep -Eq 'aa-enforce|aa-complain' "$CALLS"
    [ "$status" -eq 1 ]
}

@test 'AppArmor kernel unavailability does not report protection enabled' {
    FAIL='aa-enabled --quiet'
    run controls::apply_apparmor
    [ "$status" -ne 0 ]
    run grep -Eq '^(systemctl enable|record apparmor)' "$CALLS"
    [ "$status" -eq 1 ]
}

@test 'all package installation failures stop their security control' {
    local control package
    for control in updates apparmor; do
        case "$control" in
            firewall) package=ufw ;;
            updates) package=unattended-upgrades ;;
            apparmor) package='apparmor apparmor-utils' ;;
        esac
        : >"$CALLS"
        FAIL="install $package"
        run "controls::apply_$control"
        [ "$status" -ne 0 ]
        run grep -Eq '^(write|backup|record|systemctl)' "$CALLS"
        [ "$status" -eq 1 ]
    done
}

@test 'legacy firewall network and service commands use reversible Conference profiles' {
    profiles::apply() { fake profile "$@"; }
    for control in firewall network services; do
        run "controls::apply_$control"
        [ "$status" -eq 0 ]
        grep -Fx "profile conference $control" "$CALLS"
    done
    run grep -E '^ufw|^nmcli|^systemctl' "$CALLS"
    [ "$status" -eq 1 ]
}

@test 'legacy commands propagate profile engine failure' {
    profiles::apply() { return 7; }
    for control in firewall network services; do
        run "controls::apply_$control"
        [ "$status" -eq 7 ]
    done
}
