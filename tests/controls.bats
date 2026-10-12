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
            'show --property=LoadState --value ssh.service') printf 'loaded\n' ;;
            'show --property=LoadState --value '*) printf 'not-found\n' ;;
            'show --property=UnitFileState --value '*) printf 'enabled\n' ;;
            'show --property=ActiveState --value '*) printf 'active\n' ;;
        esac
    }
    visudo() { fake visudo "$@"; }
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
    for control in firewall network services sudo updates apparmor; do
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

@test 'declining firewall reset performs no mutations' {
    FAIL=confirm
    run controls::apply_firewall
    [ "$status" -ne 0 ]
    run grep -Eq '^(install|backup|write|ufw --force)' "$CALLS"
    [ "$status" -eq 1 ]
}

@test 'firewall backs up before reset and configures both address families' {
    run controls::apply_firewall
    [ "$status" -eq 0 ]
    [ "$(grep '^\(backup\|ufw --force\)' "$CALLS")" = $'backup /etc/ufw\nbackup /etc/default/ufw\nufw --force reset\nufw --force enable' ]
    grep -Fx 'IPV6=yes' "$WRITES/etc/default/ufw"
    grep -Fx 'ufw default deny incoming' "$CALLS"
    grep -Fx 'ufw default allow outgoing' "$CALLS"
    grep -Fx 'ufw default deny routed' "$CALLS"
    grep -Fx 'ufw logging low' "$CALLS"
}

@test 'failed backup prevents firewall reset' {
    FAIL='backup /etc/ufw'
    run controls::apply_firewall
    [ "$status" -ne 0 ]
    run grep -q '^ufw --force reset$' "$CALLS"
    [ "$status" -eq 1 ]
}

@test 'failed firewall rule never reports success or proceeds to enable' {
    FAIL='ufw default deny routed'
    run controls::apply_firewall
    [ "$status" -ne 0 ]
    run grep -Eq '^(ufw --force enable|record firewall)' "$CALLS"
    [ "$status" -eq 1 ]
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

@test 'network control addresses UUIDs, disables only Wi-Fi autoconnect, and never disconnects' {
    run controls::apply_network
    [ "$status" -eq 0 ]
    grep -Fx 'nmcli connection modify uuid 11111111-1111-1111-1111-111111111111 connection.autoconnect no 802-11-wireless.cloned-mac-address stable' "$CALLS"
    run grep -E '22222222.*autoconnect' "$CALLS"
    [ "$status" -eq 1 ]
    run grep -E '^nmcli (networking|connection (up|down))' "$CALLS"
    [ "$status" -eq 1 ]
    grep -Fx 'wifi.scan-rand-mac-address=yes' "$WRITES/etc/NetworkManager/conf.d/90-octoshield.conf"
    run grep -q ipv6 "$WRITES/etc/NetworkManager/conf.d/90-octoshield.conf"
    [ "$status" -eq 1 ]
}

@test 'network control rejects malformed UUIDs without using them in commands' {
    PROFILES='--hostile:802-11-wireless'
    run controls::apply_network
    [ "$status" -ne 0 ]
    run grep -q '^nmcli connection modify' "$CALLS"
    [ "$status" -eq 1 ]
}

@test 'network enumeration failure does not create partial configuration' {
    FAIL='nmcli --terse --fields UUID,TYPE connection show'
    run controls::apply_network
    [ "$status" -ne 0 ]
    run grep -q '^write' "$CALLS"
    [ "$status" -eq 1 ]
}

@test 'network mutation failure propagates and prevents success record' {
    FAIL='nmcli connection modify uuid 11111111-1111-1111-1111-111111111111 connection.llmnr 0 connection.mdns 0'
    run controls::apply_network
    [ "$status" -ne 0 ]
    run grep -Eq '^(nmcli general reload|record network)' "$CALLS"
    [ "$status" -eq 1 ]
}

@test 'network profile backup failure prevents persistent changes' {
    FAIL='backup /run/NetworkManager/system-connections'
    run controls::apply_network
    [ "$status" -ne 0 ]
    run grep -Eq '^(write|nmcli connection modify)' "$CALLS"
    [ "$status" -eq 1 ]
}

@test 'service control records original state and masks only installed units' {
    run controls::apply_services
    [ "$status" -eq 0 ]
    grep -Fx 'record service-before: ssh.service enabled=enabled active=active' "$CALLS"
    [ "$(grep '^systemctl mask' "$CALLS")" = 'systemctl mask --now ssh.service' ]
    grep -Fx 'backup /etc/systemd/system/ssh.service' "$CALLS"
}

@test 'service masking failure is never recorded as success' {
    FAIL='systemctl mask --now ssh.service'
    run controls::apply_services
    [ "$status" -ne 0 ]
    run grep -q '^record services:' "$CALLS"
    [ "$status" -eq 1 ]
}

@test 'sudo configuration is syntax checked and uses a sudoers-compatible filename and mode' {
    run controls::apply_sudo
    [ "$status" -eq 0 ]
    grep -Fx 'Defaults timestamp_timeout=0' "$WRITES/etc/sudoers.d/99-octoshield"
    grep -Fx 'write /etc/sudoers.d/99-octoshield 0440' "$CALLS"
    [ "$(grep -c '^visudo --check$' "$CALLS")" -eq 2 ]
    grep -q '^visudo --check --file ' "$CALLS"
}

@test 'pre-existing invalid sudo configuration prevents any new write' {
    FAIL='visudo --check'
    run controls::apply_sudo
    [ "$status" -ne 0 ]
    run grep -q '^write' "$CALLS"
    [ "$status" -eq 1 ]
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
    for control in firewall sudo updates apparmor; do
        case "$control" in
            firewall) package=ufw ;;
            sudo) package=sudo ;;
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
