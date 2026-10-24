#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Native sudo/PAM integration. All account, sudo and runtime state is private
# to a new mount/PID/network namespace; never modify the invoking host's policy.
set -Eeuo pipefail

repair_integration_isolated() {
    set -Eeuo pipefail
    local root=$1 temporary=$2 original_namespace=$3 directory
    [[ $EUID == 0 && $(readlink /proc/self/ns/mnt) != "$original_namespace" ]] || {
        echo 'Refusing sudo integration outside its private mount namespace.' >&2
        return 1
    }
    mount --make-rprivate /
    # Do not copy host passwords or account databases. Everything below these
    # existing mount points belongs to this process's disposable namespace.
    for directory in /etc /run /var/log /var/lib; do
        mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs "$directory"
        [[ $(findmnt --noheadings --output FSTYPE --target "$directory") == tmpfs ]]
    done
    install -d -m 0755 /etc/sudoers.d /etc/pam.d /run/octoshield-repair-integration
    printf 'root:x:0:0:root:/root:/bin/bash\noctoshield-repair:x:61123:61123:Integration fixture:/run/octoshield-repair-integration:/bin/bash\n' >/etc/passwd
    printf 'root:x:0:\noctoshield-repair:x:61123:\n' >/etc/group
    printf 'root:!:20000:0:99999:7:::\noctoshield-repair:!:20000:0:99999:7:::\n' >/etc/shadow
    chmod 0600 /etc/shadow
    printf 'passwd: files\ngroup: files\nshadow: files\nhosts: files\n' >/etc/nsswitch.conf
    printf '127.0.0.1 localhost\n127.0.1.1 %s\n' "$(uname -n)" >/etc/hosts
    # These are real PAM modules, with an actual local password hash. The stack
    # is deliberately restricted to the isolated fixture's Unix account.
    printf 'auth required pam_unix.so\naccount required pam_unix.so\nsession required pam_permit.so\n' >/etc/pam.d/sudo
    printf 'octoshield-repair:OctoShield-integration-fixture-only\n' | chpasswd --crypt-method SHA512
    cat >/etc/sudoers <<'SUDOERS'
Defaults timestamp_timeout=5
root ALL=(ALL:ALL) ALL
octoshield-repair ALL=(root) ALL
@includedir /etc/sudoers.d
SUDOERS
    chmod 0440 /etc/sudoers
    printf '# Independent administrator policy.\nDefaults passwd_tries=2\n' >/etc/sudoers.d/10-local-policy
    chmod 0440 /etc/sudoers.d/10-local-policy
    local independent_hash
    independent_hash=$(sha256sum /etc/sudoers.d/10-local-policy)
    visudo --check
    local sudo_version
    sudo_version=$(sudo --version)
    printf '%s\n' "${sudo_version%%$'\n'*}"

    cat >/run/octoshield-repair-integration/auth-probe.sh <<'PROBE'
#!/usr/bin/env bash
set -Eeuo pipefail
[[ $EUID == 61123 && -t 0 && -t 1 ]]
sudo -k
if [[ $OCTOSHIELD_CHECK_PASSWORD == yes ]]; then
    if printf 'deliberately-wrong-fixture-password\n' | sudo -S -p 'Reject wrong fixture password: ' /usr/bin/true; then
        echo 'FAIL: the authentication fixture accepted an incorrect password.' >&2
        exit 1
    fi
    echo 'PASS: actual PAM rejects an incorrect password'
fi
printf 'OctoShield-integration-fixture-only\n' | sudo -S -p 'Fixture authentication: ' /usr/bin/true
if sudo -n /usr/bin/true; then
    [[ $OCTOSHIELD_EXPECT_REUSE == yes ]] || {
        echo 'FAIL: zero-timeout policy unexpectedly reused authentication.' >&2
        exit 1
    }
    echo 'PASS: real sudo authentication is reused by the next command on this terminal'
else
    [[ $OCTOSHIELD_EXPECT_REUSE == no ]] || {
        echo 'FAIL: ordinary sudo authentication was not reusable.' >&2
        exit 1
    }
    echo 'PASS: real zero-timeout policy demands authentication for the next command'
fi
PROBE
    chmod 0755 /run/octoshield-repair-integration/auth-probe.sh
    repair_test_authentication() {
        OCTOSHIELD_EXPECT_REUSE=$1 OCTOSHIELD_CHECK_PASSWORD=${2:-no} SHELL=/bin/bash \
            setpriv --reuid=61123 --regid=61123 --clear-groups \
            script --quiet --return --command /run/octoshield-repair-integration/auth-probe.sh /dev/null
    }

    # Use production transactions, backups, atomic writes, repair planning and
    # native visudo validation. Only the explicit operator consent is automated.
    # shellcheck source=/dev/null
    source "$root/src/lib/core.sh"
    # shellcheck source=/dev/null
    source "$root/src/lib/repair.sh"
    umask 077
    # shellcheck disable=SC2317 # Called by the sourced production repair module.
    core::confirm() { printf 'Integration consent: %s\n' "$*"; }
    trap 'core::end' EXIT
    repair_test_generated() {
        printf '# Managed by Octoshield; passwordless grants still bypass passwords.\nDefaults timestamp_timeout=0\n'
    }
    repair_test_activation() {
        # Recreate the retired action's real backup layout without retaining a
        # callable production action that can enable this feature again.
        CORE_TRANSACTION=$1
        install -d -m 0700 "$CORE_STATE/backups/$CORE_TRANSACTION/original"
        core::record 'BEGIN apply sudo'
        repair_test_generated | core::write_file /etc/sudoers.d/99-octoshield 0440
        core::record 'sudo: timestamp_timeout=0; existing NOPASSWD/per-user overrides require manual review'
        CORE_TRANSACTION=
    }
    repair_test_run() {
        local result=0
        core::begin 'Repair retired settings'
        repair::run || result=$?
        core::end
        return "$result"
    }
    repair_test_state() { repair::status | jq --exit-status --arg expected "$1" '.state == $expected'; }
    repair_test_reset() {
        CORE_STATE="$temporary/$1"
        install -d -m 0700 "$CORE_STATE" "$CORE_STATE/backups"
        rm -f /etc/sudoers.d/99-octoshield
    }

    printf '\nCASE: real password authentication before enabling the legacy setting\n'
    repair_test_authentication yes yes
    printf '\nCASE: repeated legacy activation with an originally absent drop-in\n'
    repair_test_reset absent
    repair_test_activation 20260101T010000Z-101
    repair_test_activation 20260101T020000Z-102
    repair_test_state partial
    repair_test_authentication no
    repair_test_run
    [[ ! -e /etc/sudoers.d/99-octoshield ]]
    repair_test_state active
    repair_test_authentication yes
    repair_test_run
    [[ ! -e /etc/sudoers.d/99-octoshield ]]
    repair_test_state active
    printf 'PASS: actual cleanup removes the generated drop-in, restores authentication reuse and is repeatable\n'

    printf '\nCASE: the original local policy survives repeated legacy activation\n'
    repair_test_reset custom
    printf '# Existing administrator policy.\nDefaults timestamp_timeout=7\n' >/etc/sudoers.d/99-octoshield
    chmod 0440 /etc/sudoers.d/99-octoshield
    local original_hash
    original_hash=$(sha256sum /etc/sudoers.d/99-octoshield)
    repair_test_activation 20260102T010000Z-201
    repair_test_activation 20260102T020000Z-202
    repair_test_run
    [[ $(sha256sum /etc/sudoers.d/99-octoshield) == "$original_hash" ]]
    repair_test_state active
    repair_test_authentication yes
    repair_test_run
    [[ $(sha256sum /etc/sudoers.d/99-octoshield) == "$original_hash" ]]
    printf 'PASS: native sudo validates the restored original policy and repeated repair preserves it\n'

    printf '\nCASE: modified policy and invalid original are preserved for review\n'
    repair_test_reset conflict
    repair_test_generated >/etc/sudoers.d/99-octoshield
    printf 'Defaults timestamp_timeout=9\n' >>/etc/sudoers.d/99-octoshield
    chmod 0440 /etc/sudoers.d/99-octoshield
    original_hash=$(sha256sum /etc/sudoers.d/99-octoshield)
    repair_test_state unknown
    if repair_test_run; then
        echo 'FAIL: repair accepted a modified administrator policy.' >&2
        return 1
    fi
    [[ $(sha256sum /etc/sudoers.d/99-octoshield) == "$original_hash" ]]
    repair_test_reset invalid-original
    printf 'This is not a valid sudoers policy\n' >/etc/sudoers.d/99-octoshield
    chmod 0440 /etc/sudoers.d/99-octoshield
    repair_test_activation 20260103T010000Z-301
    original_hash=$(sha256sum /etc/sudoers.d/99-octoshield)
    if repair_test_run; then
        echo 'FAIL: real visudo accepted an invalid historical policy.' >&2
        return 1
    fi
    [[ $(sha256sum /etc/sudoers.d/99-octoshield) == "$original_hash" ]]
    visudo --check
    [[ $(sha256sum /etc/sudoers.d/10-local-policy) == "$independent_hash" ]]
    printf 'PASS: actual modified and invalid policies cause refusal; independent policy remains unchanged\n'
}

[[ $# == 0 && $EUID == 0 ]] || {
    echo 'Run without arguments as root in a disposable integration runner with namespace support.' >&2
    exit 1
}
for program in unshare mount findmnt setpriv script chpasswd sudo visudo jq sha256sum; do
    command -v "$program" >/dev/null
done
root=$(cd -- "$(dirname -- "$0")/.." && pwd)
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT
export -f repair_integration_isolated
# There is deliberately no public --isolated bypass: every invocation creates
# its own namespaces before the inner function can mount or write system paths.
unshare --mount --net --pid --fork --mount-proc /bin/bash -c 'repair_integration_isolated "$@"' \
    _ "$root" "$temporary" "$(readlink /proc/self/ns/mnt)"
