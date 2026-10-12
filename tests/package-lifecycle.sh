#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Destructive packaging integration test: only for disposable CI systems.
# It intentionally installs, upgrades, removes, and purges the specified package.
set -Eeuo pipefail
IFS=$' \t\n'

fail() {
    printf 'Package lifecycle test: %s\n' "$*" >&2
    exit 1
}
[[ $# -eq 2 && $1 == --disposable-system ]] || fail 'refusing host changes; usage: tests/package-lifecycle.sh --disposable-system PACKAGE.deb inside disposable CI only'
[[ ${CI:-} == true || ${GITHUB_ACTIONS:-} == true ]] || fail 'this destructive test requires CI=true or GITHUB_ACTIONS=true and an explicitly disposable system'
((EUID == 0)) || fail 'this disposable-system test requires root'
archive=$(realpath -- "$2")
[[ -f $archive ]] || fail 'package archive does not exist'
[[ $(dpkg-deb --field "$archive" Package) == octoshield ]] || fail 'wrong package archive'
if [[ $(dpkg-query -W -f='${Status}' octoshield 2>/dev/null || :) == 'install ok installed' ]]; then
    fail 'OctoShield is already installed; this does not appear to be a fresh disposable test system'
fi
[[ ! -e /var/lib/octoshield && ! -L /var/lib/octoshield ]] || fail 'existing OctoShield state must never be touched by this test'
[[ ! -e /usr/local/bin/octoshield && ! -e /usr/local/lib/octoshield ]] || fail 'existing standalone installation must never be touched by this test'

declare -A original_packages=()
for package in ufw usbguard apparmor apparmor-utils unattended-upgrades; do
    original_packages[$package]=$(dpkg-query -W -f='${Status}' "$package" 2>/dev/null || :)
done
marker=/var/lib/octoshield/backups/package-lifecycle-test/original/marker
install -d -m 0700 "${marker%/*}"
printf 'Private backup must survive install, upgrade, remove and purge.\n' >"$marker"
chmod 0600 "$marker"
marker_checksum=$(sha256sum "$marker")

check_preserved_state() {
    local package current
    [[ -f $marker && $(sha256sum "$marker") == "$marker_checksum" ]] || fail 'private recovery snapshot was removed or changed'
    for package in "${!original_packages[@]}"; do
        current=$(dpkg-query -W -f='${Status}' "$package" 2>/dev/null || :)
        [[ $current == "${original_packages[$package]}" ]] || fail "installation changed optional security package state: $package"
    done
}

check_inactive_services() {
    local links
    links=$(find /etc/systemd -type l -name 'octoshield-*.service' -print 2>/dev/null || :)
    [[ -z $links ]] || fail 'installation enabled an OctoShield service without an operator choice'
    if command -v systemctl >/dev/null; then
        if systemctl is-active --quiet octoshield-monitor.service 2>/dev/null; then
            fail 'installation started the security monitor without an operator choice'
        fi
    fi
}

export DEBIAN_FRONTEND=noninteractive
apt-get install --yes --no-install-recommends "$archive"
/usr/bin/octoshield --help >/dev/null
/usr/bin/octoshield --version
[[ -x /usr/bin/octoshield-gtk && -x /usr/libexec/octoshield-helper ]] || fail 'desktop executable or fixed privileged helper is missing'
[[ $(stat -c '%u:%g:%a' /usr/libexec/octoshield-helper) == 0:0:755 ]] || fail 'privileged helper ownership or permissions are incorrect'
grep -Fq '<allow_active>auth_admin</allow_active>' /usr/share/polkit-1/actions/org.octoleo.octoshield.policy || fail 'fresh administrator authentication is not required'
grep -Fq '<annotate key="org.freedesktop.policykit.exec.path">/usr/libexec/octoshield-helper</annotate>' /usr/share/polkit-1/actions/org.octoleo.octoshield.policy || fail 'PolicyKit helper path mismatch'
linked_libraries=$(ldd /usr/bin/octoshield-gtk) || fail 'desktop executable is not a valid dynamically linked binary'
if grep -Fq 'not found' <<<"$linked_libraries"; then fail 'desktop shared-library dependency is missing'; fi
# A forbidden action exercises the installed private helper and JSON boundary
# without requiring a booted systemd host, authenticating, or applying changes.
helper_status=0
helper_output=$(PKEXEC_UID=1000 /usr/libexec/octoshield-helper forbidden) || helper_status=$?
[[ $helper_status -eq 2 ]] || fail 'private helper did not reject an unknown action'
jq -e -s '.[-1] == {type:"done",success:false}' <<<"$helper_output" >/dev/null || fail 'private helper returned malformed rejection JSON'
check_preserved_state
check_inactive_services

# Reinstalling the same archive exercises the dpkg upgrade maintainer-script path.
dpkg --install "$archive"
/usr/bin/octoshield --help >/dev/null
check_preserved_state
check_inactive_services

apt-get remove --yes octoshield
check_preserved_state
[[ ! -e /usr/bin/octoshield && ! -e /usr/bin/octoshield-gtk && ! -e /usr/libexec/octoshield-helper ]] || fail 'package removal left executable entry points installed'
apt-get purge --yes octoshield
check_preserved_state
printf '%s\n' 'PASS: actual disposable-CI install, upgrade, remove, and purge preserved backups and optional security controls.'
