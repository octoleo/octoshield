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
[[ ($# -eq 2 || $# -eq 3) && $1 == --disposable-system ]] || fail 'refusing host changes; usage: tests/package-lifecycle.sh --disposable-system PACKAGE.deb [1.0.0-PACKAGE.deb] inside disposable CI only'
[[ ${CI:-} == true || ${GITHUB_ACTIONS:-} == true ]] || fail 'this destructive test requires CI=true or GITHUB_ACTIONS=true and an explicitly disposable system'
((EUID == 0)) || fail 'this disposable-system test requires root'
archive=$(realpath -- "$2")
[[ -f $archive ]] || fail 'package archive does not exist'
[[ $(dpkg-deb --field "$archive" Package) == octoshield ]] || fail 'wrong package archive'
baseline=$archive
if [[ $# -eq 3 ]]; then
    baseline=$(realpath -- "$3")
    [[ -f $baseline && $(dpkg-deb --field "$baseline" Package) == octoshield && $(dpkg-deb --field "$baseline" Version) == 1.0.0 ]] || fail 'upgrade baseline must be the actual OctoShield 1.0.0 package'
    dpkg --compare-versions "$(dpkg-deb --field "$archive" Version)" gt 1.0.0 || fail 'upgrade destination is not newer than 1.0.0'
fi
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
install -d -m 0700 /var/lib/octoshield /var/lib/octoshield/backups
install -d -m 0700 "${marker%/*}"
printf 'Private backup must survive install, upgrade, remove and purge.\n' >"$marker"
chmod 0600 "$marker"
marker_checksum=$(sha256sum "$marker")
preferences=/root/.local/state/octoshield/package-lifecycle-preference
[[ ! -e $preferences ]] || fail 'preexisting user preference fixture'
install -d -m 0700 "${preferences%/*}"
printf 'User choices must survive a package upgrade.\n' >"$preferences"
chmod 0600 "$preferences"
preferences_checksum=$(sha256sum "$preferences")
profile_checksum=''
monitor_enabled=false
policy_snapshot=$(mktemp)
trap 'rm -f -- "$policy_snapshot"' EXIT
for directory in /etc/ufw /etc/usbguard /etc/NetworkManager /etc/sudoers.d /etc/apparmor.d; do
    if [[ -d $directory ]]; then
        find "$directory" -type f -exec sha256sum {} + >>"$policy_snapshot"
    fi
done

check_preserved_state() {
    local package current
    [[ -f $marker && $(sha256sum "$marker") == "$marker_checksum" ]] || fail 'private recovery snapshot was removed or changed'
    [[ -f $preferences && $(sha256sum "$preferences") == "$preferences_checksum" ]] || fail 'user preference was removed or changed'
    if [[ -n $profile_checksum ]]; then
        [[ $(sha256sum /var/lib/octoshield/profiles/state.json) == "$profile_checksum" ]] || fail 'profile settings were reset or changed'
    fi
    if [[ -s $policy_snapshot ]]; then
        sha256sum --check --quiet "$policy_snapshot" || fail 'native security configuration changed during package lifecycle'
    fi
    for package in "${!original_packages[@]}"; do
        current=$(dpkg-query -W -f='${Status}' "$package" 2>/dev/null || :)
        [[ $current == "${original_packages[$package]}" ]] || fail "installation changed optional security package state: $package"
    done
}

check_inactive_services() {
    local links
    links=$(find /etc/systemd -type l -name 'octoshield-*.service' ! -name octoshield-status.service -print 2>/dev/null || :)
    if [[ $monitor_enabled == true ]]; then
        [[ $links == /etc/systemd/system/multi-user.target.wants/octoshield-monitor.service ]] || fail 'upgrade changed the existing monitoring enablement choice'
    else
        [[ -z $links ]] || fail 'installation enabled protection monitoring without an operator choice'
    fi
    if command -v systemctl >/dev/null; then
        if systemctl is-active --quiet octoshield-monitor.service 2>/dev/null; then
            fail 'installation started the security monitor without an operator choice'
        fi
    fi
}

export DEBIAN_FRONTEND=noninteractive
apt-get install --yes --no-install-recommends "$baseline"
[[ $(dpkg-query -W -f='${Version}' octoshield) == "$(dpkg-deb --field "$baseline" Version)" ]] || fail 'baseline version was not installed'
/usr/bin/octoshield --help >/dev/null
/usr/bin/octoshield --version
[[ -x /usr/bin/octoshield-gtk && -x /usr/libexec/octoshield-helper ]] || fail 'desktop executable or fixed privileged helper is missing'
[[ $(stat -c '%u:%g:%a' /usr/libexec/octoshield-helper) == 0:0:755 ]] || fail 'privileged helper ownership or permissions are incorrect'
grep -Fq '<allow_active>auth_admin</allow_active>' /usr/share/polkit-1/actions/io.vdm.OctoShield.policy || fail 'fresh administrator authentication is not required'
grep -Fq '<annotate key="org.freedesktop.policykit.exec.path">/usr/libexec/octoshield-helper</annotate>' /usr/share/polkit-1/actions/io.vdm.OctoShield.policy || fail 'PolicyKit helper path mismatch'
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

# Model the user's existing opt-in without starting security collection inside
# the build container. New package versions must leave this choice intact.
install -d -m 0755 /etc/systemd/system/multi-user.target.wants
ln -s /usr/lib/systemd/system/octoshield-monitor.service /etc/systemd/system/multi-user.target.wants/octoshield-monitor.service
monitor_enabled=true

# CI supplies the published 1.0.0 archive to exercise a genuine version upgrade.
# A running control must cause nonblocking refusal before package replacement.
exec 8>/var/lib/octoshield/lock
flock -n 8 || fail 'cannot acquire disposable operation lock'
if dpkg --install "$archive"; then fail 'upgrade was allowed during an active protection change'; fi
[[ ! -e /run/octoshield-package-maintenance ]] || fail 'refused upgrade left a maintenance marker'
flock -u 8
exec 8>&-
dpkg --install "$archive"
[[ $(dpkg-query -W -f='${Version}' octoshield) == "$(dpkg-deb --field "$archive" Version)" ]] || fail 'new version was not installed'
/usr/bin/octoshield --help >/dev/null
[[ ! -e /run/octoshield-package-maintenance ]] || fail 'upgrade did not release maintenance exclusion'
check_preserved_state
check_inactive_services

# Persist a valid, unselected profile configuration and confirm a subsequent
# upgrade/reinstall does not recreate defaults or activate a preset.
# shellcheck disable=SC1091
source /usr/lib/octoshield/src/lib/profiles.sh
install -d -m 0700 /var/lib/octoshield/profiles
profiles::_defaults >/var/lib/octoshield/profiles/state.json
chmod 0600 /var/lib/octoshield/profiles/state.json
profile_checksum=$(sha256sum /var/lib/octoshield/profiles/state.json)
dpkg --install "$archive"
check_preserved_state
check_inactive_services

apt-get remove --yes octoshield
[[ ! -e /run/octoshield-package-maintenance ]] || fail 'removal did not release maintenance exclusion'
check_preserved_state
[[ ! -e /usr/bin/octoshield && ! -e /usr/bin/octoshield-gtk && ! -e /usr/libexec/octoshield-helper ]] || fail 'package removal left executable entry points installed'
apt-get purge --yes octoshield
check_preserved_state
printf '%s\n' 'PASS: actual disposable-CI install, version upgrade, reinstall, remove, and purge preserved native policies, profiles, user preferences, and recovery snapshots.'
