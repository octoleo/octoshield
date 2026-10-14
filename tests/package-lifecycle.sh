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
[[ ($# -eq 2 || $# -eq 3) && $1 == --disposable-system ]] || fail 'refusing host changes; usage: tests/package-lifecycle.sh --disposable-system PACKAGE.deb [OLDER-PACKAGE.deb] inside disposable CI only'
[[ ${CI:-} == true || ${GITHUB_ACTIONS:-} == true ]] || fail 'this destructive test requires CI=true or GITHUB_ACTIONS=true and an explicitly disposable system'
((EUID == 0)) || fail 'this disposable-system test requires root'
archive=$(realpath -- "$2")
[[ -f $archive ]] || fail 'package archive does not exist'
[[ $(dpkg-deb --field "$archive" Package) == octoshield ]] || fail 'wrong package archive'
baseline=$archive
destination_version=$(dpkg-deb --field "$archive" Version)
if [[ $# -eq 3 ]]; then
    baseline=$(realpath -- "$3")
    [[ -f $baseline && $(dpkg-deb --field "$baseline" Package) == octoshield ]] || fail 'upgrade baseline must be an actual OctoShield package'
    baseline_version=$(dpkg-deb --field "$baseline" Version)
    [[ $baseline_version =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || fail 'upgrade baseline is not a stable version'
    dpkg --compare-versions "$destination_version" gt "$baseline_version" || fail 'upgrade destination is not newer than the supplied baseline'
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
usb_policy_checksum=''
monitor_enabled=false
policy_snapshot=$(mktemp)
observer_fixture=$(mktemp -d)
observer_pid=''
cleanup() {
    if [[ -n $observer_pid ]]; then
        kill "$observer_pid" 2>/dev/null || :
        wait "$observer_pid" 2>/dev/null || :
    fi
    rm -f -- "$policy_snapshot"
    rm -rf -- "$observer_fixture"
}
trap cleanup EXIT
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
    if [[ -n $usb_policy_checksum ]]; then
        [[ $(sha256sum /var/lib/octoshield/usb/profiles/lifecycle.rules) == "$usb_policy_checksum" ]] || fail 'remembered profile USB approval was removed or changed'
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

# These disposable CI containers do not boot systemd. Model only the status
# unit's service-manager boundary while keeping the real dpkg scripts and flock
# behavior. No protection daemon, policy command or unrelated unit is mocked.
export PACKAGE_LIFECYCLE_OBSERVER_PID="$observer_fixture/pid"
export PACKAGE_LIFECYCLE_OBSERVER_ACTIVE="$observer_fixture/active"
export PACKAGE_LIFECYCLE_OBSERVER_LOG="$observer_fixture/systemctl.log"
export PACKAGE_LIFECYCLE_SYSTEMCTL
PACKAGE_LIFECYCLE_SYSTEMCTL=$(command -v systemctl)
mkdir "$observer_fixture/bin"
cat >"$observer_fixture/bin/systemctl" <<'MOCK'
#!/bin/sh
printf '%s\n' "$*" >>"$PACKAGE_LIFECYCLE_OBSERVER_LOG"
case "$*" in
    'is-active --quiet octoshield-status.service') test -f "$PACKAGE_LIFECYCLE_OBSERVER_ACTIVE" ;;
    'stop octoshield-status.service')
        if [ -f "$PACKAGE_LIFECYCLE_OBSERVER_PID" ]; then
            pid=$(cat "$PACKAGE_LIFECYCLE_OBSERVER_PID")
            kill "$pid" || exit 1
            attempts=0
            while kill -0 "$pid" 2>/dev/null; do
                state=$(awk '{print $3}' "/proc/$pid/stat" 2>/dev/null) || break
                [ "$state" != Z ] || break
                attempts=$((attempts + 1))
                [ "$attempts" -lt 200 ] || exit 1
                sleep 0.01
            done
            rm -f "$PACKAGE_LIFECYCLE_OBSERVER_PID"
        fi
        rm -f "$PACKAGE_LIFECYCLE_OBSERVER_ACTIVE"
        ;;
    'start octoshield-status.service') touch "$PACKAGE_LIFECYCLE_OBSERVER_ACTIVE" ;;
    *) exec "$PACKAGE_LIFECYCLE_SYSTEMCTL" "$@" ;;
esac
MOCK
chmod 0755 "$observer_fixture/bin/systemctl"
start_observer_fixture() {
    [[ -z $observer_pid ]] || fail 'previous observer fixture was not reaped'
    rm -f "$observer_fixture/ready"
    : >"$PACKAGE_LIFECYCLE_OBSERVER_LOG"
    (
        umask 077
        exec 9>>/var/lib/octoshield/lock
        flock --shared 9
        touch "$observer_fixture/ready"
        exec sleep 120
    ) &
    observer_pid=$!
    printf '%s\n' "$observer_pid" >"$PACKAGE_LIFECYCLE_OBSERVER_PID"
    for ((attempt = 0; attempt < 200; attempt++)); do
        [[ ! -e $observer_fixture/ready ]] || break
        sleep 0.01
    done
    [[ -e $observer_fixture/ready ]] || fail 'observer fixture did not acquire its shared lock'
    touch "$PACKAGE_LIFECYCLE_OBSERVER_ACTIVE"
    if flock --nonblock /var/lib/octoshield/lock true; then fail 'observer fixture does not hold a real shared operation lock'; fi
}
upgrade_with_observer_fixture() {
    local result=0
    PATH="$observer_fixture/bin:$PATH" timeout 30 dpkg --install "$archive" >"$observer_fixture/upgrade.log" 2>&1 || result=$?
    cat "$observer_fixture/upgrade.log"
    ((result == 0)) || fail 'package upgrade failed while only the read-only observer held a shared lock'
    wait "$observer_pid" 2>/dev/null || :
    observer_pid=''
    [[ ! -e $PACKAGE_LIFECYCLE_OBSERVER_PID ]] || fail 'package upgrade did not stop the old observer'
    [[ -e $PACKAGE_LIFECYCLE_OBSERVER_ACTIVE ]] || fail 'package upgrade did not restart the previously running observer'
    [[ ! -e /run/octoshield-package-maintenance ]] || fail 'package upgrade left maintenance exclusion behind'
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

# Seed meaningful saved choices using the installed baseline's own schema. No
# policy is selected or applied: this checks persistence, not hardware access.
# Releases before named profiles are still supported as upgrade baselines.
seed_profile_choices() {
    # shellcheck disable=SC1091
    source /usr/lib/octoshield/src/lib/profiles.sh
    install -d -m 0700 /var/lib/octoshield/profiles /var/lib/octoshield/usb /var/lib/octoshield/usb/profiles
    profiles::_defaults | jq '.profiles.lifecycle = .profiles.office |
        .profiles.lifecycle.name = "Lifecycle saved choices" |
        .profiles.lifecycle.services.printing = "enabled" |
        .profiles.lifecycle.network.autoconnect = false |
        .profiles.lifecycle.firewall.rules = [{id:"r1-1-1",port:8443,protocol:"tcp",source:"192.0.2.0/24",interface:"any",expires_at:0}]' \
        >/var/lib/octoshield/profiles/state.json
    profiles::_validate_document </var/lib/octoshield/profiles/state.json || fail 'saved-profile fixture does not match the baseline schema'
    chmod 0600 /var/lib/octoshield/profiles/state.json
    profile_checksum=$(sha256sum /var/lib/octoshield/profiles/state.json)
    printf 'allow id 1234:5678 hash "lifecyclefixture" via-port "1-2"\n' >/var/lib/octoshield/usb/profiles/lifecycle.rules
    chmod 0600 /var/lib/octoshield/usb/profiles/lifecycle.rules
    usb_policy_checksum=$(sha256sum /var/lib/octoshield/usb/profiles/lifecycle.rules)
}
if [[ -f /usr/lib/octoshield/src/lib/profiles.sh ]]; then
    seed_profile_choices
fi

# Model the user's existing opt-in without starting security collection inside
# the build container. New package versions must leave this choice intact.
install -d -m 0755 /etc/systemd/system/multi-user.target.wants
ln -s /usr/lib/systemd/system/octoshield-monitor.service /etc/systemd/system/multi-user.target.wants/octoshield-monitor.service
monitor_enabled=true

# CI supplies the published previous release to exercise a genuine upgrade.
# A running control must cause bounded refusal before package replacement.
exec 8>/var/lib/octoshield/lock
chmod 0600 /var/lib/octoshield/lock
flock -n 8 || fail 'cannot acquire disposable operation lock'
if dpkg --install "$archive"; then fail 'upgrade was allowed during an active protection change'; fi
[[ $(dpkg-query -W -f='${Version}' octoshield) == "$(dpkg-deb --field "$baseline" Version)" ]] || fail 'refused upgrade replaced the installed baseline'
if flock --nonblock /var/lib/octoshield/lock true; then fail 'refused upgrade released the active operation lock'; fi
[[ ! -e /run/octoshield-package-maintenance ]] || fail 'refused upgrade left a maintenance marker'
flock -u 8
exec 8>&-

start_observer_fixture
if [[ ${baseline_version:-} == 1.1.0 || ${baseline_version:-} == 1.2.0 ]]; then
    # Demonstrate the actual published failure before trying the fixed package.
    # The old script must reject a shared read lock before it can stop the unit.
    previous_result=0
    PATH="$observer_fixture/bin:$PATH" /bin/sh /var/lib/dpkg/info/octoshield.prerm upgrade "$destination_version" >"$observer_fixture/old-prerm.log" 2>&1 || previous_result=$?
    [[ $previous_result -eq 1 ]] || fail 'published baseline no longer reproduces the reported observer-lock failure'
    grep -Fq 'a protection change is still running' "$observer_fixture/old-prerm.log" || fail 'baseline failed for a different reason'
    [[ ! -s $PACKAGE_LIFECYCLE_OBSERVER_LOG ]] || fail 'baseline unexpectedly reached observer shutdown before its lock refusal'
    [[ ! -e /run/octoshield-package-maintenance ]] || fail 'baseline refusal left maintenance exclusion behind'
    printf 'PASS: published %s reproduces the shared observer-lock refusal before replacement.\n' "$baseline_version"
fi
upgrade_with_observer_fixture
if [[ ${baseline_version:-} == 1.1.0 || ${baseline_version:-} == 1.2.0 ]]; then
    # dpkg versions phrase their recovery diagnostic differently. The old
    # package's own refusal followed by successful installation proves that
    # its failing prerm was recovered through the replacement package.
    grep -Fq 'OctoShield: a protection change is still running' "$observer_fixture/upgrade.log" || fail 'upgrade did not exercise the published baseline prerm refusal'
elif [[ ${baseline_version:-} == 1.2.1 ]]; then
    # This published baseline already quiesces its observer before locking.
    # It must upgrade normally, without falling back to the new package's prerm.
    # Match OctoShield's stable refusal text rather than dpkg's version-dependent
    # error diagnostics, and verify that shutdown was requested exactly once.
    if grep -Fq 'package changes were refused' "$observer_fixture/upgrade.log"; then
        fail 'the corrected baseline refused an upgrade while only its observer was active'
    fi
    [[ $(grep -Fxc 'stop octoshield-status.service' "$PACKAGE_LIFECYCLE_OBSERVER_LOG") == 1 ]] || fail 'the corrected baseline did not complete a single observer shutdown during upgrade'
    printf 'PASS: published %s upgrades normally with an active shared-lock observer.\n' "$baseline_version"
fi
[[ $(dpkg-query -W -f='${Version}' octoshield) == "$(dpkg-deb --field "$archive" Version)" ]] || fail 'new version was not installed'
/usr/bin/octoshield --help >/dev/null
[[ ! -e /run/octoshield-package-maintenance ]] || fail 'upgrade did not release maintenance exclusion'
[[ -x /usr/libexec/octoshield-session && $(stat -c '%u:%g:%a' /usr/libexec/octoshield-session) == 0:0:755 ]] || fail 'session broker is missing or has unsafe ownership/permissions'
grep -Fq '<action id="io.vdm.OctoShield.session">' /usr/share/polkit-1/actions/io.vdm.OctoShield.policy || fail 'session authorization policy is missing'
grep -Fq '<annotate key="org.freedesktop.policykit.exec.path">/usr/libexec/octoshield-session</annotate>' /usr/share/polkit-1/actions/io.vdm.OctoShield.policy || fail 'session broker PolicyKit path mismatch'
if grep -Fq auth_admin_keep /usr/share/polkit-1/actions/io.vdm.OctoShield.policy; then fail 'session authorization must not use a shared keep-cache'; fi
[[ -f /etc/xdg/autostart/io.vdm.OctoShield.UsbAgent.desktop && -f /usr/lib/systemd/user/octoshield-usb-agent.service ]] || fail 'USB prompt desktop integration is missing'
linked_libraries=$(ldd /usr/libexec/octoshield-session) || fail 'session broker is not a dynamically linked native executable'
if grep -Fq 'not found' <<<"$linked_libraries"; then fail 'session broker shared-library dependency is missing'; fi
check_preserved_state
check_inactive_services

# Old baselines without named profiles acquire a persistence fixture now.
if [[ -z $profile_checksum ]]; then seed_profile_choices; fi
start_observer_fixture
upgrade_with_observer_fixture
check_preserved_state
check_inactive_services

apt-get remove --yes octoshield
[[ ! -e /run/octoshield-package-maintenance ]] || fail 'removal did not release maintenance exclusion'
check_preserved_state
[[ ! -e /usr/bin/octoshield && ! -e /usr/bin/octoshield-gtk && ! -e /usr/libexec/octoshield-helper && ! -e /usr/libexec/octoshield-session ]] || fail 'package removal left executable entry points installed'
[[ ! -e /usr/lib/systemd/user/octoshield-usb-agent.service ]] || fail 'package removal left the USB prompt service installed'
apt-get purge --yes octoshield
[[ ! -e /etc/xdg/autostart/io.vdm.OctoShield.UsbAgent.desktop ]] || fail 'package purge left its USB autostart entry installed'
check_preserved_state
printf '%s\n' 'PASS: published-baseline lock recovery, observer-active upgrade/reinstall, exclusive-mutation refusal, removal and purge preserved native policies, profiles, user preferences, and recovery snapshots.'
