#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Validate metadata, real advisory-lock lifecycle behavior, and optionally a .deb.
# No package is installed and no real service or security control is invoked.
set -Eeuo pipefail
IFS=$' \t\n'
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
fixture=$(mktemp -d)
trap 'rm -rf -- "$fixture"' EXIT
export PACKAGE_TEST_LOG="$fixture/commands"
mkdir "$fixture/mock-bin"
export PACKAGE_TEST_STATE="$fixture/state"
maintenance="$fixture/package-maintenance"
mkdir "$fixture/lifecycle"
mkdir -m 0700 "$PACKAGE_TEST_STATE"
for script in prerm postinst postrm; do
    sed -e "s@/var/lib/octoshield@$PACKAGE_TEST_STATE@g" \
        -e "s@/run/octoshield-package-maintenance@$maintenance@g" \
        "$repo/debian/octoshield.$script" >"$fixture/lifecycle/$script"
done

fail() {
    printf 'Package test failed: %s\n' "$*" >&2
    exit 1
}
require() { command -v "$1" >/dev/null || fail "required validation tool is missing: $1"; }
equal() { [[ $1 == "$2" ]] || fail "$3 (got: $1)"; }

require xmllint
require desktop-file-validate
require dpkg-deb
require appstreamcli

# These helpers generate activation scripts even when passed --no-scripts.
# Unit files are staged by Make; all lifecycle behavior is maintained explicitly.
if grep -Eq '^[[:space:]]+dh_installsystemd(user)?([[:space:]]|$)' "$repo/debian/rules"; then
    fail 'systemd debhelper invocations would add unwanted service lifecycle scripts'
fi

desktop-file-validate "$repo/data/io.vdm.OctoShield.desktop"
desktop-file-validate "$repo/data/io.vdm.OctoShield.UsbAgent.desktop"
for document in "$repo"/data/*.xml "$repo"/data/*.policy "$repo"/data/branding/*.xml; do
    xmllint --nonet --noout "$document"
done
metadata=$repo/data/io.vdm.OctoShield.metainfo.xml
appstreamcli validate --no-net "$metadata"
equal "$(xmllint --xpath 'string(/component/id)' "$metadata")" io.vdm.OctoShield 'application identity'
equal "$(xmllint --xpath 'string(/component/name)' "$metadata")" OctoShield 'application display name'
equal "$(xmllint --xpath 'string(/component/developer/@id)' "$metadata")" io.vdm 'developer identity'
equal "$(xmllint --xpath 'string(/component/developer/name)' "$metadata")" 'Vast Development Method' 'application developer'
equal "$(xmllint --xpath 'string(/component/url[@type="homepage"])' "$metadata")" https://www.vdm.io 'company homepage'
equal "$(xmllint --xpath 'string(/component/launchable[@type="desktop-id"])' "$metadata")" io.vdm.OctoShield.desktop 'desktop launchable identity'
equal "$(xmllint --xpath 'count(/component/screenshots/screenshot)' "$metadata")" 6 'store screenshot catalog'
equal "$(xmllint --xpath 'count(/component/screenshots/screenshot[@type="default"])' "$metadata")" 1 'one default store screenshot'
metadata_version=$(xmllint --xpath 'string(/component/releases/release[1]/@version)' "$metadata")
equal "$metadata_version" "$(dpkg-parsechangelog -l "$repo/debian/changelog" -S Version)" 'metadata and package release versions'
for index in 1 2 3 4 5 6; do
    screenshot=$(xmllint --xpath "string(/component/screenshots/screenshot[$index]/image[@type='source'])" "$metadata")
    [[ $screenshot =~ ^https://github.com/octoleo/octoshield/releases/download/v${metadata_version//./\\.}/OctoShield-(overview|protections|usb|office|monitoring|recovery)-(light|dark)\.png$ ]] || fail 'screenshot URL does not match a captured release asset'
done
for theme in light dark; do
    branding=$repo/data/branding/OctoShield-$theme.png
    [[ -f $branding && ! -L $branding ]] || fail "missing provided $theme branding asset"
    equal "$(od -An -tx1 -N8 "$branding" | tr -d ' \n')" 89504e470d0a1a0a 'original branding must be a PNG'
done
policy=$repo/data/io.vdm.OctoShield.policy
equal "$(xmllint --xpath 'count(/policyconfig/action)' "$policy")" 2 'only fixed operation and desktop-session authorization actions'
for action in admin session; do
    expression="/policyconfig/action[@id='io.vdm.OctoShield.$action']"
    equal "$(xmllint --xpath "count($expression)" "$policy")" 1 'exactly one declaration for each fixed action'
    case "$action" in
        admin) executable=/usr/libexec/octoshield-helper ;;
        session) executable=/usr/libexec/octoshield-session ;;
    esac
    equal "$(xmllint --xpath "string($expression/annotate[@key='org.freedesktop.policykit.exec.path'])" "$policy")" "$executable" 'fixed privileged executable'
    equal "$(xmllint --xpath "string($expression/defaults/allow_active)" "$policy")" auth_admin 'fresh administrator authorization without a shared keep-cache'
    equal "$(xmllint --xpath "string($expression/defaults/allow_inactive)" "$policy")" no 'inactive sessions denied'
    equal "$(xmllint --xpath "string($expression/defaults/allow_any)" "$policy")" no 'other sessions denied'
done
equal "$(xmllint --xpath 'count(/policyconfig/action/annotate[@key="org.freedesktop.policykit.exec.allow_gui"])' "$policy")" 0 'GUI process must not gain privileges'
grep -Fx 'Exec=octoshield-gtk' "$repo/data/io.vdm.OctoShield.desktop" >/dev/null || fail 'desktop launcher does not launch the normal-user GUI'
grep -Fx 'Terminal=false' "$repo/data/io.vdm.OctoShield.desktop" >/dev/null || fail 'desktop entry unexpectedly opens a terminal'
grep -Fx 'Icon=io.vdm.OctoShield' "$repo/data/io.vdm.OctoShield.desktop" >/dev/null || fail 'desktop icon identity differs from the application'

cat >"$fixture/mock-bin/systemctl" <<'MOCK'
#!/bin/sh
printf 'systemctl %s\n' "$*" >>"$PACKAGE_TEST_LOG"
if [ "${PACKAGE_TEST_SYSTEMCTL_EXIT:-0}" -ne 0 ]; then exit "$PACKAGE_TEST_SYSTEMCTL_EXIT"; fi
case "$*" in
    'is-active --quiet octoshield-status.service') test -f "$PACKAGE_TEST_OBSERVER_ACTIVE" ;;
    'is-enabled --quiet octoshield-status.service') test -f "$PACKAGE_TEST_OBSERVER_ENABLED" ;;
    'stop octoshield-status.service')
        if [ "${PACKAGE_TEST_REQUIRE_MARKER:-false}" = true ] && [ ! -f "$PACKAGE_TEST_MAINTENANCE" ]; then
            touch "$PACKAGE_TEST_BAD_STOP"
            exit 1
        fi
        [ "${PACKAGE_TEST_STOP_FAILURE:-false}" != true ] || exit 1
        if [ -f "$PACKAGE_TEST_OBSERVER_PID" ]; then
            pid=$(cat "$PACKAGE_TEST_OBSERVER_PID")
            kill "$pid" || exit 1
            # A real observer process owns a real shared flock. Wait until it
            # exits (or is awaiting its parent's wait), as systemctl stop does.
            attempts=0
            while kill -0 "$pid" 2>/dev/null; do
                state=$(awk '{print $3}' "/proc/$pid/stat" 2>/dev/null) || break
                [ "$state" != Z ] || break
                attempts=$((attempts + 1))
                [ "$attempts" -lt 200 ] || exit 1
                sleep 0.01
            done
            rm -f "$PACKAGE_TEST_OBSERVER_PID"
        fi
        rm -f "$PACKAGE_TEST_OBSERVER_ACTIVE"
        ;;
    'start octoshield-status.service') touch "$PACKAGE_TEST_OBSERVER_ACTIVE" ;;
    'enable octoshield-status.service') touch "$PACKAGE_TEST_OBSERVER_ENABLED" ;;
    'disable octoshield-status.service') rm -f "$PACKAGE_TEST_OBSERVER_ENABLED" ;;
esac
MOCK
cat >"$fixture/mock-bin/loginctl" <<'MOCK'
#!/bin/sh
printf '1000 alice\n1001 bob\ninvalid ignored\n1002@remote ignored\n'
MOCK
cat >"$fixture/mock-bin/stat" <<'MOCK'
#!/bin/sh
# Maintainer scripts run as root; fixture directories may belong to a CI user.
# Preserve actual modes and hard-link counts so unsafe-file tests stay real.
case "$*" in
    "-c %u:%a $PACKAGE_TEST_STATE") printf '0:%s\n' "$(/usr/bin/stat -c %a "$PACKAGE_TEST_STATE")" ;;
    "-c %u:%a:%h $PACKAGE_TEST_STATE/lock" | "-c %u:%a:%h $PACKAGE_TEST_MAINTENANCE")
        printf '0:%s\n' "$(/usr/bin/stat -c '%a:%h' "$3")"
        ;;
    *) exec /usr/bin/stat "$@" ;;
esac
MOCK
chmod 0755 "$fixture/mock-bin/systemctl" "$fixture/mock-bin/loginctl" "$fixture/mock-bin/stat"
export PACKAGE_TEST_MAINTENANCE="$maintenance"
export PACKAGE_TEST_OBSERVER_ACTIVE="$fixture/observer-active"
export PACKAGE_TEST_OBSERVER_ENABLED="$fixture/observer-enabled"
export PACKAGE_TEST_OBSERVER_PID="$fixture/observer-pid"
export PACKAGE_TEST_BAD_STOP="$fixture/stop-without-marker"
observer_pid=''
cleanup() {
    if [[ -n $observer_pid ]]; then
        kill "$observer_pid" 2>/dev/null || :
        wait "$observer_pid" 2>/dev/null || :
    fi
    rm -rf -- "$fixture"
}
trap cleanup EXIT
observer_state() {
    rm -f "$PACKAGE_TEST_OBSERVER_ENABLED" "$PACKAGE_TEST_OBSERVER_ACTIVE"
    if [[ $1 == enabled ]]; then touch "$PACKAGE_TEST_OBSERVER_ENABLED"; fi
    if [[ $2 == active ]]; then touch "$PACKAGE_TEST_OBSERVER_ACTIVE"; fi
}
observer_start() {
    [[ -z $observer_pid ]] || fail 'fixture observer already started'
    rm -f "$fixture/observer-ready"
    (
        umask 077
        exec 9>"$PACKAGE_TEST_STATE/lock"
        flock --shared 9
        touch "$fixture/observer-ready"
        exec sleep 120
    ) &
    observer_pid=$!
    printf '%s\n' "$observer_pid" >"$PACKAGE_TEST_OBSERVER_PID"
    for ((attempt = 0; attempt < 200; attempt++)); do
        [[ ! -f $fixture/observer-ready ]] || break
        sleep 0.01
    done
    [[ -f $fixture/observer-ready ]] || fail 'fixture observer did not acquire its shared lock'
    touch "$PACKAGE_TEST_OBSERVER_ACTIVE"
    if flock --nonblock "$PACKAGE_TEST_STATE/lock" true; then fail 'shared fixture observer does not hold the actual operation lock'; fi
}
observer_wait() {
    wait "$observer_pid" 2>/dev/null || :
    observer_pid=''
    rm -f "$PACKAGE_TEST_OBSERVER_PID"
}
lifecycle() {
    local result=0 marker_required=false
    : >"$PACKAGE_TEST_LOG"
    [[ $1 != prerm ]] || marker_required=true
    PACKAGE_TEST_REQUIRE_MARKER="$marker_required" PATH="$fixture/mock-bin:/usr/bin:/bin" /bin/sh "$fixture/lifecycle/$1" "${@:2}" >"$fixture/lifecycle-output" 2>&1 || result=$?
    [[ ! -e $PACKAGE_TEST_BAD_STOP ]] || fail 'observer was stopped before excluding new operations'
    return "$result"
}

observer_state disabled inactive
lifecycle postinst configure
equal "$(cat "$PACKAGE_TEST_LOG")" $'systemctl daemon-reload\nsystemctl enable octoshield-status.service\nsystemctl is-enabled --quiet octoshield-status.service\nsystemctl start octoshield-status.service' 'installation starts only the status observer'
lifecycle postinst configure 1.0.0
equal "$(cat "$PACKAGE_TEST_LOG")" $'systemctl daemon-reload\nsystemctl enable octoshield-status.service\nsystemctl is-enabled --quiet octoshield-status.service\nsystemctl start octoshield-status.service' 'migration from 1.0 starts the new observer without changing controls'
lifecycle postinst configure 1.1.0
equal "$(cat "$PACKAGE_TEST_LOG")" $'systemctl daemon-reload\nsystemctl is-enabled --quiet octoshield-status.service\nsystemctl start octoshield-status.service' 'later upgrade retains observer enablement choice'
observer_state disabled inactive
lifecycle postinst configure 1.1.0
equal "$(cat "$PACKAGE_TEST_LOG")" $'systemctl daemon-reload\nsystemctl is-enabled --quiet octoshield-status.service' 'disabled observer is not enabled or started by later upgrade'

# The old installed prerm can fail on a read-only observer; dpkg then calls the
# new script with failed-upgrade. Exercise both entry points with a real child
# holding the shared operation lock, released only by the mocked service stop.
for action in upgrade failed-upgrade; do
    observer_state disabled active
    observer_start
    lifecycle prerm "$action"
    observer_wait
    equal "$(cat "$PACKAGE_TEST_LOG")" $'systemctl is-active --quiet octoshield-status.service\nsystemctl stop octoshield-status.service' 'upgrade pauses only the observer before acquiring exclusive access'
    equal "$(cat "$maintenance")" status-active 'maintenance remembers a running observer even when disabled'
    [[ $(stat -c %a "$maintenance") == 600 ]] || fail 'maintenance marker must be private'
    [[ ! -e $PACKAGE_TEST_OBSERVER_ACTIVE ]] || fail 'observer remained active during package replacement'
    flock --nonblock "$PACKAGE_TEST_STATE/lock" true || fail 'observer lock leaked after prerm completed'
    lifecycle postrm upgrade
    lifecycle postrm failed-upgrade
    equal "$(cat "$PACKAGE_TEST_LOG")" '' 'upgrade must not disable controls'
    [[ -f $maintenance ]] || fail 'old package postrm upgrade must not unlock the replacing package'
    lifecycle postinst configure 1.2.0
    equal "$(cat "$PACKAGE_TEST_LOG")" $'systemctl daemon-reload\nsystemctl start octoshield-status.service' 'upgrade restores a previously running disabled observer without enabling it'
    [[ ! -e $maintenance && -e $PACKAGE_TEST_OBSERVER_ACTIVE && ! -e $PACKAGE_TEST_OBSERVER_ENABLED ]] || fail 'successful configuration changed the observer choice or kept maintenance exclusion'
done
observer_state enabled inactive
lifecycle prerm upgrade
equal "$(cat "$maintenance")" status-inactive 'maintenance remembers a deliberately stopped observer'
lifecycle postinst configure 1.2.0
equal "$(cat "$PACKAGE_TEST_LOG")" 'systemctl daemon-reload' 'upgrade must preserve a stopped observer even when enabled'
[[ ! -e $PACKAGE_TEST_OBSERVER_ACTIVE ]] || fail 'upgrade started a deliberately stopped observer'

# An active root mutation remains protected. The observer may be quiesced, but
# refusal must restore its exact running state, remove only our new marker and
# leave the exclusive lock holder alive. No native protection is stopped.
exec 8>"$PACKAGE_TEST_STATE/lock"
chmod 0600 "$PACKAGE_TEST_STATE/lock"
flock -n 8 || fail 'cannot acquire fixture operation lock'
for action in remove upgrade failed-upgrade deconfigure; do
    observer_state disabled active
    if lifecycle prerm "$action"; then fail 'package change ignored an active protection change'; fi
    equal "$(cat "$PACKAGE_TEST_LOG")" $'systemctl is-active --quiet octoshield-status.service\nsystemctl stop octoshield-status.service\nsystemctl start octoshield-status.service' 'active mutation refusal must restore the observer and leave native protections alone'
    [[ ! -e $maintenance ]] || fail 'refused package operation left a maintenance marker'
    [[ -e $PACKAGE_TEST_OBSERVER_ACTIVE && ! -e $PACKAGE_TEST_OBSERVER_ENABLED ]] || fail 'refused package operation changed observer enablement or activity'
    grep -Fq 'Let the operation finish, then retry APT' "$fixture/lifecycle-output" || fail 'active operation refusal must explain how to retry'
    if flock --nonblock "$PACKAGE_TEST_STATE/lock" true; then fail 'refusal released another process operation lock'; fi
done
observer_state enabled inactive
if lifecycle prerm upgrade; then fail 'inactive observer bypassed an exclusive mutation lock'; fi
[[ ! -e $PACKAGE_TEST_OBSERVER_ACTIVE && ! -e $maintenance ]] || fail 'refusal started a previously stopped observer or left its marker'
flock -u 8
exec 8>&-

# Failure to stop the observer is a genuine quiescence failure: retain its
# live process, reject replacement and roll back the newly-created marker.
observer_state disabled active
observer_start
if PACKAGE_TEST_STOP_FAILURE=true lifecycle prerm upgrade; then fail 'upgrade ignored failure to stop an active observer'; fi
kill -0 "$observer_pid" || fail 'stop failure killed the observer outside systemctl'
[[ ! -e $maintenance && -e $PACKAGE_TEST_OBSERVER_ACTIVE ]] || fail 'observer stop failure did not restore pre-upgrade state'
kill "$observer_pid"
observer_wait

for action in abort-upgrade abort-remove abort-deconfigure; do
    observer_state disabled active
    lifecycle prerm upgrade
    lifecycle postinst "$action"
    equal "$(cat "$PACKAGE_TEST_LOG")" 'systemctl start octoshield-status.service' 'aborted package change restores its previously active observer'
    [[ ! -e $maintenance && -e $PACKAGE_TEST_OBSERVER_ACTIVE ]] || fail "postinst $action did not restore observer and release exclusion"
done
# A new postrm abort-upgrade can run before the old package's postinst. It
# must restore a disabled-but-running observer itself before clearing the data
# that the old script would otherwise be unable to understand.
observer_state disabled active
lifecycle prerm upgrade
lifecycle postrm abort-upgrade
equal "$(cat "$PACKAGE_TEST_LOG")" 'systemctl start octoshield-status.service' 'new postrm abort recovery restores a previously active disabled observer'
[[ ! -e $maintenance && -e $PACKAGE_TEST_OBSERVER_ACTIVE && ! -e $PACKAGE_TEST_OBSERVER_ENABLED ]] || fail 'postrm abort recovery lost the observer running choice'

observer_state disabled inactive
lifecycle prerm remove
equal "$(cat "$PACKAGE_TEST_LOG")" $'systemctl is-active --quiet octoshield-status.service\nsystemctl stop octoshield-status.service\nsystemctl stop octoshield-monitor.service\nsystemctl --user --machine=1000@.host disable --now octoshield-notify.service\nsystemctl --user --machine=1000@.host stop octoshield-usb-agent.service\nsystemctl --user --machine=1001@.host disable --now octoshield-notify.service\nsystemctl --user --machine=1001@.host stop octoshield-usb-agent.service' 'removal stops only package-owned observers and user agents'
grep -Fq 'security settings and private backups remain' "$fixture/lifecycle-output" || fail 'removal must disclose retained security settings'
[[ -f $maintenance ]] || fail 'removal must exclude new protection changes'
lifecycle postrm remove
[[ ! -e $maintenance ]] || fail 'finished removal must release maintenance exclusion for standalone CLI use'
lifecycle postrm purge
equal "$(cat "$PACKAGE_TEST_LOG")" $'systemctl disable octoshield-status.service\nsystemctl disable octoshield-monitor.service\nsystemctl --global disable octoshield-notify.service\nsystemctl daemon-reload' 'purge affects only package-owned service enablement'
for action in abort-upgrade abort-remove abort-deconfigure; do
    : >"$maintenance"
    chmod 0600 "$maintenance"
    lifecycle postinst "$action"
    [[ ! -e $maintenance ]] || fail "postinst $action failed to release legacy maintenance exclusion"
done
for action in abort-install abort-upgrade purge; do
    : >"$maintenance"
    lifecycle postrm "$action"
    [[ ! -e $maintenance ]] || fail "postrm $action failed to release maintenance exclusion"
done
for stage in 'postinst configure' 'prerm remove' 'postrm purge'; do
    : >"$maintenance"
    read -r script action <<<"$stage"
    DPKG_ROOT="$fixture/alternate-root" lifecycle "$script" "$action"
    equal "$(cat "$PACKAGE_TEST_LOG")" '' 'alternate-root installation must not change running host services'
    [[ -e $maintenance ]] || fail 'alternate-root package operation changed the host maintenance marker'
    rm "$maintenance"
done
PACKAGE_TEST_SYSTEMCTL_EXIT=1 lifecycle prerm remove
PACKAGE_TEST_SYSTEMCTL_EXIT=1 lifecycle postrm purge
printf '%s\n' 'PASS: desktop metadata, PolicyKit boundary, real upgrade locks, and isolated install/upgrade/remove/purge behavior.'

if (($# == 0)); then exit 0; fi
(($# == 1)) || fail 'usage: bash tests/package.sh [built-package.deb]'
archive=$1
[[ -f $archive ]] || fail "archive does not exist: $archive"
equal "$(dpkg-deb --field "$archive" Package)" octoshield 'binary package identity'
dependencies=$(dpkg-deb --field "$archive" Depends)
[[ $dependencies == *'coreutils (<< 9.5) | gnu-coreutils'* ]] || fail 'missing explicit GNU timeout runtime dependency'
if grep -Eq '(^|,)[[:space:]]*(usbguard|ufw|apparmor|unattended-upgrades)([[:space:],(]|$)' <<<"$dependencies"; then
    fail 'installing the package could install a security control before explicit enrollment'
fi
for dependency in jq pkexec systemd whiptail; do
    grep -Eq "(^|,)[[:space:]]*$dependency([[:space:],(]|$)" <<<"$dependencies" || fail "missing runtime dependency $dependency"
done
for dependency in libgtk-4 libadwaita-1 libjson-glib; do
    [[ $dependencies == *"$dependency"* ]] || fail "missing generated GUI dependency $dependency"
done
dpkg-deb --extract "$archive" "$fixture/root"
dpkg-deb --control "$archive" "$fixture/control"
dpkg-deb --fsys-tarfile "$archive" | tar --numeric-owner -tvf - >"$fixture/contents"
awk '$2 != "0/0" {bad=1} END {exit bad}' "$fixture/contents" || fail 'package payload must be owned by root'
[[ ! -e $fixture/root/usr/local ]] || fail 'Debian package must not own the standalone /usr/local installation'
# The user-session prompt agent uses the standard XDG autostart location. No
# native firewall, USB policy, authentication or network configuration belongs
# in the package payload.
while IFS= read -r path; do
    case "${path#"$fixture/root"}" in
        /etc | /etc/xdg | /etc/xdg/autostart)
            [[ -d $path && ! -L $path ]] || fail 'autostart parent must be a regular directory'
            ;;
        /etc/xdg/autostart/io.vdm.OctoShield.UsbAgent.desktop)
            [[ -f $path && ! -L $path ]] || fail 'autostart entry must be a regular file'
            ;;
        *) fail 'package must not install or replace system security configuration' ;;
    esac
done < <(find "$fixture/root/etc" -mindepth 0 -print)
[[ -z $(find "$fixture/root" -type f -perm /6000 -print) ]] || fail 'setuid/setgid files are forbidden'

for executable in usr/bin/octoshield usr/bin/octoshield-gtk usr/libexec/octoshield-helper usr/libexec/octoshield-session usr/lib/octoshield/bin/octoshield-monitor usr/lib/octoshield/src/status-daemon usr/lib/octoshield/src/usb-prompt.sh; do
    [[ -f $fixture/root/$executable && -x $fixture/root/$executable && ! -L $fixture/root/$executable ]] || fail "missing regular executable $executable"
done
for path in \
    usr/lib/octoshield/src/lib/core.sh \
    usr/lib/octoshield/src/lib/api.sh \
    usr/lib/octoshield/src/lib/access.sh \
    usr/lib/octoshield/src/lib/connections.sh \
    usr/lib/octoshield/src/lib/diagnostics.sh \
    usr/lib/octoshield/src/lib/containers.sh \
    usr/lib/octoshield/src/lib/updates.sh \
    usr/lib/octoshield/src/lib/profiles.sh \
    usr/lib/octoshield/src/lib/profile_controls.sh \
    usr/lib/octoshield/src/lib/status.sh \
    usr/lib/octoshield/src/notify.sh \
    usr/share/applications/io.vdm.OctoShield.desktop \
    usr/share/pixmaps/io.vdm.OctoShield.png \
    usr/share/octoshield/branding/OctoShield-light.png \
    usr/share/octoshield/branding/OctoShield-dark.png \
    usr/share/metainfo/io.vdm.OctoShield.metainfo.xml \
    usr/share/polkit-1/actions/io.vdm.OctoShield.policy \
    usr/lib/systemd/system/octoshield-monitor.service \
    usr/lib/systemd/system/octoshield-status.service \
    usr/lib/systemd/user/octoshield-notify.service \
    usr/lib/systemd/user/octoshield-usb-agent.service \
    etc/xdg/autostart/io.vdm.OctoShield.UsbAgent.desktop; do
    [[ -f $fixture/root/$path && ! -L $fixture/root/$path ]] || fail "missing regular package file $path"
done
cmp "$repo/data/branding/OctoShield-light.png" "$fixture/root/usr/share/pixmaps/io.vdm.OctoShield.png" || fail 'launcher does not preserve the provided light branding'
for theme in light dark; do
    cmp "$repo/data/branding/OctoShield-$theme.png" "$fixture/root/usr/share/octoshield/branding/OctoShield-$theme.png" || fail "packaged $theme branding differs from its source"
done
[[ -z $(find "$fixture/root/usr/share" -name 'org.octoleo*' -print) ]] || fail 'obsolete application namespace remains in the package'
[[ -z $(find "$fixture/root/usr/lib/octoshield" -type d ! -perm -0005 -print) ]] || fail 'library directories must be readable/searchable by desktop users'
[[ -z $(find "$fixture/root/usr/lib/octoshield" -type f ! -perm -0004 -print) ]] || fail 'runtime library must be readable by desktop users'
[[ -z $(find "$fixture/root/usr" -perm /0022 -print) ]] || fail 'package paths must not be writable by non-root users'
[[ -z $(find "$fixture/root/etc" -perm /0022 -print) ]] || fail 'autostart paths must not be writable by non-root users'
cmp "$repo/data/io.vdm.OctoShield.UsbAgent.desktop" "$fixture/root/etc/xdg/autostart/io.vdm.OctoShield.UsbAgent.desktop" || fail 'packaged autostart differs from reviewed source'
for path in "$fixture/root/usr/lib/systemd/system/octoshield-monitor.service" "$fixture/root/usr/lib/systemd/system/octoshield-status.service" "$fixture/root/usr/lib/systemd/user/octoshield-notify.service" "$fixture/root/usr/lib/systemd/user/octoshield-usb-agent.service"; do
    if grep -Fq /usr/local "$path"; then fail 'package service points at standalone installation'; fi
done
for script in postinst prerm postrm; do
    [[ -f $fixture/control/$script ]] || fail "missing package lifecycle script $script"
    /bin/sh -n "$fixture/control/$script"
    if grep -Fq 'Automatically added by dh_installsystemd' "$fixture/control/$script"; then
        fail "unexpected generated systemd lifecycle snippet in $script"
    fi
done
if grep -E 'deb-systemd-(invoke|helper)|(systemctl).*(start|restart|enable)' "$fixture/control/postinst" | grep -Fv 'octoshield-status.service'; then
    fail 'postinst activates a service other than the status observer'
fi
if grep -Eq '^[[:space:]]*(ufw|usbguard|apt-get|octoshield|/usr/bin/octoshield)[[:space:]]' "$fixture/control/postinst"; then
    fail 'package install unexpectedly applies hardening or installs control packages'
fi
cmp "$policy" "$fixture/root/usr/share/polkit-1/actions/io.vdm.OctoShield.policy" || fail 'packaged PolicyKit boundary differs from the reviewed source'
printf 'PASS: %s payload, ownership, dependency, service, and maintainer-script checks.\n' "$archive"
