#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Validate source metadata, mocked lifecycle behavior, and optionally a built .deb.
# No package is installed and no real service or security control is invoked.
set -Eeuo pipefail
IFS=$' \t\n'
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
fixture=$(mktemp -d)
trap 'rm -rf -- "$fixture"' EXIT
export PACKAGE_TEST_LOG="$fixture/commands"
mkdir "$fixture/mock-bin"

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
equal "$(xmllint --xpath 'count(/policyconfig/action)' "$policy")" 1 'exactly one authorization action'
equal "$(xmllint --xpath 'string(/policyconfig/action/@id)' "$policy")" io.vdm.OctoShield.admin 'fixed policy action'
equal "$(xmllint --xpath 'string(/policyconfig/action/annotate[@key="org.freedesktop.policykit.exec.path"])' "$policy")" /usr/libexec/octoshield-helper 'fixed privileged executable'
equal "$(xmllint --xpath 'string(/policyconfig/action/defaults/allow_active)' "$policy")" auth_admin 'fresh administrator authorization'
equal "$(xmllint --xpath 'string(/policyconfig/action/defaults/allow_inactive)' "$policy")" no 'inactive sessions denied'
equal "$(xmllint --xpath 'string(/policyconfig/action/defaults/allow_any)' "$policy")" no 'other sessions denied'
equal "$(xmllint --xpath 'count(/policyconfig/action/annotate[@key="org.freedesktop.policykit.exec.allow_gui"])' "$policy")" 0 'GUI process must not gain privileges'
grep -Fx 'Exec=octoshield-gtk' "$repo/data/io.vdm.OctoShield.desktop" >/dev/null || fail 'desktop launcher does not launch the normal-user GUI'
grep -Fx 'Terminal=false' "$repo/data/io.vdm.OctoShield.desktop" >/dev/null || fail 'desktop entry unexpectedly opens a terminal'
grep -Fx 'Icon=io.vdm.OctoShield' "$repo/data/io.vdm.OctoShield.desktop" >/dev/null || fail 'desktop icon identity differs from the application'

cat >"$fixture/mock-bin/systemctl" <<'MOCK'
#!/bin/sh
printf 'systemctl %s\n' "$*" >>"$PACKAGE_TEST_LOG"
exit "${PACKAGE_TEST_SYSTEMCTL_EXIT:-0}"
MOCK
cat >"$fixture/mock-bin/loginctl" <<'MOCK'
#!/bin/sh
printf '1000 alice\n1001 bob\ninvalid ignored\n1002@remote ignored\n'
MOCK
chmod 0755 "$fixture/mock-bin/systemctl" "$fixture/mock-bin/loginctl"

lifecycle() {
    : >"$PACKAGE_TEST_LOG"
    PATH="$fixture/mock-bin:/usr/bin:/bin" /bin/sh "$repo/debian/octoshield.$1" "$2" >/dev/null 2>&1
}

lifecycle postinst configure
equal "$(cat "$PACKAGE_TEST_LOG")" 'systemctl daemon-reload' 'installation only reloads unit metadata'
lifecycle prerm upgrade
equal "$(cat "$PACKAGE_TEST_LOG")" '' 'upgrade must not stop controls'
lifecycle postrm upgrade
equal "$(cat "$PACKAGE_TEST_LOG")" '' 'upgrade must not disable controls'
lifecycle prerm remove
equal "$(cat "$PACKAGE_TEST_LOG")" $'systemctl stop octoshield-monitor.service\nsystemctl --user --machine=1000@.host stop octoshield-notify.service\nsystemctl --user --machine=1001@.host stop octoshield-notify.service' 'removal stops only package-owned services for numeric local users'
lifecycle postrm purge
equal "$(cat "$PACKAGE_TEST_LOG")" $'systemctl disable octoshield-monitor.service\nsystemctl --global disable octoshield-notify.service\nsystemctl daemon-reload' 'purge affects only package-owned service enablement'
for stage in 'postinst configure' 'prerm remove' 'postrm purge'; do
    read -r script action <<<"$stage"
    DPKG_ROOT="$fixture/alternate-root" lifecycle "$script" "$action"
    equal "$(cat "$PACKAGE_TEST_LOG")" '' 'alternate-root installation must not change running host services'
done
PACKAGE_TEST_SYSTEMCTL_EXIT=1 lifecycle prerm remove
PACKAGE_TEST_SYSTEMCTL_EXIT=1 lifecycle postrm purge
printf '%s\n' 'PASS: desktop metadata, PolicyKit boundary, and mocked install/upgrade/remove/purge behavior.'

if (($# == 0)); then exit 0; fi
(($# == 1)) || fail 'usage: bash tests/package.sh [built-package.deb]'
archive=$1
[[ -f $archive ]] || fail "archive does not exist: $archive"
equal "$(dpkg-deb --field "$archive" Package)" octoshield 'binary package identity'
dependencies=$(dpkg-deb --field "$archive" Depends)
if grep -Eq '(^|,)[[:space:]]*(usbguard|ufw|apparmor|unattended-upgrades)([[:space:],(]|$)' <<<"$dependencies"; then
    fail 'installing the package could install a security control before explicit enrollment'
fi
for dependency in jq pkexec whiptail; do
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
[[ ! -e $fixture/root/etc ]] || fail 'package must not install or replace system security configuration'
[[ -z $(find "$fixture/root" -type f -perm /6000 -print) ]] || fail 'setuid/setgid files are forbidden'

for executable in usr/bin/octoshield usr/bin/octoshield-gtk usr/libexec/octoshield-helper usr/lib/octoshield/bin/octoshield-monitor; do
    [[ -f $fixture/root/$executable && -x $fixture/root/$executable && ! -L $fixture/root/$executable ]] || fail "missing regular executable $executable"
done
for path in \
    usr/lib/octoshield/src/lib/core.sh \
    usr/lib/octoshield/src/lib/api.sh \
    usr/lib/octoshield/src/notify.sh \
    usr/share/applications/io.vdm.OctoShield.desktop \
    usr/share/pixmaps/io.vdm.OctoShield.png \
    usr/share/octoshield/branding/OctoShield-light.png \
    usr/share/octoshield/branding/OctoShield-dark.png \
    usr/share/metainfo/io.vdm.OctoShield.metainfo.xml \
    usr/share/polkit-1/actions/io.vdm.OctoShield.policy \
    usr/lib/systemd/system/octoshield-monitor.service \
    usr/lib/systemd/user/octoshield-notify.service; do
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
for path in "$fixture/root/usr/lib/systemd/system/octoshield-monitor.service" "$fixture/root/usr/lib/systemd/user/octoshield-notify.service"; do
    if grep -Fq /usr/local "$path"; then fail 'package service points at standalone installation'; fi
done
for script in postinst prerm postrm; do
    [[ -f $fixture/control/$script ]] || fail "missing package lifecycle script $script"
    /bin/sh -n "$fixture/control/$script"
    if grep -Fq 'Automatically added by dh_installsystemd' "$fixture/control/$script"; then
        fail "unexpected generated systemd lifecycle snippet in $script"
    fi
done
if grep -Eq 'deb-systemd-(invoke|helper)|(systemctl).*(start|restart|enable)' "$fixture/control/postinst"; then
    fail 'generated postinst unexpectedly changes service activation state'
fi
if grep -Eq '^[[:space:]]*(ufw|usbguard|apt-get|octoshield|/usr/bin/octoshield)[[:space:]]' "$fixture/control/postinst"; then
    fail 'package install unexpectedly applies hardening or installs control packages'
fi
cmp "$policy" "$fixture/root/usr/share/polkit-1/actions/io.vdm.OctoShield.policy" || fail 'packaged PolicyKit boundary differs from the reviewed source'
printf 'PASS: %s payload, ownership, dependency, service, and maintainer-script checks.\n' "$archive"
