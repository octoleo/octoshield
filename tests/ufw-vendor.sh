#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Read-only integration check against the distribution's installed UFW package.
# No firewall activation, kernel change or live configuration edit is performed.
set -Eeuo pipefail
IFS=$' \t\n'
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
fixture=$(mktemp -d)
trap 'rm -rf -- "$fixture"' EXIT

fail() {
    printf 'UFW vendor integration test: %s\n' "$*" >&2
    exit 1
}
[[ $(dpkg-query -W -f='${Status}' ufw 2>/dev/null || :) == 'install ok installed' ]] || fail 'install the Ubuntu ufw package before running this read-only check'
# shellcheck source=../src/lib/core.sh
source "$repo/src/lib/core.sh"
# shellcheck source=../src/lib/profile_controls.sh
source "$repo/src/lib/profile_controls.sh"
CORE_STATE="$fixture/private-state"
mkdir -m 0700 "$CORE_STATE"

for file in before.rules before6.rules after.rules after6.rules; do
    [[ -f /etc/ufw/$file ]] || fail "stock UFW file is missing: $file"
done
find /etc/ufw -type f -exec sha256sum {} + >"$fixture/native.sha256"
sha256sum /etc/default/ufw >>"$fixture/native.sha256"
profile_controls::_standard_ufw_hooks || fail 'the actual installed Ubuntu vendor hooks were rejected'
sha256sum --check --quiet "$fixture/native.sha256" || fail 'read-only preflight modified native UFW files'

# Administrator modifications are rejected even when the remaining installed
# package templates are intact. Only this disposable copy is changed.
mkdir "$fixture/etc"
cp -a -- /etc/ufw "$fixture/etc/ufw"
PROFILE_ETC="$fixture/etc"
printf '\n# Administrator customization fixture\n-A ufw-before-input -p tcp --dport 9999 -j ACCEPT\n' >>"$PROFILE_ETC/ufw/before.rules"
if profile_controls::_standard_ufw_hooks >"$fixture/rejection" 2>&1; then
    fail 'a customized before.rules copy was incorrectly accepted as stock'
fi
sha256sum --check --quiet "$fixture/native.sha256" || fail 'fixture rejection modified native UFW files'
printf '%s\n' 'PASS: actual UFW vendor hooks accepted, customized copy rejected, and native configuration unchanged.'
