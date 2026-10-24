#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Real NetworkManager/keyfile integration, never the host's network namespace.
set -Eeuo pipefail

if [[ ${1-} != --isolated ]]; then
    [[ $EUID == 0 ]] || {
        echo 'Run as root in a disposable integration runner.' >&2
        exit 1
    }
    for program in unshare mount dbus-daemon NetworkManager nmcli ip jq timeout; do command -v "$program" >/dev/null; done
    root=$(cd -- "$(dirname -- "$0")/.." && pwd)
    temporary=$(mktemp -d)
    trap 'rm -rf -- "$temporary"' EXIT
    unshare --mount --net --pid --fork --mount-proc bash "$0" --isolated "$root" "$temporary" "$(readlink /proc/self/ns/net)"
    exit
fi

root=$2 temporary=$3 original_namespace=$4
[[ $(readlink /proc/self/ns/net) != "$original_namespace" ]] || {
    echo 'Refusing to use the host network namespace.' >&2
    exit 1
}
mount --make-rprivate /
for directory in /etc/NetworkManager /run/NetworkManager /var/lib/NetworkManager /run/dbus; do
    mkdir -p "$directory"
    mount -t tmpfs tmpfs "$directory"
done
# Hide vendor connection profiles as well, including any runner configuration.
mkdir -p /usr/lib/NetworkManager/system-connections
mount -t tmpfs tmpfs /usr/lib/NetworkManager/system-connections
mkdir -p /etc/NetworkManager/system-connections /etc/NetworkManager/conf.d
cat >/etc/NetworkManager/NetworkManager.conf <<'CONFIG'
[main]
plugins=keyfile
no-auto-default=*
dns=none
[device]
match-device=*
managed=1
CONFIG
export DBUS_SYSTEM_BUS_ADDRESS=unix:path=/run/dbus/system_bus_socket
bus_pid=$(dbus-daemon --system --fork --print-pid)
NetworkManager --no-daemon >"$temporary/NetworkManager.log" 2>&1 &
nm_pid=$!
cleanup() {
    result=$?
    if ((result)); then cat "$temporary/NetworkManager.log" >&2; fi
    if declare -F core::end >/dev/null; then core::end; fi
    kill "$nm_pid" "$bus_pid" 2>/dev/null || :
    wait "$nm_pid" 2>/dev/null || :
}
trap cleanup EXIT
for _attempt in {1..100}; do
    if nmcli general status >/dev/null 2>&1; then break; fi
    sleep 0.1
done
nmcli general status
nmcli --version
NetworkManager --version
ip link add octotest0 type dummy
ip link add octotest1 type dummy
nmcli connection add type ethernet ifname octotest0 con-name OctoShield-integration-a connection.autoconnect no ipv4.method disabled ipv6.method disabled
nmcli connection add type ethernet ifname octotest1 con-name OctoShield-integration-b connection.autoconnect no ipv4.method disabled ipv6.method disabled
first=$(nmcli -g connection.uuid connection show OctoShield-integration-a)
second=$(nmcli -g connection.uuid connection show OctoShield-integration-b)

# Load the production backend; only consent is automated for this isolated test.
# No native command, filesystem adapter, or state verification is substituted.
for module in core controls profiles profile_controls office status connections; do
    # shellcheck source=/dev/null
    source "$root/src/lib/$module.sh"
done
CORE_STATE="$temporary/state"
core::begin 'Real NetworkManager integration'
core::confirm() { printf 'Integration consent: %s\n' "$*"; }

connections::set "$first" autoconnect true
[[ $(nmcli -g connection.autoconnect connection show uuid "$first") == yes ]]
nmcli connection reload
[[ $(nmcli -g connection.autoconnect connection show uuid "$first") == yes ]]
printf 'PASS: actual saved autoconnect survives NetworkManager reload\n'

nmcli connection modify uuid "$second" connection.mdns 2
connections::set "$first" autoconnect false
[[ $(nmcli -g connection.autoconnect connection show uuid "$first") == no ]]
[[ $(nmcli -g connection.mdns connection show uuid "$second") == 2* ]]
if profile_controls::conflict network; then
    echo 'Unrelated external change was silently accepted.' >&2
    exit 1
fi
before=$(profile_controls::_read network)
if profile_controls::restore network; then
    echo 'Unreviewed restore succeeded.' >&2
    exit 1
fi
[[ $(profile_controls::_read network) == "$before" ]]
printf 'PASS: focused save preserves external change; rejected restore preserves tracking\n'

connections::reconcile
profile_controls::conflict network
connections::set "$first" discovery false
[[ $(nmcli -g connection.llmnr connection show uuid "$first") == 0* ]]
[[ $(nmcli -g connection.mdns connection show uuid "$first") == 0* ]]
profiles::restore network
[[ ! -e $CORE_STATE/profiles/controls/network.json ]]
[[ $(nmcli -g connection.autoconnect connection show uuid "$first") == no ]]
nmcli connection reload
[[ $(nmcli -g connection.mdns connection show uuid "$second") == -1* ]]
printf 'PASS: reviewed reconciliation and standalone baseline restore use real NetworkManager profiles\n'

# A saved Wi-Fi profile is real NetworkManager state even without a radio in CI.
# Verify Wi-Fi-specific fields and persistence; do not claim radio association.
nmcli connection add type wifi ifname octowifi0 con-name OctoShield-integration-wifi ssid OctoShield-integration connection.autoconnect no
wifi=$(nmcli -g connection.uuid connection show OctoShield-integration-wifi)
connections::set "$wifi" autoconnect true
connections::set "$wifi" mac stable
connections::set "$wifi" discovery false
nmcli connection reload
[[ $(nmcli -g connection.autoconnect connection show uuid "$wifi") == yes ]]
[[ $(nmcli -g 802-11-wireless.cloned-mac-address connection show uuid "$wifi") == stable ]]
[[ $(nmcli -g connection.mdns connection show uuid "$wifi") == 0* ]]
profiles::restore network
nmcli connection reload
[[ $(nmcli -g connection.autoconnect connection show uuid "$wifi") == no ]]
printf 'PASS: actual saved Wi-Fi autoconnect, MAC and discovery settings persist and restore; radio association is not tested\n'
