#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
temp=$(mktemp -d)
trap 'rm -rf -- "$temp"' EXIT
cc -std=c11 -Wall -Wextra -Werror -pedantic -O2 "$repo/tests/monitor.c" -o "$temp/test-monitor"
cc -std=c11 -Wall -Wextra -Werror -pedantic -O2 "$repo/src/monitor.c" -o "$temp/monitor"
"$temp/test-monitor"
# shellcheck source=src/lib/monitor.sh
source "$repo/src/lib/monitor.sh"
# shellcheck source=src/notify.sh
source "$repo/src/notify.sh"

actual=$(
    monitor::journal_filter <<'JSON'
{"_TRANSPORT":"kernel","MESSAGE":"[UFW BLOCK] IN=wlan0"}
{"SYSLOG_IDENTIFIER":"kernel","MESSAGE":"[UFW BLOCK] IN=wlan0"}
{"_TRANSPORT":"syslog","_COMM":"kernel","MESSAGE":"[UFW BLOCK] IN=wlan0"}
{"_TRANSPORT":"kernel","MESSAGE":[1,2,3]}
{"_TRANSPORT":"kernel","MESSAGE":null}
{"_EXE":"/usr/bin/sudo","MESSAGE":"pam_unix(sudo:auth): authentication failure;"}
{"_EXE":"/usr/bin/sudo-rs","MESSAGE":"sudo: maximum 3 incorrect authentication attempts"}
{"_COMM":"sudo","MESSAGE":"pam_unix(sudo:auth): authentication failure;"}
{"_EXE":"/tmp/sudo","MESSAGE":"pam_unix(sudo:auth): authentication failure;"}
{"_SYSTEMD_UNIT":"ssh.service","_EXE":"/usr/sbin/sshd","MESSAGE":"Failed password for invalid user guest"}
{"_SYSTEMD_UNIT":"user@1000.service","_EXE":"/usr/sbin/sshd","MESSAGE":"Failed password for invalid user guest"}
{"_SYSTEMD_UNIT":"ssh.service","_EXE":"/usr/sbin/sshd","MESSAGE":"Accepted password for user"}
{"_TRANSPORT":["kernel","syslog"],"MESSAGE":"[UFW BLOCK]"}
JSON
)
[[ $actual == $'firewall\nauth\nauth\nauth' ]]

actual=$(
    monitor::usb_filter <<'AUDIT'
[Audit] uid=0 pid=123 device.rule='block id abcd:1234' device.system_name='1-1' result='SUCCESS' target.new='block' target.old='allow' type='Policy.Device.Update' 
[Audit] uid=0 pid=123 device.rule='reject id abcd:1234' device.system_name='1-1' result='SUCCESS' target='reject' type='Policy.Device.Insert' 
[Audit] uid=0 pid=123 device.rule='bad name' result='FAILURE' target.new='block' target.old='allow' type='Policy.Device.Update' 
[Audit] uid=0 pid=123 device.rule="result='SUCCESS' target.new='block' target.old='allow' type='Policy.Device.Update' " result='SUCCESS' target.new='allow' target.old='block' type='Policy.Device.Update' 
AUDIT
)
[[ $actual == $'usb\nusb' ]]

# Notifications are fixed text and only change when an alert counter advances.
notify::message() { printf '%s\n' "$1"; }
[[ -z $(notify::changes 'v1 1-2-3 1 0 0' 'v1 1-2-3 1 0 0') ]]
[[ -z $(notify::changes 'v1 1-2-3 1 0 0' 'v1 2-3-4 0 0 0') ]]
[[ $(notify::changes 'v1 1-2-3 0 1 0' 'v1 2-3-4 0 1 0') == 'USB device blocked' ]]
[[ $(notify::changes 'v1 1-2-3 0 0 0' 'v1 1-2-3 1 1 1') == $'Repeated firewall blocks\nUSB device blocked\nRepeated authentication failures' ]]

# End-to-end C stream -> bounded state. EOF intentionally exits nonzero.
mkdir "$temp/state"
printf 'usb\nauth\nauth\nauth\nauth\nauth\n' | "$temp/monitor" --output-dir "$temp/state" 2>/dev/null && exit 1
[[ $(cat "$temp/state/events") =~ ^v1\ [0-9]+-[0-9]+-[0-9]+\ 0\ 1\ 1$ ]]
[[ $(stat -c '%a' "$temp/state/events") == 644 ]]
chmod 0777 "$temp/state"
if "$temp/monitor" --output-dir "$temp/state" </dev/null 2>/dev/null; then exit 1; fi
chmod 0700 "$temp/state"
ln -s "$temp/state" "$temp/link"
if "$temp/monitor" --output-dir "$temp/link" </dev/null 2>/dev/null; then exit 1; fi
printf 'monitor integration tests passed\n'
