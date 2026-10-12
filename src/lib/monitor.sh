#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

# Trusted journal fields are assigned by journald. SYSLOG_IDENTIFIER and MESSAGE
# alone are not provenance: any local process can submit either one.
monitor::journal_filter() {
    jq --unbuffered -r '
      select(type == "object" and (.MESSAGE | type == "string")) |
      if ._TRANSPORT == "kernel" and (.MESSAGE | startswith("[UFW BLOCK]")) then "firewall"
      elif (._EXE == "/usr/bin/sudo" or ._EXE == "/usr/bin/sudo-rs" or
            ._EXE == "/usr/bin/sudo.ws") and
           (.MESSAGE | test("authentication failure|[0-9]+ incorrect (password|authentication) attempt"; "i")) then "auth"
      elif (._SYSTEMD_UNIT == "ssh.service" or ._SYSTEMD_UNIT == "sshd.service") and
           (._EXE == "/usr/sbin/sshd" or ._EXE == "/usr/lib/openssh/sshd-session" or
            ._EXE == "/usr/libexec/openssh/sshd-session") and
           (.MESSAGE | test("^Failed (password|publickey|keyboard-interactive)|^error: PAM: Authentication failure"))
           then "auth"
      else empty end'
}

monitor::journal_feed() {
    journalctl --follow --lines=0 --no-pager --output=json \
        --output-fields=MESSAGE,_TRANSPORT,_EXE,_SYSTEMD_UNIT \
        _TRANSPORT=kernel + _EXE=/usr/bin/sudo + _EXE=/usr/bin/sudo-rs + _EXE=/usr/bin/sudo.ws + \
        _SYSTEMD_UNIT=ssh.service + _SYSTEMD_UNIT=sshd.service |
        monitor::journal_filter
}

# USBGuard FileAudit emits its sorted, fixed result/target/type keys at the end
# of each record. Match that suffix so an injected device name cannot masquerade
# as a successful policy decision. Do not pass any raw device text downstream.
monitor::usb_filter() {
    local line update insert
    update=" result='SUCCESS' target.new='(block|reject)' target.old='[a-z]+' type='Policy.Device.Update' *$"
    insert=" result='SUCCESS' target='(block|reject)' type='Policy.Device.[A-Za-z]+' *$"
    while IFS= read -r line; do
        if [[ $line =~ $update || $line =~ $insert ]]; then printf 'usb\n'; fi
    done
}

monitor::usb_feed() {
    local directory=/var/log/usbguard file=/var/log/usbguard/usbguard-audit.log metadata
    # USB protection can be enabled after monitoring. Wait for its audit file.
    while [[ ! -f $file ]]; do sleep 5; done
    [[ ! -L $directory && ! -L $file ]] || return 1
    metadata=$(stat -c '%u:%a' -- "$directory") || return 1
    [[ $metadata == 0:700 ]] || return 1
    metadata=$(stat -c '%u' -- "$file") || return 1
    [[ $metadata == 0 ]] || return 1
    tail --lines=0 --follow=name --retry -- "$file" | monitor::usb_filter
}

monitor::run() {
    local consumer_pid journal_pid usb_pid fifo=/run/octoshield/feed
    core::require_root || return 1
    # This internal command must run under the sandboxed service, which supplies
    # the runtime directory and owns every descendant of the feed pipeline.
    [[ ${INVOCATION_ID:-} && ${RUNTIME_DIRECTORY:-} == /run/octoshield ]] || {
        core::die 'Use systemctl start octoshield-monitor.service to run the monitor.'
        return 1
    }
    set -o pipefail
    [[ ! -L /run/octoshield && $(stat -c '%u:%a' /run/octoshield) == 0:755 ]] || return 1
    rm -f -- "$fifo" || return 1
    mkfifo -m 0600 -- "$fifo" || return 1
    "$OCTOSHIELD_ROOT/bin/octoshield-monitor" --output-dir /run/octoshield <"$fifo" &
    consumer_pid=$!
    monitor::journal_feed >"$fifo" &
    journal_pid=$!
    monitor::usb_feed >"$fifo" &
    usb_pid=$!
    # Any failed member ends the service. systemd kills remaining descendants
    # before restarting, including children of the two producer pipelines.
    wait -n "$consumer_pid" "$journal_pid" "$usb_pid" || :
    kill "$consumer_pid" "$journal_pid" "$usb_pid" 2>/dev/null || :
    return 1
}

monitor::apply() {
    core::require_root || return 1
    core::confirm 'Enable the background security-event collector and install the desktop notification unit? It reads firewall, sudo/SSH and USBGuard audit events and exposes only alert counters to desktop users. You will enable notifications separately in your own desktop session.' || return 1
    [[ -x $OCTOSHIELD_ROOT/bin/octoshield-monitor ]] || {
        core::die 'The compiled monitor is missing; reinstall Octoshield.'
        return 1
    }
    core::install_packages jq libnotify-bin || return 1
    core::write_file /etc/systemd/system/octoshield-monitor.service 0644 \
        <"$OCTOSHIELD_ROOT/systemd/octoshield-monitor.service" || return 1
    core::write_file /etc/systemd/user/octoshield-notify.service 0644 \
        <"$OCTOSHIELD_ROOT/systemd/octoshield-notify.service" || return 1
    systemctl daemon-reload || return 1
    systemctl enable --now octoshield-monitor.service || return 1
    core::record 'MONITOR enabled'
    core::log 'System monitoring enabled. In your desktop terminal run: octoshield monitor enable-desktop'
}

monitor::enable_desktop() {
    [[ $EUID -ne 0 ]] || {
        core::die 'Run this from your normal GNOME terminal without sudo.'
        return 1
    }
    systemctl --user daemon-reload || return 1
    systemctl --user enable --now octoshield-notify.service
}

monitor::disable_desktop() {
    [[ $EUID -ne 0 ]] || {
        core::die 'Run this as your desktop user without sudo.'
        return 1
    }
    systemctl --user disable --now octoshield-notify.service
}

monitor::status() {
    systemctl --no-pager --full status octoshield-monitor.service || :
    if [[ $EUID -ne 0 ]]; then systemctl --user --no-pager --full status octoshield-notify.service || :; fi
}
