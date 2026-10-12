# Recovery and narrow adjustments

Use a local terminal. If network hardening fails, disconnect Wi-Fi/Ethernet and inspect the failure before reconnecting. A failed operation can leave partial changes: Octoshield returns failure and keeps the change record; it does not promise an automatic system-wide rollback. Installation stages the application separately and attempts to retain the previous installed program when publishing fails.

## Find the relevant system snapshot

```bash
octoshield backups
```

System transactions are stored under `/var/lib/octoshield/backups/DATE-PID/` with root-only access. The actual identifier is printed after each operation. Each transaction contains:

| Path within the transaction | Meaning |
| --- | --- |
| `actions.log` | Actions, failures, and original service states when recorded |
| `original/etc/...` | Copies of files/directories that existed before the first change in this transaction |
| `saved/etc/...` | Marker containing `existing` or `absent` for each backed-up path |

For example, a backup of `/etc/default/ufw` is `original/etc/default/ufw`; its marker is `saved/etc/default/ufw`. Restoring an `absent` path means removing only the new file after reviewing it. Do not copy marker files into `/etc`.

Open a root shell and select a real transaction interactively:

```bash
sudo -i
ls -1 /var/lib/octoshield/backups
read -r -p 'Transaction ID to inspect: ' snapshot_id
if [[ ! $snapshot_id =~ ^[0-9]{8}T[0-9]{6}Z-[0-9]+$ ]] ||
   [[ ! -d /var/lib/octoshield/backups/$snapshot_id ]]; then
    printf 'No matching transaction.\n' >&2
    exit 1
fi
snapshot="/var/lib/octoshield/backups/$snapshot_id"
cat "$snapshot/actions.log"
find "$snapshot/saved" -type f -print
```

The following system restore examples assume that root shell and selected `snapshot`. Choose a transaction containing the relevant original file. Keep the current file if you need to compare changes. NetworkManager backups contain connection secrets; keep them private and do not attach them to public issues.

## Firewall

The conference action resets UFW exceptions. If it fails during reset/configuration, UFW may be disabled; remain disconnected until `ufw status verbose` confirms your intended policy.

Prefer re-running `octoshield apply firewall` from your normal terminal when you want the conference policy. To deliberately restore an earlier UFW policy from a relevant snapshot, while disconnected:

```bash
test -d "$snapshot/original/etc/ufw" &&
test -f "$snapshot/original/etc/default/ufw" &&
cp -a -- "$snapshot/original/etc/ufw/." /etc/ufw/ &&
cp -a -- "$snapshot/original/etc/default/ufw" /etc/default/ufw &&
ufw --force enable &&
ufw status verbose
```

This restores the saved rules and **enables** them; it does not restore a previous disabled runtime state. Review the restored inbound exceptions and IPv6 setting. Container-published ports still require separate checks.

For an office exception, use `octoshield office`. Before returning to an untrusted network, review `sudo ufw status numbered` and remove only the office exception with `sudo ufw delete NUMBER`, using its current displayed number. Re-running the conference firewall action removes all custom UFW exceptions after confirmation.

## Network profiles

For one trusted office connection, use `octoshield office` to re-enable autoconnect. To choose a different Wi-Fi MAC policy, inspect profiles and edit the exact UUID with NetworkManager's connection editor; reconnect after applying it.

Full profile recovery is sensitive: saved directories can contain passwords and certificates, and some profiles originate in Netplan or another backend. Compare the saved `/etc/NetworkManager/system-connections` and `/run/NetworkManager/system-connections` directories with the current state, restore only the affected profile files with their original ownership/modes, then run:

```bash
nmcli connection reload
nmcli general reload conf
```

Restore or remove `/etc/NetworkManager/conf.d/90-octoshield.conf` according to its snapshot marker if you want to change the default policy. Reconnect manually. File restoration alone does not update an already active connection, and backend-managed profiles may require editing their originating configuration.

## USB enrollment interrupted

During first enrollment, Octoshield temporarily masks `usbguard.service` and persistently masks `usbguard-dbus.service`. Until a reviewed policy starts successfully, USB protection is **not active**. Its private progress markers are under `/var/lib/octoshield/usb/`.

After resolving the package or policy error, remove untrusted devices and resume from your normal terminal:

```bash
octoshield apply usb
```

An enrolled installation reuses its existing approved rules. Do not delete its enrollment marker to “fix” an error: doing so could lead to unintended re-enrollment. The D-Bus bridge stays masked intentionally; Octoshield uses root-only policy IPC. Existing unmanaged USBGuard installations require manual integration and are not overwritten.

## USB input lockout

First try a trusted built-in keyboard or the previously approved device on its original port. If you cannot log in, use the machine's recovery console. At the GRUB editor, temporarily append this to the Linux kernel command line for one boot:

```text
systemd.mask=usbguard.service
```

This disables USBGuard for that boot, so disconnect all unfamiliar peripherals and retain physical control. A firmware/boot password or device policy may require your established recovery method instead. From a trusted recovery login, inspect:

```bash
sudo journalctl -u usbguard.service --no-pager
sudo cat /etc/usbguard/rules.conf
sudo ls -l /var/lib/octoshield/usb
```

Repair the specific rule/configuration, or restore the relevant saved `/etc/usbguard/rules.conf` and `/etc/usbguard/usbguard-daemon.conf` with their original root ownership and private modes. Remove the temporary boot argument and reboot normally. Check `sudo systemctl is-active usbguard.service` and `octoshield usb list` before relying on protection. Merely stopping USBGuard can leave already-blocked devices unauthorized; reconnect/reboot through the trusted recovery path when necessary.

To revoke permanent trust, first inspect both current devices and persisted policy:

```bash
octoshield usb list
sudo usbguard list-rules
```

Record a private copy of `/etc/usbguard/rules.conf`, then remove only the reviewed allow rule with `sudo usbguard remove-rule RULE_ID`. A rule ID differs from a device ID. Block the currently attached device using `octoshield usb block DEVICE_ID`, then test reconnecting it. Temporary device blocking alone does not remove persistent trust. Do not remove keyboard/controller/hub rules indiscriminately.

## Services

Read `service-before:` entries in the transaction's `actions.log`. The service action masks installed services and sockets; restoring one unit may also require unmasking its activation sockets/path. `octoshield office` handles the paired units for SSH, Avahi, Bluetooth, or CUPS and starts the selected service. Firewall exceptions remain separate.

For other units such as Samba, inspect the recorded state and unmask only the required exact unit with `systemctl unmask UNIT`. Start/enable it only if that matches your chosen policy. A saved `/etc/systemd/system/UNIT` override should be restored before `systemctl daemon-reload`. Do not enable every masked service or overwrite unrelated systemd configuration.

## Sudo, updates, and AppArmor

From an existing trusted administrator shell, restore the saved `/etc/sudoers.d/99-octoshield` if its marker says `existing`; remove that one drop-in if the marker says `absent` and you intentionally want the previous timeout. Validate with `visudo --check` before closing your administrator shell. Octoshield does not remove existing passwordless grants.

Automatic-update settings live in `/etc/apt/apt.conf.d/90-octoshield`. Restore/remove only this drop-in according to its snapshot marker, then inspect `apt-config dump`. Timer enablement is separate runtime state; review the timers before changing them. AppArmor activation retains installed profile modes; diagnose a specific denied application using its logs instead of disabling AppArmor globally.

## Desktop and notifications

Run these as your normal GNOME user, **without sudo**:

```bash
octoshield desktop status
octoshield desktop restore
octoshield monitor status
octoshield monitor disable-desktop
```

The desktop baseline is a private, validated data file at `${XDG_STATE_HOME:-$HOME/.local/state}/octoshield/desktop.tsv`. Restore returns the seven core GNOME settings and any recorded, still-available RDP/VNC controls to their original values and retains the baseline. First-seen optional controls are backed up before they change. It does not change USBGuard or UFW.

For monitor problems, inspect system and user journals before restarting:

```bash
sudo journalctl -u octoshield-monitor.service -n 50 --no-pager
journalctl --user -u octoshield-notify.service -n 50 --no-pager
sudo systemctl restart octoshield-monitor.service
systemctl --user restart octoshield-notify.service
```

These services affect monitoring and notification delivery only. Root-owned alert counters under `/run/octoshield` are ephemeral, not backups or a forensic event archive.
