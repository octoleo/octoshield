# Octoshield

Practical Ubuntu laptop protection for conferences and everyday work. An [OctoLeo](https://github.com/octoleo) tool built with **Bash and C**, using Ubuntu's existing firewall, USB authorization, confinement, authentication, and update mechanisms.

Octoshield installs a local `octoshield` command, opens a guided terminal menu, and lets you apply individual protections. Every disruptive system control explains its changes and asks for confirmation. There is no automatic “unharden everything” mode.

**Initial release:** targets Ubuntu 24.04 and 26.04 Desktop with GNOME and systemd. Automated tests exercise isolated fixtures and mocked commands; actual Ubuntu 26 hardware integration has not yet been validated. Complete the [hardware acceptance checklist](docs/testing.md#hardware-acceptance-checklist) on a spare installation before relying on this at an event.

## Install and run

Use a terminal in your **normal, logged-in GNOME session**, on a trusted network. Do not start the whole tool with `sudo`: it requests elevation for system changes and keeps desktop settings and notifications in your user session. Hardening is refused over SSH.

### Current development branch / private repository

With Git and an authenticated GitHub CLI installed:

```bash
gh repo clone octoleo/octoshield
cd octoshield
git switch feat/initial-laptop-hardening
bash src/octoshield install
```

If necessary, install the checkout tools with `sudo apt-get install git gh` and authenticate using `gh auth login`. After this branch is merged, use the repository's `main` branch instead.

### Public one-line installation

Once the implementation is merged into `main` **and the repository is publicly readable**:

```bash
bash <(curl -fsSL "https://raw.githubusercontent.com/octoleo/octoshield/refs/heads/main/src/octoshield")
```

A private repository cannot be installed by this unauthenticated public URL; use the authenticated checkout above. Install `curl` and `ca-certificates` with Ubuntu's package manager if missing. The bootstrap resolves `main` to one commit and downloads all implementation files from that commit. HTTPS and commit consistency do not constitute independent code signing; review the source/commit before granting administrator access. This initial bootstrap has no `--ref` option; install a reviewed branch or commit from a checkout.

The installer compiles the C monitor, stages the application under `/usr/local/lib/octoshield`, and installs `/usr/local/bin/octoshield`. It installs required Ubuntu packages when missing, then immediately opens setup. Choosing a menu item applies that specific control; installation alone does not enable every protection.

Subsequent runs need only:

```bash
octoshield
```

Re-run the checkout installation procedure to update the program. Existing system policy and USB trust are retained; the menu lets you explicitly adjust them. Restart an already running monitor after a program update to load the new executable and scripts:

```bash
sudo systemctl try-restart octoshield-monitor.service
systemctl --user try-restart octoshield-notify.service
```

## What each control does

| Control | Behavior and practical effect |
| --- | --- |
| `firewall` | Prepares/installs UFW while network access is available, then asks you to disconnect before final confirmation. Backs up and **resets existing UFW rules**; enables IPv4/IPv6 filtering, denies unsolicited inbound and forwarded traffic, permits outgoing traffic, and enables low-level logging. UFW is briefly disabled during reset; existing inbound exceptions are removed. |
| `usb` | Enrolls the physically reviewed connected device set with port-bound USBGuard rules. Unknown storage, keyboards, network adapters, and other USB devices remain blocked pending administrator authorization. USBGuard's D-Bus bridge is masked; policy IPC is root-only. |
| `network` | Disables autoconnect for existing Wi-Fi profiles, enables private stable Wi-Fi MAC addresses and randomized scanning, and disables LLMNR/mDNS in existing profiles and defaults. Reconnect manually to apply profile changes. IPv6 remains enabled. |
| `services` | Stops and masks installed SSH services/socket, Avahi, CUPS services/socket/path, Bluetooth daemon, Samba, and system GNOME remote desktop. Printing, Bluetooth input and inbound SSH may stop. Per-user sharing services require separate review. |
| `sudo` | Writes a syntax-checked sudoers drop-in setting `timestamp_timeout=0`. Existing `NOPASSWD` grants or more specific `Defaults` can override authentication. |
| `updates` | Enables daily unattended updates and appends official Ubuntu security/ESM origins while retaining administrator origin policy. Automatic reboot is disabled. This does not prove all pending updates have already installed. |
| `apparmor` | Enables AppArmor and reloads installed profiles in their existing modes. It does not force complain/disabled profiles into enforcement or confine every application. |
| `monitor` | Enables the sandboxed system event collector and installs the separate user notification service. Enable notifications from your user session afterward. |
| Desktop settings | Locks after five idle minutes, locks immediately on blanking, disables media automount/autorun, and disables available per-user GNOME RDP/VNC backends. Missing optional sharing controls are reported. System remote login is handled separately by the services control. |

Network privacy settings do not force newly created Wi-Fi profiles to disable autoconnect. Deselect automatic connection when adding a conference network. MAC-registered office networks may need an explicit per-profile adjustment. LLMNR/mDNS changes affect local discovery and depend on the DNS backend; Avahi is disabled through the services control.

**Docker/container-published ports can bypass UFW's normal host filtering.** Review published ports, bind development services to loopback, and stop unnecessary containers before connecting to an untrusted network. Octoshield does not rewrite Docker's firewall rules. Similarly, review any additional firewall manager, virtual-machine networking, per-user sharing, and application listeners.

## Everyday commands

```bash
octoshield status
octoshield apply firewall
octoshield apply usb
octoshield apply network
octoshield apply services
octoshield desktop apply
octoshield apply sudo
octoshield apply updates
octoshield apply apparmor
octoshield apply monitor
octoshield monitor enable-desktop
```

Run the controls you choose; this list is not an unattended installer. Disruptive controls request confirmation; system actions create private change records. `status` shows service state, listening ports, connection profiles, AppArmor kernel state, Secure Boot information when `mokutil` is present, and storage topology. An active service is not proof of complete protection; verify effective policy and hardware behavior.

```bash
sudo ufw status verbose
sudo aa-status
octoshield usb list
octoshield monitor status
octoshield backups
octoshield recovery
```

`octoshield password` calls the system's normal `passwd` interface for your current user. Octoshield never receives or stores your password. Changing it also changes that account's normal login password; desktop keyring/vault synchronization is outside Octoshield's scope.

## USB approval

Before initial enrollment, remove **all untrusted devices**. Keep required built-in devices, trusted keyboard/mouse, hubs and dock connected. Read the generated rules, physically verify the complete set, and have a recovery method available. The device set is checked again before enabling policy. Existing unmanaged USBGuard installations are left for manual review rather than overwritten. Re-running setup retains the approved rules and never automatically trusts every currently attached device again.

There is no automatic password popup on insertion in this release. A blocked-device notification directs you to the terminal for explicit approval:

```bash
octoshield usb list
read -r -p 'Physically reviewed device ID: ' device_id
octoshield usb allow "$device_id"
```

Temporary approval lasts until reconnection, daemon restart, or another policy change. To persist trust for the reviewed device/port:

```bash
octoshield usb allow "$device_id" --permanent
```

`octoshield usb block "$device_id"` blocks the current device temporarily. It **does not revoke an existing permanent allow rule**; that device may become authorized again on reconnect. Permanent revocation requires reviewing and removing its specific USBGuard rule; see [recovery and adjustments](docs/recovery.md).

USB approval expires sudo's cached authentication timestamp, but cannot override `NOPASSWD` policy or require a password from an already-root process. Device fingerprints/descriptors can be spoofed. Trusted hardware, firmware, physical supervision, and a locked screen remain necessary. Devices may need approval again when moved to another port.

## Security notifications

The Bash collector reads new UFW kernel blocks, recognized sudo/SSH authentication failures, and USBGuard audit decisions. A small C process accepts only fixed event categories and aggregates them; the unprivileged notifier reads root-owned counters and sends GNOME notifications. Users are not added to groups that expose all system logs, and raw device/log text is not sent to notifications.

| Observed event | Alert threshold |
| --- | --- |
| UFW block log entries | 5 within a 60-second aggregation window |
| sudo/SSH failure log entries | 5 within a 60-second aggregation window |
| USBGuard block/reject decision | 1 |

Each category has a five-minute cooldown. These are **log events**, not unique attacks, packets, or password attempts. UFW/journald rate limits can suppress events. Collection starts with new events; it is not a forensic history viewer. The notifier reports unavailable monitoring when the counter heartbeat becomes stale.

USBGuard audit-log retention/rotation remains the distribution or operator's responsibility. Octoshield follows the audit file by name across rotation but installs no rotation policy; daemon reopening after rotation still needs host validation. The collector itself stores only bounded ephemeral counters under `/run/octoshield`.

```bash
octoshield monitor status
sudo journalctl -u octoshield-monitor.service -n 50 --no-pager
journalctl --user -u octoshield-notify.service -n 50 --no-pager
octoshield monitor disable-desktop
```

Disabling desktop notifications does not disable the firewall, USB policy, or system collector. GNOME notification settings, Do Not Disturb, session state, and log availability affect delivery. Blocked probes are not proof of compromise. Passive packet sniffing, every application login failure, and all possible attacks cannot be detected by this monitor.

## Office adjustments and recovery

`octoshield office` can add one TCP firewall exception restricted to an IPv4 subnet, enable autoconnect for one trusted saved connection, or restore a selected service. It keeps other controls in place. For USB, authorize the one device you need. Office subnet rules are address-based, not authentication of the network; remove them before visiting another untrusted network that could use the same address range.

`octoshield desktop restore` restores only the saved GNOME settings from before first apply. System snapshots are private and are not automatically reapplied; see [docs/recovery.md](docs/recovery.md) for targeted recovery, partial failures, and USB lockout instructions.

## Scope and limits

This is preventive host hardening with limited event visibility, not an intrusion-detection guarantee. Disk encryption and Secure Boot are **inspected only**, not configured. USB devices can interact during early boot or before USBGuard starts; Octoshield does not configure an initramfs device policy. It cannot defeat invasive physical attacks, firmware compromise, malicious already-trusted devices, or vulnerabilities in permitted software. Browser/password/SSH vaults reduce credential exposure but do not make the browser or operating system immune to compromise.

Keep the OS and applications patched, lock the screen when leaving the laptop, avoid unfamiliar devices, and use authenticated HTTPS and a trusted VPN where appropriate. Configure enterprise Wi-Fi certificate validation correctly. These practices and firmware settings complement the controls; Octoshield does not configure a VPN, impose a browser policy, or replace backups.

## Development

```bash
sudo apt-get install build-essential bats shellcheck shfmt jq
make check
```

`make check` runs shell syntax/lint/format checks, strict C compilation, Bats tests, and C tests. Additional targets: `make test`, `make lint`, `make format`, and `make sanitize`. See [testing](docs/testing.md), [contribution guidelines](CONTRIBUTING.md), and [security reporting](SECURITY.md).

Native interfaces: [NetworkManager configuration](https://networkmanager.dev/docs/api/latest/NetworkManager.conf.html), [nmcli](https://networkmanager.dev/docs/api/latest/nmcli.html), [Ubuntu automatic updates](https://ubuntu.com/server/docs/how-to/software/automatic-updates/), and [USBGuard documentation](https://usbguard.github.io/documentation/).

Licensed under [Apache-2.0](LICENSE).
