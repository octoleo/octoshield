# OctoShield

Ubuntu laptop protection for conferences and everyday work, with a **native GNOME application and a standalone terminal interface**. Part of the [OctoLeo](https://github.com/octoleo) suite, OctoShield uses Bash and C to configure Ubuntu's established firewall, USB authorization, confinement, authentication, and update mechanisms.

The GTK4/libadwaita desktop application and Whiptail CLI use the same security controls. Choose a protection, review its impact, authenticate when required, and inspect the result. Settings remain in place when you close the application. Office adjustments grant specific access; there is no automatic “unharden everything” mode.

**Supported targets:** Ubuntu 24.04 and 26.04 with systemd; desktop features require a normal GNOME session. Container/unit tests and a graphical smoke test do not establish live hardware protection. Complete the [hardware acceptance checklist](docs/testing.md#hardware-acceptance-checklist) on a spare installation before relying on this at an event.

## Choose your installation

| Distribution | What you get | Requirements on the laptop |
| --- | --- | --- |
| Downloadable `.deb` | Native OctoShield application/icon, `octoshield` CLI, precompiled monitor, and privilege helper | Matching Ubuntu release and architecture; APT resolves runtime dependencies. No compiler is required. |
| Standalone CLI | `octoshield` terminal menus and the same system controls | Bash, local systemd terminal, and compiler/build dependencies installed by the bootstrap. No GTK/libadwaita or GNOME desktop dependencies are installed. |

### Desktop application and CLI: install the package

The repository is private. Sign in to GitHub with access to [octoleo/octoshield](https://github.com/octoleo/octoshield). During pull-request review, open the successful **Test lint and package** run for `feat/desktop-debian-package` in [Actions](https://github.com/octoleo/octoshield/actions), download the matching artifact below, and extract its ZIP. Pushing a reviewed `v*` version tag triggers release builds under [Releases](https://github.com/octoleo/octoshield/releases); a branch artifact is a review build, not a published release.

| Ubuntu / architecture | Actions artifact | Package install command for version 0.2.0 |
| --- | --- | --- |
| Ubuntu 24.04 / amd64 | `octoshield-ubuntu-24.04-amd64` | `sudo apt install ./octoshield_0.2.0_ubuntu24.04_amd64.deb` |
| Ubuntu 26.04 / amd64 | `octoshield-ubuntu-26.04-amd64` | `sudo apt install ./octoshield_0.2.0_ubuntu26.04_amd64.deb` |

Choose the package matching **both your Ubuntu release and CPU architecture**:

```bash
sed -n 's/^VERSION_ID=/Ubuntu version: /p' /etc/os-release
dpkg --print-architecture
```

Do not install a package built for Ubuntu 26.04 on Ubuntu 24.04 or use an `amd64` package on an `arm64` laptop. The automated package matrix currently provides amd64 builds; other architectures require a matching [source build](docs/packaging.md). Verify the artifact or release with its matching checksum file, for example `sha256sum -c SHA256SUMS-ubuntu24.04`. A checksum detects transfer changes but is not independent publisher authentication.

Use the matching command above, or this interactive command for the actual downloaded filename. APT resolves runtime dependencies:

```bash
read -e -r -p 'Path to the downloaded OctoShield .deb: ' package_file
if [[ -f $package_file && $package_file == *.deb ]]; then
    sudo apt install "$(realpath -- "$package_file")"
else
    printf 'Choose an existing .deb file.\n' >&2
fi
```

Open **OctoShield** from GNOME's application launcher, or run `octoshield-gtk`. No reboot is required to open the application. Run it as your normal desktop user; individual system operations show the standard administrator authentication dialog. Package installation does not apply hardening, enroll USB devices, or enable monitoring automatically. Open the application and choose the controls you want.

The package also installs `/usr/bin/octoshield`:

```bash
octoshield
```

If you previously installed the standalone version, `/usr/local/bin/octoshield` may take precedence in your shell. The package leaves that installation intact and reports it. Use **`/usr/bin/octoshield`** to select the packaged CLI explicitly; the app always uses the packaged helper. See [migration and removal](docs/recovery.md#package-upgrades-coexistence-and-removal).

### Standalone CLI: authenticated checkout

For CLI-only use, install from a reviewed checkout. With Git and an authenticated GitHub CLI available:

```bash
gh repo clone octoleo/octoshield
cd octoshield
git switch feat/desktop-debian-package
bash src/octoshield install
```

If needed, install checkout tools with `sudo apt-get install git gh` and authenticate with `gh auth login`. After the branch is merged, use `main` instead. The standalone installer compiles only the C monitor, installs `/usr/local/bin/octoshield` and `/usr/local/lib/octoshield`, and immediately opens guided terminal setup. It does not install the graphical application or its libraries. On a machine without GNOME, system controls remain usable and GNOME-only actions report the missing session.

Run from a **normal local terminal**, without prefixing the entire tool with `sudo`. System changes request elevation; user settings remain in your session. Hardening is refused over SSH. Subsequent runs need only `octoshield`.

The original public bootstrap command remains the CLI-only entry point:

```bash
bash <(curl -fsSL "https://raw.githubusercontent.com/octoleo/octoshield/refs/heads/main/src/octoshield")
```

This unauthenticated URL does **not** work while the repository is private. It also reads `main`, so it cannot install unmerged branch changes. Repository visibility is not changed by this project. Use the authenticated checkout until the relevant code is merged and the URL is accessible to you. The bootstrap resolves `main` once and downloads every implementation file from that immutable commit; this provides consistency, not independent code signing. There is no `--ref` switch: use a reviewed checkout for a different branch or commit.

Re-run the same standalone installation procedure to update its program files. System policy and trusted-device rules remain in place. See [recovery](docs/recovery.md) before switching between standalone and package installations.

## Desktop workflow

Open OctoShield and use its sidebar:

| Page | Actions |
| --- | --- |
| Overview | Inspect system state, listening services, and protection details. |
| Protections | Apply individual system controls; apply/restore GNOME settings; open the system account settings to change your password. |
| USB devices | List device state, review a numeric device ID, allow it temporarily/permanently, or block the current attachment. |
| Office access | Grant one subnet-restricted TCP exception, enable one connection's autoconnect, or restore a supported service. |
| Monitoring | Enable/disable collection, inspect status/logs, and control this user's notifications. |
| Recovery | Read recovery guidance, list backup transactions, and inspect their action history. |

The GUI is a native application, not a terminal embedded in a window. A fixed privileged helper executes the same Bash control functions used by the CLI. It presents plain-text results and explicit confirmation requests; raw output cannot become shell commands. Detailed output appears at operation boundaries, so package installation can remain busy without displaying every line immediately. USB enrollment presents the generated device policy before asking you to trust it. Leave the window open until an operation finishes; you can decline a pending confirmation without applying its next step.

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
| `monitor` | Enables the sandboxed system event collector. Enable the separate notification service from your user session afterward. |
| Desktop settings | Locks after five idle minutes, locks immediately on blanking, disables media automount/autorun, and disables available per-user GNOME RDP/VNC backends. Missing optional sharing controls are reported. System remote login is handled separately by the services control. |

Network privacy settings do not force newly created Wi-Fi profiles to disable autoconnect. Deselect automatic connection when adding a conference network. MAC-registered office networks may need an explicit per-profile adjustment. LLMNR/mDNS changes affect local discovery and depend on the DNS backend; Avahi is disabled through the services control.

**Docker/container-published ports can bypass UFW's normal host filtering.** Review published ports, bind development services to loopback, and stop unnecessary containers before connecting to an untrusted network. OctoShield does not rewrite Docker's firewall rules. Similarly, review any additional firewall manager, virtual-machine networking, per-user sharing, and application listeners.

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

`octoshield password` calls the system's normal `passwd` interface for your current user. The graphical password action opens GNOME Accounts; it does not create a separate OctoShield password. OctoShield never receives or stores your password. Changing it also changes that account's normal login password; desktop keyring/vault synchronization is outside OctoShield's scope.

## USB approval

Before initial enrollment, remove **all untrusted devices**. Keep required built-in devices, trusted keyboard/mouse, hubs and dock connected. Read the generated rules, physically verify the complete set, and have a recovery method available. The device set is checked again before enabling policy. Existing unmanaged USBGuard installations are left for manual review rather than overwritten. Re-running setup retains the approved rules and never automatically trusts every currently attached device again.

There is no automatic approval popup on insertion. Open the application's **USB devices** page to review and approve a device, or use the CLI:

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

CLI USB approval expires sudo's cached authentication timestamp. The GUI requests administrator authentication through PolicyKit for its fixed helper. Local authentication policy still applies: `NOPASSWD`, custom PolicyKit rules, or existing root access cannot be neutralized by a prompt in this tool. Device fingerprints/descriptors can be spoofed. Trusted hardware, firmware, physical supervision, and a locked screen remain necessary. Devices may need approval again when moved to another port.

## Security notifications

The Bash collector reads new UFW kernel blocks, recognized sudo/SSH authentication failures, and USBGuard audit decisions. A small C process accepts only fixed event categories and aggregates them; the unprivileged notifier reads root-owned counters and sends GNOME notifications. Users are not added to groups that expose all system logs, and raw device/log text is not sent to notifications.

Desktop notifications are optional for the standalone CLI. On a GNOME system, install `libnotify-bin` if `notify-send` is missing, then enable notifications for your user. The `.deb` includes it as a runtime dependency. The collector itself does not require desktop libraries.

| Observed event | Alert threshold |
| --- | --- |
| UFW block log entries | 5 within a 60-second aggregation window |
| sudo/SSH failure log entries | 5 within a 60-second aggregation window |
| USBGuard block/reject decision | 1 |

Each category has a five-minute cooldown. These are **log events**, not unique attacks, packets, or password attempts. UFW/journald rate limits can suppress events. Collection starts with new events; it is not a forensic history viewer. The notifier reports unavailable monitoring when the counter heartbeat becomes stale.

USBGuard audit-log retention/rotation remains the distribution or operator's responsibility. OctoShield follows the audit file by name across rotation but installs no rotation policy; daemon reopening after rotation still needs host validation. The collector itself stores only bounded ephemeral counters under `/run/octoshield`.

```bash
octoshield monitor status
octoshield monitor logs
sudo journalctl -u octoshield-monitor.service -n 50 --no-pager
journalctl --user -u octoshield-notify.service -n 50 --no-pager
octoshield monitor disable-desktop
```

Disabling desktop notifications does not disable the firewall, USB policy, or system collector. `octoshield monitor disable` stops the collector after confirmation while retaining preventive policies; `octoshield apply monitor` enables it again. GNOME notification settings, Do Not Disturb, session state, and log availability affect delivery. Blocked probes are not proof of compromise. Passive packet sniffing, every application login failure, and all possible attacks cannot be detected by this monitor.

## Office adjustments and recovery

`octoshield office` can add one TCP firewall exception restricted to an IPv4 subnet, enable autoconnect for one trusted saved connection, or restore a selected service. It keeps other controls in place. For USB, authorize the one device you need. Office subnet rules are address-based, not authentication of the network; remove them before visiting another untrusted network that could use the same address range.

`octoshield desktop restore` restores only the saved GNOME settings from before first apply. System snapshots are private and are not automatically reapplied; see [docs/recovery.md](docs/recovery.md) for targeted recovery, partial failures, and USB lockout instructions.

## Scope and limits

This is preventive host hardening with limited event visibility, not an intrusion-detection guarantee. Disk encryption and Secure Boot are **inspected only**, not configured. USB devices can interact during early boot or before USBGuard starts; OctoShield does not configure an initramfs device policy. It cannot defeat invasive physical attacks, firmware compromise, malicious already-trusted devices, or vulnerabilities in permitted software. Browser/password/SSH vaults reduce credential exposure but do not make the browser or operating system immune to compromise.

Keep the OS and applications patched, lock the screen when leaving the laptop, avoid unfamiliar devices, and use authenticated HTTPS and a trusted VPN where appropriate. Configure enterprise Wi-Fi certificate validation correctly. These practices and firmware settings complement the controls; OctoShield does not configure a VPN, impose a browser policy, or replace backups.

## Development

```bash
sudo apt-get install build-essential bats shellcheck shfmt jq
make check
```

`make check` runs the CLI/backend lint, build, and isolated tests without requiring GUI development libraries. To build and test the desktop application:

```bash
sudo apt-get install pkg-config libgtk-4-dev libadwaita-1-dev libjson-glib-dev
make gui
make ui-test
```

`make package` builds the `.deb` after Debian build dependencies are installed. Other targets include `make test`, `make lint`, `make format`, and `make sanitize`. See [testing](docs/testing.md), [packaging](docs/packaging.md), [contribution guidelines](CONTRIBUTING.md), and [security reporting](SECURITY.md).

Native interfaces: [NetworkManager configuration](https://networkmanager.dev/docs/api/latest/NetworkManager.conf.html), [nmcli](https://networkmanager.dev/docs/api/latest/nmcli.html), [Ubuntu automatic updates](https://ubuntu.com/server/docs/how-to/software/automatic-updates/), and [USBGuard documentation](https://usbguard.github.io/documentation/).

Licensed under [Apache-2.0](LICENSE).
