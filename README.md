# OctoShield

Ubuntu laptop protection for conferences and everyday work, with a **native GNOME application and a standalone terminal interface**. Maintained by [Vast Development Method](https://www.vdm.io) as part of the [Octoleo](https://github.com/octoleo) suite, OctoShield uses Bash and C to configure Ubuntu's established firewall, USB authorization, confinement, authentication, and update mechanisms.

The GTK4/libadwaita desktop application and Whiptail CLI share named security profiles, live status, and the same control functions. Start with Conference, Public, Office, or Home; customize their settings or copy one to create your own. Switch the whole profile or override one protection. The dashboard distinguishes intended settings from verified system state, and protection continues when the window closes.

**Supported targets:** Ubuntu 24.04 and 26.04 with systemd; desktop features require a normal GNOME session. Container/unit tests and a graphical smoke test do not establish live hardware protection. Complete the [hardware acceptance checklist](docs/testing.md#hardware-acceptance-checklist) on a spare installation before relying on this at an event.

## Choose your installation

| Distribution | What you get | Requirements on the laptop |
| --- | --- | --- |
| Downloadable `.deb` | Native OctoShield application/icon, `octoshield` CLI, precompiled monitor, and privilege helper | Matching Ubuntu release and architecture; APT resolves runtime dependencies. No compiler is required. |
| Standalone CLI | `octoshield` terminal menus and the same system controls | Bash, local systemd terminal, and compiler/build dependencies installed by the bootstrap. No GTK/libadwaita or GNOME desktop dependencies are installed. |

Read the [feature guide](docs/features.md) for the complete capability overview and [distribution guide](docs/distribution.md) for permissions, upgrades, removal, and release preparation. The package retains its native application description, developer details, icon, and AppStream metadata. An optional signed APT repository lets Ubuntu's package tools deliver future updates after you explicitly add its source; see [repository updates](docs/distribution.md#updates-through-a-signed-apt-repository).

### Desktop application and CLI: install the package

Download an installable package from the public [latest release](https://github.com/octoleo/octoshield/releases/latest). No GitHub account or source checkout is needed. Version 1.3.0 is published after this release branch merges and its checks pass. Its release provides these packages:

| Ubuntu / architecture | Download | Package install command for version 1.3.0 |
| --- | --- | --- |
| Ubuntu 24.04 / amd64 | [Package](https://github.com/octoleo/octoshield/releases/download/v1.3.0/octoshield_1.3.0_ubuntu24.04_amd64.deb) · [Checksums](https://github.com/octoleo/octoshield/releases/download/v1.3.0/SHA256SUMS-ubuntu24.04) | `sudo apt install ./octoshield_1.3.0_ubuntu24.04_amd64.deb` |
| Ubuntu 26.04 / amd64 | [Package](https://github.com/octoleo/octoshield/releases/download/v1.3.0/octoshield_1.3.0_ubuntu26.04_amd64.deb) · [Checksums](https://github.com/octoleo/octoshield/releases/download/v1.3.0/SHA256SUMS-ubuntu26.04) | `sudo apt install ./octoshield_1.3.0_ubuntu26.04_amd64.deb` |

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

Open **OctoShield** from GNOME's application launcher, or run `octoshield-gtk`. No reboot is required. Run it as your normal desktop user: the system administrator dialog unlocks the application once, and its authenticated session lasts until the window closes. You can then refresh status and review changes without entering a password for every action. Locking the application or desktop also ends the authorization and requires another unlock. The GTK process still runs as your own user; only the fixed system-control helper receives administrator privileges. Installation starts the background status observer, but does not apply hardening, enroll USB devices, select a profile, or enable security-event collection automatically.

To upgrade an existing 1.0.0, 1.1.0, 1.2.0, 1.2.1 or 1.2.2 installation, download the matching 1.3.0 package and open it with your desktop's Debian package installer, or use the same `sudo apt install ./...deb` command. The package manager requests administrator permission and upgrades the existing `octoshield` package in place. Policies, profile settings, user preferences and recovery snapshots are retained; installation does not switch you into a new protection profile. If your desktop does not associate `.deb` files with an installer, use APT. The application offers **Check for updates**; the equivalent CLI command is `octoshield updates check`. This checks the fixed official GitHub release source on request and offers the matching download; installation remains a package-manager operation.

Version 1.2.1 fixes upgrades incorrectly blocked by background status inspection. The installer pauses that observer before acquiring its replacement lock and restores its previous running state afterward. An older package may print a failed `prerm` warning before dpkg automatically recovers using the new package's script. You do not need to uninstall first or delete a lock file. A real protection change must finish before replacement; the installer waits briefly and safely refuses if that operation is still busy. See [upgrade troubleshooting](docs/distribution.md#upgrade-troubleshooting).

Version 1.2.2 also resolves runtime contention: Apply and USB decisions wait for an existing inspection while new background readers yield. Inspections run with deadlines, and stalled observation workers are stopped automatically. The status service stays enabled, including support for temporary firewall permissions. A second protection change remains blocked while the first is applying policy or waiting for your confirmation. See [operation recovery](docs/recovery.md#operations-and-automatic-recovery).

The package also installs `/usr/bin/octoshield`:

```bash
octoshield
```

If you previously installed the standalone version, `/usr/local/bin/octoshield` may take precedence in your shell. The package leaves that installation intact and reports it. Use **`/usr/bin/octoshield`** to select the packaged CLI explicitly; the app always uses the packaged helper. See [migration and removal](docs/recovery.md#package-upgrades-coexistence-and-removal).

### Standalone CLI: source checkout

For CLI-only use, install from the public release checkout. With Git available:

```bash
git clone --branch v1.3.0 --depth 1 https://github.com/octoleo/octoshield.git
cd octoshield
bash src/octoshield install
```

If needed, install Git with `sudo apt-get install git`. The standalone installer compiles only the C monitor, installs `/usr/local/bin/octoshield` and `/usr/local/lib/octoshield`, and immediately opens guided terminal setup. It does not install the graphical application or its libraries. On a machine without GNOME, system controls remain usable and GNOME-only actions report the missing session.

Run from a **normal local terminal**, without prefixing the entire tool with `sudo`. System changes request elevation; user settings remain in your session. Hardening is refused over SSH. Subsequent runs need only `octoshield`.

The original public bootstrap command remains the CLI-only entry point:

```bash
bash <(curl -fsSL "https://raw.githubusercontent.com/octoleo/octoshield/refs/heads/main/src/octoshield")
```

The bootstrap follows `main`, which may contain changes newer than the latest release. It resolves `main` once and downloads every implementation file from that immutable commit; this provides consistency, not independent code signing. There is no `--ref` switch: use the release checkout above to install a specific release.

Re-run the same standalone installation procedure to update its program files. System policy and trusted-device rules remain in place. See [recovery](docs/recovery.md) before switching between standalone and package installations.

## Profiles and verified status

Conference and Public begin with restrictive discovery and service settings. Office and Home retain incoming-deny firewall protection and disabled discovery, while restoring original printing, Bluetooth and saved Wi-Fi autoconnect choices. Home is not an unprotected mode. Firewall, USB, network privacy, services and monitoring can each follow the selected global profile or another profile. Security updates, AppArmor, sudo authentication and screen locking remain independent baseline protections.

Use the profile controls in the application or open `octoshield profile` for the guided Whiptail manager. Initial USB protection requires physical device enrollment, available through **Activate USB protection** / `octoshield apply usb` or the first profile switch. Firewall preparation offers to install UFW when missing, with a separate confirmation before policy changes. Existing 1.0.0 settings remain effective until you explicitly select a profile; they are not guessed from the last command you ran.

```bash
octoshield status
octoshield profile list
octoshield profile create workshop conference
octoshield profile apply conference
octoshield profile apply office usb
```

The final command changes only USB, leaving the other protections in Conference. The dashboard shows that override. Profile changes require review and administrator authorization. A successful command alone does not produce a green indicator: observed policy, profile agreement, errors and cache freshness determine status. The root-owned background observer publishes sanitized summaries under `/run/octoshield/status.json`; normal-user readers receive no network passwords or raw USB serial numbers. An unavailable or stale observer is shown as unknown.

Edit a profile, then explicitly apply it to activate the saved settings. For example, permit incoming TCP port 443 from your chosen subnet on a specific interface for thirty minutes, or enable printing without changing your firewall profile:

```bash
octoshield profile rule-add workshop 443 tcp 192.168.1.0/24 wlan0 30
octoshield profile set workshop services.printing enabled
octoshield profile apply workshop
octoshield profile show workshop
```

Use your actual network/interface. Rules accept TCP or UDP, an IPv4/IPv6 address or CIDR, and an interface name; `any` explicitly permits any source or interface. A zero-minute duration creates a permanent allowance in UFW's saved policy. A finite duration starts its deadline when saved and requires an enabled, running status observer before application. Its runtime-only kernel rule has a UTC deadline and stops admitting new connections when that deadline arrives, even if the observer stops or OctoShield is uninstalled. Unsupported kernel time matching refuses the grant rather than creating an untimed exception. A firewall reload or reboot removes temporary permissions sooner, and expired permissions cannot reopen from UFW's saved rules at boot. Apply the profile explicitly to restore any still-unexpired permissions after reload/reboot. The observer verifies expired permissions are closed and reconciles their saved metadata; inert kernel rules remain until the next Apply or reload. Delayed reconciliation does not extend their deadline.

`ufw status` lists persisted UFW exceptions and does **not** include these runtime-only timed permissions. Use OctoShield's status and `octoshield profile show workshop` to inspect the observed state and configured deadlines; OctoShield checks the kernel rules too. Saved edits and removals take effect when the firewall profile is reapplied. Profile switching never uses `ufw reset` or deliberately disables an active firewall; it removes old exceptions before adding the destination's rules. Established connections are not forcibly terminated.

Editable settings include `network.autoconnect`, `network.discovery` and `monitor.enabled` (`true`/`false`), and `services.printing`, `services.bluetooth`, `services.ssh`, `services.discovery`, `services.samba` and `services.remote_desktop` (`enabled`/`disabled`/`baseline`). Autoconnect `true` restores the saved original choices rather than enabling every saved network. `baseline` restores the captured service state. Security baselines and USB device approvals have their own explicit controls; they are not disabled by choosing Home.

`octoshield profile restore firewall` restores the saved pre-profile firewall state; omit the control to restore available baselines for every managed area. Restoration is an explicit, reviewed change. If another administrator or application changed managed settings, OctoShield reports the conflict instead of silently overwriting it. Configuration snapshots are not a whole-system rollback. See [profile behavior and recovery](docs/recovery.md#profiles-overrides-and-restoration).

## Guided access and actionable findings

To share a local web server, open **Access & exceptions**, choose **Web server · HTTP + HTTPS**, select the detected local network and duration, then **Review and allow access**. Both TCP ports 80 and 443 become one permission. The effective firewall profile is selected automatically. Existing permissions show their observed state with **Edit** and **Revoke** actions; no rule identifiers or network UUIDs need to be copied. Custom ports, addresses and interfaces remain available for advanced use. The equivalent terminal workflow is `octoshield access`.

The guided operation saves, applies and verifies the whole permission together. Temporary deadlines start after confirmation, immediately before activation. A failed application attempts to restore the previous policy and reports any incomplete recovery. Unapplied profile edits and external firewall changes must be reviewed before adding another permission. Adopting an unmanaged firewall shows its existing exceptions before replacement. A subnet and interface identify packet scope, not an authenticated trusted network; another network can reuse that subnet. Select each required IPv4/IPv6 subnet explicitly and revoke access before moving to an untrusted network. These allowances govern UFW host input; Docker-published ports have a separate packet path.

**Connection privacy** lists saved connections by name, including their interface, addresses, configuration sources and current verification. Adjust automatic connection, local discovery or Wi-Fi MAC behavior for one connection, then explicitly reconnect when required. The override belongs to the effective network profile and is retained when that profile is reapplied. Changing saved settings does not silently disconnect an active network. Unsupported active-state checks remain **Unable to verify**. Use `octoshield connections` for the same guided workflow.

Overview **Manage** and **Review** actions open the relevant control or **Details & fixes**. Encryption findings distinguish confirmed root-storage encryption from unchecked home, swap or other storage. Docker findings identify actual published bindings and Compose source hints; localhost bindings do not receive the same warning as all-interface publishing. Forwarding being enabled is reported with its required role and inspection limits, rather than treated by itself as a defect. Configuration evidence stays behind the authenticated helper and is not written into the public status cache. Use `octoshield diagnostics` to read these explanations in the terminal.

For supported Compose services, **Details & fixes** offers a concrete proposal to bind published ports to localhost and recreate only the selected service. The operation runs as your normal user with your existing Docker access; it never executes project Compose files as root. Automatic repair requires Docker Engine 28 or newer, Compose 2.24.4 or newer, a single matching running service, ordinary bridge NAT, and eligible user-owned source files. Daemon configuration evidence must be readable and must not enable direct routing or disable Docker filtering. Unsupported or changed configurations receive an explanation instead of a guessed repair. Verification checks published host bindings and the recreated service configuration; it does not certify every custom routing or firewall path.

The repair writes a dedicated `.octoshield/SERVICE.local.yaml` port override in the project and retains Docker forwarding and outbound networking. **Future deployments must include this override**, using the exact command shown in the plan; omitting it can restore the original broader bindings. The original Compose files are not rewritten. A private `.octoshield/SERVICE.reviewed.json` snapshot pins the currently running image for this recreation, retains the exact reviewed deployment model and can contain resolved environment values. The permanent port override does not pin future image upgrades. Recreation retains mounted volumes but replaces unmounted changes in the container's writable layer. Inspect and verify the result before relying on it, including access from another device. Use `octoshield containers` for guided selection without copying an ID or review token.

## Desktop workflow

Open OctoShield and use its sidebar:

| Page | Actions |
| --- | --- |
| Overview | Read refreshed protection indicators, global profile and overrides; switch profiles. |
| Protections | Activate, adjust or restore controls; edit profile settings; apply/restore GNOME settings; open the system account settings. |
| USB devices | Inspect blocked/allowed devices, review a numeric device ID, allow temporarily or remember for the effective USB profile, and revoke trust. |
| Access & exceptions | Allow web/SSH/custom service access on a selected network; review, edit and revoke grouped permissions. |
| Connection privacy | Select a named connection, adjust privacy settings, inspect active verification, and explicitly reconnect. |
| Details & fixes | Read the evidence and configuration sources behind encryption, Docker, forwarding and network findings; review supported Docker repairs. |
| Monitoring | Enable/disable collection, inspect status/logs, and control this user's notifications. |
| Recovery | Check official application updates, read recovery guidance, list saved change transactions, and inspect their action history. |

The GUI is a native application, not a terminal embedded in a window. Its administrator session calls a fixed helper API backed by the same Bash control functions used by the CLI. Unlocking the session does not approve every change: consequential operations still explain their impact and request confirmation. It presents plain-text results and explicit confirmation requests; raw output cannot become shell commands. Detailed output appears at operation boundaries, so package installation can remain busy without displaying every line immediately. USB enrollment presents the generated device policy before asking you to trust it. Leave the window open until an operation finishes; you can decline a pending confirmation without applying its next step.

## Individual baseline controls

These commands remain available for initial setup and deliberate individual hardening. `apply firewall`, `apply network` and `apply services` select Conference for that control through the shared profile engine. Use profile edits and switches to keep intended settings and restoration baselines coherent.

| Control | Behavior and practical effect |
| --- | --- |
| `firewall` | Prepares/installs UFW when needed, saves the original policy, and applies the Conference firewall profile after review. Enables IPv4/IPv6 filtering, denies unsolicited inbound and forwarded traffic, permits outgoing traffic, and replaces inbound exceptions with the profile's rules. Never uses `ufw reset` or deliberately disables an active firewall during a switch. |
| `usb` | Enrolls the physically reviewed connected device set with port-bound USBGuard rules. Unknown storage, keyboards, network adapters, and other USB devices remain blocked pending administrator authorization. USBGuard's D-Bus bridge is masked; policy IPC is root-only. |
| `network` | Disables autoconnect for existing Wi-Fi profiles, enables private stable Wi-Fi MAC addresses and randomized scanning, and disables LLMNR/mDNS in existing profiles and defaults. Reconnect manually to apply profile changes. IPv6 remains enabled. |
| `services` | Stops and masks installed SSH services/socket, Avahi, CUPS services/socket/path, Bluetooth daemon, Samba, and system GNOME remote desktop. Printing, Bluetooth input and inbound SSH may stop. Per-user sharing services require separate review. |
| `sudo` | Writes a syntax-checked sudoers drop-in setting `timestamp_timeout=0`. Existing `NOPASSWD` grants or more specific `Defaults` can override authentication. |
| `updates` | Enables daily unattended updates and appends official Ubuntu security/ESM origins while retaining administrator origin policy. Automatic reboot is disabled. This does not prove all pending updates have already installed. |
| `apparmor` | Enables AppArmor and reloads installed profiles in their existing modes. It does not force complain/disabled profiles into enforcement or confine every application. |
| `monitor` | Enables the sandboxed system event collector. Enable the separate notification service from your user session afterward. |
| Desktop settings | Locks after five idle minutes, locks immediately on blanking, disables media automount/autorun, and disables available per-user GNOME RDP/VNC backends. Missing optional sharing controls are reported. System remote login is handled separately by the services control. |

Network privacy settings do not force newly created Wi-Fi profiles to disable autoconnect. Deselect automatic connection when adding a conference network. MAC-registered office networks may need an explicit per-profile adjustment. LLMNR/mDNS changes affect local discovery and depend on the DNS backend; Avahi is disabled through the services control.

**Docker/container-published ports can bypass UFW's normal host filtering.** Use **Details & fixes** to review individual bindings and supported local-only Compose repairs. OctoShield preserves Docker's own firewall rules and required forwarding. Virtual machines, rootless runtimes, host networking and other unsupported paths retain explicit inspection limits; a UFW indicator does not certify those paths.

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

Run the controls you choose; this list is not an unattended installer. Disruptive controls request confirmation; system actions create private change records. `status` reads the verified protection summaries and exposure findings; `inspect` requests a fresh privileged inspection. An active service is not proof of complete protection; verify effective policy and hardware behavior.

```bash
sudo ufw status verbose
sudo aa-status
octoshield usb list
octoshield monitor status
octoshield backups
octoshield recovery
```

`octoshield password` calls the system's normal `passwd` interface for your current user. The graphical password action opens GNOME Settings → System → Users; it does not create a separate OctoShield password. OctoShield never receives or stores your password. Changing it also changes that account's normal login password; desktop keyring/vault synchronization is outside OctoShield's scope.

## USB approval

Before initial enrollment, remove **all untrusted devices**. Keep required built-in devices, trusted keyboard/mouse, hubs and dock connected. Read the generated rules, physically verify the complete set, and have a recovery method available. The device set is checked again before enabling policy. Existing unmanaged USBGuard installations are left for manual review rather than overwritten. Re-running setup retains the approved rules and never automatically trusts every currently attached device again.

Unknown devices remain blocked while approval is pending. In an active, unlocked local desktop session, OctoShield offers a device review with **Allow once**, **Remember for this profile**, or **Keep blocked**. Closing or cancelling the review grants nothing. The prompt identifies the effective USB profile, including an individual override: remembering a device in Office does not trust it in Conference. Authentication goes through the system administrator dialog if OctoShield is not already unlocked. The package starts a small user-session USB prompt agent through desktop autostart, and opening the application starts it for the current login. Automatic USB prompts can be disabled in the application without disabling USBGuard. This agent is independent of optional security-event notifications; a locked or inactive session never approves a device.

The **USB devices** page shows each current attachment and its observed state with actions beside it. Refreshing the list does not ask for another password in the unlocked application. A completed decision refreshes the result; a failed, disconnected or changed attachment remains an explicit error or unknown state. Device or profile changes invalidate the previous review. A dismissed device stays blocked and can be reviewed later from this page, or use the CLI:

```bash
octoshield usb list
read -r -p 'Physically reviewed device ID: ' device_id
octoshield usb allow "$device_id"
```

Temporary approval lasts until reconnection, daemon restart, or a USB profile switch. To remember the reviewed device and port for the current USB profile only:

```bash
octoshield usb allow "$device_id" --permanent
```

`octoshield usb block "$device_id"` blocks the current attachment; `octoshield usb forget "$device_id"` also removes its remembered authorization from the active USB profile. Approval in Office does not grant approval in Conference. Switching reevaluates connected devices, expires temporary approvals and reviews devices that may disconnect. Mounted storage must be safely unmounted before a switch that would block it. Inactive profiles can be prepared with `octoshield usb enroll office` after physically reviewing every attached device. Copying a profile intentionally copies that profile's remembered devices too; review the copied policy before use. Legacy 1.0 approvals are preserved separately for explicit restoration.

CLI USB approval expires sudo's cached authentication timestamp. The GUI unlocks its fixed administrator session through PolicyKit; OctoShield never reads, stores or replays a password. The system decides which accounts qualify as administrators and presents its identity chooser when needed. Membership in the Unix `root` group is not the authorization rule. A standard user can proceed only when the system accepts an administrator's authentication. Closing and reopening the application requires a new unlock; local PolicyKit rules still govern authentication. `NOPASSWD`, custom PolicyKit rules or existing root access cannot be neutralized by an application prompt. Device fingerprints/descriptors can be spoofed. Trusted hardware, firmware, physical supervision and a locked screen remain necessary. Devices may need approval again when moved to another port.

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

`octoshield office` opens the guided firewall-access or connection-privacy workflow, or restores a selected service. Existing `office firewall` and `office network` commands now use the same managed profile operations as the new workflows. For USB, authorize the one device you need. Network-scoped permissions are address-based, not authentication of the network; revoke them before visiting another untrusted network that could use the same address range.

`octoshield desktop restore` restores only the saved GNOME settings from before first apply. System snapshots are private and are not automatically reapplied; see [docs/recovery.md](docs/recovery.md) for targeted recovery, partial failures, and USB lockout instructions.

`octoshield backups` lists local configuration recovery snapshots created before OctoShield changes system settings. Their directory is restricted to root; the files are not separately encrypted by OctoShield. They are not backups of your folders or a complete system image. Restic/S3 folder backup integration is future scope and is not included in version 1.3.0.

## Scope and limits

This is preventive host hardening with limited event visibility, not an intrusion-detection guarantee. Disk encryption and Secure Boot are **inspected only**, not configured. USB devices can interact during early boot or before USBGuard starts; OctoShield does not configure an initramfs device policy. It cannot defeat invasive physical attacks, firmware compromise, malicious already-trusted devices, or vulnerabilities in permitted software. Browser/password/SSH vaults reduce credential exposure but do not make the browser or operating system immune to compromise.

Keep the OS and applications patched, lock the screen when leaving the laptop, avoid unfamiliar devices, and use authenticated HTTPS and a trusted VPN where appropriate. Configure enterprise Wi-Fi certificate validation correctly. These practices and firmware settings complement the controls; OctoShield does not configure a VPN, impose a browser policy, or replace backups.

## Development

On Ubuntu 26.04, also install `gnu-coreutils` with APT before running tests; [testing prerequisites](docs/testing.md#cli-and-shared-backend) explain the GNU supervisor requirement.

```bash
sudo apt-get install build-essential bats shellcheck shfmt jq apt-utils gnupg appstream python3
make check
```

`make check` runs the CLI/backend lint, build, and isolated tests without requiring GUI development libraries. To build and test the desktop application:

```bash
sudo apt-get install pkg-config libgtk-4-dev libadwaita-1-dev libjson-glib-dev
make gui
make ui-test
```

`make package` builds the `.deb` after Debian build dependencies are installed. Other targets include `make test`, `make lint`, `make format`, and `make sanitize`. See [testing](docs/testing.md), [packaging](docs/packaging.md), [distribution and release preparation](docs/distribution.md), [contribution guidelines](CONTRIBUTING.md), and [security reporting](SECURITY.md).

### Publish the next release

On a review branch, increment the version with `bash scripts/version.sh --bump patch` (or `minor` / `major`), review the generated release notes and run `bash scripts/version.sh --check`. For an exact version, use `--set X.Y.Z`. Merge the reviewed change into `main`: once all tests and package checks pass, CI creates the version tag and publishes the Debian packages under [Releases](https://github.com/octoleo/octoshield/releases). A version that is already published is left unchanged.

To retry publication of the current version, open **Actions → Test lint and package → Run workflow**, choose `main`, and enable `publish`. Leaving `publish` disabled runs tests and produces review artifacts only. GitHub supplies the release token automatically; no custom release secret is needed. Optional signed APT hosting has separate configuration. See the [release procedure](docs/distribution.md#versions-and-release-publication) for commands and safeguards.

Native interfaces: [NetworkManager configuration](https://networkmanager.dev/docs/api/latest/NetworkManager.conf.html), [nmcli](https://networkmanager.dev/docs/api/latest/nmcli.html), [Ubuntu automatic updates](https://ubuntu.com/server/docs/how-to/software/automatic-updates/), and [USBGuard documentation](https://usbguard.github.io/documentation/).

Licensed under [Apache-2.0](LICENSE).
