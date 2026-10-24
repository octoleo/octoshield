# Testing

## CLI and shared backend

Install test/build dependencies on Ubuntu:

```bash
sudo apt-get update
sudo apt-get install build-essential bats shellcheck shfmt jq apt-utils gnupg appstream python3
# Ubuntu 26.04 additionally requires its side-by-side GNU utilities package.
if [ "$(. /etc/os-release; printf '%s' "$VERSION_ID")" = 26.04 ]; then
    sudo apt-get install gnu-coreutils
fi
make check
```

Run ordinary tests from the repository root without root privileges. Temporary fixtures and command mocks must never harden the development host, install security packages, change its firewall, or alter real USB authorization. The separate package lifecycle test described below deliberately installs/removes the application only inside a disposable CI container.

| Target | Purpose |
| --- | --- |
| `make check` | CLI/backend lint, strict monitor compilation, Bats and C tests; no GTK development dependencies |
| `make lint` | Bash syntax, ShellCheck, and shfmt checks |
| `make test` | CLI/backend Bats and monitor C tests |
| `make format` | Apply the project's shell formatting |
| `make sanitize` | Run monitor C tests with AddressSanitizer/UndefinedBehaviorSanitizer |
| `make session-sanitize` | Run the privileged broker tests with AddressSanitizer/UndefinedBehaviorSanitizer; needs GLib/GIO and JSON-GLib development packages |
| `make gui` | Compile the native GTK4/libadwaita application |
| `make ui-test` / `make test-gui` | Compile the GUI and exercise its protocol parser, argument validation, and GUI/CLI capability parity |
| `make ui-display-test` | Run native window, exact review, and asynchronous subprocess regression tests under D-Bus/Xvfb |
| `make package` | Build the Debian package using `dpkg-buildpackage` |
| `make install DESTDIR=...` | Stage package files in the supplied directory; not a host installer |

The backend suite covers declined confirmations, failed backups/packages/native commands, invalid identifiers, preserved update origins, USB enrollment interruptions and drift, GNOME baseline validation/rollback, installer source/symlink handling, event provenance, bounded monitor parsing, thresholds, cooldowns, and notification state. A mocked successful command does not establish that a host's native package behaves identically.

`tests/locking.bats` uses real kernel locks and separate processes in private fixtures. It verifies automatic continuation after a reader or expiry worker, priority over new readers, exclusion of simultaneous mutations, bounded failure without a transaction, package-maintenance races, unsafe lock paths, and lock release after persistent CLI operations. Its stalled-worker test runs the actual status worker with a TERM-resistant fixture descendant: GNU timeout kills that owned process group, releases inherited descriptors, and lets the waiting writer proceed without deleting locks or restarting services. Native policy commands remain isolated fixtures.

Worker supervision requires GNU timeout's process-group termination behavior. Ubuntu 24.04 supplies it at `/usr/bin/timeout`; Ubuntu 26.04 supplies `/usr/bin/gnutimeout` through `gnu-coreutils`. The Debian build/runtime dependency and standalone installer ensure a GNU implementation is available. Installing `gnu-coreutils` alongside the default utilities does not switch the system's coreutils provider. CI retains Ubuntu 26.04's default tools and tests OctoShield's explicit GNU selection.

Release tests check coherent versions, fixed documentation/media assembly, package-mapped AppStream/DEP-11 catalogues, and APT indexes. APT tests create disposable packages and a temporary signing key, verify signatures and hash chains, and exercise APT with isolated state; they do not install packages, change host sources, or import keys into your normal keyring. Catalogue preparation uses Python's standard library and `appstreamcli` during the build; the installed application has no Python runtime requirement. Production signing credentials are never required for these tests.

## Native GUI

```bash
sudo apt-get install pkg-config libgtk-4-dev libadwaita-1-dev libjson-glib-dev \
    xvfb xauth dbus-daemon adwaita-icon-theme librsvg2-common
make gui ui-test ui-display-test session-sanitize

dbus-run-session -- xvfb-run -a env GTK_A11Y=none GSK_RENDERER=cairo \
    build/octoshield-gtk --smoke-test
```

Run the smoke test as an ordinary user. It opens the actual GTK window under a temporary display and exits without applying protections. It verifies startup, not live PolicyKit authentication or GNOME hardware behavior.

The display suite also captures all eight native pages in light and dark themes under `build/screenshots/`. These sixteen images use demonstration/initial data. `scripts/release-assets.sh` checks their PNG headers/dimensions and copies them unchanged with metadata and documentation; it does not establish real hardware protection or upload them.

Protocol tests exercise malformed/oversized JSON, untrusted display text, fixed argument construction, and privileged/unprivileged action separation. Capability tests route the same operations through the compiled GUI argument model and mocked CLI/backend dispatchers. Neither substitutes for clicking the actual controls on a recoverable desktop system.

## Debian metadata and lifecycle

```bash
sudo apt-get install debhelper desktop-file-utils libxml2-utils appstream
bash tests/package.sh
make package
bash tests/package.sh ../octoshield_1.3.0_amd64.deb
```

Use the emitted filename for a different package version or architecture. These package checks inspect desktop/XML/PolicyKit metadata, validate AppStream semantically with `appstreamcli validate --no-net`, and check mocked maintainer scripts, archive ownership/dependencies, and the installed payload; they do not install the package. Offline AppStream validation does not prove screenshot URLs are reachable or that any catalogue has accepted the application.

The **Test lint and package** workflow downloads the already published matching 1.1.0, 1.2.0 and 1.2.1 archives, checks their pinned SHA-256 values, installs each baseline in a fresh disposable Ubuntu container, then upgrades to the new package. Before upgrading, it seeds a custom profile with a firewall exception, service and autoconnect choices, plus a remembered USB policy, without applying any protection. It also reinstalls the new version, removes and purges it. Fixtures verify exact retention of those saved choices, native configuration, an existing monitor enablement choice, user preferences, a private recovery snapshot and optional security-package state. The generalized runner accepts an explicitly supplied older stable package; mocked coverage still checks the special 1.0.0 observer migration. The status observer is the only service introduced automatically. Do not run the destructive lifecycle runner on a workstation; it requires an explicit disposable-system flag and CI marker.

Both build and upgrade containers install their distribution's UFW package without activating firewall policy. Build jobs run `bash tests/ufw-vendor.sh` to check the actual vendor hook files read-only, verify their configuration stays unchanged, and reject an administrator-modified temporary copy. Upgrade jobs checksum-check their native UFW files throughout the package lifecycle test. This catches distribution template/layout differences that isolated command mocks cannot establish.

CI is configured for Ubuntu 24.04 and 26.04 amd64 containers, plus a native window smoke test. Successful container checks do **not** establish real systemd/PolicyKit/GNOME integration, live firewall behavior, actual USB authorization, suspend/resume behavior, or notification delivery on either Ubuntu release. Initial development used an Ubuntu 24.04 container; live Ubuntu 26 hardware validation remains outstanding.

## Hardware acceptance checklist

Guided-access regression coverage must additionally exercise:

- The effective firewall profile is selected, including a per-control override. The web preset creates TCP 80 and 443 with identical scope/deadline; cancellation changes nothing, revoke closes both, and unrelated permissions remain intact.
- LAN selection lists physical connections and real subnets without offering Docker/VPN bridges as trusted LAN defaults. Test IPv4 and IPv6 separately from an authorized second device, including blocked ingress outside the selected scope.
- The named connection editor retains its override through profile reapplication. Saved changes show pending/unverified runtime state until appropriate evidence is available; reconnect is explicit and reports failures.
- Encrypted root storage, separate unencrypted/unknown home or swap, unsupported filesystems and inspection timeouts produce accurate scoped labels and details. Profile-state failures do not overwrite independent encryption evidence.
- Docker localhost, wildcard, specific-address and host-mode cases report different evidence. A supported Compose repair changes only the reviewed service, retains local and outbound connectivity, and refuses stale plans or unsupported routing modes. Omitting the generated override on a subsequent deployment must not be described as retaining its protection.
- Private source paths and connection/container identities never enter the public status cache. Malformed/oversized structured helper results fail visibly without rendering a truncated permission list as complete.

These checks require live hosts where stated. Mocked unit tests and Xvfb GUI tests do not substitute for second-device network reachability or hardware verification.

Use a disposable Ubuntu Desktop installation or VM with a recoverable console first. USB behavior also requires representative physical hardware. Take a snapshot/backup, confirm recovery credentials, retain a trusted keyboard, and use only a network you own or are authorized to test.

1. **Package/application:** install the matching `.deb` with APT, find the OctoShield icon, open its native window as the GNOME user, and verify `/usr/bin/octoshield`. Confirm installation applies no protections and the system administrator dialog unlocks the application. Refresh devices and perform multiple reviewed actions without repeated authentication; close/reopen and verify a new unlock. Lock the desktop and the application separately, and verify both revoke authorization while native protection stays active. Test cancellation, wrong passwords, and a standard desktop user authenticating with an eligible administrator identity. Confirm the GTK process and user settings remain unprivileged. Compare equivalent GUI/CLI operations.
2. **Standalone/coexistence:** install the CLI on a system without desktop packages and check its terminal menus. On a disposable desktop with both installation types, inspect command resolution and effective monitor units; package upgrades/removal must not delete the standalone program or native protection settings.
3. **Firewall:** inspect IPv4/IPv6 UFW policy. From an authorized second host, test a deliberately opened local service and verify unsolicited access is blocked. Confirm normal outbound traffic works. Test Docker-published ports independently; do not assume UFW covers them.
4. **USB:** enroll only known devices. Reconnect the trusted keyboard, mouse, dock and internal peripherals. Insert an expendable unfamiliar storage device and test HID/network-adapter classes where available; verify they remain unauthorized. Test temporary/permanent approval, reconnect, port movement, and current blocking in both interfaces; verify the documented manual revocation procedure separately.
5. **Startup/recovery:** reboot, suspend/resume, change docks, and exercise the documented USB recovery boot. Verify interrupted enrollment is reported as incomplete and does not silently trust a newly attached device. Decline a GUI confirmation and inspect recorded partial changes.
6. **Networking:** verify existing Wi-Fi profiles do not autoconnect after manual disconnect/reboot. Reconnect and inspect effective MAC/discovery settings. Check IPv6, enterprise Wi-Fi certificate validation, captive portals, and any required VPN. Choose new-profile autoconnect explicitly.
7. **Desktop/authentication:** check five-minute idle lock, immediate lock on blanking, lack of automount, and available RDP/VNC controls. Restore the saved baseline. Test fresh sudo prompts and inspect passwordless grants/overrides; verify the GUI password action opens GNOME Settings → System → Users.
8. **Updates/confinement:** inspect unattended-upgrades origins/timers and simulate with `sudo unattended-upgrade --dry-run --debug`; review `sudo aa-status` and existing complain/disabled profiles. Apply pending updates separately on a trusted network and reboot if required.
9. **Notifications:** enable collector and notifier, then generate authorized firewall blocks, harmless failed sudo authentication, and a rejected USB device. Check thresholds/cooldowns, sanitized messages, and unavailable/resumed behavior after restarting collection. Verify log rotation on the target host; kernel/logger rate limits affect observed counts.
10. **Office/removal:** allow one subnet/port and trusted connection, verify other protections stay active, remove that exception, and restore one selected configuration. Upgrade/remove the package and confirm UFW/USB policies, user settings and backups remain intact while its monitoring processes stop on removal.

11. **Profiles and overrides:** adopt Conference, change only USB to Office, and confirm the dashboard describes the mixed state. Copy/edit a profile and verify edits stay pending until applied. Switch repeatedly, restore each original baseline, introduce a deliberate external change, and verify it is reported before replacement. Inject a failed native operation and check that its area never appears fully applied.
12. **USB profile boundaries and guided review:** remember a device in Office, switch to Conference while it remains attached, and verify it becomes blocked unless Conference separately authorized it. Insert an unfamiliar device with the application open and with the USB prompt agent active while the window is closed; verify the guided review, correct effective profile, allow-once/remember choices and post-action state. Verify USB prompts work independently of optional event notifications and that their preference disables prompts without changing USBGuard policy. Close/cancel a review and verify the attachment stays blocked without a repeated prompt loop; reopen the USB page to review it deliberately. Test allow-once expiry, forget/reconnect, device replacement during confirmation, profile changes while the review is open, multiple simultaneous insertions, and mounted storage refusal. Confirm a locked or inactive session never approves an insertion and a deferred request is offered after unlock.
13. **Scoped access and expiry:** permit a test port only on the chosen interface/source, verify another network remains blocked, and test IPv6 separately. Confirm the kernel rejects new connections at the UTC deadline while the GUI is closed, the observer is stopped, cleanup is locked, or the app has been removed; distinguish existing established sessions from new connections. Refuse timed grants if kernel time matching is unavailable, without an untimed fallback. Check that finite grants are absent from persisted UFW rules, disappear on reboot/reload, and never reopen automatically; only explicit application may restore an unexpired permission. Compare OctoShield's kernel observations with `ufw status`, which omits runtime-only grants. Refuse new timed grants without an enabled, running observer. Stopped/stale observers and policy conflicts must remain visible. Test printer access without altering unrelated firewall or USB settings.
14. **Additional observations and upgrades:** verify container/forwarding warnings against actual published ports, and check Thunderbolt/USB4, Secure Boot and storage observations on supported and unsupported hardware. Upgrade a real 1.1.0, 1.2.0, 1.2.1 or 1.2.2 desktop by opening the matching 1.3.0 `.deb`, authenticate through the package manager, and verify no profile changes without consent. Exercise the on-demand update check offline and online, and confirm it offers only the correct platform's official package.

Record Ubuntu/kernel/package versions, hardware, and actual results in the PR or follow-up issue. Do not attach connection secrets, sensitive journals, USB serial numbers, or private snapshots publicly. An acceptance item is complete only after it has actually been exercised.
