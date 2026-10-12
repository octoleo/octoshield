# Testing

## CLI and shared backend

Install test/build dependencies on Ubuntu:

```bash
sudo apt-get update
sudo apt-get install build-essential bats shellcheck shfmt jq
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
| `make gui` | Compile the native GTK4/libadwaita application |
| `make ui-test` / `make test-gui` | Compile the GUI and exercise its protocol parser, argument validation, and GUI/CLI capability parity |
| `make ui-display-test` | Run native window, exact review, and asynchronous subprocess regression tests under D-Bus/Xvfb |
| `make package` | Build the Debian package using `dpkg-buildpackage` |
| `make install DESTDIR=...` | Stage package files in the supplied directory; not a host installer |

The backend suite covers declined confirmations, failed backups/packages/native commands, invalid identifiers, preserved update origins, USB enrollment interruptions and drift, GNOME baseline validation/rollback, installer source/symlink handling, event provenance, bounded monitor parsing, thresholds, cooldowns, and notification state. A mocked successful command does not establish that a host's native package behaves identically.

## Native GUI

```bash
sudo apt-get install pkg-config libgtk-4-dev libadwaita-1-dev libjson-glib-dev \
    xvfb xauth dbus-daemon
make gui ui-test ui-display-test

dbus-run-session -- xvfb-run -a env GTK_A11Y=none GSK_RENDERER=cairo \
    build/octoshield-gtk --smoke-test
```

Run the smoke test as an ordinary user. It opens the actual GTK window under a temporary display and exits without applying protections. It verifies startup, not live PolicyKit authentication or GNOME hardware behavior.

Protocol tests exercise malformed/oversized JSON, untrusted display text, fixed argument construction, and privileged/unprivileged action separation. Capability tests route the same operations through the compiled GUI argument model and mocked CLI/backend dispatchers. Neither substitutes for clicking the actual controls on a recoverable desktop system.

## Debian metadata and lifecycle

```bash
sudo apt-get install debhelper desktop-file-utils libxml2-utils
bash tests/package.sh
make package
bash tests/package.sh ../octoshield_0.2.0_amd64.deb
```

Use the emitted filename for a different package version or architecture. These package checks inspect desktop/XML/PolicyKit metadata, mocked maintainer-script behavior, archive ownership/dependencies, and the installed payload; they do not install the package.

The **Test lint and package** workflow also performs an actual package install, upgrade/reinstall, removal, and purge in each disposable Ubuntu container. This is separate from mocked lifecycle checks. Do not run the destructive lifecycle runner on a workstation: its purpose is to verify package actions in an expendable environment, including retention of a backup fixture and optional security-package state. It requires an explicit disposable-system flag and CI marker.

CI is configured for Ubuntu 24.04 and 26.04 amd64 containers, plus a native window smoke test. Successful container checks do **not** establish real systemd/PolicyKit/GNOME integration, live firewall behavior, actual USB authorization, suspend/resume behavior, or notification delivery on either Ubuntu release. Initial development used an Ubuntu 24.04 container; live Ubuntu 26 hardware validation remains outstanding.

## Hardware acceptance checklist

Use a disposable Ubuntu Desktop installation or VM with a recoverable console first. USB behavior also requires representative physical hardware. Take a snapshot/backup, confirm recovery credentials, retain a trusted keyboard, and use only a network you own or are authorized to test.

1. **Package/application:** install the matching `.deb` with APT, find the OctoShield icon, open its native window as the GNOME user, and verify `/usr/bin/octoshield`. Confirm installation applies no protections, an administrator dialog appears for system actions, and user settings remain unprivileged. Compare equivalent GUI/CLI operations.
2. **Standalone/coexistence:** install the CLI on a system without desktop packages and check its terminal menus. On a disposable desktop with both installation types, inspect command resolution and effective monitor units; package upgrades/removal must not delete the standalone program or native protection settings.
3. **Firewall:** inspect IPv4/IPv6 UFW policy. From an authorized second host, test a deliberately opened local service and verify unsolicited access is blocked. Confirm normal outbound traffic works. Test Docker-published ports independently; do not assume UFW covers them.
4. **USB:** enroll only known devices. Reconnect the trusted keyboard, mouse, dock and internal peripherals. Insert an expendable unfamiliar storage device and test HID/network-adapter classes where available; verify they remain unauthorized. Test temporary/permanent approval, reconnect, port movement, and current blocking in both interfaces; verify the documented manual revocation procedure separately.
5. **Startup/recovery:** reboot, suspend/resume, change docks, and exercise the documented USB recovery boot. Verify interrupted enrollment is reported as incomplete and does not silently trust a newly attached device. Decline a GUI confirmation and inspect recorded partial changes.
6. **Networking:** verify existing Wi-Fi profiles do not autoconnect after manual disconnect/reboot. Reconnect and inspect effective MAC/discovery settings. Check IPv6, enterprise Wi-Fi certificate validation, captive portals, and any required VPN. Choose new-profile autoconnect explicitly.
7. **Desktop/authentication:** check five-minute idle lock, immediate lock on blanking, lack of automount, and available RDP/VNC controls. Restore the saved baseline. Test fresh sudo prompts and inspect passwordless grants/overrides; verify the GUI password action opens GNOME Accounts.
8. **Updates/confinement:** inspect unattended-upgrades origins/timers and simulate with `sudo unattended-upgrade --dry-run --debug`; review `sudo aa-status` and existing complain/disabled profiles. Apply pending updates separately on a trusted network and reboot if required.
9. **Notifications:** enable collector and notifier, then generate authorized firewall blocks, harmless failed sudo authentication, and a rejected USB device. Check thresholds/cooldowns, sanitized messages, and unavailable/resumed behavior after restarting collection. Verify log rotation on the target host; kernel/logger rate limits affect observed counts.
10. **Office/removal:** allow one subnet/port and trusted connection, verify other protections stay active, remove that exception, and restore one selected configuration. Upgrade/remove the package and confirm UFW/USB policies, user settings and backups remain intact while its monitoring processes stop on removal.

Record Ubuntu/kernel/package versions, hardware, and actual results in the PR or follow-up issue. Do not attach connection secrets, sensitive journals, USB serial numbers, or private snapshots publicly. An acceptance item is complete only after it has actually been exercised.
