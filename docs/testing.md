# Testing

## Automated checks

Install test/build dependencies on Ubuntu:

```bash
sudo apt-get update
sudo apt-get install build-essential bats shellcheck shfmt jq
make check
```

Run from the repository root as an ordinary user. The tests use temporary fixtures and command mocks; they must never harden the development host, install packages, change its firewall, or alter real USB authorization.

| Target | Purpose |
| --- | --- |
| `make check` | Complete required lint/build/test gate |
| `make lint` | Bash syntax, ShellCheck, and shfmt checks |
| `make test` | Bats and C tests |
| `make format` | Apply the project's shell formatting |
| `make sanitize` | Run the C tests with AddressSanitizer/UndefinedBehaviorSanitizer |

The test suite exercises successful operations and safety boundaries: denied confirmation, failed backups/packages/native commands, invalid identifiers, preserved update origins, USB enrollment interruptions and policy drift, GNOME baseline validation and rollback, installer source/symlink handling, event provenance/filtering, bounded C parsing, thresholds, cooldowns, and notification state validation. A mocked successful command does not establish that a host's native package will behave identically.

The initial development environment is an Ubuntu 24.04 container. Automated checks there do **not** establish hardware/systemd integration on Ubuntu 26, live firewall behavior, actual device authorization, suspend/resume behavior, or desktop notification delivery. CI checks Linux shell/C code and fixtures; validate the supported Ubuntu release and hardware separately.

## Hardware acceptance checklist

Use a disposable Ubuntu Desktop installation or VM with a recoverable console first. USB behavior also requires representative physical hardware. Take a snapshot/backup, confirm recovery credentials, retain a trusted keyboard, and connect only to a network you own or are authorized to test.

1. **Installation:** install from a reviewed checkout as the GNOME user; confirm the menu opens immediately, `octoshield` works afterward, the installed program is root-owned, and reinstall preserves configured policy.
2. **Firewall:** inspect IPv4 and IPv6 UFW policy. From an authorized second host, test a deliberately opened local service and verify unsolicited access is blocked. Confirm normal outbound connections work. Test Docker-published ports independently; do not assume UFW covers them.
3. **USB:** enroll only known devices. Reconnect the trusted keyboard, mouse, dock and internal peripherals. Insert an expendable unfamiliar storage device and test HID/network-adapter classes where available; verify they remain unauthorized. Approve one temporary device, unplug/reinsert it, then test persistent approval, port movement, blocking, and permanent rule revocation.
4. **Startup and recovery:** reboot, suspend/resume, change docks, and exercise the documented USB recovery boot on the disposable system. Confirm an interrupted enrollment remains clearly reported as incomplete and does not silently enroll a newly attached device.
5. **Networking:** verify existing Wi-Fi profiles do not autoconnect after a manual disconnect/reboot. Reconnect and inspect effective MAC/discovery settings. Check IPv6, enterprise Wi-Fi certificate validation, captive portals, and any required VPN. Verify new-profile autoconnect is chosen explicitly.
6. **Desktop/authentication:** check lock after five idle minutes, immediate lock on blanking, and lack of automount. Verify the original desktop baseline restores correctly. Test fresh sudo prompts and inspect `sudo -l` for passwordless grants/overrides.
7. **Updates/confinement:** inspect unattended-upgrades origins/timers and simulate with `sudo unattended-upgrade --dry-run --debug`; review `sudo aa-status` and existing complain/disabled profiles. Apply actual pending updates separately on a trusted network and reboot if required.
8. **Notifications:** enable collector and user notifier, then generate authorized firewall blocks, harmless failed sudo authentication, and a rejected USB device. Verify thresholds/cooldown, sanitized GNOME messages, and unavailable/resumed behavior when restarting the collector. Kernel/logger rate limits can affect the number of observed log events.
9. **Office/recovery:** allow one office subnet/port and one trusted connection, verify other controls stay active, remove the exception, and restore one selected configuration from its private snapshot.

Record Ubuntu/kernel/package versions, hardware, results, and any failed steps in the pull request or a follow-up issue. Never attach connection secrets, full sensitive journals, USB serial numbers, or private snapshots to a public report. A checklist item is not complete until actually exercised.
