# Contributing

OctoShield is part of the OctoLeo shell-tool suite. Keep the implementation small, explicit, and auditable: Bash orchestrates native Ubuntu controls; C implements the GTK4/libadwaita frontend and bounded event aggregation. The GNOME application and terminal interface share the control functions. Keep desktop dependencies out of the standalone CLI installation.

## Workflow

Create a focused branch, make reviewable commits, and open a draft pull request early. Explain the concrete behavior, privilege boundary, configuration changes, recovery path, and tests. Mark it ready only after automated checks pass and any untested hardware behavior is stated clearly.

```bash
sudo apt-get install build-essential bats shellcheck shfmt jq
make check
```

Use `make format` for shell formatting and `make sanitize` for the C sanitizer suite. Consult [docs/testing.md](docs/testing.md) for integration acceptance; do not report hardware tests that were not run.

The CLI/backend gate deliberately does not require GUI development libraries. For frontend or shared-action changes, also install `pkg-config libgtk-4-dev libadwaita-1-dev libjson-glib-dev`, run `make gui` and `make ui-test`, and exercise the actual application smoke test. `make package` builds the Debian package; package lifecycle tests belong only in a disposable container/VM. See [docs/packaging.md](docs/packaging.md).

## Implementation rules

- Keep sourced Bash modules free of system changes at load time. Use `module::function` names and fixed dispatch entries; quote variables and pass arguments as arrays where appropriate.
- Propagate external failures explicitly, including functions invoked inside `if`, `!`, or `||`, where relying on `set -e` is insufficient.
- Validate user-controlled IDs and paths before use. Never `eval` input, source saved state, interpolate user input into shell commands, or trust device-provided text in terminal/desktop messages.
- Use the core backup/atomic-write helpers for managed system configuration. Explain disruptive changes before asking for confirmation and preserve a practical local recovery route.
- Maintain strict privilege separation. Do not give the desktop user unrestricted logs or policy IPC merely to display notifications. Do not change firewall/container policy outside the selected scope.
- Keep GUI requests as fixed argument vectors and validate them again in the privileged helper. Render backend/device text as plain text; never interpret it as markup or accept it as a protocol message. Keep operations asynchronous, provide explicit impact/confirmation, and do not terminate a privileged change merely because a window is closing.
- Preserve GUI/CLI feature parity when adding a control. Use native GTK widgets and system authentication/account interfaces; do not replace the app with a terminal launcher.
- Keep Debian package scripts limited to program/service lifecycle. Installation must not apply hardening; removal and purge must retain host policies and private backups. Test upgrade/removal only inside an isolated disposable environment.
- Test meaningful failure paths as well as success. Mock native mutations; a unit test must not change the host firewall, services, user settings, or USB policy.
- Keep C inputs bounded, handle partial reads/writes and errors, use monotonic time for intervals, and retain strict compiler warnings and sanitizer coverage.
- Update README/recovery instructions alongside behavior changes. Describe effective behavior and known gaps precisely.

Contributions are licensed under the repository's Apache-2.0 license. Report security vulnerabilities privately as described in [SECURITY.md](SECURITY.md).
