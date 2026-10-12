# Contributing

Octoshield is part of the OctoLeo shell-tool suite. Keep the implementation small, explicit, and auditable: Bash orchestrates native Ubuntu controls; C handles bounded persistent event aggregation. Avoid adding a framework or a dependency where a well-supported native interface is sufficient.

## Workflow

Create a focused branch, make reviewable commits, and open a draft pull request early. Explain the concrete behavior, privilege boundary, configuration changes, recovery path, and tests. Mark it ready only after automated checks pass and any untested hardware behavior is stated clearly.

```bash
sudo apt-get install build-essential bats shellcheck shfmt jq
make check
```

Use `make format` for shell formatting and `make sanitize` for the C sanitizer suite. Consult [docs/testing.md](docs/testing.md) for integration acceptance; do not report hardware tests that were not run.

## Implementation rules

- Keep sourced Bash modules free of system changes at load time. Use `module::function` names and fixed dispatch entries; quote variables and pass arguments as arrays where appropriate.
- Propagate external failures explicitly, including functions invoked inside `if`, `!`, or `||`, where relying on `set -e` is insufficient.
- Validate user-controlled IDs and paths before use. Never `eval` input, source saved state, interpolate user input into shell commands, or trust device-provided text in terminal/desktop messages.
- Use the core backup/atomic-write helpers for managed system configuration. Explain disruptive changes before asking for confirmation and preserve a practical local recovery route.
- Maintain strict privilege separation. Do not give the desktop user unrestricted logs or policy IPC merely to display notifications. Do not change firewall/container policy outside the selected scope.
- Test meaningful failure paths as well as success. Mock native mutations; a unit test must not change the host firewall, services, user settings, or USB policy.
- Keep C inputs bounded, handle partial reads/writes and errors, use monotonic time for intervals, and retain strict compiler warnings and sanitizer coverage.
- Update README/recovery instructions alongside behavior changes. Describe effective behavior and known gaps precisely.

Contributions are licensed under the repository's Apache-2.0 license. Report security vulnerabilities privately as described in [SECURITY.md](SECURITY.md).
