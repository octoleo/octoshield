# Security policy

Octoshield manages privileged host settings. Its initial release is subject to the validation limits in [testing.md](docs/testing.md); automated tests do not establish protection against every attack or replace review on the target hardware.

## Report a vulnerability

Use the repository's private [GitHub vulnerability reporting form](https://github.com/octoleo/octoshield/security/advisories/new) when available. If private reporting is unavailable, open an issue containing only a request for a confidential reporting channel; do not disclose an exploit, credentials, sensitive logs, or affected private configuration publicly.

Include the affected commit/version, Ubuntu/kernel/package versions, minimal reproduction on a disposable host, expected versus actual behavior, and the privilege boundary involved. Redact usernames, network secrets, USB serial numbers, and token/password material.

## Design boundaries

- Bash modules use narrow functions and a fixed command registry. Persistent configuration is data, never sourced or evaluated.
- The installer publishes root-owned files and compiles the C helper from the reviewed source. Public bootstrap downloads come from one immutable resolved commit; this is consistency, not independent authenticity verification.
- System actions require administrator privileges and local interactive use. Desktop changes and notifications run as the session user.
- USB policy IPC is root-only. Sudo policy still determines authentication: `NOPASSWD`, root access, or specific overrides cannot be neutralized by a prompt in this tool.
- The monitor processes selected native log events, accepts bounded category input, and exposes sanitized counters rather than raw logs to users. A forged local syslog identifier alone must not be accepted as trusted kernel/sudo/SSH provenance.
- Backups are private because they can include network credentials. Host policy changes can be partially applied if a native command fails; recovery must be deliberate and targeted.

Full-disk encryption, Secure Boot configuration, initramfs USB policy, invasive physical access, firmware attacks, trusted-device impersonation, browser/application exploits, and third-party container firewall rules are outside the protections implemented here. See the README for operational limits. Changes must preserve these distinctions rather than claim guaranteed security.
