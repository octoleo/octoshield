# Security policy

OctoShield manages privileged host settings through native GNOME and terminal interfaces. The validation limits in [testing.md](docs/testing.md) apply to both; automated tests and graphical smoke tests do not establish protection against every attack or replace review on the target hardware.

## Report a vulnerability

Use the repository's private [GitHub vulnerability reporting form](https://github.com/octoleo/octoshield/security/advisories/new) when available. If private reporting is unavailable, open an issue containing only a request for a confidential reporting channel; do not disclose an exploit, credentials, sensitive logs, or affected private configuration publicly.

Include the affected commit/version, Ubuntu/kernel/package versions, minimal reproduction on a disposable host, expected versus actual behavior, and the privilege boundary involved. Redact usernames, network secrets, USB serial numbers, and token/password material.

## Design boundaries

- Bash modules use narrow functions and a fixed command registry. Persistent configuration is data, never sourced or evaluated.
- The standalone installer publishes root-owned files and compiles the C monitor from reviewed source; the Debian package supplies precompiled executables. Public bootstrap downloads come from one immutable resolved commit; this is consistency, not independent authenticity verification. Match downloaded packages to their release, architecture, and reviewed provenance.
- System actions require administrator privileges. The GTK application, desktop changes, and notifications run as the session user. The GUI launches a fixed PolicyKit-authorized helper using a validated argument vector; it does not launch arbitrary shell commands or run the entire desktop application as root.
- The GUI/backend boundary accepts only an explicit action allowlist and bounded typed JSON records. Native-command output is plain-text data, never markup, commands, or confirmation records. The backend independently validates identifiers even when the GUI already checked them.
- USB policy IPC is root-only. Sudo and PolicyKit policies determine authentication: passwordless grants, root access, or local overrides cannot be neutralized by a prompt in this tool.
- Installing, upgrading, removing, or purging the desktop package must not silently reset host firewall rules, USB policy, GNOME settings, or security backups. Package-owned monitoring processes have their own lifecycle; native host protections remain independent.
- The monitor processes selected native log events, accepts bounded category input, and exposes sanitized counters rather than raw logs to users. A forged local syslog identifier alone must not be accepted as trusted kernel/sudo/SSH provenance.
- Backups are private because they can include network credentials. Host policy changes can be partially applied if a native command fails; recovery must be deliberate and targeted.

Full-disk encryption, Secure Boot configuration, initramfs USB policy, invasive physical access, firmware attacks, trusted-device impersonation, browser/application exploits, and third-party container firewall rules are outside the protections implemented here. See the README for operational limits. Changes must preserve these distinctions rather than claim guaranteed security.
