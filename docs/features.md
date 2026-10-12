# OctoShield features

OctoShield prepares Ubuntu laptops for conferences, shared networks, and everyday work. Maintained by [Vast Development Method](https://www.vdm.io) as part of the **Octoleo** suite, it brings established Ubuntu security controls into a native GNOME application and a complete terminal interface.

The `.deb` includes both interfaces and a compiled monitor. After explicit enrollment in the publisher's signed APT repository, Ubuntu's package tools can deliver application updates. Native AppStream metadata retains the application's description, developer details, and screenshot references for compatible software catalogues. The independent CLI installer needs no GTK or GNOME dependencies. Supported targets are Ubuntu 24.04 and 26.04 with systemd; desktop features require a normal GNOME session. See the [README](../README.md) to install and [distribution guide](distribution.md) for release preparation and removal.

## Choose and review each protection

| Feature | What it changes |
| --- | --- |
| Host firewall | Configures UFW for IPv4 and IPv6, denying unsolicited inbound and forwarded traffic. Setup explains and confirms resetting existing rules; outgoing traffic remains allowed. |
| USB authorization | Enrolls physically reviewed devices with USBGuard. Unknown devices remain blocked pending administrator approval. Choose temporary or persistent authorization for a reviewed device and port. |
| Network privacy | Disables autoconnect for existing Wi-Fi profiles, uses private MAC addresses, and reduces local name-discovery traffic. Reconnect to apply profile changes; choose new-profile autoconnect explicitly. |
| Service exposure | Stops and masks selected sharing, printing, Bluetooth, and remote-access services after explaining the impact. |
| GNOME settings | Configures screen locking, removable-media behavior, and available per-user remote-desktop settings. Saved GNOME preferences can be restored separately. |
| Authentication | Applies a syntax-checked sudo timeout. Existing passwordless grants remain effective; normal system account settings handle password changes. |
| Security updates | Enables automatic Ubuntu security updates while retaining configured origins and disabling automatic reboots in its settings. |
| AppArmor | Enables the service and reloads installed profiles in their existing modes; it does not claim to confine every application. |

Installing the application does not select or apply these protections. Disruptive actions explain the proposed change and require confirmation. The native desktop remains a normal-user application; its fixed helper requests administrator authorization for individual system actions.

## Inspect, adjust, and recover

- Inspect protection status, listening services, connection profiles, and selected security events.
- Enable the native event collector and restrained desktop notifications for selected firewall, USB, and authentication events.
- Grant a subnet-restricted TCP exception, restore one supported service, or enable autoconnect for one trusted connection when office work requires it.
- Review private action history and practical recovery guidance. System configuration snapshots support deliberate, targeted repair.

The GTK4/libadwaita application follows the desktop's light or dark appearance. Both interfaces share the same Bash control functions; C implements the graphical application and bounded event aggregation. During an operation, the application shows its busy state and results. Native-command details appear at operation boundaries, so package installation may take time between updates. Leave the window open until the action finishes; pending confirmation can be declined.

## Understand the limits

OctoShield reduces exposure without guaranteeing protection against every attack. It cannot detect passive surveillance. USB identities can be imitated, and early boot precedes USBGuard enforcement. Docker-published ports need separate firewall review. Disk encryption and Secure Boot are inspected only. Interrupted changes can leave partial state and may require targeted recovery.

Validate the selected controls on the actual laptop before relying on them. The [hardware checklist](testing.md#hardware-acceptance-checklist) distinguishes automated checks from physical acceptance. Removing the application stops its packaged monitoring services while preserving host security policy and recovery backups; [recovery guidance](recovery.md) explains how to change those settings intentionally.
