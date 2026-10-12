# OctoShield desktop and Debian package milestone

Build one OctoShield application with a native GNOME interface and the existing Whiptail CLI. Both interfaces share the security controls, USB approvals, monitoring, office adjustments, and recovery behavior.

The Debian package includes precompiled binaries and both interfaces. Standalone CLI installation continues without GTK or other desktop build dependencies. CI will build downloadable packages, and tagged releases will publish versioned Debian artifacts.

Privileged operations remain in a narrowly scoped, administrator-authenticated helper; the graphical process remains unprivileged. Package installation does not automatically enable hardening. Existing security policy and private recovery records must survive updates and application removal.

Implementation and validation are tracked in the associated pull request.
