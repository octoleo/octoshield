# Debian packages and release builds

OctoShield's Debian package contains both the native GTK4/libadwaita application and the Bash CLI, plus the precompiled C monitor and fixed PolicyKit helper. End users install the `.deb` with APT; they do not need a compiler or a source checkout.

## Build from source

Build on the Ubuntu release and CPU architecture you intend to support, ideally in a disposable container or VM. A successful build on a newer Ubuntu release does not make its binaries compatible with an older release.

On Ubuntu 26.04, also install `gnu-coreutils` with APT before building. It supplies the explicit GNU worker supervisor without changing the system's default utilities; see [testing prerequisites](testing.md#cli-and-shared-backend).

```bash
sudo apt-get update
sudo apt-get install build-essential debhelper pkg-config \
    libgtk-4-dev libadwaita-1-dev libjson-glib-dev \
    bats jq shellcheck shfmt desktop-file-utils libxml2-utils appstream apt-utils gnupg python3

dpkg-buildpackage -us -uc -b
```

`make package` is the repository's convenience target for the package build. For version 1.3.2 on amd64, a local build emits `../octoshield_1.3.2_amd64.deb`; an arm64 build uses `_arm64.deb`. The local Debian filename does not identify which Ubuntu release built it: preserve that information when distributing it. CI renames assets to include the Ubuntu release while retaining internal package version `1.3.2`. Debian's shared-library dependency calculation lets APT reject missing or incompatible dependencies.

Inspect and install a locally built package in a disposable test system:

```bash
dpkg-deb --info ../octoshield_1.3.2_amd64.deb
dpkg-deb --contents ../octoshield_1.3.2_amd64.deb
sudo apt install ../octoshield_1.3.2_amd64.deb
```

These example filenames describe the amd64 1.3.2 build; use the actual emitted filename for another version or architecture.

## Program ownership and lifecycle

| Installed path | Purpose |
| --- | --- |
| `/usr/bin/octoshield` | Packaged terminal frontend |
| `/usr/bin/octoshield-gtk` | Native GNOME frontend |
| `/usr/lib/octoshield` | Shared Bash implementation, precompiled monitor, and supporting data |
| `/usr/libexec/octoshield-helper` | Fixed administrator-action entry point |
| `/usr/libexec/octoshield-session` | PolicyKit-authorized broker bound to one application session |
| `/usr/share/applications/io.vdm.OctoShield.desktop` | GNOME application launcher |
| `/usr/share/metainfo/io.vdm.OctoShield.metainfo.xml` | AppStream description, publisher, version, and screenshot references |
| `/usr/share/polkit-1/actions/io.vdm.OctoShield.policy` | Administrator authorization policy |
| `/usr/lib/systemd/user/octoshield-usb-agent.service` | Unprivileged USB prompt observer for the active desktop session |
| `/etc/xdg/autostart/io.vdm.OctoShield.UsbAgent.desktop` | Starts the USB prompt observer at desktop login |

Package installation does not select protections, trust USB devices, enable security-event collection, or start the GUI as root. It starts `octoshield-status.service` to report observed state without applying a profile. The observer also verifies expiry and reconciles saved firewall metadata under the operation lock; the kernel enforces each finite grant's deadline independently. Package upgrades retain configuration and profile state, stop/resume only the status observer while replacing code, and preserve the user's event-monitor enablement. Later upgrades respect a disabled or masked observer. Removal stops package-owned status and monitoring services and removes the program while retaining native host policies and private backups. Purge is not a security reset. Standalone `/usr/local` installations are retained; see [recovery.md](recovery.md#package-upgrades-coexistence-and-removal).

The package also supplies an XDG autostart entry for the normal-user USB prompt agent. It starts at the next desktop login or when opening OctoShield in the existing login. It reads sanitized status and requests a guided review; it never authorizes a device itself. This agent is independent of optional event notifications and is stopped during package removal.

The package declares GUI runtime dependencies. The independent `bash src/octoshield install` path installs the CLI only, without GTK/libadwaita/GNOME dependencies; it locally compiles the C monitor.

Applying timed firewall permissions requires an enabled, running observer, but their UTC deadline is enforced by the kernel independently of the application. An upgrade pause, stopped observer or uninstall cannot extend a timed rule's permission for new connections; established connections are not forcibly terminated. The observer maintains status and reconciles expired permissions; inert rules remain until the next Apply or reload. UFW persists permanent exceptions only, so reboot/reload drops timed grants sooner and does not reopen them from disk. Native `ufw status` omits runtime-only permissions; inspect OctoShield's status and profile configuration as well.

## Download and publication model

Installable stable packages are public downloads under [GitHub Releases](https://github.com/octoleo/octoshield/releases/latest). Select the Ubuntu-release and architecture label that matches the target laptop. Before merge, reviewers can also use package artifacts attached to a successful branch/PR Actions run. Those artifacts expire according to GitHub's displayed retention and are review builds rather than published releases.

The **Test lint and package** workflow currently builds this matrix:

| Build | Actions artifact | Distributed package |
| --- | --- | --- |
| Ubuntu 24.04 amd64 | `octoshield-ubuntu-24.04-amd64` | `octoshield_1.3.2_ubuntu24.04_amd64.deb` |
| Ubuntu 26.04 amd64 | `octoshield-ubuntu-26.04-amd64` | `octoshield_1.3.2_ubuntu26.04_amd64.deb` |

Artifacts and releases use separate `SHA256SUMS-ubuntu24.04` and `SHA256SUMS-ubuntu26.04` files. After extraction/download, run the matching command, for example `sha256sum -c SHA256SUMS-ubuntu24.04`. These detect content changes, not independent publisher identity.

After a push to `main`, CI publishes a new current version only after the complete test/package matrix and repository checks pass. It creates the matching `vX.Y.Z` tag and attaches both `.deb` files, checksums, and application assets. An already published version is not overwritten; merge a version increment to release subsequent changes. Pull requests remain test-only. Manual **Run workflow** builds are also test-only unless `publish` is explicitly enabled on `main`.

Use `bash scripts/version.sh --bump patch`, `--bump minor`, `--bump major`, or `--set X.Y.Z` on a review branch, then update release notes and merge after review. Publication uses GitHub's automatic `GITHUB_TOKEN`; no personal access token, store account, or APT signing secret is needed to make the `.deb` downloadable. See the [release procedure](distribution.md#versions-and-release-publication).

The native metadata identifies the developer as **Vast Development Method**, the application as **OctoShield**, and its desktop ID as `io.vdm.OctoShield`. The [distribution guide](distribution.md) describes release assets, semantic version maintenance, the automatic GitHub release token, and optional signed APT hosting. Direct package release needs no application-store credentials. APT publication separately requires the publisher's signing key and an explicitly configured client source.

## Acceptance

Package validation covers installation of the published 1.1.0, 1.2.0, 1.2.1 and 1.3.1 packages followed by a real upgrade to 1.3.2, reinstall, removal and purge. Each baseline has a fresh disposable container on Ubuntu 24.04 and 26.04. CI pins the old archives' SHA-256 values and checks both launchers, desktop metadata, PolicyKit policy, ownership, preserved recovery snapshots/native configuration/user preferences/profile state/monitor enablement, and the absence of automatic hardening. A live reader holds the actual operation lock during upgrade to exercise recovery from the older packages' failing removal scripts and normal observer shutdown from 1.2.1. Exclusive mutation locks still prevent replacement. Starting the status observer is intentional; starting the security-event collector without a previous user choice is forbidden. Native window tests run under an isolated display without applying privileged controls. See [testing.md](testing.md) for the separate hardware checklist.
