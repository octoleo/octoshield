# Debian packages and release builds

OctoShield's Debian package contains both the native GTK4/libadwaita application and the Bash CLI, plus the precompiled C monitor and fixed PolicyKit helper. End users install the `.deb` with APT; they do not need a compiler or a source checkout.

## Build from source

Build on the Ubuntu release and CPU architecture you intend to support, ideally in a disposable container or VM. A successful build on a newer Ubuntu release does not make its binaries compatible with an older release.

```bash
sudo apt-get update
sudo apt-get install build-essential debhelper pkg-config \
    libgtk-4-dev libadwaita-1-dev libjson-glib-dev \
    bats jq shellcheck shfmt desktop-file-utils libxml2-utils

dpkg-buildpackage -us -uc -b
```

`make package` is the repository's convenience target for the package build. For version 0.2.0 on amd64, a local build emits `../octoshield_0.2.0_amd64.deb`; an arm64 build uses `_arm64.deb`. The local Debian filename does not identify which Ubuntu release built it: preserve that information when distributing it. CI renames assets to include the Ubuntu release while retaining internal package version `0.2.0`. Debian's shared-library dependency calculation lets APT reject missing or incompatible dependencies.

Inspect and install a locally built package in a disposable test system:

```bash
dpkg-deb --info ../octoshield_0.2.0_amd64.deb
dpkg-deb --contents ../octoshield_0.2.0_amd64.deb
sudo apt install ../octoshield_0.2.0_amd64.deb
```

These example filenames describe the amd64 0.2.0 build; use the actual emitted filename for another version or architecture.

## Program ownership and lifecycle

| Installed path | Purpose |
| --- | --- |
| `/usr/bin/octoshield` | Packaged terminal frontend |
| `/usr/bin/octoshield-gtk` | Native GNOME frontend |
| `/usr/lib/octoshield` | Shared Bash implementation, precompiled monitor, and supporting data |
| `/usr/libexec/octoshield-helper` | Fixed administrator-action entry point |
| `/usr/share/applications/org.octoleo.OctoShield.desktop` | GNOME application launcher |
| `/usr/share/polkit-1/actions/org.octoleo.octoshield.policy` | Administrator authorization policy |

Package installation does not select protections, trust USB devices, enable monitoring, or start the GUI as root. Monitoring remains opt-in. Package upgrades retain configuration and do not restart active monitoring automatically. Removal stops package-owned monitoring and removes the program while retaining native host policies and private backups. Purge is not a security reset. Standalone `/usr/local` installations are retained; see [recovery.md](recovery.md#package-upgrades-coexistence-and-removal).

The package declares GUI runtime dependencies. The independent `bash src/octoshield install` path installs the CLI only, without GTK/libadwaita/GNOME dependencies; it locally compiles the C monitor.

## Download and publication model

Before merge, use the package workflow artifacts attached to the reviewed branch/PR's successful Actions run. Select the Ubuntu-release and architecture label that matches the target laptop. Artifacts are downloadable review builds with the retention shown by GitHub; they are not automatically a public release.

The **Test lint and package** workflow currently builds this matrix:

| Build | Actions artifact | Distributed package |
| --- | --- | --- |
| Ubuntu 24.04 amd64 | `octoshield-ubuntu-24.04-amd64` | `octoshield_0.2.0_ubuntu24.04_amd64.deb` |
| Ubuntu 26.04 amd64 | `octoshield-ubuntu-26.04-amd64` | `octoshield_0.2.0_ubuntu26.04_amd64.deb` |

Artifacts and releases use separate `SHA256SUMS-ubuntu24.04` and `SHA256SUMS-ubuntu26.04` files. After extraction/download, run the matching command, for example `sha256sum -c SHA256SUMS-ubuntu24.04`. These detect content changes, not independent publisher identity.

The repository remains private. Access to workflow artifacts and release assets follows the repository's GitHub permissions. Creating a release does not make the repository public, and an unauthenticated raw `main` bootstrap cannot fetch a private checkout.

Pushing a `v*` tag such as `v0.2.0` triggers release automation, which builds packages for the configured matrix and attaches assets to the GitHub release. Branch and pull-request builds validate/package code without publishing a release. Tag only a reviewed, validated commit whose version matches the Debian changelog; do not treat an unmerged PR artifact as a release. Creating these workflow files does not itself publish a release.

## Acceptance

Package validation must cover install, upgrade, and remove in a disposable environment; check both launchers, desktop metadata, PolicyKit policy, file ownership, and the absence of automatic hardening/monitor activation. A GUI smoke test should open the actual native window under a test display without executing privileged controls. See [testing.md](testing.md) for the separate hardware checklist.
