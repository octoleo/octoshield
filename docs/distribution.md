# Direct packages and release preparation

OctoShield is maintained by **Vast Development Method** (https://www.vdm.io), as part of the **Octoleo** suite. Its display name is **OctoShield**, command/package name is `octoshield`, and desktop identity is `io.vdm.OctoShield`.

The supported delivery is a downloadable `.deb` containing the native GNOME application, complete CLI, compiled monitor, and fixed administrator helper. It retains the full application description, developer identity, light/dark artwork, desktop launcher, and AppStream metadata. The standalone CLI remains available without desktop dependencies. Direct downloads need no application-store account; an optional signed APT repository supports future package updates through Ubuntu's normal package tools.

## Install the package

Choose an artifact matching **both** the laptop's Ubuntu release and architecture. Current automated builds provide amd64 packages for Ubuntu 24.04 and 26.04. For example, after downloading the Ubuntu 24.04 package and its checksum file for version 0.2.0:

```bash
sha256sum -c SHA256SUMS-ubuntu24.04
sudo apt install ./octoshield_0.2.0_ubuntu24.04_amd64.deb
```

Use the actual filename and matching checksum for your release. Checksums detect changed downloads; they do not independently authenticate the publisher. APT resolves runtime dependencies; the laptop needs no compiler. Open **OctoShield** from GNOME's launcher or run `octoshield-gtk` as your normal user. No reboot is needed to open the application. The [README](../README.md) gives complete download, architecture, and standalone instructions.

The repository remains private. Sign into GitHub with access to download Actions artifacts or releases. Release preparation does not change repository visibility.

## Updates through a signed APT repository

After the publisher deploys a signed repository and provides its independently verifiable signing-key fingerprint, users may explicitly add it. Installing a downloaded `.deb` does **not** enroll an update source automatically. The planned default address is `https://octoleo.github.io/octoshield`; do not assume it is live. GitHub Pages must be configured and reachable, or the publisher must supply another HTTPS host. No production key or live repository is claimed by these instructions.

The published repository supplies a public key and separate source definitions for Ubuntu 24.04 (`noble`) and Ubuntu 26.04 (`resolute`). Current builds are amd64. Only use the source matching your installed Ubuntu version. If needed, install the verification/download tools with `sudo apt install ca-certificates curl gnupg`. Start in a new empty directory and obtain the actual published URL:

```bash
read -r -p 'Published OctoShield HTTPS repository URL: ' repository_url
repository_url=${repository_url%/}
curl --fail --show-error --location --proto '=https' --proto-redir '=https' \
    "$repository_url/octoshield-archive-keyring.gpg" -o octoshield-archive-keyring.gpg
gpg --show-keys --with-fingerprint octoshield-archive-keyring.gpg
```

Compare the complete fingerprint with the one confirmed through a trusted publisher channel. A fingerprint downloaded beside the key alone is not independent verification. **Stop if the key differs or a trusted expected fingerprint has not been provided.** After that check, download the source file for your Ubuntu release—for 24.04:

```bash
curl --fail --show-error --location --proto '=https' --proto-redir '=https' \
    "$repository_url/octoshield-noble.sources" -o octoshield.sources
cat octoshield.sources
```

On Ubuntu 26.04, download `octoshield-resolute.sources` instead. Review that `URIs` names the intended HTTPS repository, `Suites` matches your release, `Architectures` is `amd64`, and `Signed-By` is `/etc/apt/keyrings/octoshield-archive-keyring.gpg`. The component is `main`. Then explicitly install these two files:

```bash
sudo install -d -m 0755 /etc/apt/keyrings
sudo install -m 0644 octoshield-archive-keyring.gpg \
    /etc/apt/keyrings/octoshield-archive-keyring.gpg
sudo install -m 0644 octoshield.sources /etc/apt/sources.list.d/octoshield.sources
sudo apt update
apt-cache policy octoshield
sudo apt install octoshield
```

Once configured, fetch later updates with `sudo apt update` and `sudo apt install --only-upgrade octoshield`, or the distribution's normal update interface when it offers this package. APT validates signed repository metadata and package hashes. An unsigned test artifact is not an update source: never bypass authentication with `trusted=yes`, insecure-repository switches, or global `apt-key` trust.

The installed AppStream metadata and repository's package-mapped DEP-11 catalogue retain OctoShield's name, description, developer, features, and screenshots. Repository catalogue media URLs point to the published HTTPS repository, with the supplied artwork unchanged. App Center discoverability, third-party repository support, screenshot access, and update presentation depend on the Ubuntu frontend and its catalogue; they are not guaranteed by installing a `.deb`. APT remains the explicit update path. OctoShield's Ubuntu security-update control does not by itself opt this third-party repository into unattended upgrades; administrator update policy still applies.

To stop repository updates without removing the app or its protections, set `Enabled: no` in `/etc/apt/sources.list.d/octoshield.sources`, then run `sudo apt update`. Remove only this source and its dedicated keyring if deliberately unenrolling; package removal does not silently rewrite your chosen APT sources.

## Consent and system changes

Package installation installs program files and dependencies. It does not apply hardening, enroll USB devices, or enable monitoring automatically. Choose controls after opening the app.

- The desktop runs without administrator privileges. A fixed PolicyKit helper authenticates system actions; GNOME preferences and notifications remain in the user's session.
- Each protection explains its impact. Disruptive changes require explicit confirmation, including the existing-rule reset for UFW and physical review of the USB enrollment set.
- Relevant native configuration is backed up privately before modification, and action records identify changes. The GUI exposes action history rather than saved configuration secrets.
- Operations show busy state and results; detailed package/native output arrives at operation boundaries. Declining a pending confirmation stops its next step. Interrupted actions may need repair; there is no claim of atomic rollback across native commands.
- Office actions grant specific access without broadly undoing the other protections. The application does not promise immunity to every attack.

See [features](features.md), the [control-by-control README](../README.md#what-each-control-does), and [recovery](recovery.md) before selecting changes that affect networking, input devices, or shared services.

## Upgrade and clean removal

Install a newer matching `.deb` with APT to upgrade. Package upgrades preserve policy and do not start, enable, or restart monitoring automatically. Existing monitoring processes keep running until an explicit restart or a later session/reboot.

To remove the packaged application:

```bash
sudo apt remove octoshield
```

Removal stops package-owned monitoring and notification services and removes the application, CLI, helper, and installed launcher assets. It disables notification preferences in available user managers; offline users' home directories and custom units are left for their own review. Before uninstalling, each user can run `systemctl --user disable --now octoshield-notify.service`. See [recovery](recovery.md#package-upgrades-coexistence-and-removal) for a stale offline-user enablement link. If a system action is in progress, wait for it to finish before retrying a refused upgrade/removal.

Purging with `sudo apt purge octoshield` is also supported. Neither removal nor purge resets UFW/USBGuard/NetworkManager/sudo/AppArmor policy, restores GNOME preferences, or deletes private recovery backups. These are host settings that may still be protecting the laptop, not disposable application caches. Runtime dependencies installed through APT follow APT's normal dependency management.

If you also installed the standalone CLI under `/usr/local`, that separate installation remains. Review [coexistence and recovery](recovery.md#package-upgrades-coexistence-and-removal) for effective monitor units, command selection, and targeted restoration. Do not delete native security packages or backups as a blanket uninstall step.

## Builds, screenshots, and credentials

The **Test lint and package** workflow validates source changes and builds the native Debian packages. PR/branch artifacts are review builds. A reviewed version tag triggers a GitHub release after checks pass.

| Item | Configuration |
| --- | --- |
| Build and test jobs | No publishing credentials required |
| GitHub release | Uses the automatic, temporary `GITHUB_TOKEN`, exposed as `GH_TOKEN` only to the release step; job permission is `contents: write` |
| Direct `.deb` downloads | No application-store credentials or separate signing key required |
| Package artifacts | `octoshield-ubuntu-24.04-amd64` and `octoshield-ubuntu-26.04-amd64` |
| Documentation/media artifact | `octoshield-release-assets` |
| APT layout test artifact | `octoshield-apt-repository-test`; unsigned and never a trusted install source |

The media artifact contains `release-assets/`, `octoshield-assets-VERSION.tar.gz`, and `SHA256SUMS-assets`. It preserves the supplied light/dark artwork and includes native application screenshots plus AppStream metadata. Tagged releases attach twelve screenshots, the XML, archive, and checksums alongside the packages. CI screenshots use demonstration data; they show the interface, not measured protection on real hardware. Public AppStream consumers cannot retrieve image URLs hosted in a private GitHub release without access.

Build a local media bundle after installing the [GUI test dependencies](testing.md#native-gui), using a fresh output directory:

```bash
make ui-display-test
mkdir -p dist
bash scripts/release-assets.sh dist/release-assets
```

For native package build commands and lifecycle tests, see [packaging](packaging.md) and [testing](testing.md). The installed application and standalone CLI remain Bash and C; repository/catalogue preparation adds no Python runtime dependency to the product.

## Publisher setup for optional APT hosting

Normal builds always work without a signing key. They create an **unsigned test repository** to validate layout and hashes. It contains an `UNSIGNED-TEST-ONLY` marker and no enrollment templates or release signatures. Do not deploy it as a trusted update service.

Production APT hosting is a separate opt-in step after a successful tagged GitHub release. Configure GitHub Pages to use **GitHub Actions**, with a publicly reachable site. Set the repository URL to that site's actual address, including a configured custom domain if used. The supplied workflow deploys to Pages; setting a different URL does not deploy to an arbitrary host. Other hosting requires the publisher to serve the generated signed tree through their own process. The repository's current private status does not establish that Pages is enabled or accessible. No site has been published and no signing key has been supplied merely by adding this workflow.

| Name | Location | Required value |
| --- | --- | --- |
| `APT_SIGNING_KEY` | Secret in the `github-pages` environment | ASCII-armored private repository signing key controlled by the publisher |
| `APT_SIGNING_PASSPHRASE` | Optional secret in `github-pages` | Passphrase required by that key, if any |
| `APT_SIGNING_KEY_FINGERPRINT` | Repository variable | Full expected primary-key fingerprint: 40 uppercase hexadecimal characters |
| `APT_REPOSITORY_URL` | Repository variable | Actual published HTTPS base URL; proposed default is `https://octoleo.github.io/octoshield` |
| `APT_PUBLISH_ENABLED` | Repository variable | Exactly `true` after the publisher is ready; otherwise deployment remains disabled |

An authorized maintainer creates or selects the key on a trusted workstation, for example using GnuPG's interactive `gpg --full-generate-key`, and records the complete fingerprint with `gpg --list-secret-keys --with-fingerprint`. Use real publisher-controlled identity details and a reviewed key-expiry/rotation policy. Never commit the private key or fabricate a fingerprint.

Export and configure an existing approved key without printing its contents:

```bash
read -r -p 'Approved full repository signing-key fingerprint: ' repository_fingerprint
signing_directory=$(mktemp -d)
umask 077
gpg --armor --export-secret-keys "$repository_fingerprint" > "$signing_directory/key.asc"
```

Only after export succeeds, set the environment secret and remove the temporary export:

```bash
gh secret set APT_SIGNING_KEY --repo octoleo/octoshield --env github-pages \
    < "$signing_directory/key.asc"
rm -f -- "$signing_directory/key.asc"
rmdir -- "$signing_directory"
gh variable set APT_SIGNING_KEY_FINGERPRINT --repo octoleo/octoshield \
    --body "$repository_fingerprint"
```

Set `APT_SIGNING_PASSPHRASE` through the environment's secret UI or `gh secret set` interactive input if required. Set the real URL and enable flag as repository variables after checking hosting and the independently distributed public fingerprint. Keep tracing disabled while handling key material. Limit access to the signing environment and rotate/revoke a compromised key; changing a GitHub secret alone does not update clients' trusted keyrings.

The signing workflow uses an isolated temporary GnuPG directory and checks that the imported key matches the configured fingerprint. It generates `Release`, `InRelease`, and `Release.gpg`, public `.asc`/`.gpg` exports, a fingerprint file, and per-release `.sources` files. Missing configuration skips production publication successfully; unsigned output is never deployed by the Pages job. Before deployment, it also compares the tag with the canonical version on freshly fetched `main`; rerunning an older release skips APT publication so it cannot replace the current update repository.

The workflow runs `bash scripts/apt-repository.sh --input PACKAGE_DIRECTORY --assets RELEASE_ASSETS_DIRECTORY --output NEW_DIRECTORY`. Inputs are the two release-specific amd64 packages for one version and the assembled native assets. It separates `noble` and `resolute` indexes and package pools. Each suite's `main/dep11/` directory contains validated `Components-amd64.xml`, `Components-amd64.yml`, and compressed YAML. Media use versioned paths under `media/vVERSION/`; `Release` hashes include the catalogue before signing. Pages deployment replaces the repository tree with the current version's files; older release assets remain on GitHub, and rebuilding the same version can produce different captures. The repository identifies its Origin as `OctoShield` and Label as `Vast Development Method`. The publisher must keep hosting, signatures, keys, and repository metadata current after publication.

## Versions and release tags

Use `MAJOR.MINOR.PATCH`: major for incompatible changes, minor for compatible features, and patch for compatible fixes. While the project is `0.x`, describe behavior changes explicitly. A version number is not a security assurance. The helper accepts plain `X.Y.Z` without prerelease/build suffixes or leading zeroes.

Check consistency or prepare a newer version on a review branch:

```bash
bash scripts/version.sh --check
bash scripts/version.sh --set 0.2.1
bash scripts/version.sh --check
```

The helper updates the CLI, bootstrap banner, GUI, Debian changelog, and AppStream release/screenshot references while retaining earlier release entries. Review its diff and replace the new placeholder release notes. It does not commit, push a tag, or publish.

After review, merge, and validation on `main`, tag the agreed release. For example, **only when 0.2.0 is the intended release and its tag does not already exist**:

```bash
git switch main
git pull --ff-only
bash scripts/version.sh --check v0.2.0
git tag -a v0.2.0 -m 'OctoShield 0.2.0'
git push origin v0.2.0
```

Pushing the tag starts publication. The workflow checks matching versions and that the tagged commit belongs to `main`, then builds and attaches the release assets. Optional signed APT publication follows only when configured. Never move an already-published tag to different code. These instructions do not themselves create a tag or release.

APT reference: [source definitions and scoped Signed-By keyrings](https://manpages.debian.org/trixie/apt/sources.list.5.en.html), and [repository authentication](https://manpages.debian.org/trixie/apt/apt-secure.8.en.html).
