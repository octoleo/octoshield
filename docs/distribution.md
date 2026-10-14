# Direct packages and release preparation

OctoShield is maintained by **Vast Development Method** (https://www.vdm.io), as part of the **Octoleo** suite. Its display name is **OctoShield**, command/package name is `octoshield`, and desktop identity is `io.vdm.OctoShield`.

The supported delivery is a downloadable `.deb` containing the native GNOME application, complete CLI, compiled monitor, and fixed administrator helper. It retains the full application description, developer identity, light/dark artwork, desktop launcher, and AppStream metadata. The standalone CLI remains available without desktop dependencies. Direct downloads need no application-store account; an optional signed APT repository supports future package updates through Ubuntu's normal package tools.

## Install the package

Download a package from the public [latest release](https://github.com/octoleo/octoshield/releases/latest) matching **both** the laptop's Ubuntu release and architecture. Automated builds provide amd64 packages for Ubuntu 24.04 and 26.04. For example, download and install version 1.2.2 on Ubuntu 24.04 from a new empty directory:

```bash
(
set -e
curl --fail --show-error --location --proto '=https' --proto-redir '=https' \
    -O https://github.com/octoleo/octoshield/releases/download/v1.2.2/octoshield_1.2.2_ubuntu24.04_amd64.deb
curl --fail --show-error --location --proto '=https' --proto-redir '=https' \
    -O https://github.com/octoleo/octoshield/releases/download/v1.2.2/SHA256SUMS-ubuntu24.04
sha256sum -c SHA256SUMS-ubuntu24.04
sudo apt install ./octoshield_1.2.2_ubuntu24.04_amd64.deb
)
```

Only install after all downloads and checksum verification succeed. On Ubuntu 26.04 use the `ubuntu26.04` package and checksum instead. Use the actual filename and matching checksum for a later release. Checksums detect changed downloads; they do not independently authenticate the publisher. APT resolves runtime dependencies; the laptop needs no compiler. Open **OctoShield** from GNOME's launcher or run `octoshield-gtk` as your normal user. No reboot is needed to open the application. The [README](../README.md) gives complete download, architecture, and standalone instructions.

The repository and release assets are public. Release downloads do not require a GitHub account. Pull-request Actions artifacts remain available separately for review and are not stable releases.

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

## Upgrade troubleshooting

Version 1.2.1 fixes the false “a protection change is still running” refusal caused by the background status observer holding a read lock. Package maintenance now excludes new operations, pauses the observer, and only then acquires the replacement lock. It preserves whether the observer was running, including an observer that was disabled but manually started, and restores it after a successful update or an aborted attempt. Native UFW and USBGuard enforcement remains active throughout.

When upgrading from 1.1.0 or 1.2.0, dpkg first runs the installed package's old script. That script can still print its original warning; dpkg automatically retries with the corrected script from 1.2.1 and later. A successful installation ends with the new package configured and APT returning success. Install the current release directly over the old version; uninstalling or deleting `/var/lib/octoshield/lock` is unnecessary and unsafe.

A genuine protection operation is different: it can be applying policy or waiting for APT itself. The installer allows up to five seconds for it to finish, then safely refuses replacement if it remains busy. Finish or cancel the pending operation normally and retry. It never force-kills an active protection helper or replaces its code underneath it. Disk errors, broken dependencies and other package-manager failures still require their own repair.

APT's “Download is performed unsandboxed as root” notice for a local `.deb` in a private Downloads directory is separate from the upgrade failure. It means the `_apt` download user cannot traverse that directory; the root package manager can still read and install the package. It does not require changing home-directory permissions.

## Consent and system changes

Package installation installs program files and dependencies and starts the background status observer. It does not apply hardening, enroll USB devices, select a security profile, or enable security-event collection automatically. Choose controls after opening the app. The observer reports existing state and cleans up previously authorized expired firewall rules under the operation lock; kernel time matching enforces finite deadlines independently.

- The desktop runs without administrator privileges. The system's PolicyKit dialog unlocks one administrator session for that application lifetime; the fixed helper API handles reviewed system actions without repeatedly asking for a password. Closing or locking the application, or locking the desktop, ends the session and requires a new unlock. GNOME preferences and notifications remain in the user's session. System policy selects eligible administrator identities; Unix `root` group membership is not used as an authorization shortcut.
- Each protection explains its impact. Disruptive changes require explicit confirmation, including replacement of UFW exceptions and physical review of the USB enrollment set. Firewall profile switching never uses `ufw reset`.
- Relevant native configuration is saved in local, root-restricted recovery snapshots before modification, and action records identify changes. OctoShield does not separately encrypt these files. The GUI exposes action history rather than saved configuration secrets. These snapshots support configuration recovery; general folder backups and Restic/S3 integration remain outside this release.
- Operations show busy state and results; detailed package/native output arrives at operation boundaries. Declining a pending confirmation stops its next step. Interrupted actions may need repair; there is no claim of atomic rollback across native commands.
- Office actions grant specific access without broadly undoing the other protections. The application does not promise immunity to every attack.

See [features](features.md), the [control-by-control README](../README.md#individual-baseline-controls), and [recovery](recovery.md) before selecting changes that affect networking, input devices, or shared services.

## Upgrade and clean removal

Version 1.2.2 retains the package name `octoshield`, so downloading its matching `.deb` and opening it with a supported desktop package installer upgrades an existing 1.0.0, 1.1.0, 1.2.0 or 1.2.1 installation in place. The package manager asks for administrator permission. If double-clicking opens an archive viewer or no installer, use `sudo apt install ./octoshield_1.2.2_ubuntu24.04_amd64.deb` with your actual matching filename. Do not uninstall the older version first. Package upgrades preserve native policy, profile state, user preferences and private snapshots, and do not automatically select a new security profile.

The application and `octoshield updates check` provide an explicit, normal-user release check against `https://api.github.com/repos/octoleo/octoshield/releases/latest`. The request uses HTTPS, time and size limits, canonical stable versions, and exact official package URL matching for Ubuntu 24.04/26.04 amd64. It sends no GitHub token, does not run at startup, and never downloads or executes an installer as root. A failed check is reported as unavailable, not as proof the application is current. Opening the offered release or package link uses your normal desktop browser; install the downloaded package through the system package manager. Older remote versions are not recommended as upgrades. No store keys or credentials are needed for this check.

The user-session USB prompt agent starts at desktop login through XDG autostart; opening the new application also starts it for an existing login. This does not enable optional security-event notifications or authorize connected devices.

The status observer is introduced and enabled on installation or migration from 1.0.0. Package replacement briefly stops that observer so it cannot use half-replaced modules; configuration restores its previous running state. Later upgrades respect a deliberately disabled or masked observer. An open administrator session is revoked during package maintenance or broker replacement; reopen the updated app and authenticate again. UFW, USBGuard and existing security-event collection keep their current state. Opening the upgraded application refreshes an already-active notifier in your own session; it never enables a notifier you disabled. Event collector code reloads on an explicit restart or later reboot. A stale status indicator remains visible until a new observation is available.

To remove the packaged application:

```bash
sudo apt remove octoshield
```

Removal stops package-owned status reporting, monitoring and notification services and removes the application, CLI, helper, and installed launcher assets. It disables notification preferences in available user managers; offline users' home directories and custom units are left for their own review. Before uninstalling, each user can run `systemctl --user disable --now octoshield-notify.service`. See [recovery](recovery.md#package-upgrades-coexistence-and-removal) for a stale offline-user enablement link. If a system action is in progress, wait for it to finish before retrying a refused upgrade/removal.

Purging with `sudo apt purge octoshield` is also supported. Neither removal nor purge resets UFW/USBGuard/NetworkManager/sudo/AppArmor policy, restores GNOME preferences, or deletes private recovery backups. These are host settings that may still be protecting the laptop, not disposable application caches. Runtime dependencies installed through APT follow APT's normal dependency management.

If you also installed the standalone CLI under `/usr/local`, that separate installation remains. Review [coexistence and recovery](recovery.md#package-upgrades-coexistence-and-removal) for effective monitor units, command selection, and targeted restoration. Do not delete native security packages or backups as a blanket uninstall step.

## Builds, screenshots, and credentials

The **Test lint and package** workflow validates source changes and builds the native Debian packages. PR artifacts and default manual runs are review builds. A push to `main` automatically publishes its current version after all checks pass, if that version has not already been published. Maintainers may also explicitly request publication with a manual run on `main`, or push a matching reviewed version tag. Existing published releases are left unchanged.

| Item | Configuration |
| --- | --- |
| Build and test jobs | No publishing credentials required |
| GitHub release | Uses the automatic, temporary `GITHUB_TOKEN`, exposed as `GH_TOKEN` only to publication steps; job permission is `contents: write`. Do not create a custom token secret. |
| Direct `.deb` downloads | No application-store credentials or separate signing key required |
| Package artifacts | `octoshield-ubuntu-24.04-amd64` and `octoshield-ubuntu-26.04-amd64` |
| Documentation/media artifact | `octoshield-release-assets` |
| APT layout test artifact | `octoshield-apt-repository-test`; unsigned and never a trusted install source |

The media artifact contains `release-assets/`, `octoshield-assets-VERSION.tar.gz`, and `SHA256SUMS-assets`. It preserves the supplied light/dark artwork and includes native application screenshots plus AppStream metadata. Published releases attach twelve screenshots, the XML, archive, and checksums alongside the packages. CI screenshots show the interface in an isolated test environment, not measured protection on real hardware. Public release assets allow AppStream consumers to retrieve their referenced screenshots without GitHub authentication.

Build a local media bundle after installing the [GUI test dependencies](testing.md#native-gui), using a fresh output directory:

```bash
make ui-display-test
mkdir -p dist
bash scripts/release-assets.sh dist/release-assets
```

For native package build commands and lifecycle tests, see [packaging](packaging.md) and [testing](testing.md). The installed application and standalone CLI remain Bash and C; repository/catalogue preparation adds no Python runtime dependency to the product.

## Publisher setup for optional APT hosting

Normal builds always work without a signing key. They create an **unsigned test repository** to validate layout and hashes. It contains an `UNSIGNED-TEST-ONLY` marker and no enrollment templates or release signatures. Do not deploy it as a trusted update service.

Production APT hosting is a separate opt-in step after a successful GitHub release. Configure GitHub Pages to use **GitHub Actions**, with a publicly reachable site. Set the repository URL to that site's actual address, including a configured custom domain if used. The supplied workflow deploys to Pages; setting a different URL does not deploy to an arbitrary host. Other hosting requires the publisher to serve the generated signed tree through their own process. Making the source repository public does not configure Pages or supply an APT signing key. The downloadable `.deb` release works while APT hosting remains unconfigured.

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

The signing workflow uses an isolated temporary GnuPG directory and checks that the imported key matches the configured fingerprint. It generates `Release`, `InRelease`, and `Release.gpg`, public `.asc`/`.gpg` exports, a fingerprint file, and per-release `.sources` files. Missing configuration skips APT publication successfully; unsigned output is never deployed by the Pages job. Before deployment, it also checks the release against freshly fetched `main`; rerunning an older release skips APT publication so it cannot replace the current update repository.

The workflow runs `bash scripts/apt-repository.sh --input PACKAGE_DIRECTORY --assets RELEASE_ASSETS_DIRECTORY --output NEW_DIRECTORY`. Inputs are the two release-specific amd64 packages for one version and the assembled native assets. It separates `noble` and `resolute` indexes and package pools. Each suite's `main/dep11/` directory contains validated `Components-amd64.xml`, `Components-amd64.yml`, and compressed YAML. Media use versioned paths under `media/vVERSION/`; `Release` hashes include the catalogue before signing. Pages deployment replaces the repository tree with the current version's files; older release assets remain on GitHub, and rebuilding the same version can produce different captures. The repository identifies its Origin as `OctoShield` and Label as `Vast Development Method`. The publisher must keep hosting, signatures, keys, and repository metadata current after publication.

## Versions and release publication

Use `MAJOR.MINOR.PATCH`: major for incompatible changes, minor for compatible features, and patch for compatible fixes. A version number is not a security assurance. The helper accepts plain `X.Y.Z` without prerelease/build suffixes or leading zeroes. Version 1.0.0 is the first stable packaged release; subsequent versions follow the same tested publication path.

Prepare the next release on a review branch. For a patch release after 1.2.1:

```bash
git switch main
git pull --ff-only
git switch -c release/next-patch
bash scripts/version.sh --check
bash scripts/version.sh --bump patch
bash scripts/version.sh --check
git diff
```

Use `--bump minor` or `--bump major` for those increments, or `--set 1.2.1` to choose an exact newer version. The helper updates the CLI, bootstrap banner, GUI, Debian changelog, and AppStream release/screenshot references while retaining earlier release entries. Review the generated changes and replace generic release notes with an accurate description in `debian/changelog` and `data/io.vdm.OctoShield.metainfo.xml`. Update version-specific examples in documentation when appropriate. The helper does not commit, push, or publish.

Commit the version changes and release notes, open a pull request, and merge after review and passing checks. The resulting `main` workflow rebuilds and tests both supported Ubuntu packages, validates the APT repository layout, then creates the matching `vX.Y.Z` tag and GitHub release. Packages and application assets are uploaded to a draft first; the release becomes public after uploads and validation complete. A merged change that retains an already published version is tested but does not replace that release. Increment the version when those changes are ready for users.

To explicitly publish or retry the current version through GitHub's interface, open **Actions → Test lint and package → Run workflow**, select `main`, and enable **publish**. The equivalent authenticated maintainer command is:

```bash
gh workflow run ci.yml --repo octoleo/octoshield --ref main -f publish=true
```

The manual input defaults to `false`. Omitting it produces test artifacts without publishing. A manual run on a review branch cannot publish; merge first. The workflow also retains support for manually pushed `vX.Y.Z` tags that match the reviewed version on `main`, but a separate tag push is no longer required for normal releases.

The release job verifies version consistency and the reviewed `main` relationship before publishing. It leaves an existing public release unchanged, and does not move a tag to different code. A failed draft publication can be retried for its same source commit. GitHub supplies the temporary token automatically with `contents: write`; repository or organization Actions policy must permit that workflow permission. No personal access token, store credentials, production signing key, or manually created `GITHUB_TOKEN` secret is required. Optional signed APT publication follows only when its separate settings are configured.

Check the workflow's release job if a release is missing: a pull request or default manual run produces artifacts only; failed tests prevent publication; an unchanged already published version is skipped. Repository visibility alone does not trigger a build. Use the explicit manual command above to publish the current version after configuration or a failed run is corrected.

APT reference: [source definitions and scoped Signed-By keyrings](https://manpages.debian.org/trixie/apt/sources.list.5.en.html), and [repository authentication](https://manpages.debian.org/trixie/apt/apt-secure.8.en.html).
