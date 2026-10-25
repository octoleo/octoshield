# Recovery and narrow adjustments

Use a local terminal. If network hardening fails, disconnect Wi-Fi/Ethernet and inspect the failure before reconnecting. A failed operation can leave partial changes: OctoShield returns failure and keeps the change record; it does not promise an automatic system-wide rollback. Standalone installation stages the application separately and attempts to retain the previous installed program when publishing fails.

## Package upgrades, coexistence, and removal

The Debian package owns `/usr/bin/octoshield`, `/usr/bin/octoshield-gtk`, `/usr/lib/octoshield`, its fixed PolicyKit helper at `/usr/libexec/octoshield-helper`, its application-session broker at `/usr/libexec/octoshield-session`, and its USB prompt agent/autostart entry. A standalone installation owns `/usr/local/bin/octoshield` and `/usr/local/lib/octoshield`. Package operations do not silently delete that standalone copy.

Inspect command resolution and monitoring units before switching installations:

```bash
type -a octoshield
/usr/bin/octoshield --version
systemctl cat octoshield-monitor.service
systemctl --user cat octoshield-notify.service
```

Use `/usr/bin/octoshield` for the packaged CLI and `/usr/local/bin/octoshield` for the standalone CLI. The graphical app always uses the packaged helper. Both act on the same host protections and private backup area; they are not isolated security profiles. Do not run changes concurrently or alternate incompatible versions.

An older standalone installation may have placed service overrides under `/etc/systemd/system` or `/etc/systemd/user`. Those override the package's vendor units and can still point at `/usr/local`. Keep the standalone files until you have deliberately reapplied monitoring with the packaged version and verified the effective unit paths. Do not blindly remove `/etc` service overrides.

Package upgrades replace the existing `octoshield` package without resetting protection settings, profiles, preferences or snapshots. Download the matching newer `.deb` and open it with your desktop package installer, or run the matching APT command from the README; administrator authentication belongs to the package manager. No prior uninstall is needed. The status observer is automatically introduced on upgrade from 1.0.0 and pauses during later package replacement. Opening the upgraded app refreshes an already-active notifier in your own session without enabling disabled notifications. The collector reloads on an explicit restart or reboot. To refresh an active collector, or refresh notifications from the CLI:

```bash
sudo systemctl try-restart octoshield-monitor.service
systemctl --user try-restart octoshield-notify.service
```

To remove the desktop package:

```bash
sudo apt remove octoshield
```

Removal stops the package's monitoring services and removes its application; it does **not** undo UFW rules, USBGuard trust, GNOME settings, service masks, update/sudo settings, or private backups. Purging also is not an “unharden” operation. A retained standalone installation can still manage protections; otherwise reinstall the package or use the native system tools and targeted procedures below. Check any pre-existing standalone service overrides separately.

If package upgrade/removal reports an OctoShield operation in progress, let that action finish and retry APT. Do not force package removal or kill the helper during a system change.

During package replacement/removal, `/run/octoshield-package-maintenance` prevents new system changes from starting against incomplete program files and revokes any open administrator session. Normal completion clears it. Reopen the updated application and authenticate again. If a package operation is interrupted, repair the package first with `sudo dpkg --configure -a`, then retry the intended APT operation as appropriate. Confirm that no APT/dpkg operation remains active and that package files are consistent before removing only a stale maintenance marker with `sudo rm -- /run/octoshield-package-maintenance`. Do not delete the active-operation lock. Reboot clears `/run`, but does not by itself repair an interrupted package installation.

Removal stops the USB prompt agent and disables the notifier in available user managers. Offline users' home directories and custom units are not rewritten. Each user can disable their notification preference before uninstalling:

```bash
systemctl --user disable --now octoshield-notify.service
```

After removal, an offline user's previous enablement may remain as a dangling link at `${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/graphical-session.target.wants/octoshield-notify.service`. Inspect it with `readlink` and remove only that exact link if it is dangling and points to the removed packaged unit. Retain working standalone or custom unit links; do not remove the entire user systemd directory.

## Repair retired OctoShield settings

After upgrading, open **Recovery & updates → Repair system**, or run this from your normal local terminal:

```bash
octoshield repair
```

If a standalone installation is also present, select the updated package explicitly with `/usr/bin/octoshield repair`. The graphical action uses the application's existing administrator session. The CLI requests elevation once for the complete repair operation, including inspection, backup and validation. A zero sudo timeout does not require a separate password for every command inside that already-authorized operation.

Repair inspects a fixed catalogue of known changes needed by the installed version. It shows the applicable cleanup before asking for confirmation, records the operation under `/var/lib/octoshield/backups`, and checks the result. A completed repair is safe to run again: native state is inspected again and a setting that no longer needs cleanup is left alone. An error or a preserved conflict remains visible; the action does not claim that every possible system problem has been repaired.

The first repair removes the retired **Fresh administrator authentication** policy. Earlier versions wrote `/etc/sudoers.d/99-octoshield` with `Defaults timestamp_timeout=0`, which requires a new authentication for each separate sudo command whose policy requires a password. This was a system sudo setting, not a temporary account-password change. Sudo's timestamp cache records recent authentication rather than retaining the account password.

The repair recognizes the unchanged generated file and consults its original transaction history, walking back from the newest activation past backups of the generated policy. When OctoShield created the file, cleanup removes that one drop-in. When it replaced an existing file, cleanup restores the verified original configuration from that activation chain. A successfully restored original is recognized on subsequent inspections. If no original snapshot is available, the preview explicitly explains that only the recognized generated file can be removed, and retains a recovery copy. A record claiming that an original existed but lacking its safe original contents is a conflict; it is not treated as permission to delete the file. Locally modified files, unsafe paths, invalid markers, and conflicting recovery evidence are preserved and reported for review. The repair retains a private copy outside `/etc/sudoers.d`, checks the full configuration with `visudo --check`, and restores its pre-repair copy if validation after the change fails.

The computer's existing distribution and administrator policy determines the resulting timeout. Repair does not set a new universal timeout, remove passwordless grants, or alter unrelated sudo rules. It also does not change account passwords, apply pending profile edits, or restore firewall/USB/network baselines. Use the corresponding profile controls for those deliberate changes.

Package installation and upgrade preserve native policy; the cleanup runs only when you choose **Repair system**. Stopping OctoShield, rebooting, changing your password, or uninstalling the application does not remove an existing zero-timeout drop-in. Review the repair after updating instead of reactivating the removed feature from an older standalone copy.

If automatic repair reports a conflict, use the transaction instructions below and the [manual sudo recovery guidance](#sudo-updates-and-apparmor). Preserve the current file and keep a trusted administrator shell open until the full configuration validates. A fresh normal-user sudo authentication followed promptly by another harmless sudo command in the same terminal can confirm whether the existing policy allows reuse again. Separate PolicyKit dialogs in the graphical application are governed by its application session, not by sudo's terminal timestamp.

## Profiles, overrides and restoration

Version 1.1 keeps 1.0.0 policies as they are until you explicitly adopt a profile. The profile selector is desired configuration; the live indicators report what was actually observed. A partial or failed switch can leave different areas in different states. Read each result before retrying. The observer deliberately does not treat a successful command as proof that all protections match.

Use `octoshield profile show NAME` to inspect saved choices and `octoshield profile apply NAME CONTROL` to change only one area. Saved edits are pending until applied. `octoshield profile restore CONTROL` restores that area's captured pre-profile baseline; `octoshield profile restore` attempts available baselines for all managed areas after review. USB restoration returns to the retained pre-profile authorization policy, not to unrestricted USB. Existing active connections are not forcibly terminated by firewall switching.

Profiles and original-control snapshots live privately beneath `/var/lib/octoshield/profiles`; USB profile policies live beneath `/var/lib/octoshield/usb`. They are root-owned data and are not shell scripts. Do not delete them as a first troubleshooting step. Package updates and removal retain them. Baselines capture the state before profile management; for an existing 1.0.0 user, that may already be the hardened conference configuration, not an older office configuration that was never saved.

After a native control is successfully restored, a later first adoption captures its then-current settings as the next baseline. Customized UFW before/after rule files require manual review before adoption; OctoShield does not claim that its standard profile owns arbitrary administrator-added filtering chains.

If OctoShield reports external changes or an interrupted application, inspect the native policy and private action history. Do not blindly replace the recorded baseline or edit its expected fingerprints to bypass the conflict. Reconcile the specific native settings with a known transaction or use the targeted recovery procedures below. Global profile changes span several native tools and are not atomic; unaffected areas remain enforced if another area fails.

For saved network settings, **Connection privacy → Review external changes** or `sudo octoshield connections reconcile` lists changed connection UUIDs and privacy properties, added/deleted connections, and changes to OctoShield's global NetworkManager configuration. Inspect any reported global configuration change before accepting. Acceptance records the reviewed current state without changing native settings, reconnecting, or replacing the original baseline. A change during review aborts acceptance. Individual connection saves do not require this global acceptance and do not silently accept unrelated differences.

**Restore** also finds baselines created by individual connection edits when no profile is active. Network restoration previews its actual saved-setting changes and checks them after writing. Connections added outside the baseline remain intact; deleted profiles are not recreated. Active connections are not reconnected. A restore rejected before native changes leaves its expected state unchanged, including on repeated attempts. A partial native restore retains the baseline for a later retry. Accepting external settings and subsequently restoring the original baseline can undo those reviewed external settings; inspect the restore preview first.

An action record is an audit trail, not proof that the requested setting succeeded. Open **Recovery & updates → Inspect transaction**, or use `sudo octoshield backup-show ID` with the transaction ID from the operation details. A failed connection save refreshes actual connection details automatically. Automatic-connection preferences need no reconnect; discovery and MAC-address changes can require one.

The status cache is ephemeral at `/run/octoshield/status.json`. If it is stale, inspect `sudo journalctl -u octoshield-status.service -n 50 --no-pager` and `systemctl status octoshield-status.service`. After resolving the cause, restart only that observer with `sudo systemctl restart octoshield-status.service`. Stopping it prevents fresh status and automatic cleanup of expired rule records, but does not disable UFW, USBGuard or timed rules' kernel-enforced UTC deadlines. Cleanup resumes under the operation lock when the observer runs; delays do not extend timed access.

Timed firewall permissions are runtime-only and stop permitting new connections at their kernel UTC deadline, including after uninstall. Existing established connections retain UFW's normal stateful behavior and are not forcibly terminated. A reboot or `sudo ufw reload` drops timed grants sooner while retaining permanent UFW rules. OctoShield reports that narrower state and allows explicit profile application to restore still-unexpired permissions. Expired permissions never reopen automatically during boot. Use `octoshield status` and `octoshield profile show NAME` to inspect actual state and saved deadlines, because `ufw status` alone does not list timed runtime grants. Applying a new timed grant requires a running observer for status and cleanup and kernel time-match support; unsupported matching is refused without an untimed fallback.

## Recover a failed firewall change

“The previous firewall change did not complete” is a saved operation result. It does not mean another process is still running. It deliberately blocks another permission change until the existing firewall is inspected and recovered. Deleting a lock, restarting the app or repeatedly clicking **Review and allow access** cannot resolve that recorded failure.

Before 1.3.3, the firewall verifier required UFW to display `deny (routed)`. UFW normally displays `disabled (routed)` when IP forwarding is disabled, including on ordinary laptops with the correct configured DROP policy. This could mark a successfully applied firewall as failed. Version 1.3.3 accepts that display only when the configured defaults and actual IPv4/IPv6 input paths and default policies also verify. Other native failures remain possible; inspect the saved action history and the new native finding to determine the cause on your machine. This distinction follows [UFW's default-policy reporting implementation](https://sources.debian.org/src/ufw/0.36.2-9/src/backend.py).

After installing the updated package and reopening the app, select **Overview → Review & recover**, or open **Access & exceptions → Firewall status and recovery**. The section identifies the selected saved profile, its recorded assignment, the last result and the current native finding. Permission actions remain unavailable while recovery is needed. Recovery and inspection preserve your pending service, network and duration choices.

Choose the action matching the displayed evidence:

| Action | Reviewed result |
| --- | --- |
| **Inspect / Refresh** | Refreshes the native finding and recovery choices without changing policy. |
| **Review and apply PROFILE** | Reapplies only that selected saved firewall profile and its saved exceptions, then verifies it. Other protection areas and the pending permission form are retained. |
| **Review external changes** | Shows native rule differences and current configuration before accepting the displayed state for conflict checks. It retains the original baseline, changes no firewall rules, and still requires a separate Apply or Restore. |
| **Restore original firewall** | Previews and restores the retained pre-profile configuration, including whether UFW was enabled. Native readback must succeed before the original recovery evidence is released. This can reduce protection. |
| **View last change** | Opens the verified private transaction reference when the result contains one. Older results without that reference remain inspectable through **Recovery & updates → Inspect transaction**. |

For the reported Office profile, the equivalent reviewed terminal workflow is:

```bash
octoshield access list office
octoshield access recover office
```

If inspection reports supported external changes, review them first with `octoshield access reconcile office`, then explicitly choose `octoshield access recover office` or `octoshield access restore`. Each command retains the normal authentication and confirmation flow. Select your actual saved profile name instead of `office` when appropriate. On systems with both installation types, use `/usr/bin/octoshield` to select the updated package.

After recovery succeeds, review your network permission separately. For HTTP and HTTPS, select the detected local network and **Until revoked**, then use **Review and allow access**. Recovery does not grant that pending permission automatically. An allowed IPv4 subnet does not also grant IPv6 access; Docker-published services still require their separate forwarding review.

Unsafe or missing baseline data, modified UFW hooks and unsupported native input rules are preserved for manual inspection. The application does not replace recovery evidence, erase a failure, or approve a configuration it cannot safely preview simply to enable a button. Preserve `/var/lib/octoshield/profiles` and the relevant transaction. Do not use `ufw reset` or delete profile records as a generic workaround; the targeted restoration guidance below remains available when automatic recovery cannot verify the saved state.

## Operations and automatic recovery

From 1.2.2, ordinary background observation no longer makes Apply immediately fail with “Another OctoShield operation is running.” A requested change closes admission to new readers, reports that it is waiting, and lets existing inspections finish before entering the normal review and confirmation flow. You do not need to keep retrying. No policy changes begin while the helper is waiting for the lock.

Full inspections have a 60-second deadline and a three-second termination grace; USB-only workers have an eight-second deadline and a one-second grace. These limits also cover manual inspection and the final observation after a change. The supervisor targets only the worker it started and its descendants. The background service retries subsequent observations automatically; a failed snapshot never becomes a fresh successful observation. A writer waits at most 70 seconds for inspection locks. Finishing a CLI or GUI operation releases its locks even if its parent application remains open.

OctoShield selects GNU timeout explicitly so a stalled worker's descendants are terminated together and release inherited locks. On Ubuntu 26.04, APT supplies `gnu-coreutils` alongside the distribution's default utilities; on Ubuntu 24.04, the existing GNU `/usr/bin/timeout` is used. The standalone installer supplies the same requirement. No system-wide coreutils replacement or manual process killing is needed.

An actual protection change is different from a status reader. A second change is refused while the first is running or waiting for your confirmation. Complete or decline that confirmation in the original window. The application does not kill another administrator's operation, terminate APT/dpkg mid-transaction, or delete lock files to pretend that a lock was released. If an unexpected external or older helper still owns the state after the bounded wait, the refusal explicitly says that the new change did not start. The existing operation remains intact for diagnosis.

Do not stop the status service as a routine workaround: temporary firewall permissions need the enabled, running observer. Upgrading the application preserves the existing native policy, profile choices and USB permissions. After an upgrade, reopen the app and unlock a new administrator session.

## Graphical startup and authentication

Start `octoshield-gtk` as the normal logged-in GNOME user to see startup diagnostics. Do not run the application with `sudo`. A package built for another Ubuntu release or CPU architecture is not a supported workaround for missing runtime libraries; install the matching build with APT.

The application's unlock uses GNOME's PolicyKit authentication dialog. The system selects the eligible administrator account; OctoShield never asks you to type a password into its own fields. Once unlocked, normal refreshes and reviewed controls reuse that application's private session. Closing the window or locking the application/desktop ends it; reopen or unlock and authenticate again after an interrupted or failed session. Do not add users to the Unix `root` group or install a blanket passwordless PolicyKit rule to bypass an authentication problem.

If authentication is unavailable, check that you have an active local GNOME session and the package's PolicyKit helper/policy are installed. The terminal interface remains available through `/usr/bin/octoshield`. GNOME settings and notification actions require your real user session, not a root terminal or SSH session. USB devices remain blocked when a prompt is closed, authentication is cancelled, the session is locked, or a reviewed device/profile changes. Open the USB page after unlocking to review any remaining blocked device; repeatedly dismissing the same attachment does not repeatedly authorize or enroll it.

The Recovery page displays transaction action history, not raw configuration snapshots containing network secrets. For an interrupted or failed operation, inspect that history and apply only the relevant recovery below. Keep the application open until the backend finishes; declining an outstanding confirmation cancels the next step but does not undo earlier changes from that operation.

## Find the relevant system snapshot

```bash
octoshield backups
```

The GUI Recovery page offers the same listing and an action-history view. From the CLI, inspect one selected transaction without exposing its saved configuration files:

```bash
read -r -p 'Transaction ID to inspect: ' snapshot_id
octoshield backup-show "$snapshot_id"
```

System transactions are stored under `/var/lib/octoshield/backups/DATE-PID/` with root-only access. The actual identifier is printed after each operation. Each transaction contains:

| Path within the transaction | Meaning |
| --- | --- |
| `actions.log` | Actions, failures, and original service states when recorded |
| `original/etc/...` | Copies of files/directories that existed before the first change in this transaction |
| `saved/etc/...` | Marker containing `existing` or `absent` for each backed-up path |

For example, a backup of `/etc/default/ufw` is `original/etc/default/ufw`; its marker is `saved/etc/default/ufw`. Restoring an `absent` path means removing only the new file after reviewing it. Do not copy marker files into `/etc`.

Open a root shell and select a real transaction interactively:

```bash
sudo -i
ls -1 /var/lib/octoshield/backups
read -r -p 'Transaction ID to inspect: ' snapshot_id
if [[ ! $snapshot_id =~ ^[0-9]{8}T[0-9]{6}Z-[0-9]+$ ]] ||
   [[ ! -d /var/lib/octoshield/backups/$snapshot_id ]]; then
    printf 'No matching transaction.\n' >&2
    exit 1
fi
snapshot="/var/lib/octoshield/backups/$snapshot_id"
cat "$snapshot/actions.log"
find "$snapshot/saved" -type f -print
```

The following system restore examples assume that root shell and selected `snapshot`. Choose a transaction containing the relevant original file. Keep the current file if you need to compare changes. NetworkManager backups contain connection secrets; keep them private and do not attach them to public issues.

## Firewall

The Conference firewall action replaces exceptions through the profile engine without resetting or deliberately disabling an active firewall. A failed or interrupted operation is reported as incomplete. Review the saved transaction, `ufw status verbose`, and OctoShield's observed status before relying on the policy; runtime timed grants appear only in OctoShield's verification.

Prefer re-running `octoshield apply firewall` from your normal terminal when you want the conference policy. To deliberately restore an earlier UFW policy from a relevant snapshot, while disconnected:

```bash
test -d "$snapshot/original/etc/ufw" &&
test -f "$snapshot/original/etc/default/ufw" &&
cp -a -- "$snapshot/original/etc/ufw/." /etc/ufw/ &&
cp -a -- "$snapshot/original/etc/default/ufw" /etc/default/ufw &&
ufw --force enable &&
ufw status verbose
```

This restores the saved rules and **enables** them; it does not restore a previous disabled runtime state. Review the restored inbound exceptions and IPv6 setting. Container-published ports still require separate checks.

Use **Access & exceptions** or `octoshield access` to review and revoke the selected permission. Guided changes apply and verify immediately; editing the lower-level saved profile still requires Apply. Direct `ufw` edits are treated as external changes and require reconciliation before OctoShield overwrites them. Re-running the Conference firewall action replaces the exception set after confirmation.

A failed guided access change attempts to restore the previous policy. If restoration also fails, the result stays failed and the transaction records what happened; inspect native rules and use **Protections → Restore** to restore the captured baseline after reviewing its impact. Do not infer successful closure from a failed command. Expired permissions are never renewed automatically.

## Network profiles

Use **Connection privacy** or `octoshield connections` to select a connection by name. Set autoconnect, discovery or the Wi-Fi MAC choice for that connection. The change is retained as an override in its effective network profile; the legacy office-network command uses the same path. Reconnect explicitly after reviewing the interruption. Saved settings and current runtime verification are separate; a successful save does not prove that an old active connection already uses the new settings.

## Docker and diagnostic findings

Open **Details & fixes** or `octoshield diagnostics`. The report names observed bindings, relevant configuration sources and inspection limits. Forwarding is required for common Docker bridge networks; disabling it or Docker's firewall management globally can break working containers. A localhost port mapping is different from a wildcard mapping, and neither inspection alone proves all possible network paths are isolated.

The supported Compose repair runs as your normal user, with the Docker permissions you already have. It verifies the live container and source model, writes a dedicated `.octoshield/SERVICE.local.yaml` override, and recreates only that service. The plan shows the real paths, service, bindings and exact deployment command. No original Compose source is rewritten, and no unrelated service is started deliberately. A changed source, unfamiliar network mode, missing Docker access or unsupported version stops the automatic operation with an explanation. Nondefault resource policies, static or custom network endpoints, unexpected aliases and restart-policy drift require a manual source-guided change.

The private `.octoshield/SERVICE.reviewed.json` snapshot retains the exact resolved deployment model and pins the running image for this execution and recovery. The permanent `.local.yaml` file overrides ports only, so future deployments can upgrade images normally. The snapshot is restricted to its owner and can contain environment values; do not publish it with diagnostic reports. Service recreation retains mounted volumes but replaces unmounted changes in the container's writable layer. Back up any application data held there before approving recreation.

Keep the generated override in future deployment commands. Running only the original Compose files can reopen broader ports. If recreation or verification fails, inspect the reported running state and override before retrying; the tool does not silently restore broad publication to make the command succeed. To deliberately restore earlier access, review the original configuration and recreate only the affected service using its original file set. This can expose its ports again. Verify local and outbound access as well as access from a second device after either change.

Disk-encryption details distinguish detected root backing encryption from separate home, swap or unsupported storage. An unknown result is not evidence of an unencrypted disk. These screens never format, encrypt or migrate storage.

Full profile recovery is sensitive: saved directories can contain passwords and certificates, and some profiles originate in Netplan or another backend. Compare the saved `/etc/NetworkManager/system-connections` and `/run/NetworkManager/system-connections` directories with the current state, restore only the affected profile files with their original ownership/modes, then run:

```bash
nmcli connection reload
nmcli general reload conf
```

Restore or remove `/etc/NetworkManager/conf.d/90-octoshield.conf` according to its snapshot marker if you want to change the default policy. Reconnect manually. File restoration alone does not update an already active connection, and backend-managed profiles may require editing their originating configuration.

## USB enrollment interrupted

During first enrollment, OctoShield temporarily masks `usbguard.service` and persistently masks `usbguard-dbus.service`. Until a reviewed policy starts successfully, USB protection is **not active**. Its private progress markers are under `/var/lib/octoshield/usb/`.

After resolving the package or policy error, remove untrusted devices and resume from your normal terminal:

```bash
octoshield apply usb
```

An enrolled installation reuses its existing approved rules. Do not delete its enrollment marker to “fix” an error: doing so could lead to unintended re-enrollment. The D-Bus bridge stays masked intentionally; OctoShield uses root-only policy IPC. Existing unmanaged USBGuard installations require manual integration and are not overwritten.

## USB input lockout

First try a trusted built-in keyboard or the previously approved device on its original port. If you cannot log in, use the machine's recovery console. At the GRUB editor, temporarily append this to the Linux kernel command line for one boot:

```text
systemd.mask=usbguard.service
```

This disables USBGuard for that boot, so disconnect all unfamiliar peripherals and retain physical control. A firmware/boot password or device policy may require your established recovery method instead. From a trusted recovery login, inspect:

```bash
sudo journalctl -u usbguard.service --no-pager
sudo cat /etc/usbguard/rules.conf
sudo ls -l /var/lib/octoshield/usb
```

Repair the specific rule/configuration, or restore the relevant saved `/etc/usbguard/rules.conf` and `/etc/usbguard/usbguard-daemon.conf` with their original root ownership and private modes. Remove the temporary boot argument and reboot normally. Check `sudo systemctl is-active usbguard.service` and `octoshield usb list` before relying on protection. Merely stopping USBGuard can leave already-blocked devices unauthorized; reconnect/reboot through the trusted recovery path when necessary.

For a managed profile, use `octoshield usb forget DEVICE_ID` to revoke the attached device's remembered trust in the effective USB profile and block its current attachment. Other profiles retain their own decisions. Inspect the device again after reconnecting. Keep input, hub and mounted-storage consequences in mind.

For legacy/manual recovery outside profile management, first inspect both current devices and persisted policy:

```bash
octoshield usb list
sudo usbguard list-rules
```

Record a private copy of `/etc/usbguard/rules.conf`, then remove only the reviewed allow rule with `sudo usbguard remove-rule RULE_ID`. A rule ID differs from a device ID. Block the currently attached device using `octoshield usb block DEVICE_ID`, then test reconnecting it. Temporary device blocking alone does not remove persistent trust. Do not remove keyboard/controller/hub rules indiscriminately.

## Services

Read `service-before:` entries in the transaction's `actions.log`. The service action masks installed services and sockets; restoring one unit may also require unmasking its activation sockets/path. `octoshield office` handles the paired units for SSH, Avahi, Bluetooth, or CUPS and starts the selected service. Firewall exceptions remain separate.

For other units such as Samba, inspect the recorded state and unmask only the required exact unit with `systemctl unmask UNIT`. Start/enable it only if that matches your chosen policy. A saved `/etc/systemd/system/UNIT` override should be restored before `systemctl daemon-reload`. Do not enable every masked service or overwrite unrelated systemd configuration.

## Sudo, updates, and AppArmor

First use **Recovery & updates → Repair system** or `octoshield repair` to review the retired sudo policy. For a conflict requiring manual recovery, retain a private copy of the current `/etc/sudoers.d/99-octoshield` outside `/etc/sudoers.d` and inspect the relevant activation transactions from an existing trusted administrator shell. Restore the saved original file if its marker says `existing`; remove only the unchanged OctoShield-generated drop-in if the genuine original marker says `absent`. Later activation backups can contain the already-installed zero-timeout policy, so inspect the earlier history before choosing a baseline. Preserve administrator changes and unrelated sudo rules. Validate the complete configuration with `visudo --check` before closing the administrator shell. OctoShield does not remove existing passwordless grants.

Automatic-update settings live in `/etc/apt/apt.conf.d/90-octoshield`. Restore/remove only this drop-in according to its snapshot marker, then inspect `apt-config dump`. Timer enablement is separate runtime state; review the timers before changing them. AppArmor activation retains installed profile modes; diagnose a specific denied application using its logs instead of disabling AppArmor globally.

## Desktop and notifications

Run these as your normal GNOME user, **without sudo**:

```bash
octoshield desktop status
octoshield desktop restore
octoshield monitor status
octoshield monitor disable-desktop
```

The desktop baseline is a private, validated data file at `${XDG_STATE_HOME:-$HOME/.local/state}/octoshield/desktop.tsv`. Restore returns the seven core GNOME settings and any recorded, still-available RDP/VNC controls to their original values and retains the baseline. First-seen optional controls are backed up before they change. It does not change USBGuard or UFW.

For monitor problems, inspect system and user journals before restarting:

```bash
sudo journalctl -u octoshield-monitor.service -n 50 --no-pager
journalctl --user -u octoshield-notify.service -n 50 --no-pager
sudo systemctl restart octoshield-monitor.service
systemctl --user restart octoshield-notify.service
```

These services affect monitoring and notification delivery only. Root-owned alert counters under `/run/octoshield` are ephemeral, not backups or a forensic event archive.
