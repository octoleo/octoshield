# OctoShield 1.2 USB and administrator sessions

Version 1.2 replaces repeated desktop authentication with one explicit
administrator unlock for the lifetime of the application session. GTK remains
unprivileged. PolicyKit selects and authenticates an administrator according to
Ubuntu's policy; membership in the Unix `root` group is not required or used.

## Authorization boundary

A fixed, root-owned C broker is launched through `pkexec` with its internal
text authentication agent disabled. It communicates only over inherited pipes,
binds to the launching process and its local graphical login session, and
executes only the existing fixed Bash helper after independently validating
every action. Passwords are never received or stored by OctoShield.

Requests and confirmations carry correlated identifiers. Only one operation
can run at a time. Closing or locking the application, locking the desktop,
ending the login session, losing the launching process, or breaking the channel
revokes authorization. An already-authorized package operation may finish
safely, but the revoked session cannot accept further actions or confirmations.
Reopening or unlocking requires authentication again. There is no shared sudo
or PolicyKit authorization cache.

## Guided USB decisions

The status observer publishes a bounded, sanitized inventory for navigation
without elevation. Device rows show current authorization, device type, port,
and the effective USB profile. A new blocked attachment opens a decision dialog
in an active, unlocked local desktop session, including when the main window is
closed. The user chooses to keep it blocked, allow this attachment once, or
remember it in the current USB profile. Cancel never authorizes a device.

A background prompt cannot approve anything. If the application has no
authenticated session, a positive decision requests administrator authentication
before applying it. The approval is bound to an opaque attachment token and the
profile displayed to the user; the privileged backend rechecks both immediately
before applying the decision. Device replacement, daemon restart or a profile
change invalidates an old decision. Existing input/storage disruption safeguards
remain in place. Dismissed attachments do not repeatedly reopen the same dialog.

The standalone CLI keeps its existing explicit authorization and review flow.
Desktop automatic USB prompts have a visible user preference; their absence
never changes USBGuard's enforcement policy.

## Delivery and verification

The Debian package retains its identity and upgrades existing installations.
Version 1.2.0 will publish through the verified main-branch release workflow
after the pull request merges. Verification covers broker framing and
revocation, stale USB decisions, read-only navigation, native windows, both
themes, and actual upgrades from the published 1.1.0 package. Hardware and
desktop-session acceptance checks remain explicit in the testing guide.
