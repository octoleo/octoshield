# Reviewed system repair

## Purpose

Removing a control from OctoShield does not undo the native configuration that
older releases installed. Recovery & updates therefore provides **Repair
system**, also available as `octoshield repair`, to inspect and retire known
obsolete OctoShield settings after an update.

Repair is a fixed registry of individually reviewed migrations. Each migration
has a stable identifier, a native-state check, an exact proposed change, and
verification. Running repair again rechecks the actual configuration rather
than trusting a completion flag. New cleanups require implementation and tests;
the command does not infer arbitrary system changes from version numbers.

## Authentication and review

The graphical action uses the existing authenticated application session and
fixed helper API. The CLI elevates the whole operation once. Inspection, review,
backup, mutation and verification share the normal exclusive operation lock and
private transaction log. System passwords never enter OctoShield.

The action lists the affected paths and asks for confirmation before applying a
repair. It rechecks the inspected state after confirmation. An error remains an
error; a conflicting administrator edit is preserved and explained. Existing
profile application and baseline restoration remain separately reviewed actions.

Installation and package upgrades retain their program/service lifecycle role.
The passive status observer reports pending repair in Recovery & updates; the
user starts and reviews the system change explicitly.

## Initial migration: retired sudo timeout

The removed Fresh administrator authentication control wrote
`/etc/sudoers.d/99-octoshield` with the following complete generated content:

```sudoers
# Managed by Octoshield; passwordless grants still bypass passwords.
Defaults timestamp_timeout=0
```

Its replacement is recovery, not a new authentication policy. All activation
entry points and the old protection indicator are removed. Normal system
password changes and the application administrator session remain available.

Repair recognizes only the original generated file at that fixed destination.
It verifies the file and parent directories, preserves unexpected contents and
links, and reads trusted transaction markers as data. A previous non-generated
file is restored when recoverable. Repeated activation snapshots containing the
generated policy are skipped when identifying the pre-activation state. An
original absence results in removal of the generated file. Missing or
inconsistent recovery evidence is reported explicitly in the review.

Conflicting originals recorded within the same second require manual review.
A recovered original is copied into the current private transaction, checked
against its reviewed digest and syntax-checked before publication. Its exact
policy difference is shown as escaped plain text before confirmation; policies
too large for the bounded review require manual recovery.

The current configuration is backed up privately outside the sudoers include
directory. The complete sudoers policy is checked before and after the change.
If validation fails, the just-saved policy is restored before returning failure.
No particular replacement timeout is imposed: the remaining native system and
administrator configuration determines authentication reuse.

## Verification

Tests must cover absence, the original generated policy, repeated activation,
pre-existing administrator policy, modified or linked paths, cancellation,
changes during review, failed validation and repeat execution. Native
integration in disposable Ubuntu environments must use real sudo and visudo
to verify authentication reuse before and after cleanup. GUI, protocol, CLI,
status-cache compatibility and package contents are checked alongside the
existing release gates.
