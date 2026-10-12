# OctoShield 1.1 profiles

Version 1.1 adds named, editable profiles and verified status to the existing
shared Bash controls and native GTK application. This document records the
implementation contract; the user guide describes the completed behavior.

## Profiles and overrides

Conference, Public, Office, and Home are editable presets. Home retains a
protective baseline. Administrators can copy and delete custom profiles.
A global switch applies firewall, USB, network, services, and monitoring
settings. Selecting a different profile for one control creates an explicit
override. An incomplete switch must never be reported as fully applied.
Security updates, AppArmor, sudo authentication, and user screen locking remain
independent baseline controls rather than being weakened by location changes.

Profiles are root-owned JSON data beneath `/var/lib/octoshield`; no stored
configuration is executed. Mutation uses the existing operation lock,
administrator authorization, change previews, and private transaction records.
Existing 1.0 policies remain in place until an administrator chooses a change.

## Enforcement and recovery

UFW denies unsolicited incoming and routed traffic across IPv4 and IPv6 while
preserving outgoing connections. Profiles contain scoped port, protocol,
source, and interface exceptions, with optional expiration. Switching narrows
existing allowances before adding new ones and never resets or disables the
firewall as an intermediate step. Original settings are saved for explicit
restoration; external configuration drift is surfaced before replacement.

Only permanent allowances enter UFW's saved policy. Finite permissions require
an enabled, running status observer before application and are inserted into
IPv4/IPv6 UFW user chains after reload with a kernel UTC time match. Its inclusive
`--datestop` is the saved deadline minus one second. Missing time-match support
fails closed: there is no untimed fallback. The rule stops granting new access
at its deadline even when the observer or application is absent; established
connections retain the normal stateful policy. The observer verifies expiry and reconciles saved
metadata under the operation lock, independently of deadline enforcement.
Inert kernel rules remain until the next Apply or reload; expiry does not
rebuild permanent firewall policy. Reload
or reboot withdraws grants sooner, and expired access cannot reopen from disk.
Reactivating a still-unexpired grant requires explicit Apply. Native `ufw status`
omits runtime permissions; OctoShield verifies kernel rules and their deadlines.

USB approvals belong to the effective USB profile. Temporary approvals expire
on disconnect, daemon restart, or profile switch. Already connected devices
are reevaluated when switching. Unknown devices remain blocked while approval
is pending. Enrollment and changes affecting input, storage, or docks require
explicit review and safe recovery handling.

## Status and interfaces

A root-owned background collector publishes a bounded, sanitized status
snapshot in `/run/octoshield/status.json`. Reading it does not require
administrator authentication. The GUI and CLI distinguish active, inactive,
partial, unknown, and unsupported states and identify stale observations.
Actual OS state determines status, rather than successful command exit alone.

Additional inspection covers Thunderbolt/USB4 memory-access protection,
container and forwarding exposure, Secure Boot, and storage encryption.
Detection must explain limitations rather than imply those facilities have
been reconfigured. Notifications report blocked USB and network changes while
the application window is closed. Both interfaces expose the same profile
operations and approval semantics.

## Packaging and release

The package retains the `octoshield` identity and upgrades 1.0.0 in place through
the system package manager. Installation does not activate a new security
profile. Version 1.1.0 is published by the existing verified release workflow
after the pull request merges and all build, test, and package checks pass.
Update discovery uses the fixed official release source; installation remains
an authenticated system package-manager operation.
