# Guided access and actionable diagnostics

OctoShield should explain an observed condition, identify its scope and configuration source, and offer a reviewed action that preserves unrelated protections. The native GTK application and terminal commands use the same Bash controls and fixed helper API.

## Implementation scope

- Provide a service-oriented firewall workflow with HTTP/HTTPS presets, detected physical networks, grouped permissions, immediate verified application and revocation, and the effective firewall profile selected by default.
- Keep saved policy, live policy, temporary deadlines, cancellation, failure and recovery distinct. Route legacy office firewall changes through the profile engine.
- Present named network connections with narrow privacy overrides, explicit reconnect actions, and separate saved and active verification.
- Report confirmed root-storage encryption positively without claiming every volume is encrypted. Keep incomplete inspection separate from a detected problem.
- Inspect Docker bindings, forwarding paths and configuration sources through authenticated details. Preserve container forwarding and outbound networking. Do not describe uninspected virtual machines as verified.
- Offer bounded local-only Docker configuration guidance and reviewed repairs for supported configurations; never execute arbitrary Compose configuration with administrator privileges.
- Keep device paths, connection names, container identity and configuration locations out of the public status cache.

## Shared command surface

The GUI helper and explicit terminal subcommands share `access list/allow/update/revoke/recover/restore/reconcile`, `connections list/set/reconnect`, and `diagnostics show`. Calling `octoshield access`, `octoshield connections` or `octoshield diagnostics` without arguments opens a guided terminal selection. Menus wait without retaining a mutation lock. The office menu delegates to these workflows; legacy command forms remain supported through the managed backend.

Docker `containers plan/localize` runs through the normal-user adapter. A supported Compose repair requires a reviewed token, matching live/source configuration and eligible project files. It generates a dedicated localhost override and recreates only the selected service. A private owner-only resolved-model snapshot makes the reviewed execution reproducible; it may contain environment values and is not included in logs. Nondefault resource policies and custom endpoint settings require manual review. Recreation retains mounted volumes but replaces the container writable layer. The generated override must be included in future deployment commands; it is not an invisible change to the original source.

## Firewall failure and recovery

A failed profile result is a persistent operation outcome, not evidence that a
process still holds the change lock. Access inspection must show that history
alongside a fresh native observation. UFW reports `disabled (routed)` when IP
forwarding is disabled; that valid display must not be mistaken for a failed
deny-forwarding configuration. Verification checks the configured defaults and
the actual IPv4 and IPv6 input paths and permissions.

The Access & exceptions page places firewall status and recovery above the
permission form. It identifies the selected saved profile, the recorded
assignment, the previous result and a concrete recovery action. Allow, update
and revoke remain unavailable until inspection establishes readiness. A failed
dashboard indicator links directly to this recovery section. Inspection and
recovery preserve the pending permission for a separate review afterward.

`access recover PROFILE` reviews and reapplies only the explicitly selected
firewall profile. `access restore` reviews restoration of the retained original
firewall configuration and verifies the result before releasing its recovery
baseline. Neither operation applies other profile controls or a pending form.

Native drift or an interruption before state recording requires explicit
review. `access reconcile PROFILE` displays bounded, escaped native evidence,
rechecks it after confirmation and accepts only the reviewed current state for
future conflict checks. It retains the original baseline and selected policy,
does not change firewall rules, and leaves a pending result requiring a separate
Apply or Restore. Unrecognized hooks or unsafe recovery data remain blocked.
No action clears a failure merely to enable a permission button.

## Validation

Backend tests mock native changes and cover grouped access, cancellation, partial failures, expiry, revocation, profile consistency, network discovery, privacy overrides, encryption topology and Docker binding classification. Native tests cover effective profile selection, friendly inventories, direct finding actions and meaningful status labels. Run lint, backend tests, native builds/tests, display smoke tests and sanitizers.

Live hardware acceptance must additionally verify LAN-only HTTP/HTTPS from another device, blocked unintended ingress, immediate revocation, reconnect behavior, and continued local and outbound container access. Automated fixtures alone do not establish host protection.

Required native firewall integration uses real UFW, IPv4/IPv6 rules and TCP
connections inside disposable network and mount namespaces on both supported
Ubuntu releases. It covers forwarding-disabled hosts, scoped grouped web
permissions, reload and revocation, failed application, reviewed recovery,
external drift, and restoration of active and inactive original baselines.
