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

## Validation

Backend tests mock native changes and cover grouped access, cancellation, partial failures, expiry, revocation, profile consistency, network discovery, privacy overrides, encryption topology and Docker binding classification. Native tests cover effective profile selection, friendly inventories, direct finding actions and meaningful status labels. Run lint, backend tests, native builds/tests, display smoke tests and sanitizers.

Live hardware acceptance must additionally verify LAN-only HTTP/HTTPS from another device, blocked unintended ingress, immediate revocation, reconnect behavior, and continued local and outbound container access. Automated fixtures alone do not establish host protection.
