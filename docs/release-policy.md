# Maintenance release policy

Use small patch increments for maintenance fixes: `1.3.3` → `1.3.4` → `1.3.5` → … → `1.3.9`, then `1.4.0`. Do not jump from `1.3.3` to `1.4.0` for these fixes. The patch bump helper carries a patch digit of nine into the next minor version.

Every shipped application fix must include a new synchronized version in the CLI, GTK application, Debian changelog, and AppStream metadata. Run `bash scripts/version.sh --check` before merging. A merged source change is not an installed application update.

Before reporting a fix as released, verify the main-branch publication workflow, the new GitHub release and its Ubuntu-specific Debian assets. Keep existing published releases immutable. Document the installed version required by a fix; users must install the newer package and restart the application to load its frontend and helper.

For 1.3.4, include the verified-firewall access-readiness fix from PR #15 and the automatic inspection/navigation fixes for issue #14. Preserve native-policy verification, mutation confirmations and rollback safeguards.
