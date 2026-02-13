# AGENTS.md

This file contains instructions for AI agents working on this project.

## Project Context & Critical Constraints

> [!IMPORTANT]
> **Do NOT refactor the Sensor Creation Logic** to use standard creation endpoints.
> - **addsensor3.htm** does not work via API.
> - **PRTG API v1** cannot create sensors from scratch for many types.
> - **PRTG API v2** is not supported on Hosted Monitor.
> **ALWAYS** use the `duplicateobject.htm` (Clone) strategy.
> **MANDATORY**: Always check if a sensor name already exists on a device before creating a duplicate.
14. > **PRTG Message Masking**: Be aware that when a device/parent is **Paused**, the original status message (e.g., `ifAdminStatus=down`) is replaced by `Paused by parent`. Fallback logic must run on active/unpaused devices for best results.

## Cleanup & Safety

1.  **Cleanup Strategy**: Always default to `pause` instead of `delete` for legacy sensors. Only delete if explicitly requested via `--cleanup` or config.
2.  **Import Resilience**: All non-standard library imports (`requests`, `pysnmp`, `yaml`) MUST be placed after the `check_and_install_packages()` call to ensure the auto-installer can run before module errors occur.

## Naming & Discovery Logic

1.  **Filter Parameter**: When searching for sensors via `table.json`, ALWAYS use `filter_type` instead of `filter_sensortype`.
2.  **Port Name Templates**:
    -   Default to `([ifname]) [ifalias]` if no template is found.
    -   Priority: CLI `--port-name-template` > Env `PRTG_PORT_NAME_TEMPLATE` > Device `portnametemplate` property > Fallback default.
    -   Support placeholders: `[port]`, `[ifalias]`, `[ifname]`, `[ifdescr]`, `[ifspeed]`, `[ifsensor]`.
3.  **SNMP Precision**: Always fetch `ifSpeed` (OID `1.3.6.1.2.1.2.2.1.5`) and `ifAlias` (OID `1.3.6.1.2.1.31.1.1.1.18`) for accurate naming.

## Versioning & Documentation Rules

1.  **Always Update Changelog**: When making code changes, you MUST update `CHANGELOG.md`.
    -   Use [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) format.
    -   Create a new version section (e.g., `## [1.2.0] - YYYY-MM-DD`) for your changes if one doesn't exist for the current release cycle.
    -   Do not leave changes under a generic "Unreleased" section unless specifically instructed.

2.  **Versioning Strategy**:
    -   **Patch** (x.x.1): Bug fixes, backward-compatible API fixes.
    -   **Minor** (x.1.x): New features (like the Cloning strategy), backward-compatible.
    -   **Major** (1.x.x): Breaking changes.

3.  **Sync Code Version**: If `prtg_manager.py` contains a `__version__` variable or header comment, update it to match the new version in `CHANGELOG.md`.

4.  **Mandatory Document Sync**: For every functional change, you MUST update:
    -   `README.md`: Ensure new features/flags are documented.
    -   `CHANGELOG.md`: Detail the changes under the new version.
    -   `AGENTS.md`: Capture any new rules or logic preferences discovered.
    -   `prtg_manager.py`: Update the `__version__` string, module docstrings, and CLI help messages to ensure the tool remains self-documenting.

## Testing & Verification Rules

1.  **Mandatory Testing**: Use `task_boundary` to create a `VERIFICATION` phase for every task.
2.  **Add Tests**: Whenever writing logic, creating unit tests (e.g., `unittest` or `pytest`) or verification scripts is mandatory.
3.  **Run Before Push**: You must run the tests and verify the output matches expectations before pushing any code.
4.  **User Review First**: NEVER push changes to the remote repository without asking the user to review the changes first. Use `notify_user` to request approval.

## Dependencies & Environment

1.  **Configuration Hierarchy**: Priority is CLI > Env > `config.yaml` > Interactive Prompt.
2.  **Linting**: Run `pylint` on changed files. **Compliance is mandatory.** Fix errors to maintain a high score (> 9.0).
3.  **Dependencies**: If you add a new import (like `PyYAML`), immediately update `requirements.txt` and the `check_and_install_packages` internal map.
4.  **Type Hints**: Enforce strict type hinting for all new functions.
5.  **Logging**: Always use dual logging to console and `prtg_manager.log`. Redact credentials (`apitoken`, `passhash`, `username`) in all debug outputs.

## Mandatory Pre-Completion Checklist

For EVERY task, before calling `notify_user` or finishing, the agent MUST:

1.  **Run Linting**: Execute `pylint` on all modified files. **Compliance is mandatory.** Fix all errors and warnings to maintain a score of 10.0 if possible, and never below 9.0.
2.  **Document Sync**: Synchronize the following files for every functional change:
    -   `README.md`: Document new features, flags, and config options.
    -   `CHANGELOG.md`: Record changes under a new version entry.
    -   `AGENTS.md`: Capture new rules, preferences, or project-specific logic.
    -   `prtg_manager.py`: Update the `__version__` string, module docstring, and CLI `argparse` help messages.
3.  **Verification**: Run the script in `--dry-run` or against a test environment to verify all logic paths (discovery, cloning, naming, duplicate checks).
4.  **Security**: Ensure no credentials or tokens are leaked in logs or artifacts.

## Commit Standards

Use [Conventional Commits](https://www.conventionalcommits.org/):
-   `feat: ...` for new features
-   `fix: ...` for bug fixes
-   `docs: ...` for documentation
-   `chore: ...` for maintenance/refactoring

## Security & Integrity
-   **GPG Signing**: All commits MUST be signed. Ensure your environment is configured for GPG signing or use the `-S` flag.
