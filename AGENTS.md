# AGENTS.md

This file contains instructions for AI agents working on this project.

## Project Context & Critical Constraints

> [!IMPORTANT]
> **Do NOT refactor the Sensor Creation Logic** to use standard creation endpoints.
> - **addsensor3.htm** does not work via API.
> - **PRTG API v1** cannot create sensors from scratch.
> - **PRTG API v2** is not supported on Hosted Monitor.
> **ALWAYS** use the `duplicateobject.htm` (Clone) strategy.

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

## Testing & Verification Rules

1.  **Mandatory Testing**: Use `task_boundary` to create a `VERIFICATION` phase for every task.
2.  **Add Tests**: Whenever writing logic, creating unit tests (e.g., `unittest` or `pytest`) or verification scripts is mandatory.
3.  **Run Before Push**: You must run the tests and verify the output matches expectations before pushing any code.
4.  **User Review First**: NEVER push changes to the remote repository without asking the user to review the changes first. Use `notify_user` to request approval.

## Code Quality & Standards

1.  **Linting**: Run `pylint` on changed files. **Compliance is mandatory.** Fix errors to maintain a high score (> 9.0).
2.  **Dependencies**: If you add a new import, immediately update `requirements.txt`.
3.  **Type Hints**: Enforce strict type hinting for all new functions.

## Commit Standards

Use [Conventional Commits](https://www.conventionalcommits.org/):
-   `feat: ...` for new features
-   `fix: ...` for bug fixes
-   `docs: ...` for documentation
-   `chore: ...` for maintenance/refactoring

## Security & Integrity
-   **GPG Signing**: All commits MUST be signed. Ensure your environment is configured for GPG signing or use the `-S` flag.
