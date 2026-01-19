# AGENTS.md

This file contains instructions for AI agents working on this project.

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
