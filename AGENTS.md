# AGENTS.md

Instructions for AI agents working on this project.

## Project Architecture

- **Single-file app**: `prtg_manager.py` (v1.8.5) — all logic lives here
- **Key classes**: `Config`, `SNMPScanner`, `PRTGClient`, `OnboardingResult`
- **Key functions**: `ensure_core_sensors`, `process_traffic_sensors`, `process_device`, `cleanup_legacy_sensors`
- **Tests**: `tests/test_traffic_sensors.py` (pytest + unittest.mock)
- **CI**: `.github/workflows/ci.yaml` → `run_checks.sh` (pylint + pytest)
- **Dependencies**: `requirements.txt` — `requests`, `pysnmp>=7.1.22`, `PyYAML`, `pylint`, `pytest`

## Critical PRTG API Constraints

> [!IMPORTANT]
> **Do NOT refactor sensor creation** to use standard creation endpoints.
> - `addsensor3.htm` does not work via API
> - PRTG API v1 cannot create sensors from scratch for many types
> - PRTG API v2 is not supported on Hosted Monitor
>
> **ALWAYS** use the `duplicateobject.htm` (Clone) strategy.

> [!IMPORTANT]
> **MANDATORY**: Always check if a sensor name already exists on a device before cloning. The `process_traffic_sensors` function tracks `claimed_ids` to prevent double-matching across iterations.

> [!WARNING]
> **PRTG Message Masking**: When a device/parent is **Paused**, the original status message (e.g., `ifAdminStatus=down`) is replaced by `Paused by parent`. Fallback logic must run on active/unpaused devices for best results.

## PRTG API Rules

- When searching for sensors via `table.json`, use `filter_type` (not `filter_sensortype`)
- Sensor types to handle: `snmptraffic`, `snmptraffic64`
- Core sensors: Ping, CPU (`snmpcpu`), Memory (`snmpmemory`), Uptime (`snmpuptime`)
- `clone_sensor` must snapshot existing IDs before cloning to return only newly created sensor IDs
- After processing traffic sensors, refresh the sensor list before cleanup to avoid stale snapshots

## Naming & Discovery

- **Port Name Template priority**: CLI `--port-name-template` > Env `PRTG_PORT_NAME_TEMPLATE` > Device `portnametemplate` property > fallback `([ifname]) [ifalias]`
- **Supported placeholders**: `[port]`, `[ifalias]`, `[ifname]`, `[ifdescr]`, `[ifspeed]`, `[ifsensor]`
- **SNMP OIDs**: Always fetch `ifSpeed` (`1.3.6.1.2.1.2.2.1.5`) and `ifAlias` (`1.3.6.1.2.1.31.1.1.1.18`) for accurate naming
- **Interface filtering**: Only create sensors for interfaces that are Physical and Administratively Up
- **Name exclusion**: `EXCLUDED_IF_NAMES` constant provides defense-in-depth filtering for known non-physical names (`lo`, `loopback`, `lo0`, `null`, `null0`) regardless of reported ifType

## Configuration Hierarchy

Priority: CLI flags > Environment variables > `config.yaml` > Interactive prompts

## Import Order

**Non-standard library imports** (`requests`, `pysnmp`, `yaml`) MUST be placed after `check_and_install_packages()` is called (line ~113). This ensures the auto-installer runs before any module imports that might fail.

## Cleanup & Safety

- Default to `pause` instead of `delete` for legacy sensors
- Only delete if explicitly requested via `--cleanup` flag or `cleanup_legacy: true` in config
- `cleanup_legacy_sensors` is a dedicated function — keep cleanup logic there, not inlined in `process_device`

## Versioning & Documentation

### Version Bumps

- **Patch** (x.x.1): Bug fixes, backward-compatible fixes
- **Minor** (x.1.x): New features, backward-compatible
- **Major** (1.x.x): Breaking changes

### Mandatory Syncs

For every functional change, update all of these:

1. `CHANGELOG.md` — [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) format, create a dated version section (not "Unreleased")
2. `prtg_manager.py` — `__version__` string (line ~164), module docstring, argparse help text
3. `README.md` — document new features/flags/config options
4. `AGENTS.md` — capture new rules or logic discovered

## Testing

- **Framework**: pytest with unittest.mock
- **Test file**: `tests/test_traffic_sensors.py`
- Tests mock external deps (`requests`, `pysnmp`, `yaml`) at import time since `check_and_install_packages` runs at import
- Always add tests when writing new logic
- Run tests before pushing: `python3 -m pytest tests/`

## Linting

- Run `pylint --fail-under=8.0 prtg_manager.py` on all changes
- Target score: 10.0 if possible, never below 8.0
- Common pylint disables already in code: `wrong-import-position`, `no-name-in-module`

## Commit Standards

Use [Conventional Commits](https://www.conventionalcommits.org/):
- `feat:` new features
- `fix:` bug fixes
- `docs:` documentation only
- `chore:` maintenance/refactoring

## Security

- Redact credentials (`apitoken`, `passhash`, `username`) in all debug/log output
- Never push without user review — request approval first
- All commits must be GPG-signed (use `-S` flag if not configured globally)
- No credentials or tokens in logs or artifacts

## Code Style

- Strict type hints on all new functions
- Dual logging: console + `prtg_manager.log`
- Async functions for SNMP and PRTG API operations (`asyncio`)
- If adding a new dependency, update both `requirements.txt` and the `check_and_install_packages` internal map
