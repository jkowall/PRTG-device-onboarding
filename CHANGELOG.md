# Changelog

All notable changes to this project will be documented in this file.

## [1.1.0] - 2026-01-08

### Added
- **Modern SNMP Support**: Migrated SNMP engine to `asyncio` to support Python 3.12 and 3.13.
- **API Token Authentication**: Added support for PRTG API Tokens (`--api-token` or `PRTG_API_TOKEN` environment variable).
- **Interactive Configuration**: The script now prompts for missing credentials (Base URL, Tokens, etc.) if not provided via CLI or Environment Variables.
- **Flexible CLI**: Added global arguments for configuration (`--url`, `--user`, `--passhash`, `--snmp-community`).
- **Dependency Pinning**: Updated `requirements.txt` to require `pysnmp>=7.1.22`.

### Changed
- **Windows Compatibility**: Fixed `ImportError` issues on Windows by switching to the `pysnmp` 7.x architecture.
- **Non-blocking Operations**: Replaced `time.sleep` with `asyncio.sleep` to ensure responsive network scanning.
- **Config Logic**: Updated configuration model to prioritize API Tokens over legacy User/Passhash authentication.

### Fixed
- Resolved `pysnmp` import errors caused by the removal of `asyncore` in Python 3.12.
- Improved SNMP OID parsing and indexing for modern MIB handling.
