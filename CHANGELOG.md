# Changelog

## [1.8.0] - 2026-02-16

### Added

- **Config Generation**: New `generate-config` command to crawl PRTG and generate a `config.yaml` snippet with all Group IDs and names.
- **Group-Based Credentials**: Added `group_credentials` support in `config.yaml` to map Group IDs to SNMP Community Strings.
- **Recursive Processing**: Updated `existing` command to support `--group-id`, allowing recursive onboarding/cleaning of entire device trees.

## [1.7.0] - 2026-02-16

### Added

- Configured new SNMP Traffic sensors to enable "Errors in and errors out" and "Discards in and discards out" channels.
- Set "Connection Status Handling" to "Show down status when disconnected, ignore when deactivated" for new traffic sensors.
- Expanded SNMP community candidate discovery logic with `snmpcommv2`.
- Automatic sensor resumption for newly created traffic sensors.
- Recognition for "SNMP Mem" sensor types.

### Changed

- Updated PRTG password masking detection to check for `***` (previously `****`).
- Improved logging for sensor resumption status.

## [1.6.0] - 2026-02-13

- **Sensor Deduplication**: Updated `ensure_core_sensors` to favor unpaused sensors and automatically delete duplicate core sensors.
- **Improved Management**: Enhanced `process_device` to consolidate all "keeper" sensor IDs before performing cleanup or pausing operations.
- **Refactored Legacy Cleanup**: Extracted legacy sensor cleanup into a dedicated `cleanup_legacy_sensors` function to reduce complexity and improve maintainability.
- **Improved Core Sensor Identification**: Expanded matching criteria for core sensors (CPU, Memory, Uptime) to include broader name patterns, ensuring better deduplication.
- **Enhanced Traffic Sensor Detection**: Legacy "Traffic" sensors are now identified by both type and name, ensuring they are correctly paused or deleted even if their type is unconventional.

## [1.5.1] - 2026-02-13

## [1.5.0] - 2026-01-22

### Added

- **Sensor Cleanup Option**: Introduced `--cleanup` flag and `cleanup_legacy` configuration to permanently delete old sensors instead of pausing them.
- **Improved API Support**: Added `delete_object` capability to the PRTG API client.

### Fixed

- **Legacy Identification Logic**: Refactored traffic sensor management to keep valid existing sensors active. Previously, the script would pause any existing sensor not "newly created" in the current run, even if its configuration was correct.

## [1.4.0] - 2026-01-22

### Added

- **Configuration File Support**: Introduced `config.yaml` support for persistent settings with CLI overrides.
- **Advanced Port Naming**: Implemented full PRTG placeholder support (`[port]`, `[ifalias]`, `[ifname]`, etc.).
- **Smart Template Discovery**: Script now auto-fetches `portnametemplate` from PRTG devices.
- **Duplicate Prevention**: Added mandatory name-based check to prevent redundant sensor creation.
- **Bandwidth Discovery**: Added `ifSpeed` collection to the SNMP scanner.
- **Example Configuration**: Provided `config_example.yaml`.

### Changed

- **Config Architecture**: Refactored `Config` class to support YAML, Env, and CLI hierarchies.
- **Logic Functions**: Updated `process_device` and `process_traffic_sensors` to use advanced naming logic.

### Fixed

- **API Parameter Syntax**: Corrected `filter_type` usage for sensor discovery.
- **Template Reliability**: Added support for `snmptraffic64` and alternative type naming during discovery.

## [1.3.0] - 2026-01-22

### Added

- **File Logging**: Integrated persistent logging to `prtg_manager.log`.
- **Debug Mode**: Added `--debug` flag for detailed API diagnostics and error bodies.
- **Enhanced Dry-Run**: Added exact payload previews for cloning and configuration.

### Changed

- **Asyncio Support**: Finalized and verified full async orchestration for SNMP and sensor management.
- **Robust API Client**: Improved `PRTGClient` with better error capture, redaction, and API token support.
- **CLI Standardized**: Refined argument parsing and interactive fallbacks.
- **Documentation**: Updated script docstring and README with comprehensive usage examples.

### Fixed

- **Merge Conflict Resolution**: Successfully merged logical enhancements with refactored async codebase.
- **Linting Perfection**: Addressed remaining style issues (lazy logging, line lengths, imports).
- **Concurrency**: Ensured sensor cloning retries are non-blocking using `asyncio.sleep`.

## [1.2.1] - 2026-01-19

### Changed

- **Code Refactoring**: Major refactor of `prtg_manager.py` to improve code quality and maintainability.
- **Linting**: Fixed all pylint issues to achieve a score > 9.0 (Standardized formatting, fixed line lengths, optimized imports).
- **Architecture**: Split `main()` into modular functions (`parse_arguments`, `resolve_targets`, `process_device`).

## [1.2.0] - 2026-01-19

### Added

- **Dynamic Sensor Cloning**: Implemented a "Clone & Rename" strategy to bypass PRTG API sensor creation limitations.
- **Template Discovery**: Script now automatically finds existing sensors to use as templates for new ones.
- **Dependency Auto-Install**: Script now automatically checks for and installs missing dependencies (`pysnmp`, `requests`) at runtime.

### Fixed

- **Sensor Creation Error**: Resolved HTTP 404 errors when adding sensors by replacing the invalid `addsensor3.htm` endpoint with `duplicateobject.htm`.

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
