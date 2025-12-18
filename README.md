# PRTG Onboarding Automation (Hybrid Mode)

This script automates the onboarding and updating of devices in PRTG. 
**Key Feature**: It performs a **local SNMP scan** from the machine running the script, ensuring that interface names and aliases are detected correctly (bypassing potential PRTG discovery bugs).

## Features

- **Hybrid Scanning**: Fetches device details from PRTG but scans interfaces via local SNMP.
- **Strict Filtering**: Only creates sensors for interfaces that are **Physical** and **Administratively Up**.
- **Auto-Dependency**: Automatically sets the Device dependency to the Ping sensor.
- **Legacy Cleanup**: In `existing` mode, pauses old traffic sensors to prevent duplicates.
- **Bulk Support**: Can process multiple existing devices in one run.

## Prerequisites

1.  **Python 3.x**
2.  **Network Access**: The machine running this script must have **SNMP access (UDP 161)** to the target devices.
3.  **Dependencies**:
    ```bash
    pip install requests pysnmp
    ```

## Configuration (Environment Variables)

The script relies on environment variables for credentials.

| Variable | Description | Required |
|----------|-------------|----------|
| `PRTG_BASE_URL` | URL of your PRTG server (e.g. `https://prtg.corp`) | Yes |
| `PRTG_USER` | PRTG API Username | Yes |
| `PRTG_PASSHASH` | PRTG API Passhash (Found in User Settings) | Yes |
| `PRTG_SNMP_COMMUNITY` | SNMP Community String (default: `public`) | No |
| `PRTG_VERIFY_SSL` | Verify SSL Certificates (`true`/`false`) | No |

## Usage

The script has two modes: `new` and `existing`.

### 1. Onboard a New Device

Adds a new device to PRTG, scans it locally, and adds sensors.

```bash
# Syntax
python3 prtg_manager.py new <GROUP_ID> "<DEVICE_NAME>" <IP_OR_HOSTNAME> [--dry-run]

# Example
python3 prtg_manager.py new 2001 "Core-Router-01" 192.168.1.1
```

### 2. Update Existing Device(s)

Updates sensors for devices already in PRTG. Useful for fixing missing descriptions or adding new ports.

```bash
# Syntax
python3 prtg_manager.py existing <DEVICE_ID> [DEVICE_ID_2 ...] [--dry-run]

# Example (Single)
python3 prtg_manager.py existing 5044

# Example (Multiple)
python3 prtg_manager.py existing 5044 5045 5060 --dry-run
```

## How it Works

1.  **SNMP Scan**: The script uses `pysnmp` to walk the device's Interface and ifXTable MIBs directy.
2.  **Filter**: It filters for interfaces where `ifType` is physical (Gigabit, FastEthernet, etc.) and `ifAdminStatus` is Up.
3.  **Match**: It compares found interfaces with existing PRTG sensors.
4.  **Create**: It calls PRTG API `addsensor3` to create missing traffic sensors using the correct `ifIndex` and naming convention (`Traffic [Alias]`).
5.  **Core Sensors**: Ensures Ping, CPU, Memory, and Uptime sensors exist.

## License

This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details.
