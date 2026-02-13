# PRTG Onboarding Automation (Hybrid Mode)

This script automates the onboarding and updating of devices in PRTG.
**Key Feature**: It performs a **local SNMP scan** from the machine running the script, ensuring that interface names and aliases are detected correctly (bypassing potential PRTG discovery bugs).

## Features

- **Hybrid Scanning**: Fetches device details from PRTG but scans interfaces via local SNMP.
- **Strict Filtering**: Only creates sensors for interfaces that are **Physical** and **Administratively Up**.
- **Auto-Dependency**: Automatically sets the Device dependency to the Ping sensor.
<<<<<<< HEAD
- **Legacy Cleanup**: In `existing` mode, pauses or **deletes** old traffic sensors.
- **Fallback Recovery**: If a direct SNMP scan fails, the tool parses PRTG status messages to identify and pause interfaces reporting `ifAdminStatus=down`.
=======
- **Legacy Cleanup**: In `existing` mode, pauses or **strictly deletes** non-standard sensors (via `--cleanup`) to ensure a compliant device state.

>>>>>>> 128d0e2 (feat: implement strict legacy cleanup and enhance sensor deduplication)

- **Bulk Support**: Can process multiple existing devices in one run.

## Prerequisites

1. **Python 3.12+**: Required for compatibility with modern `pysnmp` and `asyncio`.
2. **Network Access**: The machine running this script must have **SNMP access (UDP 161)** to the target devices.
3. **Dependencies**:

    ```bash
    pip install -r requirements.txt
    ```

## Configuration

The script supports four ways to configure credentials and settings, prioritized in this order:

1. **Command Line Arguments**
2. **Environment Variables**
3. **`config.yaml` File** (Recommended for persistence)
4. **Interactive Prompts** (If values are missing)

### Configuration Hierarchy

Settings are merged in the order above. CLI flags always override environment variables and configuration files.

### 1. `config.yaml` (Recommended)

You can store your persistent settings in a `config.yaml` file in the same directory. See [config_example.yaml](config_example.yaml) for a template.

```yaml
base_url: "https://your-prtg.com"
api_token: "YOUR_TOKEN"
snmp_community: "public"
port_name_template: "([ifname]) [ifalias]"
cleanup_legacy: false
```

### Command Line Flags

| Flag | Description |
|------|-------------|
| `--url` | Base URL of PRTG server |
| `--api-token` | API Token (v21.1+) |
| `--user` | PRTG Username (Legacy) |
| `--passhash` | Passhash or API Key (Legacy) |
| `--snmp-community` | SNMP Community string |
| `--config` | Path to config file (default: `config.yaml`) |
| `--port-name-template`| Custom naming template (e.g. `([port]) [ifalias]`) |
| `--cleanup` | Strictly enforce standardized sensors by deleting all others (Existing mode) |

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `PRTG_BASE_URL` | URL of your PRTG server | Yes |
| `PRTG_API_TOKEN`| PRTG API Token | No* |
| `PRTG_USER` | PRTG API Username | No* |
| `PRTG_PASSHASH` | PRTG API Passhash | No* |
| `PRTG_SNMP_COMMUNITY` | SNMP Community String (default: `public`) | No |
| `PRTG_PORT_NAME_TEMPLATE`| Custom port naming template | No |
| `PRTG_VERIFY_SSL` | Verify SSL Certificates (`true`/`false`) | No |
| `PRTG_CLEANUP_LEGACY` | Cleanup legacy sensors (`true`/`false`) | No |

*\*You must provide either an API Token OR a Username + Passhash combo.*

## Usage

The script has two modes: `new` and `existing`.

### 1. Onboard a New Device

Adds a new device to PRTG, scans it locally, and adds sensors.

```bash
# Using CLI flags
python prtg_manager.py --url "https://xxxx.my-prtg.com" --api-token "TOKEN_HERE" new <GROUP_ID> "<DEVICE_NAME>" <IP_OR_HOSTNAME>

# Using interactive fallback (prompts for missing info)
python prtg_manager.py new 2001 "Core-Router-01" 192.168.1.1
```

### 2. Update Existing Device(s)

Updates sensors for devices already in PRTG. Useful for fixing missing descriptions or adding new ports.

```bash
# Example (Multiple devices)
python prtg_manager.py --url "https://prtg.local" --user "admin" --passhash "xxx" existing 5044 5045 5060 --dry-run
```

## PRTG Hosted Monitor (PPHM) Support

This script is compatible with PRTG Hosted Monitor, but requires specific network configuration:

1. **Run Location**: You must run this script from a machine on your **local network** (e.g., a laptop on VPN or a local server) that has SNMP access to your devices. You cannot run this on the PRTG Cloud instance itself.
2. **Target Group**: When adding `new` devices, the `<GROUP_ID>` you provide **MUST** belong to a **Remote Probe** installed on your local network.
    - *Why?* The "Hosted Probe" runs in the cloud and cannot reach your private IP addresses (RFC1918).
    - The script includes a safety check that will warn you if you attempt to add a private IP to a Hosted Probe group.
3. **URL**: Set `PRTG_BASE_URL` to your hosted instance (e.g., `https://myinstance.my-prtg.com`).

## How it Works

1. **Fallback Cleanup**: If the direct SNMP scan fails, the tool performs a fallback check of PRTG's status messages for `ifAdminStatus=down` to ensure deactivated ports are still paused.
2. **Core Sensors**: Ensures Ping, CPU, Memory, and Uptime sensors exist.

## License

This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details.
