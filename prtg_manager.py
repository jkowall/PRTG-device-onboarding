#!/usr/bin/env python3
# Copyright 2026 Jonah Kowall
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
PRTG Device Onboarding Automation Script (Hybrid Mode)
======================================================

Purpose:
    Onboards devices to PRTG with strict interface filtering (Physical + Admin Up).

    CRITICAL FEATURE: This script performs a LOCAL SNMP SCAN against the device
    instead of relying on PRTG's auto-discovery data. This bypasses the
    "PRTG not updating descriptions" bug by forcing the correct name/alias
    at the time of sensor creation.

Workflows:
    1. New Devices (--mode new):
       - Scans device IP locally via SNMP.
       - Creates Device in PRTG.
       - Adds Sensors using local data.
       - Sets Dependencies.

    2. Existing Devices (--mode existing):
       - Fetches Device IP from PRTG.
       - Scans IP locally via SNMP.
       - Adds missing sensors.
       - Pauses legacy traffic sensors.

Usage:
    python prtg_manager.py [--debug] [--url URL] [--api-token TOKEN] [--user USER] [--passhash HASH] new <GROUP_ID> "<NAME>" <HOST> [--dry-run]
    python prtg_manager.py [--debug] [--url URL] [--api-token TOKEN] existing <DEVICE_ID_1> [DEVICE_ID_2 ...] [--dry-run]

Configuration:
    Options can be provided via CLI flags, Environment Variables, or Interactive Prompts.
    Environment Variables: PRTG_BASE_URL, PRTG_API_TOKEN, PRTG_USER, PRTG_PASSHASH, PRTG_SNMP_COMMUNITY.

Requirements:
    pip install requests pysnmp

Hosted Monitor (PPHM) Notes:
    - When using PRTG Hosted Monitor, you MUST run this script from a location
      with local network access to your devices (e.g., behind a VPN or on a
      local server).
    - The 'group_id' provided for new devices MUST belong to a REMOTE PROBE
      installed on your local network. Do not add local devices to the
      "Hosted Probe" (Cloud), as it cannot reach private RFC1918 addresses.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import subprocess
import importlib.util
import asyncio
import getpass
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
import ipaddress

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from pysnmp.hlapi.v3arch import (  # pylint: disable=no-name-in-module
    CommunityData, ContextData, ObjectIdentity, ObjectType,
    SnmpEngine, UdpTransportTarget, walk_cmd
)

def check_and_install_packages():
    """Checks for required packages and installs them if missing."""
    required_packages = {
        "requests": "requests",
        "pysnmp": "pysnmp>=7.1.22"
    }

    missing = []
    for package, install_name in required_packages.items():
        if importlib.util.find_spec(package) is None:
            missing.append(install_name)

    if missing:
        print(f"Missing required packages: {', '.join(missing)}")
        print("Attempting to auto-install...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install"] + missing)
            print("Installation successful. Continuing...")
        except subprocess.CalledProcessError as e:
            print(f"Failed to install packages: {e}")
            print("Please run: pip install -r requirements.txt")
            sys.exit(1)

# Required checks performed at start

def setup_logging(debug: bool = False):
    """Configures logging for the script to both console and a file."""
    level = logging.DEBUG if debug else logging.INFO

    # Identify log file name based on script name
    script_name = os.path.basename(__file__)
    log_file = os.path.splitext(script_name)[0] + ".log"

    # Formatter
    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Console Handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.setLevel(level)

    # File Handler (Always logs at least INFO, or DEBUG if flag set)
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(formatter)
    file_handler.setLevel(level)

    # Root Logger Setup
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Clear existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)

setup_logging()
logger = logging.getLogger(__name__)

__version__ = "1.3.0"

# --- Constants ---

# IANA Interface Types (Physical)
PHYSICAL_IF_TYPES = {
    6,    # ethernetCsmacd
    7,    # iso88023Csmacd
    62,   # fastEther
    117,  # gigabitEthernet
    161,  # ieee8023adLag
    # propVirtual (often used for VLANs/Subinterfaces,
    # remove if strictly physical ports desired)
    53,
}

# PRTG Sensor Types
SENSOR_TYPES = {
    "ping": "ping",
    "snmp_cpu": "snmpcpu",
    "snmp_mem": "snmpmem",
    "snmp_uptime": "snmpuptime",
    "snmp_traffic": "snmptraffic",
}

# SNMP OIDs
OID_IF_INDEX = '1.3.6.1.2.1.2.2.1.1'
OID_IF_DESCR = '1.3.6.1.2.1.2.2.1.2'
OID_IF_TYPE = '1.3.6.1.2.1.2.2.1.3'
OID_IF_ADMIN_STATUS = '1.3.6.1.2.1.2.2.1.7'
OID_IF_ALIAS = '1.3.6.1.2.1.31.1.1.1.18'  # ifXTable alias
OID_IF_NAME = '1.3.6.1.2.1.31.1.1.1.1'    # ifXTable name (e.g. Gi1/0/1)

@dataclass
class Config:
    """Application Configuration model."""
    base_url: str
    username: Optional[str] = None
    passhash: Optional[str] = None
    api_token: Optional[str] = None
    snmp_community: str = "public"
    snmp_port: int = 161
    verify_ssl: bool = True
    request_timeout: int = 60

    @staticmethod
    def get_with_prompt(
        arg_val: Optional[str],
        env_var: str,
        prompt: str,
        is_password: bool = False,
        required: bool = True
    ) -> Optional[str]:
        """Helper to get config value from CLI, Env, or Prompt."""
        if arg_val:
            return arg_val
        if env_var in os.environ:
            return os.environ[env_var]

        if not required:
            return None

        # Interactive fallback
        if is_password:
            return getpass.getpass(f"{prompt}: ")
        return input(f"{prompt}: ")

    @staticmethod
    def from_args(args: argparse.Namespace) -> "Config":
        """Loads configuration from CLI args, Env, or interactive prompt."""
        base_url = Config.get_with_prompt(
            args.url,
            "PRTG_BASE_URL",
            "PRTG Base URL (e.g. https://xxxx.my-prtg.com)"
        )

        # Check for API Token first (modern approach)
        api_token = Config.get_with_prompt(
            args.api_token,
            "PRTG_API_TOKEN",
            "PRTG API Token (leave blank for User/Passhash)",
            is_password=True,
            required=False
        )

        username = None
        passhash = None

        if not api_token:
            username = Config.get_with_prompt(args.user, "PRTG_USER", "PRTG Username")
            passhash = Config.get_with_prompt(
                args.passhash, "PRTG_PASSHASH", "PRTG Passhash/API Key", is_password=True
            )

        snmp_comm = Config.get_with_prompt(
            args.snmp_community,
            "PRTG_SNMP_COMMUNITY",
            "SNMP Community (default: public)",
            required=False
        ) or "public"

        return Config(
            base_url=base_url.rstrip("/"),
            username=username,
            passhash=passhash,
            api_token=api_token,
            snmp_community=snmp_comm,
            verify_ssl=os.environ.get("PRTG_VERIFY_SSL", "true").lower() != "false",
        )

@dataclass
class OnboardingResult:
    """Track actions taken during onboarding for summary output."""
    device_id: int
    device_ip: str = ""
    interfaces_found: int = 0
    interfaces_eligible: int = 0
    traffic_sensors_created: int = 0
    foundational_sensors_created: List[str] = field(default_factory=list)
    legacy_sensors_paused: int = 0
    dependency_set: bool = False
    errors: List[str] = field(default_factory=list)

    def print_summary(self) -> None:
        """Prints a summary of the onboarding results."""
        logger.info("=== Summary for Device %s (%s) ===", self.device_id, self.device_ip)
        logger.info("  Interfaces Scanned (Local SNMP): %s", self.interfaces_found)
        logger.info("  Eligible (Physical + Up): %s", self.interfaces_eligible)
        logger.info("  Traffic Sensors Created: %s", self.traffic_sensors_created)
        if self.foundational_sensors_created:
            logger.info("  Core Sensors Created: %s", ', '.join(self.foundational_sensors_created))
        logger.info("  Legacy Sensors Paused: %s", self.legacy_sensors_paused)
        logger.info("  PING Dependency Set: %s", self.dependency_set)
        if self.errors:
            for err in self.errors:
                logger.error("  ! Error: %s", err)

class SNMPScanner:
    """Handles direct SNMP communication with the device."""

    def __init__(self, community: str, port: int):
        """Initialize SNMP Scanner."""
        self.community = community
        self.port = port
        self.snmp_engine = SnmpEngine()

    async def _walk_oid(self, host: str, oid: str) -> Dict[int, Any]:
        """Walks a specific OID and returns {ifIndex: value}."""
        results = {}
        transport = await UdpTransportTarget.create((host, self.port), timeout=1.0, retries=1)
        iterator = walk_cmd(
            self.snmp_engine,
            CommunityData(self.community, mpModel=1), # v2c
            transport,
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
            lexicographicMode=False
        )

        async for error_indication, error_status, _error_index, var_binds in iterator:
            if error_indication:
                logger.warning("SNMP Error on %s: %s", host, error_indication)
                break
            if error_status:
                logger.warning("SNMP Error: %s", error_status.prettyPrint())
                break

            for var_bind in var_binds:
                # varBind[0] is OID, varBind[1] is Value
                # Extract the last part of OID as index
                try:
                    # var_bind[0] is the returned OID. We need the index part which is the suffix.
                    # The suffix can be multiple parts, but for these MIBs it's typically one.
                    # If we use ObjectIdentity(oid), var_bind[0] will be the full OID.
                    index = int(var_bind[0][-1])
                    value = var_bind[1].prettyPrint()
                    results[index] = value
                except (ValueError, IndexError):
                    continue
        return results

    async def scan_interfaces(self, host: str) -> List[Dict[str, Any]]:
        """
        Performs a full interface scan merging standard MIB-II and ifXTable.
        Returns list of dicts: {ifindex, iftype, ifadminstatus, ifname, ifalias}
        """
        logger.info("Starting Local SNMP Scan on %s...", host)

        # 1. Critical Filters
        indices = await self._walk_oid(host, OID_IF_INDEX)
        if not indices:
            logger.error("SNMP Walk failed or returned no interfaces for %s", host)
            return []

        admin_statuses = await self._walk_oid(host, OID_IF_ADMIN_STATUS)
        types = await self._walk_oid(host, OID_IF_TYPE)

        # 2. Descriptive Data
        names = await self._walk_oid(host, OID_IF_NAME)
        aliases = await self._walk_oid(host, OID_IF_ALIAS)
        descrs = await self._walk_oid(host, OID_IF_DESCR)

        compiled_interfaces = []
        for idx in indices:
            # PRTG expects 'ifindex', 'ifadminstatus' (1=up, 2=down), 'iftype'

            # Fallback logic for Name: ifName (Gi0/1) -> ifDescr (GigabitEthernet0/1) -> "Port X"
            if_name = names.get(idx, descrs.get(idx, f"Port {idx}"))

            interface = {
                'ifindex': idx,
                'ifadminstatus': int(admin_statuses.get(idx, 2)), # Default to Down
                'iftype': int(types.get(idx, 0)),
                'ifname': if_name,
                'ifalias': aliases.get(idx, "")
            }
            compiled_interfaces.append(interface)

        logger.info("SNMP Scan Complete. Found %s total interfaces.", len(compiled_interfaces))
        return compiled_interfaces

class PRTGClient:
    """Handles PRTG API interactions."""
    def __init__(self, config: Config):
        """Initialize PRTG Client with config."""
        self.config = config
        self.session = requests.Session()
        self.session.verify = config.verify_ssl

        retry = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
        self.session.mount("https://", HTTPAdapter(max_retries=retry))
        self.session.mount("http://", HTTPAdapter(max_retries=retry))

    def _req(self, method: str, path: str, params: Dict = None) -> Any:
        params = params or {}

        # Use API Token if available, otherwise fallback to Username/Passhash
        if self.config.api_token:
            params.update({"apitoken": self.config.api_token})
        else:
            params.update({"username": self.config.username, "passhash": self.config.passhash})

        url = f"{self.config.base_url}{path}"

        # Redact credentials for logging
        log_params = {
            k: (v if k not in ("username", "passhash", "apitoken") else "****")
            for k, v in params.items()
        }
        logger.debug("API Request: %s %s with params %s", method, url, log_params)

        try:
            resp = self.session.request(
                method, url, params=params, timeout=self.config.request_timeout
            )

            if not resp.ok:
                # PRTG often returns error messages in the body of a 4xx/5xx response
                logger.error("API Error Response (%s): %s", resp.status_code, resp.text)
                # Attach response body to the exception for higher level catch blocks
                resp.reason = f"{resp.reason} - Body: {resp.text[:200]}"

            resp.raise_for_status()
            # Handle PRTG's quirky JSON responses
            if "application/json" in resp.headers.get("Content-Type", ""):
                return resp.json()
            return resp.text
        except Exception as e:
            logger.debug("Exception during request: %s", str(e))
            raise

    def get_device_host(self, device_id: int) -> Optional[str]:
        """Fetches the IP/Hostname of a device from PRTG."""
        data = self._req("GET", "/api/table.json", params={
            "content": "devices",
            "columns": "objid,host",
            "filter_objid": device_id,
            "output": "json"
        })
        # Parse devices result
        devices = data.get("devices", [])
        if devices:
            return devices[0].get("host")
        return None

    def get_probe_for_group(self, group_id: int) -> Optional[str]:
        """Fetches the Name of the Probe for a given Group ID."""
        # Using .json?content=groups&columns=probe
        data = self._req("GET", "/api/table.json", params={
            "content": "groups",
            "columns": "probe",
            "id": group_id,
            "output": "json"
        })
        groups = data.get("groups", [])
        if groups:
            return groups[0].get("probe")
        return None

    def list_sensors(self, device_id: int) -> List[Dict]:
        """Get all sensors for a device."""
        data = self._req("GET", "/api/table.json", params={
            "content": "sensors",
            "filter_parentid": device_id,
            "columns": "objid,sensor,sensortype,status,name",
            "count": 5000,
            "output": "json"
        })
        return data.get("sensors", [])

    def set_property(self, object_id: int, name: str, value: Any):
        """Sets a property on a PRTG object."""
        self._req("POST", "/api/setobjectproperty.htm", params={
            "id": object_id, "name": name, "value": value
        })

    def find_template_sensor(self, sensor_type: str) -> Optional[int]:
        """Finds any existing sensor of the given type to use as a clone source."""
        # Using filter_sensortype to find a candidate
        try:
            data = self._req("GET", "/api/table.json", params={
                "content": "sensors",
                "filter_sensortype": sensor_type,
                "columns": "objid,sensortype,name",
                "count": 1,
                "output": "json"
            })
            sensors = data.get("sensors", [])
            if sensors:
                logger.debug(
                    "Found template sensor for '%s': %s (ID: %s)",
                    sensor_type, sensors[0]['name'], sensors[0]['objid']
                )
                return sensors[0].get("objid")
        except Exception as e:
            logger.warning("Could not find template for %s: %s", sensor_type, e)
        return None

    async def clone_sensor(
        self, source_id: int, target_device_id: int, new_name: str
    ) -> Optional[int]:
        """Clones a source sensor to the target device with a new name.
        Returns new ID if successful."""
        try:
            # 1. Perform the clone
            self._req("GET", "/api/duplicateobject.htm", params={
                "id": source_id,
                "targetid": target_device_id,
                "name": new_name
            })

            # 2. PRTG doesn't return the ID, so we must find it.
            # We search the target device for the sensor with the specific name.
            # Retry a few times as creation might be async
            for _ in range(5):
                await asyncio.sleep(1) # Wait for creation
                sensors = self.list_sensors(target_device_id)
                for s in sensors:
                    if s.get("name") == new_name:
                        return s.get("objid")

            logger.error(
                "Cloned sensor '%s' was not found on device %s after retries.",
                new_name, target_device_id
            )
            return None

        except Exception as e:
            logger.error("Failed to clone sensor '%s': %s", new_name, e)
            return None

    def pause_sensor(self, sensor_id: int, msg: str):
        """Pauses a sensor with a message."""
        self._req("GET", "/api/pause.htm", params={"id": sensor_id, "action": 0, "pausemsg": msg})

    def set_dependency(self, device_id: int, sensor_id: int):
        """Sets the device dependency to a specific sensor."""
        self.set_property(device_id, "dependencytype", 1)
        self.set_property(device_id, "dependency", sensor_id)

    def add_device(self, group_id: int, name: str, host: str) -> int:
        resp = self._req("POST", "/api/adddevice.htm", params={
            "name": name, "host": host, "id": group_id
        })
        try:
            return int(json.loads(resp).get("objid"))
        except (ValueError, KeyError, TypeError) as e:
            raise Exception(f"Failed to create device. Response: {resp}") from e

# --- Logic Functions ---

async def ensure_core_sensors(
    client: PRTGClient,
    device_id: int,
    sensors: List[Dict],
    result: OnboardingResult,
    dry_run: bool
) -> int:
    """Checks for Ping, CPU, Mem, Uptime. Returns Ping ID."""
    # existing_types = {s.get("sensortype"): s.get("objid") for s in sensors} # Unused
    ping_id = None

    # Check Ping specifically (handle variations like 'ping' or 'ping_v2')
    for s in sensors:
        if "ping" in s.get("sensortype", ""):
            ping_id = s.get("objid")
            break

    # Required Map
    required = {
        "ping": "ping",
        "snmp_cpu": "snmpcpu",
        "snmp_mem": "snmpmemory",
        "snmp_uptime": "snmpuptime"
    }

    for key, prtg_type in required.items():
        # Check if any sensor matches the type loosely
        found = False
        for s in sensors:
            if prtg_type in s.get("sensortype", ""):
                found = True
                break

        if not found:
            name = key.replace("_", " ").upper()
            if dry_run:
                # Preview info for dry-run
                logger.info(
                    "[DRY-RUN] Would clone template for %s to create %s sensor.",
                    prtg_type, name
                )
                if key == "ping":
                    ping_id = 99999
            else:
                logger.info("Creating missing %s sensor...", name)
                try:
                    # 1. Find Template
                    template_id = client.find_template_sensor(prtg_type)
                    if not template_id:
                        raise Exception(
                            f"No existing sensor of type '{prtg_type}' "
                            "found to use as template."
                        )

                    # 2. Clone
                    new_id = await client.clone_sensor(template_id, device_id, name)

                    if new_id:
                        result.foundational_sensors_created.append(name)
                        if key == "ping":
                            ping_id = new_id
                        logger.info("Successfully created %s sensor (ID: %s)", name, new_id)
                    else:
                        raise Exception("Clone operation failed to return a new ID.")

                    await asyncio.sleep(1) # Rate limit safety

                except Exception as e:
                    error_msg = str(e)
                    result.errors.append(f"Failed to create {name}: {error_msg}")
                    logger.error(f"Error creating {name}: {error_msg}")

    return ping_id

async def process_traffic_sensors(
    client: PRTGClient, device_id: int, interfaces: List[Dict],
    sensors: List[Dict], result: OnboardingResult, dry_run: bool
) -> List[int]:
    """Creates traffic sensors for eligible interfaces."""
    created_ids = []

    # 1. Identify existing ifIndexes to avoid duplicates
    # existing_indices = set() # Unused
    for s in sensors:
        if "traffic" in s.get("sensortype", ""):
            # Attempt to parse ifIndex from parameter/settings is hard via API table
            # heuristic: check if name contains ifIndex logic or rely on PRTG dupe check
            # For robustness, we assume we create new ones and rely on cleanup logic if needed
            pass

    for iface in interfaces:
        idx = iface['ifindex']
        # Filter: Physical & Admin Up
        if iface['ifadminstatus'] != 1:
            continue
        if iface['iftype'] not in PHYSICAL_IF_TYPES:
            continue

        result.interfaces_eligible += 1

        # Naming Logic: "Traffic [Alias]" or "Traffic [Name]"
        # This solves the user's "Description" issue
        alias = iface.get('ifalias', '').strip()
        name_part = alias if alias else iface.get('ifname', f'Port {idx}')
        sensor_name = f"Traffic {name_part}"

        if dry_run:
            logger.info(
                "[DRY-RUN] Would clone template for 'snmptraffic' to create %s (ifIndex %s).",
                sensor_name, idx
            )
        else:
            try:
                # 1. Find Template for Traffic
                template_id = client.find_template_sensor("snmptraffic")
                if not template_id:
                    raise Exception(
                        "No existing SNMP Traffic sensor found to use as template."
                    )

                # 2. Clone Sensor
                new_id = await client.clone_sensor(template_id, device_id, sensor_name)

                if new_id:
                    # 3. Configure Interface
                    client.set_property(new_id, "interfacenumber", idx)
                    client.set_property(new_id, "tags", "bandwidth_sensor automated")

                    created_ids.append(new_id)
                    result.traffic_sensors_created += 1
                    logger.info("Created: %s (ID: %s)", sensor_name, new_id)
                else:
                    result.errors.append(f"Failed to clone sensor: {sensor_name}")

            except Exception as e:
                error_msg = str(e)
                result.errors.append(f"Failed to create {sensor_name}: {error_msg}")
                logger.error(f"Error creating traffic sensor {sensor_name}: {error_msg}")

    return created_ids

# --- Main Execution ---

def parse_arguments():
    """Parses command line arguments."""
    parser = argparse.ArgumentParser(description="PRTG Onboarding (Hybrid Mode)")

    # Global Config Arguments
    parser.add_argument("--url", help="PRTG Base URL")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--api-token", help="PRTG API Token (v21.1+)")
    parser.add_argument("--user", help="PRTG Username")
    parser.add_argument("--passhash", help="PRTG Passhash/API Key")
    parser.add_argument("--snmp-community", help="SNMP Community String")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # Mode: Existing
    cmd_existing = subparsers.add_parser("existing", help="Process existing PRTG devices")
    cmd_existing.add_argument("device_ids", nargs="+", type=int, help="Device IDs to update")
    cmd_existing.add_argument("--dry-run", action="store_true")

    # Mode: New
    cmd_new = subparsers.add_parser("new", help="Add and onboard a new device")
    cmd_new.add_argument("group_id", type=int, help="Target Group ID")
    cmd_new.add_argument("name", help="Device Name")
    cmd_new.add_argument("host", help="IP/Hostname")
    cmd_new.add_argument("--dry-run", action="store_true")

    return parser.parse_args()

async def resolve_targets(args: argparse.Namespace, prtg: PRTGClient) -> List[tuple]:
    """Resolves target devices based on the command mode."""
    targets = [] # List of (id, ip, is_new)

    if args.command == "existing":
        for did in args.device_ids:
            ip = prtg.get_device_host(did)
            if ip:
                targets.append((did, ip, False))
            else:
                logger.error("Could not resolve IP for device %s", did)

    elif args.command == "new":
        if args.dry_run:
            logger.info("[DRY-RUN] Would create device. Skipping to simulation.")
            targets.append((99999, args.host, True))
        else:
            # Safety Check: PPHM Hosted Probe vs Private IP
            try:
                probe_name = prtg.get_probe_for_group(args.group_id)
                if probe_name and "Hosted Probe" in probe_name:
                    # Check if IP is private
                    try:
                        ip_obj = ipaddress.ip_address(args.host)
                        if ip_obj.is_private:
                            logger.warning("!!! CAUTION !!!")
                            logger.warning(
                                "You are adding a device with a PRIVATE IP (%s) to the '%s'.",
                                args.host, probe_name
                            )
                            logger.warning(
                                "The Hosted Probe runs in the cloud and "
                                "cannot reach your local network."
                            )
                            logger.warning(
                                "Verify you are using a Group ID belonging to a LOCAL REMOTE PROBE."
                            )
                            logger.warning("Waiting 10 seconds. Press Ctrl+C to cancel...")
                            await asyncio.sleep(10)
                    except ValueError:
                        # Host might be a DNS name, skip check or try resolve
                        pass
            except Exception as e:
                logger.warning("Could not verify Probe type: %s", e)

            try:
                did = prtg.add_device(args.group_id, args.name, args.host)
                logger.info("Device created with ID %s", did)
                targets.append((did, args.host, True))
                await asyncio.sleep(30) # Wait for PRTG internal commit
            except Exception as e:
                logger.error("Fatal: %s", e)
                sys.exit(1)

    return targets

async def process_device(
    device_id: int,
    device_ip: str,
    is_new: bool,
    prtg: PRTGClient,
    snmp: SNMPScanner,
    dry_run: bool
):
    """Orchestrates the onboarding process for a single device."""
    result = OnboardingResult(device_id, device_ip)

    # 1. Local SNMP Scan
    interfaces = await snmp.scan_interfaces(device_ip)
    result.interfaces_found = len(interfaces)

    if not interfaces:
        logger.error("Skipping %s - SNMP Scan failed.", device_ip)
        result.errors.append("SNMP Scan Failed")
        result.print_summary()
        return

    # 2. Get Current State
    current_sensors = [] if dry_run and is_new else prtg.list_sensors(device_id)

    # 3. Create Core Sensors
    ping_id = await ensure_core_sensors(prtg, device_id, current_sensors, result, dry_run)

    # 4. Create Traffic Sensors
    new_traffic_ids = await process_traffic_sensors(
        prtg, device_id, interfaces, current_sensors, result, dry_run
    )

    # 5. Set Dependencies
    if ping_id and not dry_run:
        prtg.set_dependency(device_id, ping_id)
        result.dependency_set = True

    # 6. Pause Legacy (Existing Mode Only)
    if not is_new and not dry_run:
        for s in current_sensors:
            if "traffic" in s.get("sensortype", "") and s.get("objid") not in new_traffic_ids:
                if s.get("status_raw") != 7: # 7 is paused
                    prtg.pause_sensor(s['objid'], "Paused by Automation (Legacy)")
                    result.legacy_sensors_paused += 1

    result.print_summary()

async def main():
    """Main entry point for the script."""
    check_and_install_packages()
    args = parse_arguments()
    if args.debug:
        setup_logging(debug=True)
        logger.debug("Debug logging enabled")

    config = Config.from_args(args)

    prtg = PRTGClient(config)
    snmp = SNMPScanner(config.snmp_community, config.snmp_port)

    # Determine targets
    targets = await resolve_targets(args, prtg)

    # Process Targets
    for device_id, device_ip, is_new in targets:
        await process_device(device_id, device_ip, is_new, prtg, snmp, args.dry_run)

if __name__ == "__main__":
    asyncio.run(main())
