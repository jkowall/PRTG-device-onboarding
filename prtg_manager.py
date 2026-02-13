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
    python prtg_manager.py [--debug] [--config CONFIG] [--url URL] [--api-token TOKEN] [--port-name-template TEMPLATE]
                           new <GROUP_ID> "<NAME>" <HOST> [--dry-run]
    python prtg_manager.py [--debug] [--config CONFIG] [--url URL] [--api-token TOKEN]
                           existing <DEVICE_ID_1> [DEVICE_ID_2 ...] [--dry-run]

Configuration:
    Options are merged in order: CLI Flags > Env Variables > config.yaml > Interactive Prompts.
    Environment Variables: PRTG_BASE_URL, PRTG_API_TOKEN, PRTG_USER, PRTG_PASSHASH, PRTG_SNMP_COMMUNITY, PRTG_PORT_NAME_TEMPLATE.

Requirements:
    pip install requests pysnmp PyYAML

Hosted Monitor (PPHM) Notes:
    - When using PRTG Hosted Monitor, you MUST run this script from local network
      access (e.g., behind a VPN or on a local server).
    - The 'group_id' provided for new devices MUST belong to a REMOTE PROBE.
"""
from __future__ import annotations

# Standard library imports first
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
import xml.etree.ElementTree as ET

# We will check and install packages before importing non-standard once
def check_and_install_packages():
    """Checks for required packages and installs them if missing."""
    required_packages = {
        "requests": "requests",
        "pysnmp": "pysnmp>=7.1.22",
        "yaml": "PyYAML"
    }

    missing = []
    for package, install_name in required_packages.items():
        if importlib.util.find_spec(package) is None:
            missing.append(install_name)

    if missing:
        print(f"Missing required packages: {', '.join(missing)}")
        print("Attempting to auto-install...")
        try:
            # We use --break-system-packages if we are in an externally managed environment
            # but only if absolutely necessary. Actually, better to just try.
            # If it fails, the user will see why.
            subprocess.check_call([sys.executable, "-m", "pip", "install"] + missing)
            print("Installation successful. Continuing...")
        except subprocess.CalledProcessError as e:
            # Try again with --break-system-packages if it fails (often needed in modern Linux)
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", "--break-system-packages"] + missing)
                print("Installation successful (with --break-system-packages). Continuing...")
            except subprocess.CalledProcessError:
                print(f"Failed to install packages: {e}")
                print("Please run: pip install -r requirements.txt")
                sys.exit(1)

check_and_install_packages()

# Now we can safely import non-standard packages
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from pysnmp.hlapi.v3arch import (  # pylint: disable=no-name-in-module
    CommunityData, ContextData, ObjectIdentity, ObjectType,
    SnmpEngine, UdpTransportTarget, walk_cmd
)

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

__version__ = "1.5.1"

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
OID_IF_SPEED = '1.3.6.1.2.1.2.2.1.5'      # ifSpeed (bandwidth)

@dataclass
class Config:
    """Application Configuration model."""
    base_url: str
    username: Optional[str] = None
    passhash: Optional[str] = None
    api_token: Optional[str] = None
    snmp_community: Optional[str] = None
    snmp_port: int = 161
    verify_ssl: bool = True
    request_timeout: int = 60
    port_name_template: Optional[str] = None
    cleanup_legacy: bool = False

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
        """Loads configuration from YAML, CLI args, Env, or interactive prompt."""
        yaml_data = {}
        config_path = getattr(args, 'config', 'config.yaml')
        if os.path.exists(config_path):
            try:
                import yaml  # pylint: disable=import-outside-toplevel
                with open(config_path, 'r', encoding='utf-8') as f:
                    yaml_data = yaml.safe_load(f) or {}
                logger.info("Loaded configuration from %s", config_path)
            except Exception as e:
                logger.warning("Could not load config file %s: %s", config_path, e)

        def get_val(cli_val, env_var, yaml_key, prompt_text, is_pwd=False, req=True):
            # Priority: CLI > Env > YAML > Prompt
            if cli_val:
                return cli_val
            if env_var in os.environ:
                return os.environ[env_var]
            if yaml_key in yaml_data:
                return yaml_data[yaml_key]
            return Config.get_with_prompt(None, env_var, prompt_text, is_pwd, req)

        base_url = get_val(
            args.url, "PRTG_BASE_URL", "base_url",
            "PRTG Base URL (e.g. https://xxxx.my-prtg.com)"
        )

        api_token = get_val(
            args.api_token, "PRTG_API_TOKEN", "api_token",
            "PRTG API Token (leave blank for User/Passhash)",
            is_pwd=True, req=False
        )

        username = None
        passhash = None
        if not api_token:
            username = get_val(args.user, "PRTG_USER", "username", "PRTG Username")
            passhash = get_val(
                args.passhash, "PRTG_PASSHASH", "passhash",
                "PRTG Passhash/API Key", is_pwd=True
            )

        snmp_comm = get_val(
            args.snmp_community, "PRTG_SNMP_COMMUNITY", "snmp_community",
            "SNMP Community (default: public)", req=False
        )

        port_template = get_val(
            getattr(args, 'port_name_template', None),
            "PRTG_PORT_NAME_TEMPLATE", "port_name_template",
            "Port Name Template (optional)", req=False
        )

        return Config(
            base_url=base_url.rstrip("/"),
            username=username,
            passhash=passhash,
            api_token=api_token,
            snmp_community=snmp_comm,
            verify_ssl=os.environ.get("PRTG_VERIFY_SSL", "true").lower() != "false",
            port_name_template=port_template,
            cleanup_legacy=get_val(
                getattr(args, 'cleanup', None),
                "PRTG_CLEANUP_LEGACY", "cleanup_legacy",
                "Cleanup legacy sensors (True/False)", req=False
            ) in (True, "True", "true", "1")
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
        speeds = await self._walk_oid(host, OID_IF_SPEED)

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
                'ifalias': aliases.get(idx, ""),
                'ifdescr': descrs.get(idx, ""),
                'ifspeed': speeds.get(idx, "")
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
                json_data = resp.json()
                # Log small JSON bodies for debugging (e.g., empty lists)
                if len(resp.text) < 500:
                    logger.debug("API Response Body: %s", resp.text)
                return json_data
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

    def get_property(self, object_id: int, name: str) -> Optional[str]:
        """Fetches a specific property of an object."""
        # Using /api/getobjectproperty.htm?id=id&name=name
        try:
            val = self._req("GET", "/api/getobjectstatus.htm", params={
                "id": object_id, "name": name, "show": "text"
            })
            return str(val).strip()
        except (requests.RequestException, json.JSONDecodeError) as e:
            logger.debug("Failed to get property %s for %s: %s", name, object_id, e)
            return None

    def get_object_setting(self, object_id: int, name: str) -> Optional[str]:
        """Fetches a setting using getobjectproperty.htm (returns XML)."""
        try:
            # PRTG returns XML by default for getobjectproperty
            response_text = self._req("GET", "/api/getobjectproperty.htm", params={
                "id": object_id, "name": name, "show": "nohtmlencode"
            })
            if not response_text:
                return None

            # Simple XML parsing: <prtg><version>...</version><result>VALUE</result></prtg>
            # However, sometimes it returns just the value if show=nohtmlencode depends on version
            # But safer to parse XML if it looks like XML
            text = response_text.strip()
            if text.startswith("<"):
                root = ET.fromstring(text)
                result = root.find("result")
                if result is not None:
                    return result.text
            return text
        except Exception as e:
            logger.debug("Failed to get setting %s for %s: %s", name, object_id, e)
            return None

    def get_inherited_snmp_community(self, device_id: int) -> Optional[str]:
        """
        Attempts to fetch the SNMP community from the device settings.
        Checks multiple property names used by PRTG for different device types.
        """
        # Property names to check in order of likelihood
        # 'snmpcommunity' is the most common for Generic/Windows
        # 'cifssnmpcommunity' is often used for Linux/Unix
        # 'snmp_community_v2' is explicit v2
        candidates = ["snmpcommunity", "cifssnmpcommunity", "snmp_community_v2"]

        for prop in candidates:
            val = self.get_object_setting(device_id, prop)
            # Filter out masked passwords or empty strings
            if val and val.strip() and "****" not in val:
                logger.info("Found inherited SNMP community via '%s'", prop)
                return val.strip()

        logger.debug("Could not determine inherited SNMP community (or it is masked).")
        return None

    def find_template_sensor(self, sensor_types: List[str] | str) -> Optional[int]:
        """Finds any existing sensor of the given type(s) to use as a clone source."""
        if isinstance(sensor_types, str):
            sensor_types = [sensor_types]

        for s_type in sensor_types:
            try:
                # Correct param: filter_type (matching column 'type')
                data = self._req("GET", "/api/table.json", params={
                    "content": "sensors",
                    "filter_type": s_type,
                    "columns": "objid,type,name",
                    "count": 1,
                    "output": "json"
                })
                sensors = data.get("sensors", [])
                if sensors:
                    logger.debug(
                        "Found template sensor for '%s': %s (ID: %s)",
                        s_type, sensors[0]['name'], sensors[0]['objid']
                    )
                    return sensors[0].get("objid")
                logger.debug("No template sensor found for type: %s", s_type)
            except (requests.RequestException, json.JSONDecodeError) as e:
                logger.warning("Could not find template for %s: %s", s_type, e)

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

        except requests.RequestException as e:
            logger.error("Failed to clone sensor '%s': %s", new_name, e)
            return None

    def pause_sensor(self, sensor_id: int, msg: str = "", action: int = 0):
        """Pauses (0) or Simulates Resume (1) a sensor.
           Note: PRTG 'pause.htm' uses action=0 to pause, action=1 to resume.
        """
        params = {"id": sensor_id, "action": action}
        if action == 0 and msg:
            params["pausemsg"] = msg
        self._req("GET", "/api/pause.htm", params=params)

    def set_dependency(self, device_id: int, sensor_id: int):
        """Sets the device dependency to a specific sensor."""
        self.set_property(device_id, "dependencytype", 1)
        self.set_property(device_id, "dependency", sensor_id)

    def delete_object(self, object_id: int):
        """Permanently deletes an object from PRTG."""
        self._req("GET", "/api/deleteobject.htm", params={"id": object_id, "approve": 1})

    def add_device(self, group_id: int, name: str, host: str) -> int:
        """Adds a new device to PRTG."""
        resp = self._req("POST", "/api/adddevice.htm", params={
            "name": name, "host": host, "id": group_id
        })
        try:
            return int(json.loads(resp).get("objid"))
        except (ValueError, KeyError, TypeError, json.JSONDecodeError) as e:
            raise RuntimeError(f"Failed to create device. Response: {resp}") from e

# --- Logic Functions ---

async def ensure_core_sensors(
    client: PRTGClient,
    device_id: int,
    sensors: List[Dict],
    result: OnboardingResult,
    dry_run: bool
) -> int:
    """Checks for Ping, CPU, Mem, Uptime. Handles duplicates. Returns Ping ID."""
    ping_id = None

    # Required Map: Internal Key -> PRTG Sensor Type (normalized to lowercase for check)
    required = {
        "ping": ["ping"],
        "snmp_cpu": ["snmpcpu", "snmp cpu load"],
        "snmp_mem": ["snmpmemory", "snmp memory"],
        "snmp_uptime": ["snmpuptime", "snmp system uptime"]
    }

    # Helper to find all sensors matching a key
    def find_matching_sensors(key_types):
        matches = []
        for s in sensors:
            s_type = s.get("sensortype", "").lower()
            s_name = s.get("name", "").lower()
            # Match by type OR name (for some legacy sensors)
            if any(t in s_type for t in key_types) or any(t in s_name for t in key_types):
                matches.append(s)
        return matches

    for key, valid_types in required.items():
        name = key.replace("_", " ").upper()
        matches = find_matching_sensors(valid_types)
        
        selected_sensor = None

        if matches:
            # 1. Deduplication Strategy
            # Priority: Active (Up/Down/Warning) > Paused > Unknown
            # Sort by status (Up/Down/Warn < Paused)
            # Status Raw: 3=Up, 5=Down, 13=Warn, 7=Paused, 8=PausedByDep
            # We want to prefer non-7/8.
            
            def specific_sort(s):
                status = s.get("status_raw", 0)
                # Give priority to Up(3)/Down(5)/Warn(13) over Paused(7/8)
                priority = 0 if status in [3, 5, 13, 2, 4] else 1 
                return (priority, s.get("objid"))

            matches.sort(key=specific_sort)
            selected_sensor = matches[0]
            
            # Resume if paused
            if selected_sensor.get("status_raw") in [7, 8, 9, 11, 12]: # Paused states
                if dry_run:
                    logger.info("[DRY-RUN] Would RESUME existing %s sensor (ID: %s)", name, selected_sensor['objid'])
                else:
                    logger.info("Resuming existing %s sensor (ID: %s)", name, selected_sensor['objid'])
                    try:
                        client._req("GET", "/api/pause.htm", params={"id": selected_sensor['objid'], "action": 1})
                    except Exception as e:
                        logger.error("Failed to resume sensor %s: %s", selected_sensor['objid'], e)
            
            # Delete duplicates
            if len(matches) > 1:
                for duplicate in matches[1:]:
                    if dry_run:
                        logger.info("[DRY-RUN] Would DELETE duplicate %s sensor (ID: %s)", name, duplicate['objid'])
                    else:
                        logger.info("Deleting duplicate %s sensor (ID: %s)", name, duplicate['objid'])
                        try:
                            client.delete_object(duplicate['objid'])
                        except Exception as e:
                            logger.error("Failed to delete duplicate %s: %s", duplicate['objid'], e)

            # Assign Ping ID if this is the ping sensor
            if key == "ping":
                ping_id = selected_sensor['objid']

            result.foundational_sensors_created.append(f"{name} (Existing)")

        else:
            # Create New
            if dry_run:
                logger.info("[DRY-RUN] Would clone template for %s to create %s sensor.", valid_types[0], name)
                if key == "ping":
                    ping_id = 99999
            else:
                logger.info("Creating missing %s sensor...", name)
                try:
                    # Try to find a template using the valid types
                    template_id = client.find_template_sensor(valid_types)
                    if not template_id:
                        # Fallback for generic types if exact match fails
                        if key == "snmp_mem": 
                            template_id = client.find_template_sensor(["snmpmem", "snmpmemory"])
                    
                    if not template_id:
                        raise Exception(f"No template found for {name}")

                    new_id = await client.clone_sensor(template_id, device_id, name)
                    if new_id:
                        result.foundational_sensors_created.append(f"{name} (New)")
                        if key == "ping":
                            ping_id = new_id
                        
                        # Resume the new sensor immediately
                        if dry_run:
                            logger.info("[DRY-RUN] Would RESUME new %s sensor (ID: %s)", name, new_id)
                        else:
                            try:
                                client.pause_sensor(new_id, action=1)
                                logger.info("Successfully created and RESUMED %s sensor (ID: %s)", name, new_id)
                            except Exception as e:
                                logger.error("Created %s (ID: %s) but failed to RESUME: %s", name, new_id, e)
                    else:
                        raise Exception("Clone failed")
                except Exception as e:
                    error_msg = str(e)
                    result.errors.append(f"Failed to create {name}: {error_msg}")
                    logger.error("Error creating %s: %s", name, error_msg)

    return ping_id

# pylint: disable=too-many-arguments,too-many-locals,too-many-branches
async def process_traffic_sensors(
    client: PRTGClient, device_id: int, interfaces: List[Dict],
    sensors: List[Dict], result: OnboardingResult, config: Config, dry_run: bool
) -> List[int]:
    """Creates traffic sensors for eligible interfaces. Returns list of all relevant sensor IDs."""
    relevant_ids = []

    # 1. Identify existing sensor names and IDs
    existing_sensors = {s.get("name"): s.get("objid") for s in sensors}

    # Debug: Log existing status of sensors to understand why they aren't being picked up or resumed
    for s in sensors:
         if "traffic" in s.get("sensortype", "").lower():
             logger.debug("Existing Traffic Sensor: %s (ID: %s, Type: %s, Status: %s)", 
                          s.get("name"), s.get("objid"), s.get("sensortype"), s.get("status_raw"))

    for iface in interfaces:
        idx = iface['ifindex']
        name = iface.get('ifname', '')
        alias = iface.get('ifalias', '')
        descr = iface.get('ifdescr', '')
        
        logger.debug("Processing Interface %s: ifName='%s', ifAlias='%s', ifDescr='%s', Status=%s", 
                     idx, name, alias, descr, iface['ifadminstatus'])

        # Filter: Physical & Admin Up
        if iface['ifadminstatus'] != 1:
            continue
        if iface['iftype'] not in PHYSICAL_IF_TYPES:
            continue

        result.interfaces_eligible += 1

        # 2. Template Interpolation
        # Placeholders: [port], [ifalias], [ifname], [ifdescr], [ifspeed], [ifsensor]
        sensor_name = config.port_name_template
        sensor_name = sensor_name.replace("[port]", f"{idx:03}") # 3-digit padding common in PRTG
        sensor_name = sensor_name.replace("[ifalias]", iface.get('ifalias', ''))
        sensor_name = sensor_name.replace("[ifname]", iface.get('ifname', ''))
        sensor_name = sensor_name.replace("[ifdescr]", iface.get('ifdescr', ''))
        sensor_name = sensor_name.replace("[ifspeed]", iface.get('ifspeed', ''))
        sensor_name = sensor_name.replace("[ifsensor]", "SNMP Traffic")
        
        # Clean up double spaces or brackets if values were empty
        sensor_name = ' '.join(sensor_name.split())
        
        # 3. Duplicate Check
        if sensor_name in existing_sensors:
            existing_id = existing_sensors[sensor_name]
            logger.debug("Existing sensor matches name: %s (ID: %s)", sensor_name, existing_id)
            relevant_ids.append(existing_id)
            
            # CRITICAL FIX: Ensure existing sensor is unpaused
            # Find the sensor dict to check status
            s = next((s for s in sensors if s['objid'] == existing_id), None)
            if s and s.get("status_raw") in [7, 8, 9, 11, 12]: # Paused
                 if dry_run:
                     logger.info("[DRY-RUN] Would RESUME matched traffic sensor: %s", sensor_name)
                 else:
                     logger.info("Resuming matched traffic sensor: %s", sensor_name)
                     try:
                         client.pause_sensor(existing_id, action=1) # 1 = Resume
                     except Exception as e:
                         logger.error("Failed to resume sensor %s: %s", existing_id, e)
            continue

        if dry_run:
            logger.info(
                "[DRY-RUN] Would clone template for 'snmptraffic' to create %s (ifIndex %s).",
                sensor_name, idx
            )
        else:
            try:
                # 1. Find Template for Traffic (Try both 32/64-bit types)
                type_candidates = ["snmptraffic", "snmptraffic64"]
                template_id = client.find_template_sensor(type_candidates)
                if not template_id:
                    raise Exception(
                        f"No existing sensor of types {type_candidates} "
                        "found to use as template."
                    )

                # 2. Clone Sensor
                new_id = await client.clone_sensor(template_id, device_id, sensor_name)

                if new_id:
                    # 3. Configure Interface
                    client.set_property(new_id, "interfacenumber", idx)
                    client.set_property(new_id, "tags", "bandwidth_sensor automated")

                    relevant_ids.append(new_id)
                    result.traffic_sensors_created += 1
                    logger.info("Created: %s (ID: %s)", sensor_name, new_id)
                else:
                    result.errors.append(f"Failed to clone sensor: {sensor_name}")

            except Exception as e:
                error_msg = str(e)
                result.errors.append(f"Failed to create {sensor_name}: {error_msg}")
                logger.error("Error creating traffic sensor %s: %s", sensor_name, error_msg)

    return relevant_ids

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
    parser.add_argument("--config", default="config.yaml", help="Path to config file")
    parser.add_argument(
        "--port-name-template", help="Port Name Template (e.g. '([port]) [ifalias]')"
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # Mode: Existing
    cmd_existing = subparsers.add_parser("existing", help="Process existing PRTG devices")
    cmd_existing.add_argument("device_ids", nargs="+", type=int, help="Device IDs to update")
    cmd_existing.add_argument("--dry-run", action="store_true")
    cmd_existing.add_argument("--cleanup", action="store_true", help="Delete legacy sensors instead of pausing")

    # Mode: New
    cmd_new = subparsers.add_parser("new", help="Add and onboard a new device")
    cmd_new.add_argument("group_id", type=int, help="Target Group ID")
    cmd_new.add_argument("name", help="Device Name")
    cmd_new.add_argument("host", help="IP/Hostname")
    cmd_new.add_argument("--dry-run", action="store_true")
    cmd_new.add_argument("--cleanup", action="store_true", help="Delete legacy sensors instead of pausing")

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

# pylint: disable=too-many-arguments,too-many-locals,too-many-branches,too-many-statements
async def process_device(
    device_id: int,
    device_ip: str,
    is_new: bool,
    prtg: PRTGClient,
    config: Config,
    dry_run: bool
):
    """Orchestrates the onboarding process for a single device."""
    result = OnboardingResult(device_id, device_ip)

    # 1. Fetch/Set Port Name Template
    if not config.port_name_template:
        device_template = prtg.get_property(device_id, "portnametemplate")
        if device_template:
            config.port_name_template = device_template
            logger.info("Using Port Name Template from device: %s", device_template)
        else:
            config.port_name_template = "([ifname]) [ifalias]"
            logger.info("No template found on device. Using default: %s", config.port_name_template)

    # 2. SNMP Community Resolution
    community = config.snmp_community
    if not community:
        # Attempt to fetch from PRTG
        community = prtg.get_inherited_snmp_community(device_id)
        if not community:
            community = "public"
            logger.warning("No SNMP community provided or inherited. Defaulting to 'public'.")
    
    # 3. Local SNMP Scan
    snmp = SNMPScanner(community, config.snmp_port)
    interfaces = await snmp.scan_interfaces(device_ip)
    result.interfaces_found = len(interfaces)

    if not interfaces:
        logger.error("Skipping %s - SNMP Scan failed.", device_ip)
        result.errors.append("SNMP Scan Failed")
        result.print_summary()
        return

    # 3. Get Current State
    current_sensors = [] if dry_run and is_new else prtg.list_sensors(device_id)

    # 3. Create Core Sensors
    ping_id = await ensure_core_sensors(prtg, device_id, current_sensors, result, dry_run)

    # 4. Create Traffic Sensors
    relevant_traffic_ids = await process_traffic_sensors(
        prtg, device_id, interfaces, current_sensors, result, config, dry_run
    )

    # 5. Set Dependencies
    if ping_id and not dry_run:
        prtg.set_dependency(device_id, ping_id)
        result.dependency_set = True

    # 6. Clean up Legacy (Existing Mode Only)
    if not is_new:
        for s in current_sensors:
            # Case-insensitive check for traffic sensors
            if "traffic" in s.get("sensortype", "").lower() and s.get("objid") not in relevant_traffic_ids:
                if config.cleanup_legacy:
                    if dry_run:
                        logger.info("[DRY-RUN] Would delete legacy sensor: %s (ID: %s)", s.get("name"), s.get("objid"))
                    else:
                        logger.info("Deleting legacy sensor: %s (ID: %s)", s.get("name"), s.get("objid"))
                        try:
                            prtg.delete_object(s['objid'])
                        except Exception as e:
                            logger.error("Failed to delete sensor %s: %s", s.get("objid"), e)
                else:
                    # Only pause if not already paused
                    if s.get("status_raw") not in [7, 8, 9, 11, 12]: # Not Paused
                        if dry_run:
                            logger.info("[DRY-RUN] Would pause legacy sensor: %s (ID: %s)", s.get("name"), s.get("objid"))
                        else:
                            prtg.pause_sensor(s['objid'], "Paused by Automation (Legacy)")
                            result.legacy_sensors_paused += 1
                            logger.info("Paused legacy sensor: %s (ID: %s)", s.get("name"), s.get("objid"))
                    else:
                        logger.debug("Skipping legacy purge for %s (ID: %s) - Already Paused", s.get("name"), s.get("objid"))

    result.print_summary()

async def main():
    """Main entry point for the script."""
    args = parse_arguments()
    if args.debug:
        setup_logging(debug=True)
        logger.debug("Debug logging enabled")

    config = Config.from_args(args)
    prtg = PRTGClient(config)

    # Determine targets
    targets = await resolve_targets(args, prtg)

    # Process Targets
    for device_id, device_ip, is_new in targets:
        await process_device(device_id, device_ip, is_new, prtg, config, args.dry_run)

if __name__ == "__main__":
    asyncio.run(main())
