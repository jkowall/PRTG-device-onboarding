#!/usr/bin/env python3
# Copyright 2025 Jonah Kowall
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
    python prtg_onboarding.py existing 1234 5678 --dry-run
    python prtg_onboarding.py new 100 "Core Switch" 10.10.10.1
 
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
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
import ipaddress

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from pysnmp.hlapi import *

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# --- Constants ---

# IANA Interface Types (Physical)
PHYSICAL_IF_TYPES = {
    6,    # ethernetCsmacd
    7,    # iso88023Csmacd
    62,   # fastEther
    117,  # gigabitEthernet
    161,  # ieee8023adLag
    53,   # propVirtual (often used for VLANs/Subinterfaces, remove if strictly physical ports desired)
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
    base_url: str
    username: str
    passhash: str
    snmp_community: str
    snmp_port: int = 161
    verify_ssl: bool = True
    request_timeout: int = 60

    @staticmethod
    def from_env() -> "Config":
        """Loads configuration from Environment Variables."""
        # Defaults
        snmp_comm = os.environ.get("PRTG_SNMP_COMMUNITY", "public")
        
        missing = [key for key in ("PRTG_BASE_URL", "PRTG_USER", "PRTG_PASSHASH") if key not in os.environ]
        if missing:
            logger.error(f"Missing env vars: {', '.join(missing)}")
            sys.exit(1)
            
        return Config(
            base_url=os.environ["PRTG_BASE_URL"].rstrip("/"),
            username=os.environ["PRTG_USER"],
            passhash=os.environ["PRTG_PASSHASH"],
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
        logger.info(f"=== Summary for Device {self.device_id} ({self.device_ip}) ===")
        logger.info(f"  Interfaces Scanned (Local SNMP): {self.interfaces_found}")
        logger.info(f"  Eligible (Physical + Up): {self.interfaces_eligible}")
        logger.info(f"  Traffic Sensors Created: {self.traffic_sensors_created}")
        if self.foundational_sensors_created:
            logger.info(f"  Core Sensors Created: {', '.join(self.foundational_sensors_created)}")
        logger.info(f"  Legacy Sensors Paused: {self.legacy_sensors_paused}")
        logger.info(f"  PING Dependency Set: {self.dependency_set}")
        if self.errors:
            for err in self.errors:
                logger.error(f"  ! Error: {err}")

class SNMPScanner:
    """Handles direct SNMP communication with the device."""
    
    def __init__(self, community: str, port: int):
        self.community = community
        self.port = port
        self.snmp_engine = SnmpEngine()

    def _walk_oid(self, host: str, oid: str) -> Dict[int, Any]:
        """Walks a specific OID and returns {ifIndex: value}."""
        results = {}
        iterator = nextCmd(
            self.snmp_engine,
            CommunityData(self.community, mpModel=1), # v2c
            UdpTransportTarget((host, self.port), timeout=1.0, retries=1),
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
            lexicographicMode=False
        )

        for errorIndication, errorStatus, errorIndex, varBinds in iterator:
            if errorIndication:
                logger.warning(f"SNMP Error on {host}: {errorIndication}")
                break
            elif errorStatus:
                logger.warning(f"SNMP Error: {errorStatus.prettyPrint()}")
                break
            
            for varBind in varBinds:
                # varBind[0] is OID, varBind[1] is Value
                # Extract the last part of OID as index
                try:
                    index = int(varBind[0][-1])
                    value = varBind[1].prettyPrint()
                    results[index] = value
                except (ValueError, IndexError):
                    continue
        return results

    def scan_interfaces(self, host: str) -> List[Dict[str, Any]]:
        """
        Performs a full interface scan merging standard MIB-II and ifXTable.
        Returns list of dicts: {ifindex, iftype, ifadminstatus, ifname, ifalias}
        """
        logger.info(f"Starting Local SNMP Scan on {host}...")
        
        # Parallel-ish fetching (sequential here for simplicity, but cleaner than monolithic)
        # 1. Critical Filters
        indices = self._walk_oid(host, OID_IF_INDEX)
        if not indices:
            logger.error(f"SNMP Walk failed or returned no interfaces for {host}")
            return []

        admin_statuses = self._walk_oid(host, OID_IF_ADMIN_STATUS)
        types = self._walk_oid(host, OID_IF_TYPE)
        
        # 2. Descriptive Data
        names = self._walk_oid(host, OID_IF_NAME)
        aliases = self._walk_oid(host, OID_IF_ALIAS)
        descrs = self._walk_oid(host, OID_IF_DESCR)

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

        logger.info(f"SNMP Scan Complete. Found {len(compiled_interfaces)} total interfaces.")
        return compiled_interfaces

class PRTGClient:
    """Handles PRTG API interactions."""
    def __init__(self, config: Config):
        self.config = config
        self.session = requests.Session()
        self.session.verify = config.verify_ssl
        
        retry = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
        self.session.mount("https://", HTTPAdapter(max_retries=retry))
        self.session.mount("http://", HTTPAdapter(max_retries=retry))

    def _req(self, method: str, path: str, params: Dict = None) -> Any:
        params = params or {}
        params.update({"username": self.config.username, "passhash": self.config.passhash})
        url = f"{self.config.base_url}{path}"
        
        try:
            resp = self.session.request(method, url, params=params, timeout=self.config.request_timeout)
            resp.raise_for_status()
            # Handle PRTG's quirky JSON responses
            if "application/json" in resp.headers.get("Content-Type", ""):
                return resp.json()
            return resp.text
        except Exception as e:
            logger.error(f"API Request Failed ({path}): {e}")
            raise

    def get_device_host(self, device_id: int) -> Optional[str]:
        """Fetches the IP/Hostname of a device from PRTG."""
        data = self._req("GET", "/api/table.json", params={
            "content": "devices",
            "columns": "host",
            "id": device_id,
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

    def add_sensor(self, device_id: int, sensortype: str, payload: Dict) -> int:
        payload["id"] = device_id
        payload["sensortype"] = sensortype
        # PRTG 'addsensor3' is more programmatic friendly than 'addsensor'
        resp = self._req("POST", "/api/addsensor3.htm", params=payload)
        try:
            # addsensor3 returns JSON with objid
            return int(json.loads(resp).get("objid"))
        except:
            # Fallback if text returned
            logger.warning(f"Could not parse ID from creation response: {resp}")
            return 0

    def pause_sensor(self, sensor_id: int, msg: str):
        self._req("GET", "/api/pause.htm", params={"id": sensor_id, "action": 0, "pausemsg": msg})

    def set_dependency(self, device_id: int, sensor_id: int):
        self._req("POST", "/api/setobjectproperty.htm", params={
            "id": device_id, "name": "dependencytype", "value": 1
        })
        self._req("POST", "/api/setobjectproperty.htm", params={
            "id": device_id, "name": "dependency", "value": sensor_id
        })

    def add_device(self, group_id: int, name: str, host: str) -> int:
        resp = self._req("POST", "/api/adddevice.htm", params={
            "name": name, "host": host, "id": group_id
        })
        try:
            return int(json.loads(resp).get("objid"))
        except:
            raise Exception(f"Failed to create device. Response: {resp}")

# --- Logic Functions ---

def ensure_core_sensors(client: PRTGClient, device_id: int, sensors: List[Dict], result: OnboardingResult, dry_run: bool) -> int:
    """Checks for Ping, CPU, Mem, Uptime. Returns Ping ID."""
    existing_types = {s.get("sensortype"): s.get("objid") for s in sensors}
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
                logger.info(f"[DRY-RUN] Would create {name}")
                if key == "ping": ping_id = 99999
            else:
                logger.info(f"Creating missing {name} sensor...")
                try:
                    new_id = client.add_sensor(device_id, prtg_type, {"name": name})
                    result.foundational_sensors_created.append(name)
                    if key == "ping": ping_id = new_id
                    time.sleep(1) # Rate limit safety
                except Exception as e:
                    result.errors.append(f"Failed to create {name}: {e}")

    return ping_id

def process_traffic_sensors(client: PRTGClient, device_id: int, interfaces: List[Dict], sensors: List[Dict], result: OnboardingResult, dry_run: bool) -> List[int]:
    """Creates traffic sensors for eligible interfaces."""
    created_ids = []
    
    # 1. Identify existing ifIndexes to avoid duplicates
    existing_indices = set()
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
            logger.info(f"[DRY-RUN] Would create sensor: {sensor_name} (ifIndex {idx})")
        else:
            try:
                # Payload for snmptraffic
                # 'interfacenumber' is the key param for OID lookup
                payload = {
                    "name": sensor_name,
                    "interfacenumber": idx,
                    "tags": "bandwidth_sensor automated"
                }
                new_id = client.add_sensor(device_id, "snmptraffic", payload)
                if new_id:
                    created_ids.append(new_id)
                    result.traffic_sensors_created += 1
                    logger.info(f"Created: {sensor_name}")
            except Exception as e:
                result.errors.append(f"Failed to create {sensor_name}: {e}")

    return created_ids

# --- Main Execution ---

def main():
    parser = argparse.ArgumentParser(description="PRTG Onboarding (Hybrid Mode)")
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

    args = parser.parse_args()
    config = Config.from_env()
    
    prtg = PRTGClient(config)
    snmp = SNMPScanner(config.snmp_community, config.snmp_port)

    # Determine targets
    targets = [] # List of (id, ip, is_new)
    
    if args.command == "existing":
        for did in args.device_ids:
            ip = prtg.get_device_host(did)
            if ip:
                targets.append((did, ip, False))
            else:
                logger.error(f"Could not resolve IP for device {did}")

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
                            logger.warning(f"!!! CAUTION !!!")
                            logger.warning(f"You are adding a device with a PRIVATE IP ({args.host}) to the '{probe_name}'.")
                            logger.warning(f"The Hosted Probe runs in the cloud and cannot reach your local network.")
                            logger.warning(f"Verify you are using a Group ID belonging to a LOCAL REMOTE PROBE.")
                            logger.warning(f"Waiting 10 seconds. Press Ctrl+C to cancel...")
                            time.sleep(10)
                    except ValueError:
                        # Host might be a DNS name, skip check or try resolve (skipping for now)
                        pass
            except Exception as e:
                logger.warning(f"Could not verify Probe type: {e}")

            try:
                did = prtg.add_device(args.group_id, args.name, args.host)
                logger.info(f"Device created with ID {did}")
                targets.append((did, args.host, True))
                time.sleep(30) # Wait for PRTG internal commit
            except Exception as e:
                logger.error(f"Fatal: {e}")
                sys.exit(1)

    # Process Targets
    for device_id, device_ip, is_new in targets:
        result = OnboardingResult(device_id, device_ip)
        
        # 1. Local SNMP Scan (The Core Fix)
        interfaces = snmp.scan_interfaces(device_ip)
        result.interfaces_found = len(interfaces)
        
        if not interfaces:
            logger.error(f"Skipping {device_ip} - SNMP Scan failed.")
            result.errors.append("SNMP Scan Failed")
            result.print_summary()
            continue

        # 2. Get Current State
        current_sensors = [] if args.dry_run and is_new else prtg.list_sensors(device_id)

        # 3. Create Core Sensors
        ping_id = ensure_core_sensors(prtg, device_id, current_sensors, result, args.dry_run)

        # 4. Create Traffic Sensors
        new_traffic_ids = process_traffic_sensors(prtg, device_id, interfaces, current_sensors, result, args.dry_run)

        # 5. Set Dependencies
        if ping_id and not args.dry_run:
            prtg.set_dependency(device_id, ping_id)
            result.dependency_set = True

        # 6. Pause Legacy (Existing Mode Only)
        if not is_new and not args.dry_run:
            for s in current_sensors:
                if "traffic" in s.get("sensortype", "") and s.get("objid") not in new_traffic_ids:
                    # Don't pause what we just created (safety check)
                    # Note: new_traffic_ids might be empty if we rely on PRTG async
                    # But generally we want to pause OLD ones.
                    if s.get("status_raw") != 7: # 7 is paused
                        prtg.pause_sensor(s['objid'], "Paused by Automation (Legacy)")
                        result.legacy_sensors_paused += 1

        result.print_summary()

if __name__ == "__main__":
    main()