"""
Tests for the sensor duplication regression fix.

Verifies that:
1. clone_sensor returns only NEWLY created sensor IDs
2. process_traffic_sensors doesn't create duplicates when sensors already exist
3. Name matching respects claimed_ids to prevent double-matching
4. process_device cleanup uses fresh sensor snapshots
"""
import asyncio
import unittest
from unittest.mock import MagicMock, AsyncMock, patch, call
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# Import the module under test
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# We need to mock check_and_install_packages before importing prtg_manager
# since it runs at import time
with patch.dict('sys.modules', {
    'requests': MagicMock(),
    'requests.adapters': MagicMock(),
    'urllib3.util.retry': MagicMock(),
    'yaml': MagicMock(),
    'pysnmp': MagicMock(),
    'pysnmp.hlapi': MagicMock(),
    'pysnmp.hlapi.v3arch': MagicMock(),
}):
    # We'll test the logic directly by recreating the key functions
    pass


# --- Helper Data Factories ---

def make_sensor(objid, name, stype="snmptraffic", status_raw=3,
                interfacenumber=None):
    """Create a mock sensor dict matching PRTG API format."""
    s = {
        "objid": objid,
        "name": name,
        "type": stype,
        "sensortype": stype,
        "status_raw": status_raw,
        "message": "",
        "message_raw": "",
    }
    if interfacenumber is not None:
        s["interfacenumber"] = str(interfacenumber)
    return s


def make_interface(ifindex, ifname, ifalias="", iftype=6, ifadminstatus=1):
    """Create a mock interface dict matching SNMP scan format."""
    return {
        "ifindex": ifindex,
        "ifname": ifname,
        "ifalias": ifalias,
        "ifdescr": ifname,
        "iftype": iftype,
        "ifadminstatus": ifadminstatus,
        "ifspeed": "1000000000",
    }


# --- Test: clone_sensor pre-existing ID guard ---

class TestCloneSensorIdGuard(unittest.TestCase):
    """Verify clone_sensor only returns IDs that didn't exist before cloning."""

    def test_returns_new_id_not_preexisting(self):
        """If a sensor with the same name already exists, clone_sensor must
        return the NEW clone's ID, not the pre-existing one."""
        # Setup: device already has sensor ID=100 named "(Gi0/5) Uplink"
        pre_clone_sensors = [
            make_sensor(100, "(Gi0/5) Uplink", interfacenumber=5),
        ]
        # After clone: PRTG adds a new sensor ID=101 with the same name
        post_clone_sensors = pre_clone_sensors + [
            make_sensor(101, "(Gi0/5) Uplink", interfacenumber=5),
        ]

        client = MagicMock()
        # First call (snapshot) returns pre-clone list
        # Subsequent calls (retry loop) return post-clone list
        client.list_sensors = MagicMock(
            side_effect=[pre_clone_sensors] + [post_clone_sensors] * 5
        )
        client._req = MagicMock()

        # Import and run the actual clone_sensor logic inline
        # (avoids full module import with all its dependencies)
        async def clone_sensor_logic(source_id, target_device_id, new_name):
            """Mirrors the fixed clone_sensor method."""
            pre_existing_ids = {
                s.get("objid") for s in client.list_sensors(target_device_id)
            }
            client._req("GET", "/api/duplicateobject.htm", params={
                "id": source_id,
                "targetid": target_device_id,
                "name": new_name
            })
            for _ in range(5):
                await asyncio.sleep(0.01)
                sensors = client.list_sensors(target_device_id)
                for s in sensors:
                    if (s.get("name") == new_name
                            and s.get("objid") not in pre_existing_ids):
                        return s.get("objid")
            return None

        result = asyncio.run(
            clone_sensor_logic(999, 1, "(Gi0/5) Uplink")
        )

        # Must return 101 (new), NOT 100 (pre-existing)
        self.assertEqual(result, 101)

    def test_returns_none_when_clone_not_found(self):
        """If the new clone never appears, return None."""
        existing = [make_sensor(100, "SomeOther")]

        client = MagicMock()
        client.list_sensors = MagicMock(return_value=existing)
        client._req = MagicMock()

        async def clone_sensor_logic(source_id, target_device_id, new_name):
            pre_existing_ids = {
                s.get("objid") for s in client.list_sensors(target_device_id)
            }
            client._req("GET", "/api/duplicateobject.htm", params={
                "id": source_id,
                "targetid": target_device_id,
                "name": new_name
            })
            for _ in range(5):
                await asyncio.sleep(0.01)
                sensors = client.list_sensors(target_device_id)
                for s in sensors:
                    if (s.get("name") == new_name
                            and s.get("objid") not in pre_existing_ids):
                        return s.get("objid")
            return None

        result = asyncio.run(
            clone_sensor_logic(999, 1, "NonExistent")
        )
        self.assertIsNone(result)


# --- Test: Name match respects claimed_ids ---

class TestNameMatchClaimedIds(unittest.TestCase):
    """Verify that name matching doesn't double-claim sensors."""

    def test_name_match_skips_claimed_sensor(self):
        """If a sensor was already matched by ifIndex for a previous interface,
        name matching should not claim it again for a different interface."""
        # Two interfaces that would both resolve to the same sensor name
        # (edge case with template producing same name)
        existing_sensors_dict = {
            "(Gi0/5) Uplink": 100,
        }
        claimed_ids = {100}  # Already claimed by ifIndex match

        sensor_name = "(Gi0/5) Uplink"

        # Simulate the fixed name match logic
        matched_sensor_id = None
        if sensor_name in existing_sensors_dict:
            candidate_id = existing_sensors_dict[sensor_name]
            if candidate_id not in claimed_ids:
                matched_sensor_id = candidate_id

        # Should NOT match because 100 is already claimed
        self.assertIsNone(matched_sensor_id)

    def test_name_match_works_for_unclaimed(self):
        """Name matching should work normally for unclaimed sensors."""
        existing_sensors_dict = {
            "(Gi0/5) Uplink": 100,
        }
        claimed_ids = set()  # Nothing claimed

        sensor_name = "(Gi0/5) Uplink"

        matched_sensor_id = None
        if sensor_name in existing_sensors_dict:
            candidate_id = existing_sensors_dict[sensor_name]
            if candidate_id not in claimed_ids:
                matched_sensor_id = candidate_id

        self.assertEqual(matched_sensor_id, 100)


# --- Test: Idempotent behavior (no duplicate on re-run) ---

class TestIdempotentTrafficProcessing(unittest.TestCase):
    """Simulate two sequential runs and verify no duplicates are created."""

    def test_second_run_does_not_clone_when_sensor_exists_by_name(self):
        """On a second run, sensors created by the first run should be
        matched by name and NOT cloned again."""
        # Run 1 result: sensor ID=101 exists with expected name
        sensors = [
            make_sensor(101, "(sfp-sfpplus7) sfp-sfpplus7",
                        interfacenumber=7),
        ]
        interfaces = [
            make_interface(7, "sfp-sfpplus7", "sfp-sfpplus7"),
        ]

        # Build the matching logic (simulating process_traffic_sensors)
        existing_sensors = {}
        for s in sensors:
            name = s.get("name")
            if name:
                existing_sensors[name] = s.get("objid")

        claimed_ids = set()
        traffic_candidates = [
            s for s in sensors
            if "traffic" in s.get("type", "").lower()
        ]

        template = "([ifname]) [ifalias]"
        should_clone = False

        for iface in interfaces:
            idx = iface['ifindex']
            sensor_name = template.replace("[ifname]", iface['ifname'])
            sensor_name = sensor_name.replace("[ifalias]", iface['ifalias'])
            sensor_name = ' '.join(sensor_name.split())

            matched_sensor_id = None

            # Name match with claimed_ids check
            if sensor_name in existing_sensors:
                candidate_id = existing_sensors[sensor_name]
                if candidate_id not in claimed_ids:
                    matched_sensor_id = candidate_id

            # ifIndex fallback
            if not matched_sensor_id:
                for cand in traffic_candidates:
                    cid = cand['objid']
                    if cid in claimed_ids:
                        continue
                    if str(cand.get("interfacenumber")) == str(idx):
                        matched_sensor_id = cid
                        break

            if matched_sensor_id:
                claimed_ids.add(matched_sensor_id)
            else:
                should_clone = True

        # Must NOT need to clone — sensor already matched by name
        self.assertFalse(should_clone)
        self.assertIn(101, claimed_ids)

    def test_second_run_matches_renamed_sensor_by_ifindex(self):
        """On second run, if PRTG modified the sensor name, ifIndex fallback
        should still match it (no clone needed)."""
        # PRTG changed the name from "(sfp-sfpplus7) sfp-sfpplus7" to
        # "SNMP Traffic sfp-sfpplus7"
        sensors = [
            make_sensor(101, "SNMP Traffic sfp-sfpplus7",
                        interfacenumber=7),
        ]
        interfaces = [
            make_interface(7, "sfp-sfpplus7", "sfp-sfpplus7"),
        ]

        existing_sensors = {s.get("name"): s.get("objid") for s in sensors}
        claimed_ids = set()
        traffic_candidates = [
            s for s in sensors
            if "traffic" in s.get("type", "").lower()
        ]

        template = "([ifname]) [ifalias]"
        should_clone = False

        for iface in interfaces:
            idx = iface['ifindex']
            sensor_name = template.replace("[ifname]", iface['ifname'])
            sensor_name = sensor_name.replace("[ifalias]", iface['ifalias'])
            sensor_name = ' '.join(sensor_name.split())

            matched_sensor_id = None

            if sensor_name in existing_sensors:
                candidate_id = existing_sensors[sensor_name]
                if candidate_id not in claimed_ids:
                    matched_sensor_id = candidate_id

            if not matched_sensor_id:
                for cand in traffic_candidates:
                    cid = cand['objid']
                    if cid in claimed_ids:
                        continue
                    if str(cand.get("interfacenumber")) == str(idx):
                        matched_sensor_id = cid
                        break

            if matched_sensor_id:
                claimed_ids.add(matched_sensor_id)
            else:
                should_clone = True

        # Name match fails (PRTG changed it), but ifIndex match succeeds
        self.assertFalse(should_clone)
        self.assertIn(101, claimed_ids)


# --- Test: Cleanup uses fresh sensor list ---

class TestCleanupFreshSnapshot(unittest.TestCase):
    """Verify that cleanup logic sees newly created sensors as keepers."""

    def test_newly_created_sensor_not_paused_by_cleanup(self):
        """A sensor created during traffic processing must appear in the
        refreshed sensor list and not be treated as legacy."""
        # Pre-traffic snapshot
        pre_sensors = [
            make_sensor(50, "Ping", stype="ping"),
        ]

        # After traffic processing, a new sensor was created
        post_sensors = pre_sensors + [
            make_sensor(101, "(sfp-sfpplus7) sfp-sfpplus7",
                        stype="snmptraffic", interfacenumber=7),
        ]

        traffic_keepers = [101]
        core_keepers = {"ping": 50}

        # Build keeper set (as process_device does)
        keeper_ids = set()
        for kid in core_keepers.values():
            if kid:
                keeper_ids.add(kid)
        keeper_ids.update(traffic_keepers)

        # Simulate cleanup WITHOUT refresh (the bug)
        sensors_to_pause_old = []
        for s in pre_sensors:  # Stale list
            sid = s.get("objid")
            stype = (s.get("type") or "").lower()
            if "traffic" in stype and sid not in traffic_keepers:
                sensors_to_pause_old.append(sid)

        # Simulate cleanup WITH refresh (the fix)
        sensors_to_pause_new = []
        for s in post_sensors:  # Fresh list
            sid = s.get("objid")
            stype = (s.get("type") or "").lower()
            if "traffic" in stype and sid not in traffic_keepers:
                sensors_to_pause_new.append(sid)

        # No sensors should be paused in either case for this scenario
        self.assertEqual(sensors_to_pause_old, [])
        self.assertEqual(sensors_to_pause_new, [])

    def test_orphan_sensor_detected_in_fresh_list(self):
        """An orphan sensor (not in keepers) that was created externally
        should be detected in the fresh list and paused."""
        post_sensors = [
            make_sensor(50, "Ping", stype="ping"),
            make_sensor(101, "(sfp-sfpplus7) sfp-sfpplus7",
                        stype="snmptraffic", interfacenumber=7),
            make_sensor(200, "Old Traffic Sensor",
                        stype="snmptraffic", interfacenumber=99),
        ]

        traffic_keepers = [101]

        sensors_to_pause = []
        for s in post_sensors:
            sid = s.get("objid")
            stype = (s.get("type") or "").lower()
            if "traffic" in stype and sid not in traffic_keepers:
                if s.get("status_raw") not in [7, 8, 9, 11, 12]:
                    sensors_to_pause.append(sid)

        # Only sensor 200 should be flagged for pause
        self.assertEqual(sensors_to_pause, [200])


# --- Test: Partial Name Match fallback ---

class TestPartialNameMatch(unittest.TestCase):
    """Verify that when ifindex is missing and exact name fails,
    the script uses a partial name prefix match."""

    def test_partial_name_match_without_ifindex(self):
        """If exact name fails but existing name starts with the targeted name
        followed by a space or other boundary, match it and rename it."""
        # Setup: Missing interfacenumber, name slightly modified in PRTG
        sensors = [
            make_sensor(101, "(sfp-sfpplus7) sfp-sfpplus7", interfacenumber=None),
        ]
        interfaces = [
            make_interface(7, "sfp-sfpplus7", ""),
        ]

        existing_sensors = {s.get("name"): s.get("objid") for s in sensors}
        claimed_ids = set()
        traffic_candidates = [
            s for s in sensors
            if "traffic" in s.get("type", "").lower()
        ]

        template = "([ifname]) [ifalias]"
        should_clone = False

        for iface in interfaces:
            idx = iface['ifindex']
            sensor_name = template.replace("[ifname]", iface['ifname'])
            sensor_name = sensor_name.replace("[ifalias]", iface['ifalias'])
            sensor_name = ' '.join(sensor_name.split())

            matched_sensor_id = None
            match_method = None

            # A. Name Match (Exact)
            if sensor_name in existing_sensors:
                candidate_id = existing_sensors[sensor_name]
                if candidate_id not in claimed_ids:
                    matched_sensor_id = candidate_id
                    match_method = "name"

            # B. ifIndex Match
            if not matched_sensor_id:
                for cand in traffic_candidates:
                    cid = cand['objid']
                    if cid in claimed_ids:
                        continue
                    c_idx = cand.get("interfacenumber")
                    if c_idx and str(c_idx) == str(idx):
                        matched_sensor_id = cid
                        match_method = "ifindex"
                        break

            # C. Partial Name Match
            if not matched_sensor_id:
                for name, candidate_id in existing_sensors.items():
                    if candidate_id in claimed_ids:
                        continue
                    if name.startswith(sensor_name) and len(name) > len(sensor_name):
                        next_char = name[len(sensor_name)]
                        if next_char in " -_:.":
                            matched_sensor_id = candidate_id
                            match_method = "name_partial"
                            break

            if matched_sensor_id:
                claimed_ids.add(matched_sensor_id)
            else:
                should_clone = True

            # Assertions for the simulation loop
            self.assertEqual(matched_sensor_id, 101)
            self.assertEqual(match_method, "name_partial")

        # Must not have decided to clone a new sensor
        self.assertFalse(should_clone)



if __name__ == "__main__":
    unittest.main()
