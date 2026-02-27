"""
Tests for core sensor name normalization in ensure_core_sensors().

Verifies that:
1. Existing sensors with non-standard names get renamed to the standard format
2. Sensors already matching the standard name are left unchanged
3. Dry-run mode logs but does not rename
4. The onboarding result reflects renamed sensors
"""
import asyncio
import unittest
from unittest.mock import MagicMock, AsyncMock, patch
import sys
import os
import importlib
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Create mock modules with proper __spec__ to pass importlib.util.find_spec checks
def _make_mock_module(name):
    mod = MagicMock()
    mod.__spec__ = importlib.machinery.ModuleSpec(name, None)
    return mod

_mock_modules = {
    'requests': _make_mock_module('requests'),
    'requests.adapters': _make_mock_module('requests.adapters'),
    'urllib3': _make_mock_module('urllib3'),
    'urllib3.util': _make_mock_module('urllib3.util'),
    'urllib3.util.retry': _make_mock_module('urllib3.util.retry'),
    'yaml': _make_mock_module('yaml'),
    'pysnmp': _make_mock_module('pysnmp'),
    'pysnmp.hlapi': _make_mock_module('pysnmp.hlapi'),
    'pysnmp.hlapi.v3arch': _make_mock_module('pysnmp.hlapi.v3arch'),
}

with patch.dict('sys.modules', _mock_modules):
    from prtg_manager import ensure_core_sensors, OnboardingResult


def make_sensor(objid, name, stype="snmpcpu", status_raw=3):
    """Create a mock sensor dict matching PRTG API format."""
    return {
        "objid": objid,
        "name": name,
        "type": stype,
        "status_raw": status_raw,
    }


def _all_four_types(overrides=None):
    """Return sensors for all 4 core types so ensure_core_sensors never
    falls into the 'create missing' branch. Override specific types via dict."""
    defaults = {
        "ping": make_sensor(200, "PING", stype="ping"),
        "snmp_cpu": make_sensor(201, "SNMP CPU", stype="snmpcpu"),
        "snmp_mem": make_sensor(202, "SNMP MEM", stype="snmpmemory"),
        "snmp_uptime": make_sensor(203, "SNMP UPTIME", stype="snmpuptime"),
    }
    if overrides:
        defaults.update(overrides)
    return list(defaults.values())


class TestCoreSensorRename(unittest.TestCase):
    """Verify ensure_core_sensors normalizes sensor names."""

    def _run(self, coro):
        return asyncio.run(coro)

    def _make_client(self):
        client = MagicMock()
        client.set_property = MagicMock()
        client.pause_sensor = MagicMock()
        client.delete_object = MagicMock()
        # clone_sensor is async in the real code
        client.clone_sensor = AsyncMock(return_value=None)
        client.find_template_sensor = MagicMock(return_value=None)
        return client

    def test_renames_nonstandard_cpu_sensor(self):
        """A sensor named 'SNMP CPU Load' should be renamed to 'SNMP CPU'."""
        client = self._make_client()
        sensors = _all_four_types(overrides={
            "snmp_cpu": make_sensor(101, "SNMP CPU Load", stype="snmpcpu"),
        })
        result = OnboardingResult(device_id=1000)

        self._run(ensure_core_sensors(client, 1000, sensors, result, dry_run=False))

        client.set_property.assert_any_call(101, "name", "SNMP CPU")
        self.assertTrue(any("Renamed from 'SNMP CPU Load'" in s
                            for s in result.foundational_sensors_created))

    def test_renames_nonstandard_memory_sensor(self):
        """A sensor named 'SNMP Memory' should be renamed to 'SNMP MEM'."""
        client = self._make_client()
        sensors = _all_four_types(overrides={
            "snmp_mem": make_sensor(102, "SNMP Memory", stype="snmpmemory"),
        })
        result = OnboardingResult(device_id=1000)

        self._run(ensure_core_sensors(client, 1000, sensors, result, dry_run=False))

        client.set_property.assert_any_call(102, "name", "SNMP MEM")
        self.assertTrue(any("Renamed from 'SNMP Memory'" in s
                            for s in result.foundational_sensors_created))

    def test_renames_nonstandard_uptime_sensor(self):
        """A sensor named 'SNMP System Uptime' should be renamed to 'SNMP UPTIME'."""
        client = self._make_client()
        sensors = _all_four_types(overrides={
            "snmp_uptime": make_sensor(103, "SNMP System Uptime", stype="snmpuptime"),
        })
        result = OnboardingResult(device_id=1000)

        self._run(ensure_core_sensors(client, 1000, sensors, result, dry_run=False))

        client.set_property.assert_any_call(103, "name", "SNMP UPTIME")
        self.assertTrue(any("Renamed from 'SNMP System Uptime'" in s
                            for s in result.foundational_sensors_created))

    def test_no_rename_when_name_matches_standard(self):
        """A sensor already named 'SNMP CPU' should NOT be renamed."""
        client = self._make_client()
        sensors = _all_four_types()  # all standard names
        result = OnboardingResult(device_id=1000)

        self._run(ensure_core_sensors(client, 1000, sensors, result, dry_run=False))

        # set_property should never be called (no renames needed)
        client.set_property.assert_not_called()
        self.assertTrue(any("SNMP CPU (Existing)" in s
                            for s in result.foundational_sensors_created))

    def test_dry_run_does_not_rename(self):
        """In dry-run mode, no rename API call should be made."""
        client = self._make_client()
        sensors = _all_four_types(overrides={
            "snmp_cpu": make_sensor(101, "SNMP CPU Load", stype="snmpcpu"),
        })
        result = OnboardingResult(device_id=1000)

        self._run(ensure_core_sensors(client, 1000, sensors, result, dry_run=True))

        client.set_property.assert_not_called()

    def test_rename_all_three_types_together(self):
        """All three non-standard sensors should be renamed in a single pass."""
        client = self._make_client()
        sensors = _all_four_types(overrides={
            "snmp_cpu": make_sensor(101, "SNMP CPU Load", stype="snmpcpu"),
            "snmp_mem": make_sensor(102, "SNMP Memory", stype="snmpmemory"),
            "snmp_uptime": make_sensor(103, "SNMP System Uptime", stype="snmpuptime"),
            # PING already matches standard
        })
        result = OnboardingResult(device_id=1000)

        self._run(ensure_core_sensors(client, 1000, sensors, result, dry_run=False))

        rename_calls = [(c[0][0], c[0][2]) for c in client.set_property.call_args_list
                        if c[0][1] == "name"]
        self.assertIn((101, "SNMP CPU"), rename_calls)
        self.assertIn((102, "SNMP MEM"), rename_calls)
        self.assertIn((103, "SNMP UPTIME"), rename_calls)
        # Ping already has standard name - should not appear in renames
        ping_renames = [c for c in rename_calls if c[0] == 200]
        self.assertEqual(ping_renames, [])


if __name__ == "__main__":
    unittest.main()
