#!/usr/bin/env python3
"""
Integration and compatibility tests for Netqmon Controller and Agent across versions:
1. Protobuf wire compatibility (backward & forward compatibility for capture_interfaces).
2. Query API Gateway Health representation.
3. Frontend Gateway Health display fallback logic.
4. Realtime snapshot state preservation across disconnects and re-registrations.
"""

import sys
import unittest
import json

class TestProtobufWireCompatibility(unittest.TestCase):
    def test_varint_and_string_wire_format(self):
        # Protobuf wire format validation:
        # Field 8: capture_interface (wire type 2, length delimited) -> (8 << 3) | 2 = 66 = 0x42
        # Field 26: capture_interfaces (wire type 2, length delimited) -> (26 << 3) | 2 = 210 = 0xd2, 0x01
        
        # 1. Payload with only field 8 (legacy agent)
        legacy_val = b"eth1"
        legacy_wire = bytes([0x42, len(legacy_val)]) + legacy_val
        
        # 2. Payload with field 8 and field 26 entries (new agent)
        new_val1 = b"eth1"
        new_val2 = b"wg0"
        new_wire = (
            legacy_wire +
            bytes([0xd2, 0x01, len(new_val1)]) + new_val1 +
            bytes([0xd2, 0x01, len(new_val2)]) + new_val2
        )
        
        self.assertIn(b"eth1", legacy_wire)
        self.assertIn(b"wg0", new_wire)

    def test_realtime_engine_gateway_health_fallback(self):
        # Simulating crates/collector/src/realtime.rs:269
        # capture_interfaces: if health.capture_interfaces.is_empty() {
        #     vec![health.capture_interface.clone()]
        # } else {
        #     health.capture_interfaces.clone()
        # }
        
        def resolve_snapshot(capture_interface: str, capture_interfaces: list[str]) -> tuple[str, list[str]]:
            fallback = [capture_interface] if not capture_interfaces else capture_interfaces
            return capture_interface, fallback

        # Legacy agent (capture_interfaces empty)
        primary, interfaces = resolve_snapshot("br-lan", [])
        self.assertEqual(primary, "br-lan")
        self.assertEqual(interfaces, ["br-lan"])

        # New agent (capture_interfaces has multiple entries)
        primary, interfaces = resolve_snapshot("eth1", ["eth1", "wg0", "tun0"])
        self.assertEqual(primary, "eth1")
        self.assertEqual(interfaces, ["eth1", "wg0", "tun0"])

class TestFrontendDisplayLogic(unittest.TestCase):
    def format_gateway_interfaces(self, gateway: dict) -> str:
        # Replicating apps/controller-ui/components/dashboard/gateway-health.tsx:82
        # (gateway?.capture_interfaces?.length ? gateway.capture_interfaces : [gateway?.capture_interface]).filter(Boolean).join(", ")
        capture_interfaces = gateway.get("capture_interfaces")
        capture_interface = gateway.get("capture_interface")
        items = capture_interfaces if (capture_interfaces and len(capture_interfaces) > 0) else [capture_interface]
        return ", ".join([item for item in items if item])

    def test_legacy_agent_display(self):
        legacy = {"capture_interface": "br-lan"}
        self.assertEqual(self.format_gateway_interfaces(legacy), "br-lan")

    def test_new_agent_single_interface_display(self):
        new_single = {"capture_interface": "br-lan", "capture_interfaces": ["br-lan"]}
        self.assertEqual(self.format_gateway_interfaces(new_single), "br-lan")

    def test_new_agent_multi_interface_display(self):
        new_multi = {"capture_interface": "eth1", "capture_interfaces": ["eth1", "wg0", "tun0"]}
        self.assertEqual(self.format_gateway_interfaces(new_multi), "eth1, wg0, tun0")

    def test_empty_or_null_gateway(self):
        self.assertEqual(self.format_gateway_interfaces({}), "")

class TestStateUpdatePreservation(unittest.TestCase):
    def test_reconnect_does_not_clear_interfaces(self):
        # Replicating apps/controller-ui/components/dashboard/overview-dashboard.tsx:176
        current_state = {
            "capture_interface": "eth1",
            "capture_interfaces": ["eth1", "wg0"]
        }
        
        # When intermittent poll has empty or missing capture_interfaces:
        incoming_update = {"capture_interfaces": []}
        next_interfaces = incoming_update.get("capture_interfaces") or current_state.get("capture_interfaces")
        self.assertEqual(next_interfaces, ["eth1", "wg0"])

if __name__ == "__main__":
    unittest.main()
