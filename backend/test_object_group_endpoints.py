import unittest
from unittest.mock import patch

import main
import schemas as sch
import switch_service as svc
from validators import ValidationError


class _FakeTarget:
    """Minimal stand-in for switch_service.SwitchTarget."""
    def __init__(self, switch_type):
        self._type = switch_type

    @property
    def type(self):
        return self._type

    @property
    def is_nexus(self):
        return self._type in ("nexus", "nxos", "cisco_nxos")

    @property
    def label(self):
        return f"test-{self._type}"


NXOS_INVENTORY = [
    {"name": "EXISTING_ADDR", "kind": "address", "members": ["10 host 10.0.0.1"]},
    {"name": "EXISTING_PORT", "kind": "port", "members": ["10 eq 443"]},
]
IOS_INVENTORY = [
    {"name": "EXISTING_ADDR", "kind": "address", "members": ["host 10.0.0.1"]},
    {"name": "EXISTING_PORT", "kind": "port", "members": ["tcp eq 443"]},
]


class OgMemberLineTests(unittest.TestCase):
    @patch("switch_service.get_object_groups", return_value=NXOS_INVENTORY)
    def test_nxos_address_prefix(self, _mock):
        t = _FakeTarget("nexus")
        line = main._og_member_line(t, "user", "address",
                                    sch.ObjectGroupMemberInput(prefix="10.0.0.0/24"))
        self.assertEqual(line, "10.0.0.0/24")

    @patch("switch_service.get_object_groups", return_value=NXOS_INVENTORY)
    def test_nxos_address_rejects_group_ref(self, _mock):
        t = _FakeTarget("nexus")
        with self.assertRaises(ValidationError):
            main._og_member_line(t, "user", "address",
                                 sch.ObjectGroupMemberInput(group_ref="EXISTING_ADDR"))

    @patch("switch_service.get_object_groups", return_value=IOS_INVENTORY)
    def test_ios_address_nested_group_must_exist_as_address(self, _mock):
        t = _FakeTarget("ios")
        line = main._og_member_line(t, "user", "address",
                                    sch.ObjectGroupMemberInput(group_ref="EXISTING_ADDR"))
        self.assertEqual(line, "group-object EXISTING_ADDR")

    @patch("switch_service.get_object_groups", return_value=IOS_INVENTORY)
    def test_ios_address_nested_group_wrong_kind_rejected(self, _mock):
        t = _FakeTarget("ios")
        with self.assertRaises(ValidationError):
            main._og_member_line(t, "user", "address",
                                 sch.ObjectGroupMemberInput(group_ref="EXISTING_PORT"))

    @patch("switch_service.get_object_groups", return_value=IOS_INVENTORY)
    def test_ios_address_unknown_nested_group_rejected(self, _mock):
        t = _FakeTarget("ios")
        with self.assertRaises(ValidationError):
            main._og_member_line(t, "user", "address",
                                 sch.ObjectGroupMemberInput(group_ref="NOPE"))

    @patch("switch_service.get_object_groups", return_value=NXOS_INVENTORY)
    def test_nxos_port_member(self, _mock):
        t = _FakeTarget("nxos")
        line = main._og_member_line(t, "user", "port",
                                    sch.ObjectGroupMemberInput(port="8080-9000"))
        self.assertEqual(line, "range 8080 9000")

    @patch("switch_service.get_object_groups", return_value=NXOS_INVENTORY)
    def test_nxos_port_rejects_protocol(self, _mock):
        t = _FakeTarget("nxos")
        with self.assertRaises(ValidationError):
            main._og_member_line(t, "user", "port",
                                 sch.ObjectGroupMemberInput(protocol="tcp", port="443"))

    @patch("switch_service.get_object_groups", return_value=IOS_INVENTORY)
    def test_ios_port_requires_protocol_or_group(self, _mock):
        t = _FakeTarget("ios")
        with self.assertRaises(ValidationError):
            main._og_member_line(t, "user", "port", sch.ObjectGroupMemberInput(port="443"))

    @patch("switch_service.get_object_groups", return_value=IOS_INVENTORY)
    def test_ios_port_protocol_and_port(self, _mock):
        t = _FakeTarget("ios")
        line = main._og_member_line(
            t, "user", "port",
            sch.ObjectGroupMemberInput(protocol="udp", port="5000-5010"))
        self.assertEqual(line, "udp range 5000 5010")


class OgDeleteTargetTests(unittest.TestCase):
    def test_nxos_uses_sequence_number(self):
        t = _FakeTarget("nexus")
        self.assertEqual(main._og_delete_target(t, "10 host 10.0.0.1"), "10")

    def test_ios_uses_full_line(self):
        t = _FakeTarget("ios")
        self.assertEqual(main._og_delete_target(t, "host 10.0.0.1"), "host 10.0.0.1")

    def test_nxos_without_seq_falls_back_to_stripped_line(self):
        t = _FakeTarget("nexus")
        self.assertEqual(main._og_delete_target(t, "host 10.0.0.1"), "host 10.0.0.1")


class ValidateGroupRefTests(unittest.TestCase):
    @patch("switch_service.get_object_groups", return_value=IOS_INVENTORY)
    def test_existing_correct_kind(self, _mock):
        t = _FakeTarget("ios")
        item = main._validate_group_ref(t, "user", "EXISTING_PORT", "port", "Port group")
        self.assertEqual(item["kind"], "port")

    @patch("switch_service.get_object_groups", return_value=IOS_INVENTORY)
    def test_missing_raises(self, _mock):
        t = _FakeTarget("ios")
        with self.assertRaises(ValidationError):
            main._validate_group_ref(t, "user", "GHOST", "port", "Port group")


if __name__ == "__main__":
    unittest.main()
