import unittest
from unittest.mock import patch

import acl_parser
import switch_service


class ObjectGroupClassificationTests(unittest.TestCase):
    def test_nxos_uses_only_nxos_headers(self):
        output = """IPv4 address object-group CLIENTS
  10 host 10.0.0.1
Protocol port object-group WEB
  10 eq 443
Network object group WRONG_IOS_ADDRESS
  host 192.0.2.1
"""
        self.assertEqual(
            acl_parser.parse_object_groups(output, "nexus"),
            [
                {"name": "CLIENTS", "kind": "address", "members": ["10 host 10.0.0.1"]},
                {"name": "WEB", "kind": "port", "members": ["10 eq 443"]},
            ],
        )

    def test_ios_uses_only_ios_headers(self):
        output = """Network object group CLIENTS
  host 10.0.0.1
Service object group WEB
  tcp eq 443
IPv4 address object-group WRONG_NXOS_ADDRESS
  10 host 192.0.2.1
"""
        self.assertEqual(
            acl_parser.parse_object_groups(output, "ios"),
            [
                {"name": "CLIENTS", "kind": "address", "members": ["host 10.0.0.1"]},
                {"name": "WEB", "kind": "port", "members": ["tcp eq 443"]},
            ],
        )

    def test_member_syntax_never_changes_header_type(self):
        output = """IPv4 address object-group ODD_BUT_ADDRESS
  10 eq 443
"""
        groups = acl_parser.parse_object_groups(output, "nxos")
        self.assertEqual(groups[0]["kind"], "address")

    def test_legacy_or_ambiguous_headers_are_ignored(self):
        output = """object-group network LEGACY
  host 10.0.0.1
IP port object-group AMBIGUOUS
  eq 443
object-group ip address ALTERNATIVE
  host 10.0.0.2
"""
        self.assertEqual(acl_parser.parse_object_groups(output, "ios"), [])
        self.assertEqual(acl_parser.parse_object_groups(output, "nexus"), [])


class _Target:
    def __init__(self, switch_type):
        self.type = switch_type


class ObjectGroupServiceTests(unittest.TestCase):
    NXOS_OUTPUT = """IPv4 address object-group CLIENTS
  10 host 10.0.0.1
Protocol port object-group WEB
  10 eq 443
"""

    @patch("switch_service.show", return_value=NXOS_OUTPUT)
    def test_discovery_uses_show_object_group_and_switch_type(self, show):
        groups = switch_service.get_object_groups(_Target("nexus"), "user")
        show.assert_called_once_with(
            unittest.mock.ANY, "user", "show object-group", timeout=40)
        self.assertEqual([g["kind"] for g in groups], ["address", "port"])

    @patch("switch_service.show", return_value=NXOS_OUTPUT)
    def test_resolution_rejects_a_group_of_the_wrong_type(self, _show):
        target = _Target("nexus")
        self.assertEqual(
            switch_service.resolve_addr_group(target, "user", "CLIENTS"),
            ["10.0.0.1/32"],
        )
        self.assertEqual(
            switch_service.resolve_addr_group(target, "user", "WEB"), [])
        self.assertEqual(
            switch_service.resolve_port_group(target, "user", "WEB"),
            [(None, None, "eq", [443])],
        )
        self.assertEqual(
            switch_service.resolve_port_group(target, "user", "CLIENTS"), [])


if __name__ == "__main__":
    unittest.main()
