import unittest

import rule_generator as rg
from validators import (ValidationError, validate_prefix, validate_object_group_ip,
                        validate_port_only, validate_protocol_only,
                        validate_object_group_member_line, validate_object_group_name,
                        validate_ios_port_spec)


class ObjectGroupHeaderTests(unittest.TestCase):
    def test_nxos_address_header(self):
        self.assertEqual(rg.object_group_header("CLIENTS", "address", "nexus"),
                         "object-group ip address CLIENTS")

    def test_nxos_port_header(self):
        self.assertEqual(rg.object_group_header("WEB", "port", "nxos"),
                         "object-group ip port WEB")

    def test_ios_address_header(self):
        self.assertEqual(rg.object_group_header("CLIENTS", "address", "ios"),
                         "object-group network CLIENTS")

    def test_ios_port_header(self):
        self.assertEqual(rg.object_group_header("WEB", "port", "ios"),
                         "object-group service WEB")


class ObjectGroupAddressMemberTests(unittest.TestCase):
    def test_nxos_subnet_stays_cidr(self):
        self.assertEqual(
            rg.object_group_address_member(prefix="10.0.0.0/24", switch_type="nexus"),
            "10.0.0.0/24")

    def test_nxos_explicit_32_becomes_host(self):
        self.assertEqual(
            rg.object_group_address_member(prefix="10.0.0.1/32", switch_type="nexus"),
            "host 10.0.0.1")

    def test_nxos_bare_ip_becomes_host(self):
        self.assertEqual(
            rg.object_group_address_member(prefix="10.0.0.1", switch_type="nexus"),
            "host 10.0.0.1")

    def test_ios_host_prefix_becomes_host_keyword(self):
        self.assertEqual(
            rg.object_group_address_member(prefix="10.0.0.1/32", switch_type="ios"),
            "host 10.0.0.1")

    def test_ios_bare_ip_becomes_host(self):
        self.assertEqual(
            rg.object_group_address_member(prefix="10.0.0.1", switch_type="ios"),
            "host 10.0.0.1")

    def test_ios_subnet_becomes_network_mask(self):
        self.assertEqual(
            rg.object_group_address_member(prefix="10.0.0.0/24", switch_type="ios"),
            "10.0.0.0 255.255.255.0")

    def test_ios_nested_group(self):
        self.assertEqual(
            rg.object_group_address_member(group_ref="OTHER", switch_type="ios"),
            "group-object OTHER")

    def test_nxos_rejects_nested_group(self):
        with self.assertRaises(ValueError):
            rg.object_group_address_member(group_ref="OTHER", switch_type="nexus")

    def test_missing_prefix_and_group_raises(self):
        with self.assertRaises(ValueError):
            rg.object_group_address_member(switch_type="ios")


class ObjectGroupPortMemberTests(unittest.TestCase):
    def test_nxos_single_port(self):
        self.assertEqual(
            rg.object_group_port_member(port="443", switch_type="nexus"), "eq 443")

    def test_nxos_port_range(self):
        self.assertEqual(
            rg.object_group_port_member(port="8080-9000", switch_type="nxos"),
            "range 8080 9000")

    def test_nxos_rejects_protocol(self):
        with self.assertRaises(ValueError):
            rg.object_group_port_member(protocol="tcp", port="443", switch_type="nexus")

    def test_ios_requires_protocol(self):
        with self.assertRaises(ValueError):
            rg.object_group_port_member(port="443", switch_type="ios")

    def test_ios_protocol_and_port(self):
        self.assertEqual(
            rg.object_group_port_member(protocol="tcp", port="443", switch_type="ios"),
            "tcp eq 443")

    def test_ios_protocol_and_range(self):
        self.assertEqual(
            rg.object_group_port_member(protocol="udp", port="5000-5010", switch_type="ios"),
            "udp range 5000 5010")

    def test_ios_nested_group(self):
        self.assertEqual(
            rg.object_group_port_member(group_ref="SVC", switch_type="ios"),
            "group-object SVC")

    def test_nxos_rejects_nested_group(self):
        with self.assertRaises(ValueError):
            rg.object_group_port_member(group_ref="SVC", switch_type="nexus")

    def test_ios_hyphenated_keyword_is_not_treated_as_range(self):
        self.assertEqual(
            rg.object_group_port_member(protocol="tcp", port="ftp-data", switch_type="ios"),
            "tcp eq ftp-data")

    def test_ios_www_keyword(self):
        self.assertEqual(
            rg.object_group_port_member(protocol="tcp", port="www", switch_type="ios"),
            "tcp eq www")


class StripOgSeqTests(unittest.TestCase):
    def test_strips_leading_sequence(self):
        self.assertEqual(rg.strip_og_seq("10 host 10.0.0.1"), "host 10.0.0.1")

    def test_no_sequence_is_unchanged(self):
        self.assertEqual(rg.strip_og_seq("host 10.0.0.1"), "host 10.0.0.1")
        self.assertEqual(rg.strip_og_seq("tcp eq 443"), "tcp eq 443")


class ValidatorTests(unittest.TestCase):
    def test_validate_prefix_accepts_bare_ip(self):
        self.assertEqual(validate_prefix("10.0.0.1", "Prefix"), "10.0.0.1/32")

    def test_validate_prefix_accepts_cidr(self):
        self.assertEqual(validate_prefix("10.0.0.0/24", "Prefix"), "10.0.0.0/24")

    def test_validate_ios_port_spec_accepts_number(self):
        self.assertEqual(validate_ios_port_spec("443", "tcp"), "443")

    def test_validate_ios_port_spec_accepts_numeric_range(self):
        self.assertEqual(validate_ios_port_spec("5000-5010", "udp"), "5000-5010")

    def test_validate_ios_port_spec_accepts_tcp_keyword(self):
        self.assertEqual(validate_ios_port_spec("www", "tcp"), "www")
        self.assertEqual(validate_ios_port_spec("FTP-Data", "tcp"), "ftp-data")

    def test_validate_ios_port_spec_rejects_keyword_for_wrong_protocol(self):
        with self.assertRaises(ValidationError):
            validate_ios_port_spec("www", "udp")

    def test_validate_ios_port_spec_accepts_udp_keyword(self):
        self.assertEqual(validate_ios_port_spec("tftp", "udp"), "tftp")

    def test_validate_ios_port_spec_accepts_tcpudp_keyword(self):
        self.assertEqual(validate_ios_port_spec("syslog", "tcp-udp"), "syslog")

    def test_validate_ios_port_spec_rejects_keyword_in_range(self):
        with self.assertRaises(ValidationError):
            validate_ios_port_spec("www-443", "tcp")

    def test_validate_ios_port_spec_rejects_unknown_keyword(self):
        with self.assertRaises(ValidationError):
            validate_ios_port_spec("not-a-real-port", "tcp")

    def test_validate_object_group_ip_accepts_bare_host(self):
        self.assertEqual(validate_object_group_ip("10.0.0.1", "Address"), "10.0.0.1")

    def test_validate_object_group_ip_rejects_any(self):
        with self.assertRaises(ValidationError):
            validate_object_group_ip("any", "Address")

    def test_validate_port_only_accepts_range(self):
        self.assertEqual(validate_port_only("8080-9000"), "8080-9000")

    def test_validate_port_only_rejects_portgroup(self):
        with self.assertRaises(ValidationError):
            validate_port_only("portgroup WEB")

    def test_validate_port_only_rejects_backwards_range(self):
        with self.assertRaises(ValidationError):
            validate_port_only("9000-8080")

    def test_validate_protocol_only_accepts_tcp_udp_tcpudp(self):
        self.assertEqual(validate_protocol_only("TCP"), "tcp")
        self.assertEqual(validate_protocol_only("udp"), "udp")
        self.assertEqual(validate_protocol_only("Tcp-Udp"), "tcp-udp")

    def test_validate_protocol_only_rejects_other(self):
        with self.assertRaises(ValidationError):
            validate_protocol_only("icmp")

    def test_validate_object_group_member_line_rejects_unsafe(self):
        with self.assertRaises(ValidationError):
            validate_object_group_member_line("host 10.0.0.1; reload", "Member")

    def test_validate_object_group_name_allows_slash(self):
        self.assertEqual(validate_object_group_name("CLIENTS/1", "Name"), "CLIENTS/1")


if __name__ == "__main__":
    unittest.main()
