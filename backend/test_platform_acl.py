import unittest

import acl_parser


IOS_GROUPS = {
    "WEB_PORT": "port",
    "Managment-Web": "address",
    "management-range": "address",
    "DNS-Servers": "address",
}

NXOS_GROUPS = {
    "Admin_Ports": "port",
    "ADDC_Admins": "address",
    "Repo_VMs": "address",
    "Web_Services_Ports": "port",
}


class IOSACLParsingTests(unittest.TestCase):
    def test_service_group_precedes_both_addresses(self):
        rule = acl_parser.parse_acl_rule(
            "20 permit object-group WEB_PORT host 172.30.7.12 any",
            "ios", IOS_GROUPS)
        self.assertEqual(rule["proto"], "ip")
        self.assertEqual(rule["service_group"], "WEB_PORT")
        self.assertEqual(rule["src_ip"], "172.30.7.12")
        self.assertEqual(rule["dst_ip"], "any")

    def test_service_and_two_network_groups_use_header_types(self):
        rule = acl_parser.parse_acl_rule(
            "29 permit object-group WEB_PORT object-group Managment-Web "
            "object-group management-range", "ios", IOS_GROUPS)
        self.assertEqual(rule["service_group"], "WEB_PORT")
        self.assertEqual(rule["src_addrgroup"], "Managment-Web")
        self.assertEqual(rule["dst_addrgroup"], "management-range")

    def test_network_group_is_valid_in_address_position(self):
        rule = acl_parser.parse_acl_rule(
            "10 permit udp object-group DNS-Servers eq domain any",
            "ios", IOS_GROUPS)
        self.assertEqual(rule["src_addrgroup"], "DNS-Servers")
        self.assertEqual(rule["src_port_op"], "eq")
        self.assertEqual(rule["src_ports"], [53])

    def test_ios_rejects_nxos_keywords_and_prefixes(self):
        self.assertIsNone(acl_parser.parse_acl_rule(
            "permit tcp addrgroup Repo_VMs any eq 443", "ios", IOS_GROUPS))
        self.assertIsNone(acl_parser.parse_acl_rule(
            "permit tcp 192.168.1.0/24 any eq 443", "ios", IOS_GROUPS))

    def test_ios_eq_can_contain_multiple_ports(self):
        rule = acl_parser.parse_acl_rule(
            "50 permit tcp host 192.168.1.1 host 192.168.1.2 eq 8843 8880",
            "ios", IOS_GROUPS)
        self.assertEqual(rule["dst_ports"], [8843, 8880])

    def test_cisco_named_ports_from_capture_are_resolved(self):
        rule = acl_parser.parse_acl_rule(
            "20 permit udp any eq isakmp any eq isakmp",
            "ios", IOS_GROUPS)
        self.assertEqual(rule["src_ports"], [500])
        self.assertEqual(rule["dst_ports"], [500])


class ACLKindDetectionTests(unittest.TestCase):
    """Real 'show ip access-lists' output pasted from a live IOS switch,
    mixing a standard and an extended ACL."""

    SAMPLE = (
        "Standard IP access list snmp-user\n"
        " 10 permit 192.168.48.100 (48330953 matches)\n"
        " 20 permit 192.168.1.7 (42418159 matches)\n"
        " 30 permit 192.168.50.5\n"
        " 40 permit 192.168.50.179\n"
        " 50 permit 192.168.48.53 (149863670 matches)\n"
        "Extended IP access list Ali-No\n"
        " 5 permit ip host 172.30.201.114 any\n"
        " 10 permit ip host 172.30.201.48 any\n"
        " 30 deny ip 192.168.0.0 0.0.255.255 any\n"
        " 40 permit ip any any\n"
    )

    def test_standard_and_extended_acls_are_distinguished(self):
        kinds = acl_parser.parse_acl_kinds(self.SAMPLE)
        self.assertEqual(kinds["snmp-user"], "standard")
        self.assertEqual(kinds["Ali-No"], "extended")

    def test_unknown_acl_name_defaults_to_extended(self):
        self.assertEqual(
            acl_parser.parse_acl_kinds(self.SAMPLE).get("not-there", "extended"),
            "extended")

    def test_rules_are_split_per_acl(self):
        rules = acl_parser.parse_all_acl_rules(self.SAMPLE)
        self.assertEqual(len(rules["snmp-user"]), 5)
        self.assertEqual(len(rules["Ali-No"]), 4)
        self.assertTrue(rules["snmp-user"][0].startswith("10 permit 192.168.48.100"))
        self.assertTrue(rules["Ali-No"][2].startswith("30 deny ip 192.168.0.0"))


class NXOSACLParsingTests(unittest.TestCase):
    def test_portgroup_can_follow_the_first_address(self):
        rule = acl_parser.parse_acl_rule(
            "30 permit tcp any portgroup Admin_Ports addrgroup ADDC_Admins",
            "nexus", NXOS_GROUPS)
        self.assertEqual(rule["src_portgroup"], "Admin_Ports")
        self.assertEqual(rule["dst_addrgroup"], "ADDC_Admins")

    def test_prefix_address_is_normalized(self):
        rule = acl_parser.parse_acl_rule(
            "155 permit tcp any 192.168.48.74/32 portgroup Web_Services_Ports",
            "nexus", NXOS_GROUPS)
        self.assertEqual(rule["dst_ip"], "192.168.48.74")
        self.assertEqual(rule["dst_wc"], "0.0.0.0")
        self.assertEqual(rule["dst_portgroup"], "Web_Services_Ports")

    def test_group_keyword_must_match_header_type(self):
        self.assertIsNone(acl_parser.parse_acl_rule(
            "permit tcp any addrgroup Admin_Ports", "nexus", NXOS_GROUPS))
        self.assertIsNone(acl_parser.parse_acl_rule(
            "permit tcp any portgroup ADDC_Admins any", "nexus", NXOS_GROUPS))


class ServiceGroupEvaluationTests(unittest.TestCase):
    def setUp(self):
        self.rule = acl_parser.parse_acl_rule(
            "permit object-group WEB_PORT host 10.0.0.1 host 10.0.0.2",
            "ios", IOS_GROUPS)
        self.services = {
            "WEB_PORT": [
                ("tcp", None, "eq", [443]),
                ("udp", None, "eq", [53]),
            ]
        }

    def evaluate(self, protocol, port):
        return acl_parser.evaluate_rule(
            self.rule, "10.0.0.1", "10.0.0.2", protocol, port,
            "in", "src", {}, self.services)

    def test_member_protocol_and_port_must_both_match(self):
        self.assertEqual(self.evaluate("tcp", 443), "permit")
        self.assertEqual(self.evaluate("udp", 53), "permit")
        self.assertIsNone(self.evaluate("udp", 443))
        self.assertIsNone(self.evaluate("tcp", 53))

    def test_tcp_udp_member_matches_either_protocol(self):
        services = acl_parser.parse_object_group_services(
            "tcp-udp eq 9664\ntcp range 8000 8100\ntcp")
        self.assertEqual(services, [
            ("tcp-udp", None, "eq", [9664]),
            ("tcp", None, "range", [8000, 8100]),
            ("tcp", None, "", []),
        ])

    def test_protocol_only_service_member_matches_all_protocol_ports(self):
        services = {"WEB_PORT": [("tcp", None, "", [])]}
        self.assertEqual(acl_parser.evaluate_rule(
            self.rule, "10.0.0.1", "10.0.0.2", "tcp", 12345,
            "in", "src", {}, services), "permit")
        self.assertIsNone(acl_parser.evaluate_rule(
            self.rule, "10.0.0.1", "10.0.0.2", "udp", 12345,
            "in", "src", {}, services))

    def test_service_group_member_does_not_cover_all_protocols(self):
        self.assertIsNone(self.evaluate("all", 443))

    def test_source_service_member_uses_first_address_port_position(self):
        services = {
            "WEB_PORT": [("tcp-udp", "source", "range", [6160, 6199])]
        }
        forward = acl_parser.evaluate_rule(
            self.rule, "10.0.0.1", "10.0.0.2", "tcp", 6165,
            "in", "src", {}, services)
        reverse = acl_parser.evaluate_rule(
            self.rule, "10.0.0.2", "10.0.0.1", "tcp", 6165,
            "in", "src", {}, services)
        self.assertIsNone(forward)
        self.assertEqual(reverse, "permit")


if __name__ == "__main__":
    unittest.main()
