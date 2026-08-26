import unittest

import acl_parser as ap


class ParseVlanAclBindingsAndSubnetsTests(unittest.TestCase):

    def test_extracts_bindings_and_subnets_nxos_cidr(self):
        config = """
interface Vlan10
  ip address 10.0.0.1/24
  ip access-group MYACL in
interface Vlan20
  ip address 10.0.20.1/24
"""
        bindings, subnets = ap.parse_vlan_acl_bindings_and_subnets(config)
        self.assertEqual(bindings, {"MYACL": [{"interface": "Vlan10", "direction": "in"}]})
        self.assertEqual(subnets, {"Vlan10": "10.0.0.0/24", "Vlan20": "10.0.20.0/24"})

    def test_extracts_subnet_ios_netmask_form(self):
        config = """
interface Vlan10
  ip address 10.0.0.1 255.255.255.0
  ip access-group MYACL out
"""
        bindings, subnets = ap.parse_vlan_acl_bindings_and_subnets(config)
        self.assertEqual(subnets, {"Vlan10": "10.0.0.0/24"})
        self.assertEqual(bindings, {"MYACL": [{"interface": "Vlan10", "direction": "out"}]})

    def test_ignores_non_vlan_interfaces(self):
        config = """
interface Ethernet1/1
  ip address 10.0.0.1/24
  ip access-group MYACL in
"""
        bindings, subnets = ap.parse_vlan_acl_bindings_and_subnets(config)
        self.assertEqual(bindings, {})
        self.assertEqual(subnets, {})

    def test_multiple_bindings_for_same_acl_on_different_vlans(self):
        config = """
interface Vlan10
  ip address 10.0.0.1/24
  ip access-group SHARED in
interface Vlan20
  ip address 10.0.20.1/24
  ip access-group SHARED out
"""
        bindings, subnets = ap.parse_vlan_acl_bindings_and_subnets(config)
        self.assertEqual(bindings["SHARED"], [
            {"interface": "Vlan10", "direction": "in"},
            {"interface": "Vlan20", "direction": "out"},
        ])

    def test_secondary_address_does_not_override_primary(self):
        config = """
interface Vlan10
  ip address 10.0.0.1/24
  ip address 10.0.1.1/24 secondary
"""
        _, subnets = ap.parse_vlan_acl_bindings_and_subnets(config)
        self.assertEqual(subnets, {"Vlan10": "10.0.0.0/24"})


class FindWrongDirectionRulesTests(unittest.TestCase):

    def setUp(self):
        config = """
interface Vlan10
  ip address 10.0.0.1/24
  ip access-group TEST-ACL in
interface Vlan20
  ip address 10.0.20.1/24
  ip access-group TEST-ACL out
"""
        self.bindings, self.subnets = ap.parse_vlan_acl_bindings_and_subnets(config)

    def test_source_matching_the_inbound_vlan_is_fine(self):
        rules = ["10 permit tcp host 10.0.0.5 host 172.30.1.1 eq 22"]
        wrong = ap.find_wrong_direction_rules(rules, self.bindings["TEST-ACL"], self.subnets, "nexus")
        self.assertEqual(wrong, [])

    def test_neither_side_matching_any_binding_is_wrong(self):
        rules = ["20 permit tcp host 192.168.99.5 host 172.30.1.2 eq 22"]
        wrong = ap.find_wrong_direction_rules(rules, self.bindings["TEST-ACL"], self.subnets, "nexus")
        self.assertEqual(len(wrong), 1)
        self.assertEqual(wrong[0]["sequence"], 20)

    def test_any_source_is_never_wrong(self):
        rules = ["30 permit tcp any host 172.30.1.2 eq 22"]
        wrong = ap.find_wrong_direction_rules(rules, self.bindings["TEST-ACL"], self.subnets, "nexus")
        self.assertEqual(wrong, [])

    def test_any_destination_is_never_wrong(self):
        rules = ["40 permit tcp host 192.168.99.5 any eq 22"]
        wrong = ap.find_wrong_direction_rules(rules, self.bindings["TEST-ACL"], self.subnets, "nexus")
        self.assertEqual(wrong, [])

    def test_fine_for_one_binding_is_okay_even_if_wrong_for_the_other(self):
        # src is in Vlan10 (fine for the inbound binding) even though the
        # destination has nothing to do with Vlan20 (the outbound binding).
        # Per spec: passing just one binding is enough.
        rules = ["50 permit tcp host 10.0.0.77 host 8.8.8.8 eq 53"]
        wrong = ap.find_wrong_direction_rules(rules, self.bindings["TEST-ACL"], self.subnets, "nexus")
        self.assertEqual(wrong, [])

    def test_deny_rules_are_checked_too(self):
        rules = ["60 deny tcp host 192.168.99.5 host 172.30.1.2 eq 22"]
        wrong = ap.find_wrong_direction_rules(rules, self.bindings["TEST-ACL"], self.subnets, "nexus")
        self.assertEqual(len(wrong), 1)

    def test_object_group_member_inside_the_vlan_is_fine(self):
        rules = ["70 permit tcp addrgroup MYHOSTS host 172.30.1.2 eq 22"]
        address_groups = {"MYHOSTS": ["10.0.0.50/32", "10.0.0.51/32"]}
        wrong = ap.find_wrong_direction_rules(
            rules, self.bindings["TEST-ACL"], self.subnets, "nexus",
            address_groups=address_groups)
        self.assertEqual(wrong, [])

    def test_object_group_with_no_members_in_either_vlan_is_wrong(self):
        rules = ["80 permit tcp addrgroup OTHERHOSTS host 172.30.1.2 eq 22"]
        address_groups = {"OTHERHOSTS": ["192.168.1.0/24"]}
        wrong = ap.find_wrong_direction_rules(
            rules, self.bindings["TEST-ACL"], self.subnets, "nexus",
            address_groups=address_groups)
        self.assertEqual(len(wrong), 1)

    def test_binding_with_unknown_subnet_is_skipped_not_fatal(self):
        bindings = self.bindings["TEST-ACL"] + [{"interface": "Vlan999", "direction": "in"}]
        rules = ["90 permit tcp host 10.0.0.5 host 172.30.1.1 eq 22"]
        wrong = ap.find_wrong_direction_rules(rules, bindings, self.subnets, "nexus")
        self.assertEqual(wrong, [])

    def test_acl_with_no_known_subnet_bindings_flags_nothing(self):
        rules = ["10 permit tcp host 192.168.99.5 host 172.30.1.2 eq 22"]
        wrong = ap.find_wrong_direction_rules(
            rules, [{"interface": "Vlan999", "direction": "in"}], self.subnets, "nexus")
        self.assertEqual(wrong, [])

    def test_no_bindings_at_all_flags_nothing(self):
        rules = ["10 permit tcp host 192.168.99.5 host 172.30.1.2 eq 22"]
        wrong = ap.find_wrong_direction_rules(rules, [], self.subnets, "nexus")
        self.assertEqual(wrong, [])


if __name__ == "__main__":
    unittest.main()
