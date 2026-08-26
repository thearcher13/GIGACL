import unittest

import acl_parser as ap


class OriginalThreeExamplesTests(unittest.TestCase):
    """Reproduces the three examples from the request verbatim."""

    def test_protocol_widening_tcp_and_udp_covered_by_ip(self):
        rules = [
            "10 permit ip host 192.168.1.1 host 192.168.2.1",
            "20 permit tcp host 192.168.1.1 host 192.168.2.1",
            "30 permit udp host 192.168.1.1 host 192.168.2.1",
        ]
        groups = ap.check_redundant_rules(rules, "ios")
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["covered_by_sequence"], 10)
        covered_seqs = {r["sequence"] for r in groups[0]["redundant_rules"]}
        self.assertEqual(covered_seqs, {20, 30})

    def test_port_widening_eq_covered_by_no_port(self):
        rules = [
            "10 permit tcp host 192.168.1.1 host 192.168.2.1",
            "20 permit tcp host 192.168.1.1 host 192.168.2.1 eq 22",
        ]
        groups = ap.check_redundant_rules(rules, "ios")
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["covered_by_sequence"], 10)
        self.assertEqual(groups[0]["redundant_rules"][0]["sequence"], 20)

    def test_address_widening_two_hosts_covered_by_subnet(self):
        rules = [
            "10 permit ip 192.168.1.0 0.0.0.255 host 192.168.2.1",
            "20 permit tcp host 192.168.1.1 host 192.168.2.1",
            "30 permit tcp host 192.168.1.3 host 192.168.2.1",
        ]
        groups = ap.check_redundant_rules(rules, "ios")
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["covered_by_sequence"], 10)
        covered_seqs = {r["sequence"] for r in groups[0]["redundant_rules"]}
        self.assertEqual(covered_seqs, {20, 30})


class ObjectGroupRedundancyTests(unittest.TestCase):
    """A rule referencing one group is covered by a rule referencing a
    *different* group whose members are a superset — this only works via
    rule_covers_with_group_members, confirming it's wired into
    check_redundant_rules now."""

    def test_address_group_subset_different_names_nxos(self):
        rules = [
            "10 permit ip addrgroup ALL_HOSTS host 10.0.0.1",
            "20 permit tcp addrgroup A_HOSTS host 10.0.0.1 eq 80",
        ]
        group_types = {"ALL_HOSTS": "address", "A_HOSTS": "address"}
        address_groups = {"ALL_HOSTS": ["10.0.0.0/16"], "A_HOSTS": ["10.0.0.0/24"]}
        groups = ap.check_redundant_rules(
            rules, "nexus", group_types,
            address_groups=address_groups)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["covered_by_sequence"], 10)
        self.assertEqual(groups[0]["redundant_rules"][0]["sequence"], 20)

    def test_address_group_not_subset_is_not_flagged(self):
        rules = [
            "10 permit ip addrgroup NET_A host 10.0.0.1",
            "20 permit tcp addrgroup NET_B host 10.0.0.1 eq 80",
        ]
        group_types = {"NET_A": "address", "NET_B": "address"}
        # NET_B is NOT a subset of NET_A (disjoint ranges).
        address_groups = {"NET_A": ["10.0.0.0/24"], "NET_B": ["10.0.1.0/24"]}
        groups = ap.check_redundant_rules(
            rules, "nexus", group_types,
            address_groups=address_groups)
        self.assertEqual(groups, [])

    def test_port_group_subset_different_names(self):
        rules = [
            "10 permit tcp host 10.0.0.1 host 10.0.0.2 portgroup ALL_PORTS",
            "20 permit tcp host 10.0.0.1 host 10.0.0.2 portgroup WEB_PORTS",
        ]
        group_types = {"ALL_PORTS": "port", "WEB_PORTS": "port"}
        service_groups = {
            "ALL_PORTS": [(None, None, "range", [1, 65535])],
            "WEB_PORTS": [(None, None, "eq", [80])],
        }
        groups = ap.check_redundant_rules(
            rules, "nexus", group_types,
            service_groups=service_groups)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["covered_by_sequence"], 10)
        self.assertEqual(groups[0]["redundant_rules"][0]["sequence"], 20)

    def test_without_group_data_plain_comparison_misses_it(self):
        # Sanity check: omitting address_groups/service_groups falls back to
        # plain rule_covers, which only matches identical group names — so
        # this same scenario is correctly NOT found without group data.
        rules = [
            "10 permit ip addrgroup ALL_HOSTS host 10.0.0.1",
            "20 permit tcp addrgroup A_HOSTS host 10.0.0.1 eq 80",
        ]
        group_types = {"ALL_HOSTS": "address", "A_HOSTS": "address"}
        groups = ap.check_redundant_rules(rules, "nexus", group_types)
        self.assertEqual(groups, [])


class StandardAclRedundancyTests(unittest.TestCase):
    def test_host_covered_by_broader_standard_permit(self):
        rules = [
            "10 permit 192.168.1.0 0.0.0.255",
            "20 permit host 192.168.1.5",
        ]
        groups = ap.check_redundant_rules(rules, "ios", acl_kind="standard")
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["covered_by_sequence"], 10)
        self.assertEqual(groups[0]["redundant_rules"][0]["sequence"], 20)

    def test_disjoint_standard_hosts_not_flagged(self):
        rules = [
            "10 permit host 192.168.1.5",
            "20 permit host 192.168.1.6",
        ]
        groups = ap.check_redundant_rules(rules, "ios", acl_kind="standard")
        self.assertEqual(groups, [])


class IcmpFalsePositiveRegressionTests(unittest.TestCase):
    """The bug: two rules with two different *unrecognized* ICMP types used
    to both parse to icmp_type=None and incorrectly match each other."""

    def test_different_unrecognized_types_are_not_flagged(self):
        rules = [
            "10 permit icmp any any port-unreachable",
            "20 permit icmp any any host-unreachable",
        ]
        groups = ap.check_redundant_rules(rules, "ios")
        self.assertEqual(groups, [])

    def test_same_unrecognized_type_is_flagged(self):
        rules = [
            "10 permit icmp host 1.1.1.1 host 2.2.2.2 port-unreachable",
            "20 permit icmp host 1.1.1.1 host 2.2.2.2 port-unreachable",
        ]
        groups = ap.check_redundant_rules(rules, "ios")
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["redundant_rules"][0]["sequence"], 20)

    def test_untyped_still_covers_any_type(self):
        rules = [
            "10 permit icmp any any",
            "20 permit icmp any any port-unreachable",
        ]
        groups = ap.check_redundant_rules(rules, "ios")
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["redundant_rules"][0]["sequence"], 20)

    def test_typed_does_not_cover_untyped(self):
        rules = [
            "10 permit icmp any any port-unreachable",
            "20 permit icmp any any",
        ]
        groups = ap.check_redundant_rules(rules, "ios")
        self.assertEqual(groups, [])


class GroupedShapeTests(unittest.TestCase):
    def test_multiple_covering_rules_produce_separate_groups(self):
        rules = [
            "10 permit ip host 1.1.1.1 host 2.2.2.2",
            "20 permit tcp host 1.1.1.1 host 2.2.2.2 eq 80",
            "30 permit ip host 3.3.3.3 host 4.4.4.4",
            "40 permit tcp host 3.3.3.3 host 4.4.4.4 eq 443",
        ]
        groups = ap.check_redundant_rules(rules, "ios")
        self.assertEqual(len(groups), 2)
        by_covering = {g["covered_by_sequence"]: g for g in groups}
        self.assertEqual(by_covering[10]["redundant_rules"][0]["sequence"], 20)
        self.assertEqual(by_covering[30]["redundant_rules"][0]["sequence"], 40)

    def test_empty_when_nothing_redundant(self):
        rules = [
            "10 permit tcp host 1.1.1.1 host 2.2.2.2 eq 80",
            "20 permit tcp host 1.1.1.1 host 2.2.2.2 eq 443",
        ]
        groups = ap.check_redundant_rules(rules, "ios")
        self.assertEqual(groups, [])

    def test_different_actions_never_grouped(self):
        rules = [
            "10 permit ip host 1.1.1.1 host 2.2.2.2",
            "20 deny tcp host 1.1.1.1 host 2.2.2.2 eq 80",
        ]
        groups = ap.check_redundant_rules(rules, "ios")
        self.assertEqual(groups, [])


class RulesTrafficOverlapsTests(unittest.TestCase):
    def test_overlapping_subnets_overlap(self):
        a = ap.parse_acl_rule("permit ip host 10.0.0.5 any", "ios")
        b = ap.parse_acl_rule("permit ip 10.0.0.0 0.0.0.255 any", "ios")
        self.assertTrue(ap.rules_traffic_overlaps(a, b))

    def test_disjoint_subnets_do_not_overlap(self):
        a = ap.parse_acl_rule("permit ip host 10.0.0.5 any", "ios")
        b = ap.parse_acl_rule("permit ip host 10.0.1.5 any", "ios")
        self.assertFalse(ap.rules_traffic_overlaps(a, b))

    def test_overlapping_ports_overlap(self):
        a = ap.parse_acl_rule("permit tcp any any eq 80", "ios")
        b = ap.parse_acl_rule("permit tcp any any range 1 1000", "ios")
        self.assertTrue(ap.rules_traffic_overlaps(a, b))

    def test_disjoint_ports_do_not_overlap(self):
        a = ap.parse_acl_rule("permit tcp any any eq 80", "ios")
        b = ap.parse_acl_rule("permit tcp any any eq 443", "ios")
        self.assertFalse(ap.rules_traffic_overlaps(a, b))

    def test_ip_protocol_overlaps_any_specific_protocol(self):
        a = ap.parse_acl_rule("permit ip host 1.1.1.1 host 2.2.2.2", "ios")
        b = ap.parse_acl_rule("permit tcp host 1.1.1.1 host 2.2.2.2 eq 80", "ios")
        self.assertTrue(ap.rules_traffic_overlaps(a, b))

    def test_different_specific_protocols_do_not_overlap(self):
        a = ap.parse_acl_rule("permit tcp host 1.1.1.1 host 2.2.2.2 eq 80", "ios")
        b = ap.parse_acl_rule("permit udp host 1.1.1.1 host 2.2.2.2 eq 80", "ios")
        self.assertFalse(ap.rules_traffic_overlaps(a, b))

    def test_icmp_same_type_overlaps(self):
        a = ap.parse_acl_rule("permit icmp any any echo", "ios")
        b = ap.parse_acl_rule("permit icmp any any echo", "ios")
        self.assertTrue(ap.rules_traffic_overlaps(a, b))

    def test_icmp_different_types_do_not_overlap(self):
        a = ap.parse_acl_rule("permit icmp any any echo", "ios")
        b = ap.parse_acl_rule("permit icmp any any echo-reply", "ios")
        self.assertFalse(ap.rules_traffic_overlaps(a, b))

    def test_icmp_untyped_overlaps_any_type(self):
        a = ap.parse_acl_rule("permit icmp any any", "ios")
        b = ap.parse_acl_rule("permit icmp any any echo", "ios")
        self.assertTrue(ap.rules_traffic_overlaps(a, b))

    def test_object_group_member_overlap(self):
        a = ap.parse_acl_rule("permit ip addrgroup A_HOSTS any", "nexus",
                              {"A_HOSTS": "address"})
        b = ap.parse_acl_rule("permit ip host 10.0.0.5 any", "nexus")
        address_groups = {"A_HOSTS": ["10.0.0.0/24"]}
        self.assertTrue(ap.rules_traffic_overlaps(a, b, address_groups))

    def test_object_group_member_no_overlap(self):
        a = ap.parse_acl_rule("permit ip addrgroup A_HOSTS any", "nexus",
                              {"A_HOSTS": "address"})
        b = ap.parse_acl_rule("permit ip host 10.0.1.5 any", "nexus")
        address_groups = {"A_HOSTS": ["10.0.0.0/24"]}
        self.assertFalse(ap.rules_traffic_overlaps(a, b, address_groups))


class TrailingRedundancyTests(unittest.TestCase):
    """The new 'superseded by a later, broader rule' check."""

    def test_motivating_case_no_conflict_is_flagged(self):
        rules = [
            "10 permit tcp host 1.1.1.1 host 2.2.2.2 eq 80",
            "20 permit ip any any",
        ]
        groups = ap.find_trailing_redundant_rules(rules, "ios")
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["covered_by_sequence"], 20)
        self.assertEqual(groups[0]["redundant_rules"][0]["sequence"], 10)

    def test_critical_safety_case_overlapping_deny_blocks_it(self):
        """The test that matters most: a deny rule between the candidate and
        the later broader permit, whose traffic overlaps the candidate,
        must prevent the candidate from being flagged."""
        rules = [
            "10 permit tcp host 1.1.1.1 host 2.2.2.2 eq 80",
            "15 deny tcp host 1.1.1.1 host 2.2.2.2 eq 80",
            "20 permit ip any any",
        ]
        groups = ap.find_trailing_redundant_rules(rules, "ios")
        self.assertEqual(groups, [])

    def test_unrelated_deny_in_gap_does_not_block(self):
        rules = [
            "10 permit tcp host 1.1.1.1 host 2.2.2.2 eq 80",
            "15 deny tcp host 9.9.9.9 host 8.8.8.8 eq 443",
            "20 permit ip any any",
        ]
        groups = ap.find_trailing_redundant_rules(rules, "ios")
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["redundant_rules"][0]["sequence"], 10)

    def test_partial_address_overlap_still_blocks(self):
        # The deny only overlaps PART of the candidate's range, but any
        # overlap at all must block — the candidate rule's other, non-
        # overlapping traffic doesn't make the overlapping part safe to lose.
        rules = [
            "10 permit ip 10.0.0.0 0.0.0.255 any",
            "15 deny ip host 10.0.0.5 any",
            "20 permit ip any any",
        ]
        groups = ap.find_trailing_redundant_rules(rules, "ios")
        self.assertEqual(groups, [])

    def test_object_group_case_matches_the_real_scenario(self):
        """Reproduces the exact motivating example: a permit rule exists to
        carve out an exception to a later deny that uses object groups."""
        rules = [
            "250 permit ip host 172.30.201.114 object-group Ceph-Hosts",
            "980 deny ip object-group Part_Buildings_IPs object-group Ceph-Hosts",
            "1000 permit ip any any",
        ]
        group_types = {"Ceph-Hosts": "address", "Part_Buildings_IPs": "address"}

        # The exception-carving host IS inside the deny's source group ->
        # must not be flagged.
        blocked = ap.find_trailing_redundant_rules(
            rules, "ios", group_types,
            address_groups={"Ceph-Hosts": ["10.0.0.0/24"],
                            "Part_Buildings_IPs": ["172.30.201.0/24"]})
        self.assertEqual(blocked, [])

        # The host is NOT inside the deny's source group -> safe to flag.
        flagged = ap.find_trailing_redundant_rules(
            rules, "ios", group_types,
            address_groups={"Ceph-Hosts": ["10.0.0.0/24"],
                            "Part_Buildings_IPs": ["192.168.99.0/24"]})
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0]["covered_by_sequence"], 1000)
        self.assertEqual(flagged[0]["redundant_rules"][0]["sequence"], 250)

    def test_different_action_pair_with_no_later_cover_is_not_flagged(self):
        rules = [
            "10 permit tcp host 1.1.1.1 host 2.2.2.2 eq 80",
            "20 deny tcp host 9.9.9.9 host 8.8.8.8 eq 443",
        ]
        groups = ap.find_trailing_redundant_rules(rules, "ios")
        self.assertEqual(groups, [])

    def test_does_not_duplicate_what_check_redundant_rules_already_finds(self):
        # An earlier rule already covers this one (classic case) — the
        # trailing check should find nothing new here since there's no
        # LATER covering rule at all.
        rules = [
            "10 permit ip host 1.1.1.1 host 2.2.2.2",
            "20 permit tcp host 1.1.1.1 host 2.2.2.2 eq 80",
        ]
        self.assertEqual(ap.find_trailing_redundant_rules(rules, "ios"), [])
        # Confirm the classic check DOES find it (sanity check the two are
        # genuinely complementary, not overlapping).
        classic = ap.check_redundant_rules(rules, "ios")
        self.assertEqual(len(classic), 1)


if __name__ == "__main__":
    unittest.main()
