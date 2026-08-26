import unittest

import acl_parser as ap


class ReverseRuleDirectionTests(unittest.TestCase):

    def _rule(self, line, switch_type="nexus", group_types=None, acl_kind="extended"):
        return ap.parse_acl_rule(line, switch_type, group_types, acl_kind)

    def test_simple_two_host_swap(self):
        rule = self._rule("permit tcp host 192.168.10.1 host 192.168.20.1")
        self.assertEqual(ap.reverse_rule_direction(rule, "nexus"),
                         "permit tcp host 192.168.20.1 host 192.168.10.1")

    def test_port_travels_with_its_original_operand(self):
        # eq 22 was a SOURCE port -> after reversal it must be a
        # DESTINATION port on the same address it originally belonged to.
        rule = self._rule("permit tcp host 192.168.10.1 eq 22 host 192.168.20.1")
        self.assertEqual(ap.reverse_rule_direction(rule, "nexus"),
                         "permit tcp host 192.168.20.1 host 192.168.10.1 eq 22")

    def test_destination_port_becomes_source_port(self):
        rule = self._rule("permit tcp host 10.0.0.1 host 10.0.0.2 eq 443")
        self.assertEqual(ap.reverse_rule_direction(rule, "nexus"),
                         "permit tcp host 10.0.0.2 eq 443 host 10.0.0.1")

    def test_subnet_and_any_swap(self):
        rule = self._rule("permit tcp 10.0.0.0 0.0.0.255 any eq 80")
        self.assertEqual(ap.reverse_rule_direction(rule, "nexus"),
                         "permit tcp any eq 80 10.0.0.0 0.0.0.255")

    def test_deny_action_is_preserved(self):
        rule = self._rule("deny tcp host 1.1.1.1 host 2.2.2.2")
        self.assertEqual(ap.reverse_rule_direction(rule, "nexus"),
                         "deny tcp host 2.2.2.2 host 1.1.1.1")

    def test_icmp_type_and_time_range_are_unaffected(self):
        rule = self._rule("permit icmp host 1.1.1.1 host 2.2.2.2 echo-reply time-range T")
        self.assertEqual(ap.reverse_rule_direction(rule, "nexus"),
                         "permit icmp host 2.2.2.2 host 1.1.1.1 echo-reply time-range T")

    def test_nxos_addrgroup_and_portgroup_swap_cleanly(self):
        group_types = {"A": "address", "B": "address"}
        rule = self._rule("permit tcp addrgroup A eq 22 addrgroup B", "nexus", group_types)
        self.assertEqual(ap.reverse_rule_direction(rule, "nexus"),
                         "permit tcp addrgroup B addrgroup A eq 22")

    def test_ios_address_object_group_returns_none(self):
        group_types = {"MYADDR": "address"}
        rule = self._rule("permit tcp object-group MYADDR host 10.0.0.2 eq 22", "ios", group_types)
        self.assertIsNone(ap.reverse_rule_direction(rule, "ios"))

    def test_ios_service_group_as_protocol_returns_none(self):
        group_types = {"MYSVC": "port"}
        rule = self._rule("permit object-group MYSVC host 10.0.0.1 host 10.0.0.2", "ios", group_types)
        self.assertIsNone(ap.reverse_rule_direction(rule, "ios"))

    def test_ios_plain_rule_without_groups_still_reverses(self):
        rule = self._rule("permit tcp host 10.0.0.1 eq 443 host 10.0.0.2", "ios")
        self.assertEqual(ap.reverse_rule_direction(rule, "ios"),
                         "permit tcp host 10.0.0.2 host 10.0.0.1 eq 443")


class PlanAclReversalTests(unittest.TestCase):

    def test_user_examples_produce_expected_reversals(self):
        rules = [
            "10 permit tcp host 192.168.10.1 host 192.168.20.1",
            "20 permit tcp host 192.168.10.1 eq 22 host 192.168.20.1",
        ]
        plan = ap.plan_acl_reversal(rules, "nexus")
        self.assertEqual(len(plan["reversible"]), 2)
        self.assertEqual(plan["manual"], [])
        self.assertEqual(plan["reversible"][0]["reversed"],
                         "permit tcp host 192.168.20.1 host 192.168.10.1")
        self.assertEqual(plan["reversible"][1]["reversed"],
                         "permit tcp host 192.168.20.1 host 192.168.10.1 eq 22")
        self.assertEqual(plan["reversible"][0]["sequence"], 10)
        self.assertEqual(plan["reversible"][1]["sequence"], 20)

    def test_ios_object_group_rules_go_to_manual_with_a_reason(self):
        rules = ["10 permit tcp object-group MYADDR host 10.0.0.2 eq 22"]
        group_types = {"MYADDR": "address"}
        plan = ap.plan_acl_reversal(rules, "ios", group_types)
        self.assertEqual(plan["reversible"], [])
        self.assertEqual(len(plan["manual"]), 1)
        self.assertEqual(plan["manual"][0]["sequence"], 10)
        self.assertIn("manually", plan["manual"][0]["reason"])

    def test_standard_acl_has_nothing_reversible(self):
        rules = ["10 permit 10.0.0.0 0.0.0.255"]
        plan = ap.plan_acl_reversal(rules, "ios", acl_kind="standard")
        self.assertEqual(plan, {"reversible": [], "manual": []})

    def test_remark_lines_are_skipped_not_flagged(self):
        rules = ["5 remark hello world", "10 permit tcp host 1.1.1.1 host 2.2.2.2"]
        plan = ap.plan_acl_reversal(rules, "nexus")
        self.assertEqual(len(plan["reversible"]), 1)
        self.assertEqual(plan["manual"], [])

    def test_mixed_acl_splits_reversible_and_manual_correctly(self):
        rules = [
            "10 permit tcp host 1.1.1.1 host 2.2.2.2",
            "20 permit tcp object-group A host 3.3.3.3 eq 22",
        ]
        group_types = {"A": "address"}
        plan = ap.plan_acl_reversal(rules, "ios", group_types)
        self.assertEqual(len(plan["reversible"]), 1)
        self.assertEqual(plan["reversible"][0]["sequence"], 10)
        self.assertEqual(len(plan["manual"]), 1)
        self.assertEqual(plan["manual"][0]["sequence"], 20)


if __name__ == "__main__":
    unittest.main()
