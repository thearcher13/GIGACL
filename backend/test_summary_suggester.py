import unittest

import acl_parser as ap


class BestSummaryNetworkTests(unittest.TestCase):
    """Direct tests of the core width-selection algorithm."""

    def _nets(self, *cidrs):
        import ipaddress
        return [ipaddress.IPv4Network(c) for c in cidrs]

    def test_three_scattered_hosts_prefers_29_over_30_and_28(self):
        # The user's own motivating example: .1, .2, .3 must NOT become a
        # /30 (that would land .3 on the block's broadcast address) and
        # must NOT become a /28 (too wide for 3 real hosts).
        nets = self._nets("192.168.1.1/32", "192.168.1.2/32", "192.168.1.3/32")
        result = ap._best_summary_network(nets)
        self.assertEqual(str(result), "192.168.1.0/29")

    def test_exact_perfect_fit_uses_the_tight_block(self):
        # All 4 addresses of a /30 are present — no extra addresses get
        # added, so landing on the block's broadcast is fine here.
        nets = self._nets("192.168.1.0/32", "192.168.1.1/32",
                          "192.168.1.2/32", "192.168.1.3/32")
        result = ap._best_summary_network(nets)
        self.assertEqual(str(result), "192.168.1.0/30")

    def test_two_far_apart_hosts_returns_none(self):
        nets = self._nets("10.0.0.1/32", "10.0.5.200/32")
        self.assertIsNone(ap._best_summary_network(nets))

    def test_single_network_returns_none(self):
        self.assertIsNone(ap._best_summary_network(self._nets("10.0.0.1/32")))

    def test_adjacent_pair_collapses_to_a_31(self):
        nets = self._nets("10.0.0.0/32", "10.0.0.1/32")
        self.assertEqual(str(ap._best_summary_network(nets)), "10.0.0.0/31")


class SuggestSummaryRulesTests(unittest.TestCase):

    def test_user_example_three_hosts_to_29_with_first_sequence(self):
        rules = [
            "10 permit tcp 192.168.1.1 0.0.0.0 any",
            "20 permit tcp 192.168.1.2 0.0.0.0 any",
            "30 permit tcp 192.168.1.3 0.0.0.0 any",
        ]
        suggestions = ap.suggest_summary_rules(rules, "nexus")
        self.assertEqual(len(suggestions), 1)
        s = suggestions[0]
        self.assertEqual(s["suggestion"], "10 permit tcp 192.168.1.0 0.0.0.7 any")
        self.assertEqual(len(s["replaces"]), 3)
        # Every replaced entry must carry its own original sequence number
        # (the frontend extracts these to build the apply/undo commands).
        for original, replaced in zip(rules, s["replaces"]):
            self.assertEqual(replaced, original)

    def test_exact_four_host_block_uses_30_not_29(self):
        rules = [
            "10 permit tcp host 192.168.1.0 any eq 443",
            "20 permit tcp host 192.168.1.1 any eq 443",
            "30 permit tcp host 192.168.1.2 any eq 443",
            "40 permit tcp host 192.168.1.3 any eq 443",
        ]
        suggestions = ap.suggest_summary_rules(rules, "nexus")
        self.assertEqual(len(suggestions), 1)
        self.assertEqual(suggestions[0]["suggestion"],
                         "10 permit tcp 192.168.1.0 0.0.0.3 any eq 443")

    def test_far_apart_hosts_produce_no_suggestion(self):
        rules = [
            "10 permit tcp host 10.0.0.1 any eq 80",
            "20 permit tcp host 10.0.5.200 any eq 80",
        ]
        self.assertEqual(ap.suggest_summary_rules(rules, "nexus"), [])

    def test_single_rule_produces_no_suggestion(self):
        rules = ["10 permit tcp host 10.0.0.1 any eq 80"]
        self.assertEqual(ap.suggest_summary_rules(rules, "nexus"), [])

    def test_different_time_range_blocks_the_merge(self):
        rules = [
            "10 permit tcp host 192.168.2.1 any eq 22 time-range BUSINESS",
            "20 permit tcp host 192.168.2.2 any eq 22",
        ]
        self.assertEqual(ap.suggest_summary_rules(rules, "nexus"), [])

    def test_same_time_range_allows_the_merge(self):
        rules = [
            "10 permit tcp host 192.168.2.1 any eq 22 time-range BUSINESS",
            "20 permit tcp host 192.168.2.2 any eq 22 time-range BUSINESS",
        ]
        suggestions = ap.suggest_summary_rules(rules, "nexus")
        self.assertEqual(len(suggestions), 1)
        self.assertTrue(suggestions[0]["suggestion"].endswith("time-range BUSINESS"))

    def test_different_destination_port_blocks_the_merge(self):
        rules = [
            "10 permit tcp host 192.168.3.1 any eq 22",
            "20 permit tcp host 192.168.3.2 any eq 23",
        ]
        self.assertEqual(ap.suggest_summary_rules(rules, "nexus"), [])

    def test_different_destination_addrgroup_blocks_the_merge(self):
        group_types = {"WEB": "address", "DB": "address"}
        rules = [
            "10 permit tcp host 10.1.1.1 addrgroup WEB eq 443",
            "20 permit tcp host 10.1.1.2 addrgroup DB eq 443",
        ]
        self.assertEqual(ap.suggest_summary_rules(rules, "nexus", group_types), [])

    def test_src_addrgroup_rules_are_never_widened(self):
        group_types = {"CLIENTS": "address"}
        rules = [
            "10 permit tcp addrgroup CLIENTS any eq 443",
            "20 permit tcp addrgroup CLIENTS any eq 443",
        ]
        self.assertEqual(ap.suggest_summary_rules(rules, "nexus", group_types), [])

    def test_any_source_is_never_a_summarization_candidate(self):
        rules = [
            "10 permit tcp any any eq 443",
            "20 permit tcp host 10.1.1.2 any eq 443",
        ]
        self.assertEqual(ap.suggest_summary_rules(rules, "nexus"), [])

    def test_ios_platform_keeps_object_group_keyword_on_destination(self):
        group_types = {"WEBSRV": "address"}
        rules = [
            "10 permit tcp host 172.16.0.1 object-group WEBSRV eq 443",
            "20 permit tcp host 172.16.0.2 object-group WEBSRV eq 443",
        ]
        suggestions = ap.suggest_summary_rules(rules, "ios", group_types)
        self.assertEqual(len(suggestions), 1)
        self.assertIn("object-group WEBSRV", suggestions[0]["suggestion"])
        self.assertNotIn("addrgroup", suggestions[0]["suggestion"])

    def test_nxos_platform_keeps_addrgroup_keyword_on_destination(self):
        group_types = {"WEBSRV": "address"}
        rules = [
            "10 permit tcp host 172.16.0.1 addrgroup WEBSRV eq 443",
            "20 permit tcp host 172.16.0.2 addrgroup WEBSRV eq 443",
        ]
        suggestions = ap.suggest_summary_rules(rules, "nexus", group_types)
        self.assertEqual(len(suggestions), 1)
        self.assertIn("addrgroup WEBSRV", suggestions[0]["suggestion"])

    def test_ios_service_group_as_protocol_is_preserved(self):
        group_types = {"WEB_PORT": "port"}
        rules = [
            "10 permit object-group WEB_PORT host 10.5.5.1 any",
            "20 permit object-group WEB_PORT host 10.5.5.2 any",
        ]
        suggestions = ap.suggest_summary_rules(rules, "ios", group_types)
        self.assertEqual(len(suggestions), 1)
        self.assertTrue(suggestions[0]["suggestion"].startswith(
            "10 permit object-group WEB_PORT "))

    def test_clustering_finds_a_useful_subset_among_scattered_hosts(self):
        # Three tightly clustered hosts plus one far-away straggler in the
        # same proto/dst/port group — the cluster should still get
        # summarized even though the whole group can't be.
        rules = [
            "10 permit tcp host 192.168.9.1 any eq 80",
            "20 permit tcp host 192.168.9.2 any eq 80",
            "30 permit tcp host 192.168.9.3 any eq 80",
            "40 permit tcp host 10.0.0.99 any eq 80",
        ]
        suggestions = ap.suggest_summary_rules(rules, "nexus")
        self.assertEqual(len(suggestions), 1)
        self.assertEqual(suggestions[0]["suggestion"],
                         "10 permit tcp 192.168.9.0 0.0.0.7 any eq 80")
        self.assertEqual(len(suggestions[0]["replaces"]), 3)

    def test_existing_broader_rule_covering_others_is_not_resuggested(self):
        # 192.168.4.0/24 already covers .5 entirely — that's an existing
        # redundancy (Redundancy Checker's job), not a new summary.
        rules = [
            "10 permit tcp 192.168.4.0 0.0.0.255 any eq 22",
            "20 permit tcp host 192.168.4.5 any eq 22",
        ]
        self.assertEqual(ap.suggest_summary_rules(rules, "nexus"), [])

    def test_deny_rules_are_not_summarized(self):
        rules = [
            "10 deny tcp host 192.168.5.1 any eq 22",
            "20 deny tcp host 192.168.5.2 any eq 22",
        ]
        self.assertEqual(ap.suggest_summary_rules(rules, "nexus"), [])

    def test_no_sequence_numbers_still_produces_a_suggestion(self):
        rules = [
            "permit tcp host 192.168.6.1 any eq 22",
            "permit tcp host 192.168.6.2 any eq 22",
        ]
        suggestions = ap.suggest_summary_rules(rules, "nexus")
        self.assertEqual(len(suggestions), 1)
        self.assertTrue(suggestions[0]["suggestion"].startswith("permit tcp "))


class ExtraAddressesTests(unittest.TestCase):

    def test_user_example_reports_the_five_extra_addresses(self):
        rules = [
            "10 permit tcp 192.168.1.1 0.0.0.0 any",
            "20 permit tcp 192.168.1.2 0.0.0.0 any",
            "30 permit tcp 192.168.1.3 0.0.0.0 any",
        ]
        s = ap.suggest_summary_rules(rules, "nexus")[0]
        self.assertEqual(s["widened_side"], "src")
        self.assertEqual(s["extra_addresses"],
                         ["192.168.1.0", "192.168.1.4", "192.168.1.5",
                          "192.168.1.6", "192.168.1.7"])
        self.assertIn("also permits 5 address(es)", s["note"])

    def test_exact_fit_reports_no_extra_addresses(self):
        rules = [
            "10 permit tcp host 192.168.1.0 any eq 443",
            "20 permit tcp host 192.168.1.1 any eq 443",
            "30 permit tcp host 192.168.1.2 any eq 443",
            "40 permit tcp host 192.168.1.3 any eq 443",
        ]
        s = ap.suggest_summary_rules(rules, "nexus")[0]
        self.assertEqual(s["extra_addresses"], [])
        self.assertIn("no extra addresses added", s["note"])


class DestinationWideningTests(unittest.TestCase):

    def test_symmetric_destination_widening_keeps_source_fixed(self):
        rules = [
            "10 permit tcp host 10.5.5.1 host 192.168.9.1 eq 443",
            "20 permit tcp host 10.5.5.1 host 192.168.9.2 eq 443",
            "30 permit tcp host 10.5.5.1 host 192.168.9.3 eq 443",
        ]
        suggestions = ap.suggest_summary_rules(rules, "nexus")
        self.assertEqual(len(suggestions), 1)
        s = suggestions[0]
        self.assertEqual(s["widened_side"], "dst")
        self.assertEqual(s["suggestion"],
                         "10 permit tcp host 10.5.5.1 192.168.9.0 0.0.0.7 eq 443")

    def test_different_source_addresses_block_destination_widening(self):
        rules = [
            "10 permit tcp host 10.5.5.1 host 192.168.9.1 eq 443",
            "20 permit tcp host 10.5.5.2 host 192.168.9.2 eq 443",
        ]
        self.assertEqual(ap.suggest_summary_rules(rules, "nexus"), [])

    def test_different_source_ports_block_source_widening(self):
        # Regression test: the grouping key must include BOTH sides' ports,
        # not just the destination's — otherwise two rules with different
        # source-port restrictions could silently merge and lose one of
        # them.
        rules = [
            "10 permit tcp host 192.168.1.1 eq 1024 any",
            "20 permit tcp host 192.168.1.2 eq 2048 any",
        ]
        self.assertEqual(ap.suggest_summary_rules(rules, "nexus"), [])


if __name__ == "__main__":
    unittest.main()
