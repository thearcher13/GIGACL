import unittest

import acl_parser as ap
import rule_generator as rg
from validators import ValidationError, validate_established


class GeneratePermitRuleEstablishedTests(unittest.TestCase):
    """The keyword belongs only on the line where the user's DESTINATION
    (the service being reached) lands in the source position -- that line
    carries the return traffic. On the opposite line the user's source is
    first, which is the client opening the connection, and 'established'
    would drop the initial SYN."""

    SRC = "10.0.0.1"   # the client (form source)
    DST = "10.0.1.5"   # the server being reached (form destination)

    def _rule(self, acl_direction, vlan_ip_side, **kw):
        rule, _ = rg.generate_permit_rule(
            self.SRC, self.DST, "tcp", "22",
            acl_direction, vlan_ip_side, switch_type="ios",
            established=True, **kw)
        return rule

    # --- the two orderings that put the form-source first: no keyword ---

    def test_inbound_on_source_vlan_puts_source_first_so_no_established(self):
        rule = self._rule("in", "src")
        self.assertEqual(rule, "permit tcp host 10.0.0.1 host 10.0.1.5 eq 22")
        self.assertNotIn("established", rule)

    def test_outbound_on_destination_vlan_puts_source_first_so_no_established(self):
        rule = self._rule("out", "dst")
        self.assertEqual(rule, "permit tcp host 10.0.0.1 host 10.0.1.5 eq 22")
        self.assertNotIn("established", rule)

    # --- the two orderings that put the form-destination first: keyword ---

    def test_inbound_on_destination_vlan_puts_destination_first_so_established(self):
        rule = self._rule("in", "dst")
        self.assertEqual(
            rule, "permit tcp host 10.0.1.5 eq 22 host 10.0.0.1 established")

    def test_outbound_on_source_vlan_puts_destination_first_so_established(self):
        rule = self._rule("out", "src")
        self.assertEqual(
            rule, "permit tcp host 10.0.1.5 eq 22 host 10.0.0.1 established")

    # --- placement and guards ---

    def test_established_precedes_time_range(self):
        rule = self._rule("in", "dst", time_range="BUSINESS-HOURS")
        self.assertEqual(
            rule,
            "permit tcp host 10.0.1.5 eq 22 host 10.0.0.1 established "
            "time-range BUSINESS-HOURS")

    def test_not_requested_means_never_added(self):
        rule, _ = rg.generate_permit_rule(
            self.SRC, self.DST, "tcp", "22", "in", "dst", switch_type="ios")
        self.assertNotIn("established", rule)

    def test_non_tcp_protocol_never_gets_the_keyword(self):
        rule, _ = rg.generate_permit_rule(
            self.SRC, self.DST, "udp", "53", "in", "dst",
            switch_type="ios", established=True)
        self.assertNotIn("established", rule)

    def test_ios_service_group_replaces_protocol_token_so_no_keyword(self):
        # The service object-group defines its own protocols in place of the
        # 'tcp' token, so 'established' is not attached to those lines.
        rule, _ = rg.generate_permit_rule(
            self.SRC, self.DST, "tcp", "portgroup WEB_PORT", "in", "dst",
            switch_type="ios", established=True)
        self.assertNotIn("established", rule)

    def test_nxos_portgroup_still_keeps_tcp_token_and_gets_keyword(self):
        rule, _ = rg.generate_permit_rule(
            self.SRC, self.DST, "tcp", "portgroup WEB", "in", "dst",
            switch_type="nexus", established=True)
        self.assertTrue(rule.endswith("established"), rule)

    def test_explanation_says_why_it_was_omitted_on_the_forward_line(self):
        _, explanation = rg.generate_permit_rule(
            self.SRC, self.DST, "tcp", "22", "in", "src",
            switch_type="ios", established=True)
        self.assertIn("NOT added", explanation)


class ParseEstablishedTests(unittest.TestCase):

    def test_keyword_is_captured_not_silently_dropped(self):
        parsed = ap.parse_acl_rule(
            "permit tcp host 10.0.0.1 host 10.0.0.2 eq 22 established", "ios")
        self.assertTrue(parsed["established"])

    def test_absent_keyword_parses_false(self):
        parsed = ap.parse_acl_rule(
            "permit tcp host 10.0.0.1 host 10.0.0.2 eq 22", "ios")
        self.assertFalse(parsed["established"])

    def test_parsed_alongside_a_trailing_time_range(self):
        parsed = ap.parse_acl_rule(
            "permit tcp host 10.0.0.1 host 10.0.0.2 eq 22 established "
            "time-range AFTER-HOURS", "ios")
        self.assertTrue(parsed["established"])
        self.assertEqual(parsed["time_range"], "AFTER-HOURS")

    def test_parsed_with_wildcard_source(self):
        parsed = ap.parse_acl_rule(
            "permit tcp 10.0.0.0 0.0.0.255 host 10.0.1.1 eq 443 established", "ios")
        self.assertTrue(parsed["established"])
        self.assertEqual(parsed["src_ip"], "10.0.0.0")

    def test_standard_acl_rule_reports_false(self):
        parsed = ap.parse_acl_rule("permit 10.0.0.0 0.0.0.255", "ios", None, "standard")
        self.assertFalse(parsed["established"])


class EstablishedCoverageTests(unittest.TestCase):
    """An 'established' rule matches only ACK/RST segments, so it is
    strictly narrower and must never be reported as covering a rule
    without it -- otherwise Redundancy would recommend deleting the rule
    that actually permits connection setup."""

    PLAIN = "permit tcp host 10.0.0.1 host 10.0.0.2 eq 22"
    EST = "permit tcp host 10.0.0.1 host 10.0.0.2 eq 22 established"

    def test_established_does_not_cover_plain(self):
        a = ap.parse_acl_rule(self.EST, "ios")
        b = ap.parse_acl_rule(self.PLAIN, "ios")
        self.assertFalse(ap.rule_covers(a, b))

    def test_plain_does_cover_established(self):
        a = ap.parse_acl_rule(self.PLAIN, "ios")
        b = ap.parse_acl_rule(self.EST, "ios")
        self.assertTrue(ap.rule_covers(a, b))

    def test_two_established_rules_still_compare_normally(self):
        a = ap.parse_acl_rule("permit tcp any host 10.0.0.2 eq 22 established", "ios")
        b = ap.parse_acl_rule(self.EST, "ios")
        self.assertTrue(ap.rule_covers(a, b))

    def test_group_member_variant_applies_the_same_guard(self):
        a = ap.parse_acl_rule(self.EST, "ios")
        b = ap.parse_acl_rule(self.PLAIN, "ios")
        self.assertFalse(ap.rule_covers_with_group_members(a, b, {}, {}))


class ReverseDirectionEstablishedTests(unittest.TestCase):

    def test_reversal_preserves_the_keyword(self):
        # Dropping it would silently broaden the reversed rule from
        # return-traffic-only to full access, including connection setup.
        parsed = ap.parse_acl_rule(
            "permit tcp host 10.0.0.2 eq 22 host 10.0.0.1 established", "nexus")
        reversed_line = ap.reverse_rule_direction(parsed, "nexus")
        self.assertEqual(
            reversed_line,
            "permit tcp host 10.0.0.1 host 10.0.0.2 eq 22 established")

    def test_reversal_keeps_established_before_time_range(self):
        parsed = ap.parse_acl_rule(
            "permit tcp host 10.0.0.2 eq 22 host 10.0.0.1 established "
            "time-range NIGHTS", "nexus")
        reversed_line = ap.reverse_rule_direction(parsed, "nexus")
        self.assertEqual(
            reversed_line,
            "permit tcp host 10.0.0.1 host 10.0.0.2 eq 22 established "
            "time-range NIGHTS")


class SummaryEstablishedTests(unittest.TestCase):

    def test_established_rules_summarize_together_and_keep_the_keyword(self):
        rules = [
            "10 permit tcp host 10.0.0.0 host 10.9.9.9 eq 22 established",
            "20 permit tcp host 10.0.0.1 host 10.9.9.9 eq 22 established",
        ]
        suggestions = ap.suggest_summary_rules(rules, "ios")
        self.assertTrue(suggestions)
        self.assertIn("established", suggestions[0]["suggestion"])

    def test_mixed_established_and_plain_are_never_merged(self):
        # Merging them would widen the summary to admit connection setup
        # that the established rule never permitted.
        rules = [
            "10 permit tcp host 10.0.0.0 host 10.9.9.9 eq 22 established",
            "20 permit tcp host 10.0.0.1 host 10.9.9.9 eq 22",
        ]
        self.assertEqual(ap.suggest_summary_rules(rules, "ios"), [])


class ValidateEstablishedTests(unittest.TestCase):

    def test_false_passes_through_regardless_of_protocol(self):
        self.assertFalse(validate_established(False, "udp", None))

    def test_tcp_with_port_is_accepted(self):
        self.assertTrue(validate_established(True, "tcp", "22"))

    def test_non_tcp_is_rejected(self):
        with self.assertRaises(ValidationError) as ctx:
            validate_established(True, "udp", "53")
        self.assertIn("only applies to TCP", str(ctx.exception))

    def test_tcp_without_a_port_is_rejected(self):
        with self.assertRaises(ValidationError) as ctx:
            validate_established(True, "tcp", None)
        self.assertIn("needs a service port", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
