import unittest

import acl_parser as ap
import rule_generator as rg
from validators import ValidationError, validate_icmp_type


class ParseIcmpTypeTests(unittest.TestCase):
    def test_no_type_is_none(self):
        rule = ap.parse_acl_rule("permit icmp any any", "ios")
        self.assertEqual(rule["proto"], "icmp")
        self.assertIsNone(rule["icmp_type"])

    def test_specific_type_is_extracted(self):
        rule = ap.parse_acl_rule("permit icmp any any echo", "ios")
        self.assertEqual(rule["icmp_type"], "echo")

    def test_each_listed_type_is_recognized(self):
        for t in ap.ICMP_TYPES:
            rule = ap.parse_acl_rule(f"permit icmp any any {t}", "nexus")
            self.assertEqual(rule["icmp_type"], t)

    def test_trailing_non_type_token_does_not_break_parsing(self):
        # e.g. a time-range still parses fine when no type is present
        rule = ap.parse_acl_rule(
            "permit icmp any any time-range BUSINESS_HOURS", "ios")
        self.assertIsNone(rule["icmp_type"])
        self.assertEqual(rule["time_range"], "BUSINESS_HOURS")

    def test_non_icmp_protocol_has_no_type_field_populated(self):
        rule = ap.parse_acl_rule("permit tcp any any eq 80", "ios")
        self.assertIsNone(rule["icmp_type"])


class IcmpTypeMatchesTests(unittest.TestCase):
    def test_no_type_rule_matches_any_query(self):
        self.assertTrue(ap.icmp_type_matches(None, None))
        self.assertTrue(ap.icmp_type_matches("echo", None))

    def test_typed_rule_requires_equal_type(self):
        self.assertTrue(ap.icmp_type_matches("echo", "echo"))
        self.assertFalse(ap.icmp_type_matches("echo-reply", "echo"))

    def test_typed_rule_does_not_match_unspecified_query(self):
        self.assertFalse(ap.icmp_type_matches(None, "echo"))


class IcmpTypeCoversTests(unittest.TestCase):
    def test_no_type_covers_everything(self):
        self.assertTrue(ap.icmp_type_covers(None, None))
        self.assertTrue(ap.icmp_type_covers(None, "echo"))
        self.assertTrue(ap.icmp_type_covers(None, "echo-reply"))
        self.assertTrue(ap.icmp_type_covers(None, "time-exceeded"))

    def test_specific_type_does_not_cover_no_type(self):
        self.assertFalse(ap.icmp_type_covers("echo", None))

    def test_different_specific_types_never_cover_each_other(self):
        self.assertFalse(ap.icmp_type_covers("echo", "echo-reply"))
        self.assertFalse(ap.icmp_type_covers("echo-reply", "echo"))

    def test_identical_specific_types_cover(self):
        self.assertTrue(ap.icmp_type_covers("echo", "echo"))


class RuleCoversIcmpTests(unittest.TestCase):
    """Reproduces the exact example from the request."""

    def test_untyped_rule_covers_each_typed_rule_individually(self):
        broad = ap.parse_acl_rule("permit icmp any any", "ios")
        for t in ("echo", "echo-reply", "time-exceeded"):
            narrow = ap.parse_acl_rule(f"permit icmp any any {t}", "ios")
            self.assertTrue(ap.rule_covers(broad, narrow),
                            f"any-any should cover the {t} rule")

    def test_typed_rules_do_not_cover_the_untyped_rule(self):
        broad = ap.parse_acl_rule("permit icmp any any", "ios")
        echo = ap.parse_acl_rule("permit icmp any any echo", "ios")
        echo_reply = ap.parse_acl_rule("permit icmp any any echo-reply", "ios")
        self.assertFalse(ap.rule_covers(echo, broad))
        self.assertFalse(ap.rule_covers(echo_reply, broad))

    def test_two_different_typed_rules_are_not_redundant(self):
        echo = ap.parse_acl_rule("permit icmp any any echo", "ios")
        echo_reply = ap.parse_acl_rule("permit icmp any any echo-reply", "ios")
        self.assertFalse(ap.rule_covers(echo, echo_reply))
        self.assertFalse(ap.rule_covers(echo_reply, echo))

    def test_check_redundant_rules_end_to_end(self):
        # check_redundant_rules stores each rule's line with its leading
        # sequence number stripped (parse_acl_rule's "raw"), so compare
        # against the bare permit/deny text. Results are grouped by covering
        # rule: one group here, listing all 3 covered rules.
        rules = [
            "10 permit icmp any any",
            "20 permit icmp any any echo",
            "30 permit icmp any any echo-reply",
            "40 permit icmp any any time-exceeded",
        ]
        bare = [r.split(None, 1)[1] for r in rules]
        groups = ap.check_redundant_rules(rules, "ios")
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["covered_by_rule"], bare[0])
        self.assertEqual(groups[0]["covered_by_sequence"], 10)
        redundant_lines = {r["raw"] for r in groups[0]["redundant_rules"]}
        for line in bare[1:]:
            self.assertIn(line, redundant_lines)
        self.assertNotIn(bare[0], redundant_lines)


class EvaluateRuleIcmpTests(unittest.TestCase):
    def _rule(self, line):
        return ap.parse_acl_rule(line, "ios")

    def test_untyped_rule_matches_unspecified_and_typed_query(self):
        rule = self._rule("permit icmp any any")
        v1 = ap.evaluate_rule(rule, "1.1.1.1", "2.2.2.2", "icmp", None,
                              "in", "src", {}, {}, user_icmp_type=None)
        v2 = ap.evaluate_rule(rule, "1.1.1.1", "2.2.2.2", "icmp", None,
                              "in", "src", {}, {}, user_icmp_type="echo")
        self.assertEqual(v1, "permit")
        self.assertEqual(v2, "permit")

    def test_typed_rule_only_matches_same_type_query(self):
        rule = self._rule("permit icmp any any echo")
        matches_same = ap.evaluate_rule(rule, "1.1.1.1", "2.2.2.2", "icmp", None,
                                        "in", "src", {}, {}, user_icmp_type="echo")
        matches_other = ap.evaluate_rule(rule, "1.1.1.1", "2.2.2.2", "icmp", None,
                                         "in", "src", {}, {}, user_icmp_type="echo-reply")
        matches_unspecified = ap.evaluate_rule(rule, "1.1.1.1", "2.2.2.2", "icmp", None,
                                               "in", "src", {}, {}, user_icmp_type=None)
        self.assertEqual(matches_same, "permit")
        self.assertIsNone(matches_other)
        self.assertIsNone(matches_unspecified)


class SuggestSummaryIcmpTests(unittest.TestCase):
    # 10.0.0.0/10.0.0.1 and 10.0.1.0/10.0.1.1 are each a collapsible /31 pair,
    # so ipaddress.collapse_addresses can actually produce a supernet for them.
    ECHO_RULES = [
        "permit icmp 10.0.0.0 0.0.0.0 any echo",
        "permit icmp 10.0.0.1 0.0.0.0 any echo",
    ]
    ECHO_REPLY_RULES = [
        "permit icmp 10.0.1.0 0.0.0.0 any echo-reply",
        "permit icmp 10.0.1.1 0.0.0.0 any echo-reply",
    ]

    def test_different_icmp_types_are_not_merged_into_one_summary(self):
        suggestions = ap.suggest_summary_rules(
            self.ECHO_RULES + self.ECHO_REPLY_RULES, "ios")
        self.assertEqual(len(suggestions), 2)
        for s in suggestions:
            types = {ap.parse_acl_rule(r, "ios")["icmp_type"] for r in s["replaces"]}
            self.assertEqual(len(types), 1)

    def test_summary_suggestion_includes_icmp_type(self):
        suggestions = ap.suggest_summary_rules(self.ECHO_RULES, "ios")
        self.assertTrue(suggestions)
        self.assertTrue(suggestions[0]["suggestion"].endswith("echo"))


class MultiPortTests(unittest.TestCase):
    """Multi-port `eq` is a plain-ACL-rule-line feature only — a real Cisco
    object-group service member takes exactly one port each, so the
    object-group parser deliberately stays single-token there."""

    def test_acl_rule_line_multi_port_eq_ios(self):
        # Exact example from the request.
        rule = ap.parse_acl_rule(
            "50 permit tcp 172.30.52.0 0.0.0.255 host 172.30.48.200 eq 8843 8880",
            "ios")
        self.assertEqual(rule["dst_port_op"], "eq")
        self.assertEqual(rule["dst_ports"], [8843, 8880])

    def test_acl_rule_line_multi_port_eq_more_than_two(self):
        rule = ap.parse_acl_rule(
            "permit tcp any host 10.0.0.1 eq 80 443 8080 8443", "ios")
        self.assertEqual(rule["dst_port_op"], "eq")
        self.assertEqual(rule["dst_ports"], [80, 443, 8080, 8443])

    def test_acl_rule_line_multi_port_eq_nxos(self):
        rule = ap.parse_acl_rule(
            "permit tcp any any eq 8843 8880", "nexus")
        self.assertEqual(rule["dst_ports"], [8843, 8880])

    def test_object_group_service_member_stays_single_port(self):
        conditions = ap.parse_object_group_services("  eq 8843")
        self.assertEqual(conditions, [(None, None, "eq", [8843])])

    def test_object_group_service_member_lt_stays_single_port(self):
        conditions = ap.parse_object_group_services("lt 1024")
        self.assertEqual(conditions, [(None, None, "lt", [1024])])

    def test_port_matches_against_multi_port_list(self):
        self.assertTrue(ap.port_matches(8843, "eq", [8843, 8880]))
        self.assertTrue(ap.port_matches(8880, "eq", [8843, 8880]))
        self.assertFalse(ap.port_matches(8000, "eq", [8843, 8880]))

    def test_access_check_matches_either_multi_port(self):
        # End-to-end: Access Checker evaluating against the exact rule from
        # the request, for each of the two listed ports plus a non-member one.
        rule = ap.parse_acl_rule(
            "50 permit tcp 172.30.52.0 0.0.0.255 host 172.30.48.200 eq 8843 8880",
            "ios")
        for port in (8843, 8880):
            verdict = ap.evaluate_rule(
                rule, "172.30.52.5", "172.30.48.200", "tcp", port,
                "in", "src", {}, {})
            self.assertEqual(verdict, "permit", f"port {port} should match")
        verdict = ap.evaluate_rule(
            rule, "172.30.52.5", "172.30.48.200", "tcp", 9999,
            "in", "src", {}, {})
        self.assertIsNone(verdict)


class NamedPortsTests(unittest.TestCase):
    def test_new_tcp_keywords(self):
        self.assertEqual(ap.NAMED_PORTS["onep-plain"], 15001)
        self.assertEqual(ap.NAMED_PORTS["onep-tls"], 15002)

    def test_new_udp_keywords(self):
        self.assertEqual(ap.NAMED_PORTS["biff"], 512)
        self.assertEqual(ap.NAMED_PORTS["dnsix"], 195)
        self.assertEqual(ap.NAMED_PORTS["mobile-ip"], 434)
        self.assertEqual(ap.NAMED_PORTS["nameserver"], 42)
        self.assertEqual(ap.NAMED_PORTS["netbios-ss"], 139)
        self.assertEqual(ap.NAMED_PORTS["non500-isakmp"], 4500)
        self.assertEqual(ap.NAMED_PORTS["ripv6"], 521)
        self.assertEqual(ap.NAMED_PORTS["who"], 513)
        self.assertEqual(ap.NAMED_PORTS["xdmcp"], 177)

    def test_resolve_port_uses_named_ports(self):
        self.assertEqual(ap.resolve_port("www"), 80)
        self.assertEqual(ap.resolve_port("bgp"), 179)
        self.assertEqual(ap.resolve_port("443"), 443)


class OtherProtocolsTests(unittest.TestCase):
    """Confirms protocols outside tcp/udp/icmp already parse and compare
    correctly with no special-casing needed (existing generic string-based
    design), per the request's "just know this exists" scope."""

    def test_ospf_rule_parses_with_no_port_or_type_fields(self):
        rule = ap.parse_acl_rule("permit ospf any any", "ios")
        self.assertEqual(rule["proto"], "ospf")
        self.assertEqual(rule["dst_port_op"], "")
        self.assertIsNone(rule["icmp_type"])

    def test_broader_ospf_rule_covers_narrower_one(self):
        broad = ap.parse_acl_rule("permit ospf any any", "ios")
        narrow = ap.parse_acl_rule("permit ospf host 10.0.0.1 any", "ios")
        self.assertTrue(ap.rule_covers(broad, narrow))

    def test_ospf_rule_does_not_cover_esp_rule(self):
        ospf = ap.parse_acl_rule("permit ospf any any", "ios")
        esp = ap.parse_acl_rule("permit esp any any", "ios")
        self.assertFalse(ap.rule_covers(ospf, esp))

    def test_ip_rule_still_covers_other_protocols_including_icmp_types(self):
        ip_rule = ap.parse_acl_rule("permit ip any any", "ios")
        icmp_typed = ap.parse_acl_rule("permit icmp any any echo", "ios")
        self.assertTrue(ap.rule_covers(ip_rule, icmp_typed))


class GeneratePermitRuleIcmpTests(unittest.TestCase):
    def test_no_type_omits_suffix(self):
        rule, _ = rg.generate_permit_rule(
            "10.0.0.1", "10.0.0.2", "icmp", None, "in", "src",
            switch_type="ios")
        self.assertEqual(rule, "permit icmp host 10.0.0.1 host 10.0.0.2")

    def test_specific_type_is_appended_after_destination(self):
        rule, _ = rg.generate_permit_rule(
            "10.0.0.1", "10.0.0.2", "icmp", None, "in", "src",
            switch_type="ios", icmp_type="echo")
        self.assertEqual(rule, "permit icmp host 10.0.0.1 host 10.0.0.2 echo")

    def test_type_always_trails_both_addresses_regardless_of_reordering(self):
        # Cisco syntax always puts the ICMP type after BOTH addresses, never
        # attached to whichever one is literally "source" or "destination" —
        # so it must land at the end even when direction/vlan-side reorders
        # dst ahead of src.
        rule, _ = rg.generate_permit_rule(
            "10.0.0.1", "10.0.0.2", "icmp", None, "out", "src",
            switch_type="ios", icmp_type="unreachable")
        self.assertEqual(rule, "permit icmp host 10.0.0.2 host 10.0.0.1 unreachable")

    def test_type_precedes_time_range(self):
        # Exact shape from the request:
        # 60 permit icmp host X host Y echo-reply time-range NAME
        rule, _ = rg.generate_permit_rule(
            "172.30.201.165", "172.30.48.1", "icmp", None, "out", "src",
            switch_type="ios", icmp_type="echo-reply", time_range="Camera-OneMonth")
        self.assertEqual(
            rule,
            "permit icmp host 172.30.48.1 host 172.30.201.165 "
            "echo-reply time-range Camera-OneMonth")

    def test_non_icmp_protocol_ignores_icmp_type(self):
        rule, _ = rg.generate_permit_rule(
            "10.0.0.1", "10.0.0.2", "tcp", "80", "in", "src",
            switch_type="ios", icmp_type="echo")
        self.assertNotIn("echo", rule)


class ValidateIcmpTypeTests(unittest.TestCase):
    def test_empty_is_none(self):
        self.assertIsNone(validate_icmp_type(None, "icmp"))
        self.assertIsNone(validate_icmp_type("", "icmp"))

    def test_valid_type_is_lowercased(self):
        self.assertEqual(validate_icmp_type("ECHO", "icmp"), "echo")

    def test_rejects_unknown_type(self):
        with self.assertRaises(ValidationError):
            validate_icmp_type("ping", "icmp")

    def test_rejects_type_on_non_icmp_protocol(self):
        with self.assertRaises(ValidationError):
            validate_icmp_type("echo", "tcp")


if __name__ == "__main__":
    unittest.main()
