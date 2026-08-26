import unittest
from unittest.mock import patch
from types import SimpleNamespace

import acl_service
import main
import rule_generator
import ssh_manager
from validators import (ValidationError, validate_ip_or_network,
                        validate_port_spec, validate_remark)


class RuleGeneratorPlatformTests(unittest.TestCase):
    def test_nxos_keeps_native_group_keywords(self):
        rule, _ = rule_generator.generate_permit_rule(
            "addrgroup CLIENTS", "addrgroup SERVERS", "tcp",
            "portgroup HTTP/HTTPS", "out", "dst", "nexus")
        self.assertEqual(
            rule,
            "permit tcp addrgroup CLIENTS addrgroup SERVERS "
            "portgroup HTTP/HTTPS",
        )

    def test_ios_uses_network_object_groups_in_address_positions(self):
        rule, _ = rule_generator.generate_permit_rule(
            "addrgroup CLIENTS", "addrgroup SERVERS", "tcp",
            "443", "out", "dst", "ios")
        self.assertEqual(
            rule,
            "permit tcp object-group CLIENTS object-group SERVERS eq 443",
        )

    def test_ios_service_group_replaces_protocol_and_precedes_addresses(self):
        rule, explanation = rule_generator.generate_permit_rule(
            "addrgroup CLIENTS", "10.0.0.10", "tcp",
            "portgroup WEB_PORT", "out", "dst", "ios")
        self.assertEqual(
            rule,
            "permit object-group WEB_PORT object-group CLIENTS "
            "host 10.0.0.10",
        )
        self.assertIn("defines the permitted protocol and port", explanation)

    def test_acl_context_is_platform_specific(self):
        self.assertEqual(main._acl_ctx("EDGE", "ios"),
                         "ip access-list extended EDGE")
        self.assertEqual(main._acl_ctx("EDGE", "nexus"),
                         "ip access-list EDGE")

    def test_port_stays_on_destination_when_acl_order_is_reversed(self):
        rule, _ = rule_generator.generate_permit_rule(
            "172.30.48.1", "172.30.54.218", "tcp", "22",
            "out", "src", "ios")
        self.assertEqual(
            rule,
            "permit tcp host 172.30.54.218 eq 22 host 172.30.48.1",
        )

    def test_time_range_is_appended_to_generated_rule(self):
        rule, explanation = rule_generator.generate_permit_rule(
            "10.0.0.1", "10.0.0.2", "tcp", "443",
            "out", "dst", "nexus", "BUSINESS-HOURS")
        self.assertEqual(
            rule,
            "permit tcp host 10.0.0.1 host 10.0.0.2 eq 443 "
            "time-range BUSINESS-HOURS",
        )
        self.assertIn("BUSINESS-HOURS", explanation)


class _Target:
    label = "switch-1"

    def __init__(self, is_nexus):
        self.is_nexus = is_nexus


class RuleGroupValidationTests(unittest.TestCase):
    GROUPS = [
        {"name": "CLIENTS", "kind": "address", "members": ["host 10.0.0.1"]},
        {"name": "WEB_PORT", "kind": "port", "members": ["tcp eq 443"]},
        {"name": "DNS_ONLY", "kind": "port", "members": ["udp eq domain"]},
    ]

    @patch("main.svc.get_object_groups", return_value=GROUPS)
    def test_valid_ios_groups_are_accepted(self, _groups):
        main._validate_rule_groups(
            _Target(False), "user", "addrgroup CLIENTS", "any",
            "portgroup WEB_PORT", "tcp")

    @patch("main.svc.get_object_groups", return_value=GROUPS)
    def test_wrong_group_type_is_rejected(self, _groups):
        with self.assertRaisesRegex(ValidationError, "port group, not a address"):
            main._validate_rule_groups(
                _Target(False), "user", "addrgroup WEB_PORT", "any",
                None, "tcp")

    @patch("main.svc.get_object_groups", return_value=GROUPS)
    def test_missing_group_is_rejected(self, _groups):
        with self.assertRaisesRegex(ValidationError, "does not exist"):
            main._validate_rule_groups(
                _Target(False), "user", "addrgroup MISSING", "any",
                None, "tcp")

    @patch("main.svc.get_object_groups", return_value=GROUPS)
    def test_ios_service_group_must_include_selected_protocol(self, _groups):
        with self.assertRaisesRegex(ValidationError, "no TCP members"):
            main._validate_rule_groups(
                _Target(False), "user", "any", "any",
                "portgroup DNS_ONLY", "tcp")

    def test_slash_is_allowed_in_object_group_names(self):
        self.assertEqual(
            validate_port_spec("portgroup HTTP/HTTPS", "tcp"),
            "portgroup HTTP/HTTPS",
        )
        self.assertEqual(
            validate_ip_or_network("addrgroup NET/OPS", "Source"),
            "addrgroup NET/OPS",
        )


class RulePreviewSafetyTests(unittest.TestCase):
    def test_overall_access_is_denied_when_either_side_denies(self):
        results = [{
            "on_this_switch": True,
            "source_side": {"verdict": "PERMITTED"},
            "destination_side": {"verdict": "DENIED"},
        }]
        self.assertEqual(main._overall_access_verdict(results), "DENY")

    def test_overall_access_is_permit_without_any_denied_side(self):
        results = [{
            "on_this_switch": True,
            "source_side": {"verdict": "N/A"},
            "destination_side": {"verdict": "PERMITTED"},
        }]
        self.assertEqual(main._overall_access_verdict(results), "PERMIT")

    def test_auto_sequence_skips_rule_without_preceding_remark_slot(self):
        rule_seq, remark_seq, blocker = main._select_rule_and_remark_sequence(
            ["9 permit ip any any"], [], None, True, {9})
        self.assertEqual((rule_seq, remark_seq, blocker), (20, 19, None))

    def test_auto_sequence_warns_by_omitting_remark_when_no_pair_exists(self):
        lines = ["2 deny ip any any"]
        inspections = [{"verdict": "DENIED", "matched_rule": lines[0]}]
        rule_seq, remark_seq, blocker = main._select_rule_and_remark_sequence(
            lines, inspections, None, True, {2})
        self.assertEqual(rule_seq, 1)
        self.assertIsNone(remark_seq)
        self.assertEqual(blocker, lines[0])

    def test_requested_sequence_kept_when_remark_slot_is_occupied(self):
        rule_seq, remark_seq, _ = main._select_rule_and_remark_sequence(
            [], [], 10, True, {9})
        self.assertEqual(rule_seq, 10)
        self.assertIsNone(remark_seq)

    def test_remark_uses_sequence_immediately_before_rule(self):
        rule_seq, remark_seq, _ = main._select_rule_and_remark_sequence(
            [], [], None, True, set())
        self.assertEqual((rule_seq, remark_seq), (10, 9))

    def test_manual_remark_sequence_is_preserved(self):
        rule_seq, remark_seq, _ = main._select_rule_and_remark_sequence(
            [], [], None, True, set(), 5)
        self.assertEqual((rule_seq, remark_seq), (6, 5))

    def test_auto_rule_moves_after_manual_remark_sequence(self):
        rule_seq, remark_seq, _ = main._select_rule_and_remark_sequence(
            [], [], None, True, set(), 15)
        self.assertEqual((rule_seq, remark_seq), (16, 15))

    def test_taken_sequence_after_manual_remark_uses_normal_auto_order(self):
        rule_seq, remark_seq, _ = main._select_rule_and_remark_sequence(
            ["16 permit ip any any"], [], None, True, {16}, 15)
        self.assertEqual((rule_seq, remark_seq), (20, 15))

    def test_manual_remark_must_precede_manual_rule(self):
        with self.assertRaisesRegex(ValidationError, "must be lower"):
            main._select_rule_and_remark_sequence(
                [], [], 10, True, set(), 15)

    def test_no_remark_uses_original_sequence_logic(self):
        rule_seq, remark_seq, _ = main._select_rule_and_remark_sequence(
            [], [], None, False, {10, 20})
        self.assertEqual((rule_seq, remark_seq), (10, None))

    def test_remark_accepts_one_hundred_characters(self):
        value = "r" * 100
        self.assertEqual(validate_remark(value), value)

    def test_remark_rejects_more_than_one_hundred_characters(self):
        with self.assertRaisesRegex(ValidationError, "maximum 100"):
            validate_remark("r" * 101)

    def test_remark_rejects_multiple_cli_lines(self):
        with self.assertRaisesRegex(ValidationError, "newlines"):
            validate_remark("approved\n20 deny ip any any")

    def test_acl_remark_is_found_and_verified_by_sequence(self):
        output = """IP access list EDGE
  20 remark approved by network team
  20 permit tcp any any eq 443"""
        expected = "20 remark approved by network team"
        self.assertEqual(main._find_acl_remark(output, 20), expected)
        self.assertTrue(main._remark_was_applied(output, expected))
        self.assertIsNone(main._find_acl_remark(output, 30))
        self.assertEqual(main._acl_sequence_numbers(output), {20})

    @patch("main.svc.show", return_value="20 remark approved")
    def test_ios_remark_verification_reads_running_config(self, show):
        target = SimpleNamespace(is_nexus=False)
        output = main._acl_remark_output(target, "operator", "EDGE")
        self.assertEqual(output, "20 remark approved")
        show.assert_called_once_with(
            target, "operator",
            "show running-config | section ip access-list extended EDGE",
            timeout=30,
        )

    def test_all_protocol_is_not_covered_by_icmp_rule(self):
        rule = acl_service.acl_parser.parse_acl_rule(
            "997 permit icmp any any", "ios")
        verdict = acl_service.acl_parser.evaluate_rule(
            rule, "172.30.201.165", "192.168.254.225", "all", None,
            "out", "dst", {}, {})
        self.assertIsNone(verdict)

    def test_ip_rule_covers_specific_protocol_query(self):
        rule = acl_service.acl_parser.parse_acl_rule(
            "997 permit ip any any", "ios")
        verdict = acl_service.acl_parser.evaluate_rule(
            rule, "172.30.201.165", "192.168.254.225", "icmp", None,
            "out", "dst", {}, {})
        self.assertEqual(verdict, "permit")

    def test_time_range_config_parser_ignores_switch_errors(self):
        output = """show running-config | section time-range test
                                                     ^
% Invalid command at '^' marker.
switch#"""
        self.assertEqual(
            acl_service.acl_parser.parse_time_range_config(output, "test"),
            [],
        )

    def test_time_range_config_parser_keeps_only_config(self):
        output = """time-range BUSINESS
 periodic weekdays 08:00 to 18:00
!
interface Vlan10"""
        self.assertEqual(
            acl_service.acl_parser.parse_time_range_config(
                output, "BUSINESS"),
            ["time-range BUSINESS", "periodic weekdays 08:00 to 18:00"],
        )

    def test_legacy_time_range_undo_error_restores_empty_range(self):
        commands = [
            "show running-config | section time-range teset",
            "^",
            "% Invalid command at '^' marker.",
        ]
        self.assertEqual(
            main._normalized_log_undo_commands(
                commands, "restore time-range teset"),
            ["time-range teset"],
        )

    def test_unrelated_invalid_undo_output_is_rejected(self):
        with self.assertRaisesRegex(ValidationError, "switch error output"):
            main._normalized_log_undo_commands(
                ["% Invalid command at '^' marker."], "restore ACL rule")

    def test_empty_time_range_is_reported_as_empty(self):
        parsed = acl_service.acl_parser.parse_time_ranges(
            "time-range entry: EMPTY-RANGE (active)\n No entries listed")
        self.assertEqual(parsed[0]["status"], "empty")

    def test_group_rule_is_redundant_under_ip_permit(self):
        groups = {"part3-camera": "address"}
        inspections = main._structural_acl_inspections(
            ["28 permit ip host 192.168.48.53 object-group Part3-Camera"],
            "permit tcp host 192.168.48.53 object-group Part3-Camera eq 22",
            "ios", groups)
        self.assertEqual(inspections[0]["verdict"], "PERMITTED")
        self.assertEqual(inspections[0]["matched_rule"].split()[0], "28")

    def test_unconditional_rule_covers_timed_rule(self):
        broader = acl_service.acl_parser.parse_acl_rule(
            "10 permit tcp any any eq 443", "ios")
        timed = acl_service.acl_parser.parse_acl_rule(
            "20 permit tcp any any eq 443 time-range BUSINESS", "ios")
        self.assertTrue(acl_service.acl_parser.rule_covers(broader, timed))

    def test_same_time_range_can_cover_timed_rule(self):
        broader = acl_service.acl_parser.parse_acl_rule(
            "10 permit tcp any any time-range BUSINESS", "ios")
        timed = acl_service.acl_parser.parse_acl_rule(
            "20 permit tcp any any eq 443 time-range business", "ios")
        self.assertTrue(acl_service.acl_parser.rule_covers(broader, timed))

    def test_different_time_range_does_not_cover_timed_rule(self):
        first = acl_service.acl_parser.parse_acl_rule(
            "10 permit tcp any any time-range NIGHT", "ios")
        second = acl_service.acl_parser.parse_acl_rule(
            "20 permit tcp any any eq 443 time-range BUSINESS", "ios")
        self.assertFalse(acl_service.acl_parser.rule_covers(first, second))

    def test_different_timed_deny_still_controls_sequence(self):
        groups = {}
        lines = [
            "50 deny tcp any any eq 443 time-range NIGHT",
        ]
        inspections = main._structural_acl_inspections(
            lines,
            "permit tcp any any eq 443 time-range BUSINESS",
            "ios", groups)
        sequence, blocker = main._select_rule_sequence(
            lines, inspections, None)
        self.assertEqual(sequence, 10)
        self.assertEqual(blocker, lines[0])

    def test_ip_permit_covers_icmp_group_rule(self):
        groups = {"part3-camera": "address"}
        inspections = main._structural_acl_inspections(
            ["28 permit ip host 192.168.48.53 object-group Part3-Camera"],
            "permit icmp host 192.168.48.53 object-group Part3-Camera",
            "ios", groups)
        self.assertEqual(inspections[0]["verdict"], "PERMITTED")

    def test_group_rule_is_redundant_under_unrestricted_tcp_permit(self):
        groups = {"part3-camera": "address"}
        inspections = main._structural_acl_inspections(
            ["28 permit tcp host 192.168.48.53 object-group Part3-Camera"],
            "permit tcp host 192.168.48.53 object-group Part3-Camera eq 22",
            "ios", groups)
        self.assertEqual(inspections[0]["verdict"], "PERMITTED")

    def test_unrestricted_udp_covers_port_specific_udp(self):
        groups = {"part3-camera": "address"}
        inspections = main._structural_acl_inspections(
            ["28 permit udp host 192.168.48.53 object-group Part3-Camera"],
            "permit udp host 192.168.48.53 object-group Part3-Camera eq 53",
            "ios", groups)
        self.assertEqual(inspections[0]["verdict"], "PERMITTED")

    def test_tcp_does_not_cover_udp(self):
        groups = {"part3-camera": "address"}
        inspections = main._structural_acl_inspections(
            ["28 permit tcp host 192.168.48.53 object-group Part3-Camera"],
            "permit udp host 192.168.48.53 object-group Part3-Camera eq 53",
            "ios", groups)
        self.assertEqual(inspections[0]["verdict"], "DENIED")
        self.assertIsNone(inspections[0]["matched_rule"])

    def test_network_source_covers_host_source_with_same_group(self):
        groups = {"part3-camera": "address"}
        inspections = main._structural_acl_inspections(
            ["28 permit ip 192.168.48.0 0.0.0.255 object-group Part3-Camera"],
            "permit ip host 192.168.48.53 object-group Part3-Camera",
            "ios", groups)
        self.assertEqual(inspections[0]["verdict"], "PERMITTED")

    def test_same_nxos_portgroup_is_compared_without_expansion(self):
        groups = {"clients": "address", "servers": "address",
                  "web": "port"}
        inspections = main._structural_acl_inspections(
            ["10 permit tcp addrgroup CLIENTS addrgroup SERVERS portgroup WEB"],
            "permit tcp addrgroup CLIENTS addrgroup SERVERS portgroup WEB",
            "nexus", groups)
        self.assertEqual(inspections[0]["verdict"], "PERMITTED")

    def test_ios_service_group_covers_requested_member_port(self):
        groups = {"mohammadhesam.imanirad": "address",
                  "web_port": "port"}
        addresses = {
            "mohammadhesam.imanirad": [
                "172.30.201.140/32", "192.168.52.130/32"],
        }
        services = {
            "WEB_PORT": acl_service.acl_parser.parse_object_group_services(
                "tcp eq www\ntcp eq 443"),
        }
        existing = (
            "20 permit object-group WEB_PORT "
            "object-group mohammadhesam.imanirad host 172.30.48.215")
        proposed = (
            "permit tcp object-group mohammadhesam.imanirad "
            "host 172.30.48.215 eq 443")
        inspections = main._structural_acl_inspections(
            [existing], proposed, "ios", groups, addresses, services)
        self.assertEqual(inspections[0]["verdict"], "PERMITTED")
        self.assertEqual(inspections[0]["matched_rule"], existing)

    def test_ios_address_group_covers_requested_member_host(self):
        groups = {"mohammadhesam.imanirad": "address",
                  "web_port": "port"}
        addresses = {
            "mohammadhesam.imanirad": [
                "172.30.201.140/32", "192.168.52.130/32"],
        }
        services = {
            "WEB_PORT": acl_service.acl_parser.parse_object_group_services(
                "tcp eq www\ntcp eq 443"),
        }
        existing = (
            "20 permit object-group WEB_PORT "
            "object-group mohammadhesam.imanirad host 172.30.48.215")
        proposed = (
            "permit object-group WEB_PORT host 172.30.201.140 "
            "host 172.30.48.215")
        inspections = main._structural_acl_inspections(
            [existing], proposed, "ios", groups, addresses, services)
        self.assertEqual(inspections[0]["verdict"], "PERMITTED")
        self.assertEqual(inspections[0]["matched_rule"], existing)

    def test_covering_group_deny_controls_sequence(self):
        groups = {"clients": "address", "servers": "address",
                  "web": "port"}
        lines = [
            "50 deny tcp addrgroup CLIENTS addrgroup SERVERS portgroup WEB",
        ]
        inspections = main._structural_acl_inspections(
            lines,
            "permit tcp addrgroup CLIENTS addrgroup SERVERS portgroup WEB",
            "nexus", groups)
        sequence, blocker = main._select_rule_sequence(
            lines, inspections, None)
        self.assertEqual(sequence, 10)
        self.assertEqual(blocker, lines[0])

    def test_narrower_group_deny_prevents_false_redundancy_warning(self):
        groups = {"clients": "address", "servers": "address"}
        lines = [
            "20 deny tcp addrgroup CLIENTS addrgroup SERVERS eq 22",
            "30 permit tcp addrgroup CLIENTS addrgroup SERVERS",
        ]
        inspections = main._structural_acl_inspections(
            lines,
            "permit tcp addrgroup CLIENTS addrgroup SERVERS",
            "nexus", groups)
        self.assertEqual(inspections[0]["verdict"], "DENIED")
        self.assertEqual(inspections[0]["matched_rule"], lines[0])

    def test_full_product_is_aggregated_after_permits_and_denies(self):
        samples = [
            ("10.0.0.1", "10.0.1.1", "tcp", 80),
            ("10.0.0.2", "10.0.1.1", "tcp", 80),
            ("10.0.0.3", "10.0.1.1", "tcp", 80),
        ]

        def record(sample, verdict, rule):
            return {"sample": sample, "check": {"source_side": {
                "vlan": "Vlan10",
                "acl_applied": True,
                "evaluated_acls": [{
                    "acl_name": "EDGE", "direction": "out",
                    "verdict": verdict, "matched_rule": rule,
                }],
            }}}

        policies, _ = main._aggregate_policy_checks([
            record(samples[0], "PERMITTED", "10 permit tcp any any eq 80"),
            record(samples[1], "DENIED", "20 deny tcp any any eq 80"),
            record(samples[2], "PERMITTED", "30 permit ip any any"),
        ])
        inspections = policies[("source", "Vlan10", "EDGE", "out")]

        self.assertEqual(
            [item["verdict"] for item in inspections],
            ["PERMITTED", "DENIED", "PERMITTED"],
        )

    def test_implicit_deny_does_not_hide_a_later_explicit_deny(self):
        samples = [
            ("10.0.0.1", "10.0.1.1", "tcp", 443),
            ("10.0.0.2", "10.0.1.1", "tcp", 443),
            ("10.0.0.3", "10.0.1.1", "tcp", 443),
        ]

        def record(sample, rule):
            return {"sample": sample, "check": {"source_side": {
                "vlan": "Vlan10",
                "acl_applied": True,
                "evaluated_acls": [{
                    "acl_name": "EDGE", "direction": "out",
                    "verdict": "DENIED", "matched_rule": rule,
                }],
            }}}

        policies, _ = main._aggregate_policy_checks([
            record(samples[0], None),
            record(samples[1], "200 deny tcp any any eq 443"),
            record(samples[2], "300 deny ip any any"),
        ])
        inspections = policies[("source", "Vlan10", "EDGE", "out")]

        sequence, blocker = main._select_rule_sequence(
            ["200 deny tcp any any eq 443", "300 deny ip any any"],
            inspections, None)
        self.assertEqual(sequence, 10)
        self.assertEqual(blocker, "200 deny tcp any any eq 443")

    def test_access_checker_normalizes_explicit_deny(self):
        target = SimpleNamespace(type="ios")
        with patch("acl_service.svc.get_interface_acls", return_value=[
                {"acl_name": "EDGE", "direction": "out"}]), \
             patch("acl_service.svc.get_acl_rules", return_value=(
                 "", ["10 deny ip any any"])), \
             patch("acl_service._prefetch_groups", return_value=({}, {}, {})):
            result = acl_service.evaluate_interface(
                target, "user", "Vlan10", "10.0.0.1", "10.0.0.2",
                "ip", None, "dst")
        self.assertEqual(result["verdict"], "DENIED")
        self.assertEqual(result["matched_rule"], "10 deny ip any any")

    def test_access_checker_normalizes_explicit_permit(self):
        target = SimpleNamespace(type="ios")
        with patch("acl_service.svc.get_interface_acls", return_value=[
                {"acl_name": "EDGE", "direction": "out"}]), \
             patch("acl_service.svc.get_acl_rules", return_value=(
                 "", ["10 permit ip any any"])), \
             patch("acl_service._prefetch_groups", return_value=({}, {}, {})):
            result = acl_service.evaluate_interface(
                target, "user", "Vlan10", "10.0.0.1", "10.0.0.2",
                "ip", None, "dst")
        self.assertEqual(result["verdict"], "PERMITTED")
        self.assertEqual(result["matched_rule"], "10 permit ip any any")

    def test_auto_sequence_is_inserted_before_matching_deny(self):
        lines = [
            "1000 permit ip any any",
            "1020 deny tcp any host 172.30.54.218 eq 22",
            "2000 permit ip any any",
        ]
        inspections = [{
            "verdict": "DENIED", "matched_rule": lines[1],
        }]
        sequence, blocker = main._select_rule_sequence(
            lines, inspections, None)
        self.assertEqual(sequence, 10)
        self.assertEqual(blocker, lines[1])

    def test_requested_sequence_below_deny_is_required(self):
        lines = ["100 deny ip any any"]
        inspections = [{"verdict": "DENIED", "matched_rule": lines[0]}]
        with self.assertRaisesRegex(ValidationError, "below 100"):
            main._select_rule_sequence(lines, inspections, 101)

    def test_no_sequence_gap_is_reported(self):
        lines = [f"{seq} permit ip any any" for seq in range(1, 100)]
        lines.append("100 deny ip any any")
        inspections = [{"verdict": "DENIED", "matched_rule": lines[-1]}]
        with self.assertRaisesRegex(ValidationError, "no unused sequence"):
            main._select_rule_sequence(lines, inspections, None)

    def test_auto_sequence_skips_numbers_already_in_use(self):
        lines = ["10 permit ip any any", "20 permit ip any any",
                 "100 deny ip any any"]
        inspections = [{"verdict": "DENIED", "matched_rule": lines[-1]}]
        sequence, _ = main._select_rule_sequence(lines, inspections, None)
        self.assertEqual(sequence, 30)

    def test_auto_sequence_falls_back_to_one_when_tens_are_full(self):
        lines = ["10 permit ip any any", "20 permit ip any any",
                 "25 deny ip any any"]
        inspections = [{"verdict": "DENIED", "matched_rule": lines[-1]}]
        sequence, _ = main._select_rule_sequence(lines, inspections, None)
        self.assertEqual(sequence, 1)

    def test_auto_sequence_starts_at_one_when_deny_precedes_ten(self):
        lines = ["5 deny ip any any"]
        inspections = [{"verdict": "DENIED", "matched_rule": lines[0]}]
        sequence, _ = main._select_rule_sequence(lines, inspections, None)
        self.assertEqual(sequence, 1)

    def test_auto_sequence_without_deny_uses_first_free_multiple_of_ten(self):
        sequence, blocker = main._select_rule_sequence(
            ["10 permit ip any any", "20 permit ip any any"], [], None)
        self.assertEqual(sequence, 30)
        self.assertIsNone(blocker)

    def test_every_group_member_contributes_route_probes(self):
        inventory = {
            "clients": {
                "name": "CLIENTS", "kind": "address",
                "members": [
                    "host 10.0.0.1",
                    "10.0.1.0 255.255.255.252",
                    "range 10.0.2.10 10.0.2.11",
                ],
            }
        }
        probes = main._representative_ips("addrgroup CLIENTS", inventory)
        self.assertEqual(probes, [
            "10.0.0.1", "10.0.1.0", "10.0.1.1", "10.0.1.2",
            "10.0.1.3", "10.0.2.10", "10.0.2.11",
        ])

    def test_fast_group_route_discovery_does_not_expand_members(self):
        inventory = {
            "clients": {
                "name": "CLIENTS", "kind": "address",
                "members": [
                    "host 10.0.0.1",
                    "10.0.1.0 255.255.255.0",
                    "range 10.0.2.10 10.0.2.20",
                ],
            }
        }
        self.assertEqual(
            main._group_route_probes("addrgroup CLIENTS", inventory),
            ["10.0.0.1", "10.0.1.1", "10.0.2.10"],
        )

    def test_every_port_in_service_range_is_checked(self):
        inventory = {
            "web": {
                "name": "WEB", "kind": "port",
                "members": ["tcp range 8000 8003"],
            }
        }
        self.assertEqual(
            main._port_probes("portgroup WEB", "tcp", inventory),
            [8000, 8001, 8002, 8003],
        )

    def test_applied_rule_verification_ignores_match_counter(self):
        self.assertTrue(main._rule_was_applied(
            ["1010 permit tcp host 172.30.54.218 eq 22 "
             "host 172.30.48.1 (3 matches)"],
            "1010 permit tcp host 172.30.54.218 eq 22 host 172.30.48.1",
        ))
        self.assertFalse(main._rule_was_applied(
            ["1010 permit tcp host 172.30.54.218 eq 80 host 172.30.48.1"],
            "1010 permit tcp host 172.30.54.218 eq 22 host 172.30.48.1",
        ))

    def test_applied_rule_verification_accepts_nxos_host_as_prefix(self):
        self.assertTrue(main._rule_was_applied(
            ["60 permit ip 172.30.201.165/32 "
             "addrgroup lms-archpartpay_VMs"],
            "60 permit ip host 172.30.201.165 "
            "addrgroup lms-archpartpay_VMs",
        ))

    def test_additional_switch_errors_are_detected(self):
        self.assertIsNotNone(ssh_manager.detect_switch_error(
            "% object-group WEB does not exist"))
        self.assertIsNotNone(ssh_manager.detect_switch_error(
            "% Command failed validation"))


if __name__ == "__main__":
    unittest.main()
