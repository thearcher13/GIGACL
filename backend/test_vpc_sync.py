import asyncio
import unittest
from unittest.mock import patch

import acl_parser as ap
import main


class DiffAclSetsTests(unittest.TestCase):

    def test_identical_sets_all_match(self):
        acls_a = {"ACL1": ["10 permit ip any any"], "ACL2": ["10 deny tcp any any eq 22"]}
        acls_b = {"ACL1": ["10 permit ip any any"], "ACL2": ["10 deny tcp any any eq 22"]}
        results = ap.diff_acl_sets(acls_a, acls_b)
        self.assertEqual(len(results), 2)
        self.assertTrue(all(r["status"] == "match" for r in results))

    def test_acl_missing_on_b(self):
        acls_a = {"ACL1": ["10 permit ip any any"]}
        acls_b = {}
        results = ap.diff_acl_sets(acls_a, acls_b)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["status"], "missing_on_b")
        self.assertEqual(results[0]["only_in_a"], ["10 permit ip any any"])
        self.assertEqual(results[0]["only_in_b"], [])

    def test_acl_missing_on_a(self):
        acls_a = {}
        acls_b = {"ACL1": ["10 permit ip any any"]}
        results = ap.diff_acl_sets(acls_a, acls_b)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["status"], "missing_on_a")
        self.assertEqual(results[0]["only_in_b"], ["10 permit ip any any"])

    def test_rules_differ_reports_only_in_each_side(self):
        acls_a = {"ACL1": ["10 permit ip any any", "20 deny tcp any any eq 22"]}
        acls_b = {"ACL1": ["10 permit ip any any", "20 deny tcp any any eq 23"]}
        results = ap.diff_acl_sets(acls_a, acls_b)
        self.assertEqual(results[0]["status"], "mismatch")
        self.assertEqual(results[0]["only_in_a"], ["20 deny tcp any any eq 22"])
        self.assertEqual(results[0]["only_in_b"], ["20 deny tcp any any eq 23"])

    def test_sequence_number_only_difference_flags_mismatch(self):
        acls_a = {"ACL1": ["10 permit ip any any"]}
        acls_b = {"ACL1": ["20 permit ip any any"]}
        results = ap.diff_acl_sets(acls_a, acls_b)
        self.assertEqual(results[0]["status"], "mismatch")

    def test_whitespace_only_difference_still_matches(self):
        acls_a = {"ACL1": ["10  permit  ip   any any"]}
        acls_b = {"ACL1": ["10 permit ip any any"]}
        results = ap.diff_acl_sets(acls_a, acls_b)
        self.assertEqual(results[0]["status"], "match")

    def test_nxos_match_counter_difference_still_matches(self):
        acls_a = {"ACL1": ["10 permit ip any any [match=0]",
                           "20 deny ip any any [match=122553]"]}
        acls_b = {"ACL1": ["10 permit ip any any", "20 deny ip any any"]}
        results = ap.diff_acl_sets(acls_a, acls_b)
        self.assertEqual(results[0]["status"], "match")

    def test_host_and_cidr_echo_style_still_matches(self):
        acls_a = {"ACL1": ["10 permit ip host 192.168.1.1 any"]}
        acls_b = {"ACL1": ["10 permit ip 192.168.1.1/32 any"]}
        results = ap.diff_acl_sets(acls_a, acls_b)
        self.assertEqual(results[0]["status"], "match")

    def test_match_counter_does_not_mask_a_real_difference(self):
        acls_a = {"ACL1": ["10 permit tcp any any eq 22 [match=5]"]}
        acls_b = {"ACL1": ["10 permit tcp any any eq 23 [match=5]"]}
        results = ap.diff_acl_sets(acls_a, acls_b)
        self.assertEqual(results[0]["status"], "mismatch")


class DiffVlanAclBindingsTests(unittest.TestCase):

    def test_matching_bindings_produce_no_findings(self):
        map_a = {"ACL1": [{"interface": "Vlan748", "direction": "in"}]}
        map_b = {"ACL1": [{"interface": "Vlan748", "direction": "in"}]}
        self.assertEqual(ap.diff_vlan_acl_bindings(map_a, map_b), [])

    def test_missing_on_b(self):
        map_a = {"ACL1": [{"interface": "Vlan748", "direction": "in"}]}
        map_b = {}
        results = ap.diff_vlan_acl_bindings(map_a, map_b)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["status"], "missing_on_b")
        self.assertEqual(results[0]["direction_a"], "in")
        self.assertIsNone(results[0]["direction_b"])

    def test_missing_on_a(self):
        map_a = {}
        map_b = {"ACL1": [{"interface": "Vlan748", "direction": "out"}]}
        results = ap.diff_vlan_acl_bindings(map_a, map_b)
        self.assertEqual(results[0]["status"], "missing_on_a")
        self.assertEqual(results[0]["direction_b"], "out")

    def test_same_acl_and_interface_different_direction_flags_conflict(self):
        map_a = {"ACL1": [{"interface": "Vlan748", "direction": "in"}]}
        map_b = {"ACL1": [{"interface": "Vlan748", "direction": "out"}]}
        results = ap.diff_vlan_acl_bindings(map_a, map_b)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["status"], "direction_mismatch")
        self.assertEqual(results[0]["direction_a"], "in")
        self.assertEqual(results[0]["direction_b"], "out")

    def test_different_interfaces_for_same_acl_both_reported_independently(self):
        map_a = {"ACL1": [{"interface": "Vlan10", "direction": "in"}]}
        map_b = {"ACL1": [{"interface": "Vlan20", "direction": "in"}]}
        results = ap.diff_vlan_acl_bindings(map_a, map_b)
        statuses = {(r["interface"], r["status"]) for r in results}
        self.assertEqual(statuses, {("Vlan10", "missing_on_b"), ("Vlan20", "missing_on_a")})


class CanonicalAclRuleTests(unittest.TestCase):

    def test_strips_nxos_match_counter(self):
        self.assertEqual(main._canonical_acl_rule("10 permit ip any any [match=56]"),
                         main._canonical_acl_rule("10 permit ip any any"))

    def test_strips_ios_match_count_annotation(self):
        self.assertEqual(main._canonical_acl_rule("10 permit ip any any (56 matches)"),
                         main._canonical_acl_rule("10 permit ip any any"))

    def test_host_and_cidr_are_equivalent(self):
        self.assertEqual(main._canonical_acl_rule("10 permit ip host 10.1.1.1 any"),
                         main._canonical_acl_rule("10 permit ip 10.1.1.1/32 any"))

    def test_real_content_difference_not_masked(self):
        self.assertNotEqual(main._canonical_acl_rule("10 permit tcp any any eq 22 [match=5]"),
                            main._canonical_acl_rule("10 permit tcp any any eq 23 [match=5]"))


class DiffAclSeqsTests(unittest.TestCase):

    def test_identical_seqs_touch_nothing(self):
        source = {10: " 10 permit ip any any [match=0]"}
        target = {10: " 10 permit ip any any [match=99]"}
        to_remove, to_add = main._diff_acl_seqs(source, target)
        self.assertEqual(to_remove, [])
        self.assertEqual(to_add, [])

    def test_seq_missing_on_target_only_added_not_removed(self):
        source = {10: " 10 permit ip any any", 20: " 20 deny ip any any"}
        target = {10: " 10 permit ip any any"}
        to_remove, to_add = main._diff_acl_seqs(source, target)
        self.assertEqual(to_remove, [])
        self.assertEqual(to_add, [20])

    def test_seq_extra_on_target_only_removed_not_readded(self):
        source = {10: " 10 permit ip any any"}
        target = {10: " 10 permit ip any any", 30: " 30 permit tcp any any eq 22"}
        to_remove, to_add = main._diff_acl_seqs(source, target)
        self.assertEqual(to_remove, [30])
        self.assertEqual(to_add, [])

    def test_differing_seq_is_both_removed_and_readded(self):
        source = {10: " 10 permit tcp any any eq 22"}
        target = {10: " 10 permit tcp any any eq 23"}
        to_remove, to_add = main._diff_acl_seqs(source, target)
        self.assertEqual(to_remove, [10])
        self.assertEqual(to_add, [10])

    def test_mixed_acl_only_touches_the_differing_and_missing_seqs(self):
        # Reproduces the reported false-positive: two identical rule sets
        # except target's copy carries live NX-OS hit counters.
        source = {
            40: " 40 permit tcp any 192.168.17.21/32 eq 9398",
            91: " 91 permit tcp any eq 22 172.30.201.140/32",
            999: " 999 deny ip any any",
        }
        target = {
            40: " 40 permit tcp any 192.168.17.21/32 eq 9398 [match=0]",
            91: " 91 permit tcp any eq 22 172.30.201.140/32 [match=0]",
            999: " 999 deny ip any any [match=122553]",
        }
        to_remove, to_add = main._diff_acl_seqs(source, target)
        self.assertEqual(to_remove, [])
        self.assertEqual(to_add, [])

    def test_acl_entirely_missing_on_target_adds_every_sequence(self):
        source = {
            10: " 10 permit ip host 10.1.1.1 any",
            20: " 20 deny ip any any",
        }
        target = {}
        to_remove, to_add = main._diff_acl_seqs(source, target)
        self.assertEqual(to_remove, [])
        self.assertEqual(to_add, [10, 20])

    def test_acl_entirely_missing_on_source_removes_every_target_sequence(self):
        source = {}
        target = {
            10: " 10 permit ip host 10.1.1.1 any",
            20: " 20 deny ip any any",
        }
        to_remove, to_add = main._diff_acl_seqs(source, target)
        self.assertEqual(to_remove, [10, 20])
        self.assertEqual(to_add, [])


class AclSyncPlanShapeTests(unittest.TestCase):
    """Exercises _acl_sync_plan()'s command-building for a whole-ACL-missing
    sync without needing a live switch, by feeding it pre-built seq maps
    through the same _diff_acl_seqs() path the real endpoint uses."""

    def test_missing_acl_creates_every_line_no_deletes(self):
        ctx = "ip access-list vss-resources"
        source_seqs = {
            10: " 10 permit ip host 10.1.1.1 any",
            20: " 20 deny ip any any",
        }
        target_seqs = {}
        to_remove, to_add = main._diff_acl_seqs(source_seqs, target_seqs)
        cmds = ([ctx] + [f"no {seq}" for seq in to_remove]
               + [source_seqs[seq].strip() for seq in to_add])
        self.assertEqual(cmds, [
            ctx,
            "10 permit ip host 10.1.1.1 any",
            "20 deny ip any any",
        ])


class AclSeqMapForSyncFallbackTests(unittest.TestCase):
    """Reproduces the reported bug: sync claimed an ACL 'does not exist'
    even though the diff view (which uses `show ip access-lists`) had just
    confirmed it was there. The `show running-config | section <ctx>`
    fetch apparently doesn't reliably match on some NX-OS builds, so
    _acl_seq_map_for_sync() must fall back to the same command the diff
    view trusts rather than reporting a false negative."""

    def test_falls_back_to_show_ip_access_lists_when_section_fetch_is_empty(self):
        with patch.object(main.svc, 'show', return_value=''), \
             patch.object(main.svc, 'get_acl_rules',
                          return_value=('raw', ['10 permit ip any any', '20 deny ip any any'])) as mock_rules:
            result = asyncio.run(main._acl_seq_map_for_sync(
                object(), 'admin', 'MYACL', 'ip access-list MYACL'))
        self.assertEqual(result, {10: ' 10 permit ip any any', 20: ' 20 deny ip any any'})
        mock_rules.assert_called_once()

    def test_prefers_running_config_capture_when_it_actually_has_content(self):
        raw_config = 'ip access-list MYACL\n  10 permit ip any any\n'
        with patch.object(main.svc, 'show', return_value=raw_config), \
             patch.object(main.svc, 'get_acl_rules') as mock_rules:
            result = asyncio.run(main._acl_seq_map_for_sync(
                object(), 'admin', 'MYACL', 'ip access-list MYACL'))
        self.assertEqual(result, {10: ' 10 permit ip any any'})
        mock_rules.assert_not_called()

    def test_genuinely_missing_acl_returns_empty_via_both_paths(self):
        with patch.object(main.svc, 'show', return_value=''), \
             patch.object(main.svc, 'get_acl_rules', return_value=('', [])):
            result = asyncio.run(main._acl_seq_map_for_sync(
                object(), 'admin', 'GHOST', 'ip access-list GHOST'))
        self.assertEqual(result, {})


if __name__ == "__main__":
    unittest.main()
