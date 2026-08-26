import unittest

import main


def group(name, kind, members):
    return {"name": name, "kind": kind, "members": members}


class ExpandNestedGroupMembersTests(unittest.TestCase):

    def test_flat_group_returns_its_own_members_unchanged(self):
        groups = {"a": group("A", "address", ["host 10.1.1.1", "10.2.0.0/24"])}
        self.assertEqual(main._expand_nested_group_members("A", groups),
                         ["host 10.1.1.1", "10.2.0.0/24"])

    def test_nested_group_object_reference_is_inlined(self):
        groups = {
            "big":   group("BIG", "address", ["group-object SMALL", "host 10.9.9.9"]),
            "small": group("SMALL", "address", ["host 10.1.1.1", "host 10.1.1.2"]),
        }
        self.assertEqual(
            main._expand_nested_group_members("BIG", groups),
            ["host 10.1.1.1", "host 10.1.1.2", "host 10.9.9.9"])

    def test_nxos_sequence_numbered_group_object_line_is_recognized(self):
        # The seq-numbered reference line itself is recognized and expanded;
        # a seq-numbered *non*-reference line is passed through verbatim —
        # stripping that prefix is parse_object_group_addresses()'s job,
        # exercised separately below.
        groups = {
            "big":   group("BIG", "address", ["10 group-object SMALL", "20 host 10.9.9.9"]),
            "small": group("SMALL", "address", ["host 10.1.1.1"]),
        }
        self.assertEqual(main._expand_nested_group_members("BIG", groups),
                         ["host 10.1.1.1", "20 host 10.9.9.9"])

    def test_transitively_nested_groups_are_fully_expanded(self):
        groups = {
            "big":    group("BIG", "address", ["group-object MID"]),
            "mid":    group("MID", "address", ["group-object SMALL", "host 10.5.5.5"]),
            "small":  group("SMALL", "address", ["host 10.1.1.1"]),
        }
        self.assertEqual(main._expand_nested_group_members("BIG", groups),
                         ["host 10.1.1.1", "host 10.5.5.5"])

    def test_reference_cycle_does_not_infinite_loop(self):
        groups = {
            "a": group("A", "address", ["group-object B"]),
            "b": group("B", "address", ["group-object A", "host 10.1.1.1"]),
        }
        # Must terminate and simply drop the cyclic reference once revisited.
        self.assertEqual(main._expand_nested_group_members("A", groups), ["host 10.1.1.1"])

    def test_reference_to_unknown_group_is_dropped_not_crashed(self):
        groups = {"a": group("A", "address", ["group-object GHOST", "host 10.1.1.1"])}
        self.assertEqual(main._expand_nested_group_members("A", groups), ["host 10.1.1.1"])

    def test_port_group_nesting_also_supported(self):
        groups = {
            "big":   group("BIG", "port", ["group-object SMALL", "eq 443"]),
            "small": group("SMALL", "port", ["eq 80"]),
        }
        self.assertEqual(main._expand_nested_group_members("BIG", groups), ["eq 80", "eq 443"])


class ObjectGroupMembersNestedResolutionTests(unittest.TestCase):
    """End-to-end through parse_object_group_addresses/services, matching
    how _object_group_members() actually feeds the redundancy checker."""

    def test_nested_address_group_resolves_to_real_ip_ranges(self):
        import acl_parser as ap
        groups_by_name = {
            "big":   group("BIG", "address", ["group-object SMALL", "host 10.9.9.9"]),
            "small": group("SMALL", "address", ["10.1.1.0/24"]),
        }
        expanded = main._expand_nested_group_members("BIG", groups_by_name)
        addrs = ap.parse_object_group_addresses("\n".join(expanded))
        self.assertIn("10.1.1.0/24", addrs)
        self.assertIn("10.9.9.9/32", addrs)


class NestedGroupRedundancyEndToEndTests(unittest.TestCase):
    """Reproduces the actual scenario a user hits: a rule covered only
    through a nested object-group reference. Confirms the fix is load-
    bearing end-to-end through check_redundant_rules()/
    find_trailing_redundant_rules(), not just through the resolver helper
    in isolation."""

    def _resolved_and_unresolved_address_groups(self):
        import acl_parser as ap
        groups_list = [
            {"name": "BIG_HOSTS", "kind": "address",
             "members": ["group-object SMALL_HOSTS", "host 10.9.9.9"]},
            {"name": "SMALL_HOSTS", "kind": "address", "members": ["10.1.1.0/24"]},
        ]
        group_types = {g["name"]: g["kind"] for g in groups_list}
        groups_by_name = {g["name"].lower(): g for g in groups_list}
        resolved = {
            g["name"]: ap.parse_object_group_addresses(
                "\n".join(main._expand_nested_group_members(g["name"], groups_by_name)))
            for g in groups_list
        }
        unresolved = {
            g["name"]: ap.parse_object_group_addresses("\n".join(g["members"]))
            for g in groups_list
        }
        return group_types, resolved, unresolved

    def test_earlier_broad_nested_group_rule_covers_later_narrow_rule(self):
        import acl_parser as ap
        group_types, resolved, unresolved = self._resolved_and_unresolved_address_groups()
        rules = [
            "10 permit ip addrgroup BIG_HOSTS any",
            "20 permit ip host 10.1.1.5 any",
        ]
        with_fix = ap.check_redundant_rules(rules, "nexus", group_types, "extended", resolved, {})
        self.assertEqual(len(with_fix), 1)
        self.assertEqual(with_fix[0]["covered_by_sequence"], 10)
        self.assertEqual(with_fix[0]["redundant_rules"][0]["sequence"], 20)

        without_fix = ap.check_redundant_rules(rules, "nexus", group_types, "extended", unresolved, {})
        self.assertEqual(without_fix, [],
                         "without nested expansion this coverage must be missed entirely, "
                         "proving the fix actually matters")

    def test_later_broad_nested_group_rule_covers_earlier_narrow_rule(self):
        import acl_parser as ap
        group_types, resolved, unresolved = self._resolved_and_unresolved_address_groups()
        rules = [
            "10 permit ip host 10.1.1.5 any",
            "20 permit ip addrgroup BIG_HOSTS any",
        ]
        with_fix = ap.find_trailing_redundant_rules(rules, "nexus", group_types, "extended", resolved, {})
        self.assertEqual(len(with_fix), 1)
        self.assertEqual(with_fix[0]["covered_by_sequence"], 20)
        self.assertEqual(with_fix[0]["redundant_rules"][0]["sequence"], 10)

        without_fix = ap.find_trailing_redundant_rules(rules, "nexus", group_types, "extended", unresolved, {})
        self.assertEqual(without_fix, [],
                         "without nested expansion this coverage must be missed entirely, "
                         "proving the fix actually matters")


if __name__ == "__main__":
    unittest.main()
