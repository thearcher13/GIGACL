import re
import unittest

import acl_report


def _report(rules, switch_type="ios", acl_kind="extended",
            groups=None, time_ranges=None):
    """Build a report the way the endpoint does, with group expansion."""
    groups = groups or []
    by_name = {g["name"].lower(): g for g in groups}

    def expand(name, seen=None):
        seen = (seen or set()) | {name.lower()}
        g = by_name.get(name.lower())
        out = []
        for m in (g or {}).get("members", []):
            nested = re.match(r"^\s*(?:\d+\s+)?group-object\s+(\S+)\s*$", m, re.I)
            if nested:
                if nested.group(1).lower() not in seen:
                    out.extend(expand(nested.group(1), seen))
            else:
                out.append(m)
        return out

    expanded = {g["name"]: expand(g["name"]) for g in groups}
    return acl_report.build_acl_report(
        acl_name="TEST", switch_label="sw1", switch_type=switch_type,
        acl_kind=acl_kind, rule_lines=rules, groups_list=groups,
        expanded_members=expanded, time_ranges=time_ranges or [])


class EveryRuleIsReportedTests(unittest.TestCase):

    def test_all_rules_land_in_allowed_or_blocked(self):
        rep = _report([
            "10 permit tcp any host 10.0.1.5 eq 443",
            "20 deny tcp host 10.0.0.50 host 10.0.1.5 eq 443",
            "30 permit ip any any",
        ])
        self.assertEqual(rep["summary"]["total"], 3)
        self.assertEqual(len(rep["allowed"]) + len(rep["blocked"]), 3)

    def test_report_has_no_ineffective_section(self):
        rep = _report(["10 permit ip any any", "20 permit ip any any"])
        self.assertNotIn("ineffective", rep)
        self.assertNotIn("ineffective", rep["summary"])


class DefaultActionTests(unittest.TestCase):

    def test_implicit_deny_is_stated_when_there_is_no_catch_all(self):
        rep = _report(["10 permit tcp any host 10.0.1.5 eq 443"])
        self.assertIn("BLOCKED", rep["default_action"])
        self.assertIn("invisible", rep["default_action"])

    def test_explicit_deny_catch_all_is_recognised(self):
        rep = _report([
            "10 permit tcp any host 10.0.1.5 eq 443",
            "999 deny ip any any",
        ])
        self.assertIn("BLOCKED", rep["default_action"])
        self.assertIn("catch-all", rep["default_action"])

    def test_explicit_permit_catch_all_is_reported_as_allowing_everything(self):
        rep = _report([
            "10 deny tcp any host 10.0.1.5 eq 22",
            "999 permit ip any any",
        ])
        self.assertIn("ALLOWED", rep["default_action"])


class GroupExpansionTests(unittest.TestCase):

    GROUPS = [
        {"name": "PCS", "kind": "address",
         "members": ["host 10.0.0.11", "host 10.0.0.12", "group-object ADMIN"]},
        {"name": "ADMIN", "kind": "address", "members": ["host 10.0.0.99"]},
    ]

    def test_group_size_is_used_in_the_prose(self):
        rep = _report(["10 permit tcp object-group PCS any eq 443"], groups=self.GROUPS)
        self.assertIn("PCS", rep["allowed"][0]["text"])
        self.assertIn("group", rep["allowed"][0]["text"])

    def test_referenced_groups_appear_in_the_appendix(self):
        rep = _report(["10 permit tcp object-group PCS any eq 443"], groups=self.GROUPS)
        names = {g["name"] for g in rep["groups"]}
        self.assertIn("PCS", names)

    def test_appendix_reports_member_counts(self):
        rep = _report(["10 permit tcp object-group PCS any eq 443"], groups=self.GROUPS)
        pcs = next(g for g in rep["groups"] if g["name"] == "PCS")
        self.assertEqual(pcs["count"], len(pcs["members"]))


class UnparsedLineTests(unittest.TestCase):

    def test_untranslatable_line_is_surfaced_not_dropped(self):
        # A report claiming to cover every access must not quietly omit a
        # line it failed to understand.
        rep = _report([
            "10 permit tcp any host 10.0.1.5 eq 443",
            "20 permit somethingweird not-a-rule at all",
        ])
        self.assertEqual(len(rep["unparsed"]), 1)
        self.assertIn("somethingweird", rep["unparsed"][0])

    def test_remarks_are_skipped_without_being_flagged_as_unparsed(self):
        rep = _report([
            "10 remark this is a comment",
            "20 permit tcp any host 10.0.1.5 eq 443",
        ])
        self.assertEqual(rep["unparsed"], [])
        self.assertEqual(rep["summary"]["total"], 1)


class WordingTests(unittest.TestCase):
    """Phrasing the report's audience asked for."""

    def test_plain_ip_is_used_without_the_device_at(self):
        rep = _report(["10 permit ip host 192.168.10.97 host 192.168.254.137"])
        self.assertEqual(
            rep["allowed"][0]["text"],
            "192.168.10.97 can reach 192.168.254.137 using any type of traffic.")

    def test_can_reach_not_may_reach(self):
        rep = _report(["10 permit ip host 10.0.0.1 host 10.0.0.2"])
        self.assertIn("can reach", rep["allowed"][0]["text"])
        self.assertNotIn("may reach", rep["allowed"][0]["text"])

    def test_group_reference_omits_the_member_count(self):
        groups = [{"name": "Mon_Servers_IP", "kind": "address",
                   "members": ["host 10.0.0.1", "host 10.0.0.2",
                               "host 10.0.0.3", "host 10.0.0.4"]}]
        rep = _report(["10 permit ip object-group Mon_Servers_IP any"], groups=groups)
        text = rep["allowed"][0]["text"]
        self.assertIn('of the addresses in group "Mon_Servers_IP"', text)
        self.assertNotIn("4 addresses", text)

    def test_port_group_is_called_ports_not_services(self):
        groups = [{"name": "Mon_Server_Port", "kind": "port", "members": ["tcp eq 9273"]}]
        rep = _report(["10 permit object-group Mon_Server_Port any any"], groups=groups)
        text = rep["allowed"][0]["text"]
        self.assertIn('the ports in group "Mon_Server_Port"', text)
        self.assertNotIn("service", text.lower())

    def test_rule_lists_the_groups_it_references_for_linking(self):
        groups = [{"name": "SRC", "kind": "address", "members": ["host 10.0.0.1"]},
                  {"name": "DST", "kind": "address", "members": ["host 10.0.1.1"]}]
        rep = _report(["10 permit ip object-group SRC object-group DST"], groups=groups)
        self.assertEqual(rep["allowed"][0]["groups"], ["SRC", "DST"])

    def test_rule_lists_the_schedule_it_references_for_linking(self):
        ranges = [{"name": "WORKHOURS", "status": "active",
                   "entries": ["periodic weekdays 8:00 to 17:00"]}]
        rep = _report(["10 permit ip any any time-range WORKHOURS"], time_ranges=ranges)
        self.assertEqual(rep["allowed"][0]["schedules"], ["WORKHOURS"])

    def test_source_port_group_is_named_for_linking_from_a_detail(self):
        # The group is mentioned in a detail line, not the headline sentence.
        groups = [{"name": "Net_Server_Port", "kind": "port", "members": ["tcp eq 9273"]}]
        rep = _report(["10 permit tcp any portgroup Net_Server_Port any"],
                      switch_type="nexus", groups=groups)
        item = rep["allowed"][0]
        self.assertIn("Net_Server_Port", " ".join(item["details"]))
        self.assertIn("Net_Server_Port", item["groups"])


class DenyWordingTests(unittest.TestCase):
    """A deny only stops what no earlier rule already permitted, so once
    there are rules above it the report has to say so -- otherwise the
    block reads as absolute."""

    def test_deny_below_other_rules_notes_the_earlier_allow_caveat(self):
        rep = _report([
            "10 permit ip host 10.0.0.1 any",
            "998 deny ip object-group Part_IPs any",
        ], groups=[{"name": "Part_IPs", "kind": "address", "members": ["host 10.0.0.1"]}])
        self.assertIn("unless an earlier rule already allowed it",
                      rep["blocked"][0]["text"])

    def test_first_rule_deny_has_no_caveat(self):
        # Nothing precedes it, so the qualifier would be noise.
        rep = _report(["10 deny ip any any"])
        self.assertNotIn("unless an earlier rule", rep["blocked"][0]["text"])

    def test_permit_never_gets_the_caveat(self):
        rep = _report(["10 deny ip host 10.0.0.9 any", "20 permit ip any any"])
        self.assertNotIn("unless an earlier rule", rep["allowed"][0]["text"])


class ScopeNoteTests(unittest.TestCase):

    def test_report_warns_it_covers_only_this_access_list(self):
        rep = _report(["10 permit ip any any"])
        self.assertIn("only this one access list", rep["scope_note"])
        self.assertIn("further along", rep["scope_note"])

    def test_scope_note_appears_in_the_markdown_render(self):
        rep = _report(["10 permit ip any any"])
        self.assertIn("only this one access list", acl_report.render_markdown(rep))

    def test_scope_note_appears_in_the_html_render(self):
        rep = _report(["10 permit ip any any"])
        self.assertIn("only this one access list", acl_report.render_html(rep))


class GroupMemberWordingTests(unittest.TestCase):

    def test_host_member_becomes_a_bare_ip(self):
        self.assertEqual(acl_report.describe_group_member("host 10.0.0.5", "address"),
                         "10.0.0.5")

    def test_range_member_is_spelled_out(self):
        self.assertEqual(
            acl_report.describe_group_member("range 172.30.48.150 172.30.48.152", "address"),
            "172.30.48.150 to 172.30.48.152")

    def test_netmask_member_becomes_cidr(self):
        self.assertEqual(
            acl_report.describe_group_member("172.30.51.80 255.255.255.240", "address"),
            "172.30.51.80/28")

    def test_service_member_reads_as_a_port(self):
        self.assertEqual(acl_report.describe_group_member("tcp eq 443", "port"),
                         "secure web traffic (HTTPS) on TCP port 443")

    def test_named_port_member_is_resolved_to_a_number(self):
        # Config commonly writes "tcp eq www"; the reader should see the port.
        self.assertEqual(acl_report.describe_group_member("tcp eq www", "port"),
                         "web traffic (HTTP) on TCP port 80")

    def test_unknown_named_port_member_keeps_the_original_token(self):
        self.assertEqual(acl_report.describe_group_member("tcp eq zzz", "port"),
                         "TCP port zzz")

    def test_tcp_udp_source_port_member(self):
        self.assertEqual(
            acl_report.describe_group_member("tcp-udp source eq 13000", "port"),
            "TCP/UDP source port 13000")

    def test_port_range_member(self):
        self.assertEqual(
            acl_report.describe_group_member("tcp range 49152 65535", "port"),
            "TCP ports 49152 to 65535")

    def test_bare_protocol_member(self):
        self.assertEqual(acl_report.describe_group_member("tcp", "port"), "all TCP")


class PhrasingTests(unittest.TestCase):

    def test_established_is_explained_in_plain_words(self):
        rep = _report(["10 permit tcp host 10.0.1.5 eq 443 any established"])
        details = " ".join(rep["allowed"][0]["details"])
        self.assertIn("already opened", details)
        self.assertIn("cannot", details)

    def test_named_service_is_used_for_a_well_known_port(self):
        rep = _report(["10 permit tcp any host 10.0.1.5 eq 443"])
        self.assertIn("HTTPS", rep["allowed"][0]["text"])

    def test_wildcard_is_expressed_as_a_subnet_and_range(self):
        rep = _report(["10 permit ip 10.0.0.0 0.0.0.255 any"])
        text = rep["allowed"][0]["text"]
        self.assertIn("10.0.0.0/24", text)
        self.assertIn("10.0.0.255", text)

    def test_standard_acl_does_not_invent_a_destination(self):
        rep = _report(["10 permit 10.0.0.0 0.0.0.255"], acl_kind="standard")
        text = rep["allowed"][0]["text"]
        self.assertNotIn("may reach", text)
        self.assertIn("allowed", text)

    def test_nxos_addrgroup_rule_is_described(self):
        groups = [{"name": "SRV", "kind": "address", "members": ["host 10.0.1.5"]}]
        rep = _report(["10 permit tcp addrgroup SRV any eq 443"],
                      switch_type="nexus", groups=groups)
        self.assertEqual(rep["summary"]["allowed"], 1)
        self.assertIn("SRV", rep["allowed"][0]["text"])

    def test_deny_rule_uses_blocking_language(self):
        rep = _report(["10 deny tcp any host 10.0.1.5 eq 22"])
        self.assertIn("blocked", rep["blocked"][0]["text"])


class TimeRangeDescriptionTests(unittest.TestCase):

    def test_weekday_periodic_entry_is_translated(self):
        self.assertEqual(
            acl_report.describe_time_range_entry("periodic weekdays 8:00 to 17:00"),
            "Monday to Friday, 8:00 to 17:00")

    def test_daily_entry_is_translated(self):
        self.assertEqual(
            acl_report.describe_time_range_entry("periodic daily 0:00 to 23:59"),
            "every day, 0:00 to 23:59")

    def test_sequence_numbered_entry_is_handled(self):
        self.assertEqual(
            acl_report.describe_time_range_entry("10 periodic daily 8:00 to 17:00"),
            "every day, 8:00 to 17:00")

    def test_unrecognised_entry_falls_back_to_the_original_text(self):
        self.assertEqual(
            acl_report.describe_time_range_entry("something unexpected"),
            "something unexpected")

    def test_only_schedules_actually_referenced_are_included(self):
        ranges = [{"name": "USED", "status": "active", "entries": ["periodic daily 8:00 to 9:00"]},
                  {"name": "UNUSED", "status": "inactive", "entries": []}]
        rep = _report(["10 permit ip any any time-range USED"], time_ranges=ranges)
        self.assertEqual([t["name"] for t in rep["time_ranges"]], ["USED"])


class RenderingTests(unittest.TestCase):

    def test_markdown_states_the_default_action(self):
        rep = _report(["10 permit tcp any host 10.0.1.5 eq 443"])
        self.assertIn("BLOCKED", acl_report.render_markdown(rep))

    def test_markdown_group_links_all_resolve_to_a_heading(self):
        groups = [{"name": "Net_Servers_IP", "kind": "address",
                   "members": ["host 10.0.0.1"]}]
        ranges = [{"name": "WORKHOURS", "status": "active",
                   "entries": ["periodic daily 8:00 to 17:00"]}]
        rep = _report(["10 permit ip object-group Net_Servers_IP any time-range WORKHOURS"],
                      groups=groups, time_ranges=ranges)
        md = acl_report.render_markdown(rep)
        targets = set(re.findall(r"\]\(#([^)]+)\)", md))
        # Slugify headings the way a Markdown renderer does: a backslash
        # escape renders as the bare character.
        headings = {re.sub(r"[^a-z0-9_-]+", "-", h.replace("\\", "").lower()).strip("-")
                    for h in re.findall(r"^### (.+)$", md, re.M)}
        self.assertTrue(targets, "expected at least one link")
        self.assertEqual(targets - headings, set())

    def test_markdown_escapes_underscores_in_prose(self):
        groups = [{"name": "A_B", "kind": "address", "members": ["host 10.0.0.1"]}]
        rep = _report(["10 permit ip object-group A_B any"], groups=groups)
        self.assertIn(r"A\_B", acl_report.render_markdown(rep))

    def test_html_escapes_acl_and_group_names(self):
        groups = [{"name": "<img src=x>", "kind": "address", "members": ["host 10.0.0.1"]}]
        rep = _report(["10 permit tcp object-group <img src=x> any eq 443"], groups=groups)
        html = acl_report.render_html(rep)
        self.assertNotIn("<img src=x>", html)

    def test_html_is_a_complete_document(self):
        rep = _report(["10 permit tcp any host 10.0.1.5 eq 443"])
        html = acl_report.render_html(rep)
        self.assertTrue(html.startswith("<!doctype html>"))
        self.assertIn("</html>", html)


if __name__ == "__main__":
    unittest.main()
