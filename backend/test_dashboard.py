import unittest
from datetime import datetime

import acl_parser
import health_collector as hc
import tcam_parser as tp


NXOS_TCAM = """
INSTANCE 0x0
-------------

              ACL Hardware Resource Utilization (Mod 1)
              --------------------------------------------

                                        Used    Free    Percent
                                                        Utilization
-----------------------------------------------------------------------
Ingress RACL                            1381    411     77.06
Egress RACL                             1471    321     82.08
Ingress PACL                            0       0       0.00
"""

IOS_TCAM = """
Resource                Type       Dir      Max      Used   %Used      V4       V6     MPLS   Other
--------------------------------------------------------------------------------------------------
Security ACL           TCAM         IO       5120      852   16.64%      747       60        0       45
                       TCAM         I                   88    1.72%       12       36        0       40
                       TCAM         O                  764   14.92%      735       24        0        5
"""

# A second block whose continuation rows must not be mistaken for the
# Security ACL ones.
IOS_TCAM_WITH_LATER_BLOCK = IOS_TCAM + """
Netflow ACL            TCAM         IO       1024      100    9.76%      100        0        0        0
                       TCAM         I                  900   87.89%      900        0        0        0
                       TCAM         O                  900   87.89%      900        0        0        0
"""

INVALID = "% Invalid input detected at '^' marker."


class NxosTcamTests(unittest.TestCase):

    def test_reads_used_free_and_percent_for_both_directions(self):
        r = tp.parse_nxos_tcam_utilization(NXOS_TCAM)
        self.assertEqual(r["status"], tp.STATUS_OK)
        self.assertEqual((r["ingress"]["used"], r["ingress"]["free"],
                          r["ingress"]["percent"]), (1381, 411, 77.06))
        self.assertEqual((r["egress"]["used"], r["egress"]["free"],
                          r["egress"]["percent"]), (1471, 321, 82.08))

    def test_max_is_derived_because_the_platform_reports_free(self):
        r = tp.parse_nxos_tcam_utilization(NXOS_TCAM)
        self.assertEqual(r["ingress"]["max"], 1792)

    def test_worst_module_wins_on_a_multi_module_chassis(self):
        two_modules = NXOS_TCAM + """
              ACL Hardware Resource Utilization (Mod 2)
Ingress RACL                            1700    92      94.87
Egress RACL                             100     1692    5.58
"""
        r = tp.parse_nxos_tcam_utilization(two_modules)
        self.assertEqual(r["ingress"]["percent"], 94.87)
        # The worse egress reading is still module 1's.
        self.assertEqual(r["egress"]["percent"], 82.08)

    def test_pipe_delimited_variant_is_read(self):
        boxed = "| Ingress RACL | 10 | 90 | 10.00 |"
        r = tp.parse_nxos_tcam_utilization(boxed)
        self.assertEqual(r["status"], tp.STATUS_OK)
        self.assertEqual(r["ingress"]["used"], 10)

    def test_rejected_command_is_unsupported_not_an_error(self):
        self.assertEqual(tp.parse_nxos_tcam_utilization(INVALID)["status"],
                         tp.STATUS_UNSUPPORTED)

    def test_blank_output_is_unsupported(self):
        for blank in ("", "   \n\n  "):
            self.assertEqual(tp.parse_nxos_tcam_utilization(blank)["status"],
                             tp.STATUS_UNSUPPORTED)

    def test_ios_output_fed_to_the_nxos_parser_is_unsupported(self):
        self.assertEqual(tp.parse_nxos_tcam_utilization(IOS_TCAM)["status"],
                         tp.STATUS_UNSUPPORTED)


class IosTcamTests(unittest.TestCase):

    def test_ingress_and_egress_come_from_the_continuation_rows(self):
        r = tp.parse_ios_tcam_utilization(IOS_TCAM)
        self.assertEqual(r["status"], tp.STATUS_OK)
        self.assertEqual((r["ingress"]["used"], r["ingress"]["percent"]),
                         (88, 1.72))
        self.assertEqual((r["egress"]["used"], r["egress"]["percent"]),
                         (764, 14.92))

    def test_max_comes_from_the_io_row_and_free_is_derived(self):
        r = tp.parse_ios_tcam_utilization(IOS_TCAM)
        self.assertEqual(r["ingress"]["max"], 5120)
        self.assertEqual(r["ingress"]["free"], 5120 - 88)
        self.assertEqual(r["egress"]["free"], 5120 - 764)

    def test_a_later_resource_block_is_not_mistaken_for_security_acl(self):
        r = tp.parse_ios_tcam_utilization(IOS_TCAM_WITH_LATER_BLOCK)
        self.assertEqual(r["ingress"]["used"], 88)
        self.assertEqual(r["egress"]["used"], 764)

    def test_header_without_direction_rows_is_unsupported(self):
        header_only = ("Security ACL           TCAM         IO       "
                       "5120      852   16.64%      747       60        0       45")
        r = tp.parse_ios_tcam_utilization(header_only)
        self.assertEqual(r["status"], tp.STATUS_UNSUPPORTED)
        self.assertIsNone(r["ingress"]["used"])

    def test_rejected_command_and_blank_output_are_unsupported(self):
        for out in (INVALID, "", "   "):
            self.assertEqual(tp.parse_ios_tcam_utilization(out)["status"],
                             tp.STATUS_UNSUPPORTED)

    def test_nxos_output_fed_to_the_ios_parser_is_unsupported(self):
        self.assertEqual(tp.parse_ios_tcam_utilization(NXOS_TCAM)["status"],
                         tp.STATUS_UNSUPPORTED)


class TcamDispatchTests(unittest.TestCase):

    def test_dispatches_on_source(self):
        self.assertEqual(
            tp.parse_tcam_utilization(NXOS_TCAM, "nexus")["status"], tp.STATUS_OK)
        self.assertEqual(
            tp.parse_tcam_utilization(IOS_TCAM, "ios")["status"], tp.STATUS_OK)

    def test_every_result_carries_the_full_shape(self):
        for out, source in ((NXOS_TCAM, "nexus"), (INVALID, "ios"), ("", "nexus")):
            r = tp.parse_tcam_utilization(out, source)
            for side in ("ingress", "egress"):
                self.assertEqual(set(r[side]), {"used", "free", "max", "percent"})


class TimeRangeExpiryTests(unittest.TestCase):

    NOW = datetime(2026, 8, 22, 12, 0)

    def expired(self, *entries):
        return acl_parser.time_range_is_expired({"entries": list(entries)}, self.NOW)

    def test_absolute_end_in_the_past_is_expired(self):
        self.assertTrue(self.expired(
            "absolute start 00:00 1 January 2020 end 23:59 31 December 2024"))

    def test_nxos_sequence_numbered_entry_is_read(self):
        self.assertTrue(self.expired(
            "10 absolute start 00:00 1 January 2020 end 23:59 31 December 2024"))

    def test_nxos_writes_seconds_in_the_end_time(self):
        # Regression: NX-OS emits HH:MM:SS. A pattern accepting only HH:MM
        # matched nothing, so every NX-OS switch reported zero expired ranges
        # while actually holding a dozen or more.
        self.assertTrue(self.expired(
            "10 absolute start 07:00:00 16 December 2024 "
            "end 23:59:59 16 January 2025"))
        self.assertTrue(self.expired("10 absolute end 18:00:00 02 May 2026"))
        self.assertFalse(self.expired("10 absolute end 18:00:00 02 May 2027"))

    def test_seconds_are_kept_in_the_parsed_end(self):
        self.assertEqual(
            acl_parser.parse_absolute_end("absolute end 23:59:59 16 January 2025"),
            datetime(2025, 1, 16, 23, 59, 59))
        self.assertEqual(
            acl_parser.parse_absolute_end("absolute end 23:59 16 January 2025"),
            datetime(2025, 1, 16, 23, 59))

    def test_a_zero_padded_day_is_read(self):
        self.assertTrue(self.expired("10 absolute end 09:00:00 04 January 2026"))

    def test_absolute_end_in_the_future_is_not_expired(self):
        self.assertFalse(self.expired("absolute end 23:59 31 December 2027"))

    def test_periodic_is_never_expired_even_when_inactive_right_now(self):
        # The distinction the dashboard depends on: a weekday schedule is
        # inactive every night without being stale.
        self.assertFalse(self.expired("periodic weekdays 08:00 to 18:00"))

    def test_one_live_periodic_entry_keeps_the_range_alive(self):
        self.assertFalse(self.expired(
            "absolute end 23:59 31 December 2024",
            "periodic daily 0:00 to 23:59"))

    def test_absolute_without_an_end_never_expires(self):
        self.assertFalse(self.expired("absolute start 00:00 1 January 2020"))

    def test_a_range_with_no_entries_is_not_expired(self):
        self.assertFalse(self.expired())


class _FakeSwitch:
    def __init__(self, switch_type="nexus"):
        self.id = 7
        self.ip_address = "10.0.0.7"
        self.hostname = "core-07"
        self.switch_type = switch_type


class _FakeTarget:
    def __init__(self, switch_type="nexus"):
        self.sw = _FakeSwitch(switch_type)
        self.ssh_username = "amir"

    id = 7
    ip = "10.0.0.7"
    label = "core-07"

    @property
    def type(self):
        return self.sw.switch_type

    @property
    def is_nexus(self):
        return self.sw.switch_type == "nexus"


class _RecordingShow:
    """Stands in for svc.show, recording every command it is asked to run."""

    def __init__(self, replies=None):
        self.replies = replies or {}
        self.calls = []

    def __call__(self, t, username, command, timeout=25, enable_password=None):
        self.calls.append((command, timeout))
        reply = self.replies.get(command, "")
        if isinstance(reply, Exception):
            raise reply
        return reply

    @property
    def commands(self):
        return [c for c, _ in self.calls]


ACL_OUTPUT = """IP access list EDGE
        10 permit ip 10.1.1.0/24 any
        20 permit ip 10.1.1.0/25 any
        30 permit tcp 10.9.9.9/32 any eq 80 time-range OLDJOB
"""

TIME_RANGE_OUTPUT = """time-range entry: OLDJOB (inactive)
   10 absolute start 00:00 1 January 2020 end 23:59 31 December 2024
"""


def _replies(**overrides):
    base = {
        hc.SHOW_ACLS: ACL_OUTPUT,
        hc.SHOW_RUNNING: "",
        hc.SHOW_OBJECT_GROUPS: "",
        hc.SHOW_TIME_RANGES: TIME_RANGE_OUTPUT,
        tp.NXOS_COMMAND: NXOS_TCAM,
        tp.IOS_COMMAND: INVALID,
    }
    base.update(overrides)
    return base


class CollectorFetchBudgetTests(unittest.TestCase):
    """The whole point of the collector: fetch each thing once."""

    def setUp(self):
        self.show = _RecordingShow(_replies())
        self._original = hc.svc.show
        hc.svc.show = self.show

    def tearDown(self):
        hc.svc.show = self._original

    def test_a_healthy_switch_costs_exactly_five_commands(self):
        hc.collect_one(_FakeTarget(), "amir")
        self.assertEqual(len(self.show.calls), 5, self.show.commands)

    def test_every_command_is_distinct(self):
        hc.collect_one(_FakeTarget(), "amir")
        self.assertEqual(len(set(self.show.commands)), 5)

    def test_the_running_config_is_pulled_only_once(self):
        # The existing analysis endpoints pull it twice; that is the cost this
        # collector exists to remove, so it is worth asserting directly.
        hc.collect_one(_FakeTarget(), "amir")
        self.assertEqual(self.show.commands.count(hc.SHOW_RUNNING), 1)

    def test_each_command_carries_its_intended_timeout(self):
        hc.collect_one(_FakeTarget(), "amir")
        timeouts = dict(self.show.calls)
        self.assertEqual(timeouts[hc.SHOW_ACLS], hc.TIMEOUT_ACLS)
        self.assertEqual(timeouts[hc.SHOW_RUNNING], hc.TIMEOUT_RUNNING)
        self.assertEqual(timeouts[hc.SHOW_OBJECT_GROUPS], hc.TIMEOUT_OBJECT_GROUPS)
        self.assertEqual(timeouts[hc.SHOW_TIME_RANGES], hc.TIMEOUT_TIME_RANGES)


class CollectorResultTests(unittest.TestCase):

    def setUp(self):
        self._original = hc.svc.show

    def tearDown(self):
        hc.svc.show = self._original

    def collect(self, replies, switch_type="nexus"):
        hc.svc.show = _RecordingShow(replies)
        return hc.collect_one(_FakeTarget(switch_type), "amir",
                              now=datetime(2026, 8, 22, 12, 0))

    def test_counts_the_redundant_rule(self):
        row = self.collect(_replies())
        self.assertEqual(row["status"], hc.HEALTH_OK)
        self.assertEqual(row["acl_count"], 1)
        self.assertEqual(row["rule_count"], 3)
        self.assertEqual(row["redundant_count"], 1)

    def test_counts_the_expired_schedule_and_the_rule_pinned_to_it(self):
        row = self.collect(_replies())
        self.assertEqual(row["time_ranges_total"], 1)
        self.assertEqual(row["time_ranges_expired"], 1)
        self.assertEqual(row["rules_with_dead_schedule"], 1)

    def test_tcam_is_flattened_onto_the_snapshot_columns(self):
        row = self.collect(_replies())
        self.assertEqual(row["tcam_status"], hc.TCAM_OK)
        self.assertEqual(row["tcam_source"], "nexus")
        self.assertEqual(row["tcam_in_used"], 1381)
        self.assertEqual(row["tcam_out_pct"], 82.08)

    def test_a_later_failure_is_partial_and_keeps_the_earlier_counts(self):
        row = self.collect(_replies(
            **{hc.SHOW_TIME_RANGES: hc.ssh_manager.SSHError("timed out")}))
        self.assertEqual(row["status"], hc.HEALTH_PARTIAL)
        self.assertIn("time ranges", row["error"])
        self.assertEqual(row["redundant_count"], 1)

    def test_a_first_command_failure_short_circuits(self):
        show = _RecordingShow(_replies(
            **{hc.SHOW_ACLS: hc.ssh_manager.SSHError("unreachable")}))
        hc.svc.show = show
        row = hc.collect_one(_FakeTarget(), "amir")
        self.assertEqual(row["status"], hc.HEALTH_ERROR)
        self.assertEqual(len(show.calls), 1)
        # Zeros, but flagged — never presented as a clean bill of health.
        self.assertEqual(row["rule_count"], 0)

    def test_unsupported_tcam_does_not_fail_the_switch(self):
        row = self.collect(_replies(**{tp.NXOS_COMMAND: INVALID,
                                       tp.IOS_COMMAND: INVALID}))
        self.assertEqual(row["status"], hc.HEALTH_OK)
        self.assertEqual(row["tcam_status"], hc.TCAM_UNSUPPORTED)
        self.assertIsNone(row["tcam_source"])

    def test_a_mislabelled_switch_is_rescued_by_the_fallback_command(self):
        # Configured as nexus, actually IOS: the nxos command is rejected and
        # the ios one answers, so tcam_source disagrees with switch_type.
        row = self.collect(_replies(**{tp.NXOS_COMMAND: INVALID,
                                       tp.IOS_COMMAND: IOS_TCAM}))
        self.assertEqual(row["tcam_status"], hc.TCAM_OK)
        self.assertEqual(row["tcam_source"], "ios")
        self.assertNotEqual(row["tcam_source"], row["switch_type"])

    def test_the_acl_map_is_handed_back_for_vpc_diffing(self):
        row = self.collect(_replies())
        self.assertIn("EDGE", row["_acl_map"])


class AnalyzeTests(unittest.TestCase):

    def test_empty_input_yields_zeros_without_raising(self):
        counts = hc.analyze("", "", "", "", "nexus")
        self.assertEqual(counts["acl_count"], 0)
        self.assertEqual(counts["rule_count"], 0)
        self.assertEqual(counts["rules_with_dead_schedule"], 0)
        self.assertFalse(counts["analysis_skipped"])

    def test_an_oversized_acl_skips_the_quadratic_passes(self):
        rules = "\n".join(f"        {i * 10} permit ip 10.1.{i % 250}.0/24 any"
                          for i in range(hc.MAX_RULES_FOR_DEEP_ANALYSIS + 5))
        counts = hc.analyze("IP access list BIG\n" + rules, "", "", "", "nexus")
        self.assertTrue(counts["analysis_skipped"])
        self.assertEqual(counts["redundant_count"], 0)
        # The cheap counts are still reported.
        self.assertGreater(counts["rule_count"], hc.MAX_RULES_FOR_DEEP_ANALYSIS)


class SnapshotColumnTests(unittest.TestCase):
    """Guards against a count being computed and then silently not stored."""

    def test_every_collected_count_maps_to_a_real_column(self):
        from database import SwitchHealth
        columns = set(SwitchHealth.__table__.columns.keys())
        row = dict(hc._zero_counts())
        row.update(hc._tcam_columns(
            {"status": tp.STATUS_OK, "reason": None, "source": "nexus",
             "ingress": {"used": 1, "free": 2, "max": 3, "percent": 4.0},
             "egress": {"used": 5, "free": 6, "max": 3, "percent": 7.0}}))
        missing = set(row) - columns
        self.assertEqual(missing, set(), f"not persisted: {missing}")


if __name__ == "__main__":
    unittest.main()


# ── Endpoints ──

import asyncio
from datetime import timedelta
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import main
import schemas as sch
import auth
from auth import require_super_admin
from database import (AuditLog, Base, Switch, SwitchHealth, User,
                      ROLE_ADMIN, ROLE_SUPER_ADMIN,
                      EV_RULE_ADD, EV_RULE_DELETE, EV_UNDO, EV_CONFIG_SAVE,
                      EV_LOGIN_FAILED, EV_ANALYSIS, EV_TIME_RANGE,
                      get_app_settings)
from fastapi import HTTPException


class DashboardEndpointTests(unittest.TestCase):

    def setUp(self):
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        self.Session = sessionmaker(bind=engine)
        self.db = self.Session()
        self.boss = User(username="boss", hashed_password="x",
                         role=ROLE_SUPER_ADMIN)
        self.db.add(self.boss)
        self.db.add_all([
            Switch(id=1, ip_address="10.0.0.1", hostname="edge-a",
                   switch_type="nexus", owner_username="boss", vpc_peer_id=2),
            Switch(id=2, ip_address="10.0.0.2", hostname="edge-b",
                   switch_type="nexus", owner_username="boss", vpc_peer_id=1),
            Switch(id=3, ip_address="10.0.0.3", hostname="other-owner",
                   switch_type="ios", owner_username="someone-else"),
        ])
        now = datetime.utcnow()
        self.db.add_all([
            # Inside every window.
            AuditLog(timestamp=now - timedelta(minutes=5), level="SUCCESS",
                     username="boss", message="Added a rule to EDGE",
                     switch_id=1, event_type=EV_RULE_ADD),
            AuditLog(timestamp=now - timedelta(minutes=6), level="SUCCESS",
                     username="mina", message="Deleted rule 10 from EDGE",
                     switch_id=1, event_type=EV_RULE_DELETE),
            # Inside 24h but outside 1h.
            AuditLog(timestamp=now - timedelta(hours=5), level="SUCCESS",
                     username="boss", message="Undid a change",
                     switch_id=2, event_type=EV_UNDO),
            # Real, unsaved state for edge-b: an undoable change with no
            # later save. Kept well outside every tested window so it does
            # not affect the change-count assertions below — "unsaved"
            # describes current state, not the selected period.
            AuditLog(timestamp=now - timedelta(days=45), level="SUCCESS",
                     username="boss", message="Added rule 20 to edge-b",
                     switch_id=2, event_type=EV_RULE_ADD,
                     undo_commands='["no 20"]', undo_label="remove rule 20"),
            # Inside 7d but outside 24h.
            AuditLog(timestamp=now - timedelta(days=3), level="SUCCESS",
                     username="boss", message="Created time-range MAINT",
                     switch_id=1, event_type=EV_TIME_RANGE),
            # Saving is persisting a change, not making one, so it is never
            # counted among the changes.
            AuditLog(timestamp=now - timedelta(minutes=4), level="SUCCESS",
                     username="boss", message="Saved configuration on edge-a",
                     switch_id=1, event_type=EV_CONFIG_SAVE),
            # Never counted as a change: a read and a failed sign-in.
            AuditLog(timestamp=now - timedelta(minutes=7), level="INFO",
                     username="boss", message="Redundancy check on all ACLs",
                     switch_id=1, event_type=EV_ANALYSIS),
            AuditLog(timestamp=now - timedelta(minutes=8), level="WARN",
                     username="boss", message="Failed login attempt",
                     event_type=EV_LOGIN_FAILED),
            AuditLog(timestamp=now - timedelta(minutes=9), level="ERROR",
                     username="boss", message="Failed to add a rule to EDGE",
                     switch_id=2, event_type="write_failed"),
        ])
        self.db.commit()

    def tearDown(self):
        self.db.close()

    def activity(self, window="24h"):
        return asyncio.run(main.dashboard_activity(
            window=window, cu=self.boss, db=self.db))

    def test_only_write_events_count_as_changes(self):
        k = self.activity("24h")["kpis"]
        self.assertEqual(k["changes"], 3)          # add + delete + undo
        self.assertEqual(k["rules_added"], 1)
        self.assertEqual(k["rules_removed"], 1)

    def test_switch_tiles_describe_now_not_the_window(self):
        # Two of the tiles are a current state, not a count over the period,
        # so narrowing the window must not change them.
        for window in ("1h", "30d"):
            k = self.activity(window)["kpis"]
            self.assertEqual(k["switches"], 3)
            self.assertEqual(k["unsaved"], 1)

    def test_a_super_admin_counts_every_accounts_inventory(self):
        # "other-owner" (switch 3) belongs to someone else, and a super admin
        # is meant to see the whole estate.
        self.assertEqual(self.activity("24h")["kpis"]["switches"], 3)

    def test_a_plain_admin_counts_only_their_own_inventory(self):
        admin = User(username="mina", hashed_password="x", role=ROLE_ADMIN)
        self.db.add(admin)
        self.db.add(Switch(id=4, ip_address="10.0.0.4", hostname="mina-a",
                           switch_type="ios", owner_username="mina"))
        self.db.commit()
        k = asyncio.run(main.dashboard_activity(
            window="24h", cu=admin, db=self.db))["kpis"]
        self.assertEqual(k["switches"], 1)

    def test_unsaved_stays_the_callers_own_work_list(self):
        # Widening the inventory count must not widen this one: it is the
        # configs you still have to write, not a fleet-wide total.
        self.db.add(Switch(id=5, ip_address="10.0.0.5", hostname="theirs",
                           switch_type="ios", owner_username="someone-else"))
        self.db.add(AuditLog(timestamp=datetime.utcnow() - timedelta(days=40),
                             level="SUCCESS", username="someone-else",
                             message="Added rule 30 to theirs", switch_id=5,
                             event_type=EV_RULE_ADD,
                             undo_commands='["no 30"]', undo_label="remove 30"))
        self.db.commit()
        self.assertEqual(self.activity("24h")["kpis"]["unsaved"], 1)

    def test_reads_and_sign_ins_are_excluded_from_changes(self):
        k = self.activity("24h")["kpis"]
        self.assertEqual(k["failed_logins"], 1)
        self.assertEqual(k["failed_operations"], 1)
        self.assertNotIn("analysis", str(k))

    def test_the_window_actually_narrows_the_result(self):
        self.assertEqual(self.activity("1h")["kpis"]["changes"], 2)
        self.assertEqual(self.activity("24h")["kpis"]["changes"], 3)
        self.assertEqual(self.activity("7d")["kpis"]["changes"], 4)

    def test_saving_a_config_is_not_counted_as_a_change(self):
        # It persists a change rather than making one; counting it would
        # double every edit that was followed by a save.
        self.assertEqual(self.activity("1h")["kpis"]["changes"], 2)
        self.assertTrue(any(e["event_type"] == EV_CONFIG_SAVE
                            for e in self.activity("1h")["recent_activity"]))

    def test_an_unknown_window_is_rejected(self):
        with self.assertRaises(main.ValidationError):
            self.activity("all-time")

    def test_buckets_cover_the_window_and_sum_to_the_change_count(self):
        for window, expected in (("1h", 12), ("24h", 24), ("7d", 7), ("30d", 30)):
            d = self.activity(window)
            self.assertEqual(len(d["buckets"]), expected, window)
            self.assertEqual(sum(b["count"] for b in d["buckets"]),
                             d["kpis"]["changes"], window)

    def test_activity_spans_every_user_not_just_the_caller(self):
        users = {e["username"] for e in self.activity("24h")["recent_actions"]}
        self.assertEqual(users, {"boss", "mina"})

    def test_the_two_feeds_differ_in_what_they_admit(self):
        d = self.activity("24h")
        # Last actions is writes only; user activity is everything logged.
        self.assertEqual(len(d["recent_actions"]), 3)
        self.assertGreater(len(d["recent_activity"]), len(d["recent_actions"]))
        self.assertTrue(any(e["event_type"] == EV_ANALYSIS
                            for e in d["recent_activity"]))

    def test_selecting_a_slice_narrows_the_tiles_but_not_the_bars(self):
        full = self.activity("24h")
        bucket = next(b for b in full["buckets"] if b["count"])
        sliced = asyncio.run(main.dashboard_activity(
            window="24h", start=bucket["start"], end=bucket["end"],
            cu=self.boss, db=self.db))
        self.assertTrue(sliced["range"]["sliced"])
        self.assertEqual(sliced["kpis"]["changes"], bucket["count"])
        # The strip still covers the whole window, so context is not lost.
        self.assertEqual(len(sliced["buckets"]), len(full["buckets"]))
        self.assertEqual([b["count"] for b in sliced["buckets"]],
                         [b["count"] for b in full["buckets"]])

    def test_an_inverted_slice_is_rejected(self):
        with self.assertRaises(main.ValidationError):
            asyncio.run(main.dashboard_activity(
                window="24h", start="2026-08-22T10:00:00",
                end="2026-08-22T09:00:00", cu=self.boss, db=self.db))

    def detail(self, kind, **kw):
        return asyncio.run(main.dashboard_activity_detail(
            kind=kind, window=kw.pop("window", "24h"), cu=self.boss,
            db=self.db, **kw))

    def test_each_tile_can_be_opened_up(self):
        self.assertEqual(self.detail("changes")["total"], 3)
        self.assertEqual(self.detail("rules_added")["total"], 1)
        self.assertEqual(self.detail("rules_removed")["total"], 1)
        self.assertEqual(self.detail("failed_operations")["total"], 1)
        self.assertEqual(self.detail("failed_logins")["total"], 1)

    def test_the_detail_matches_the_tile_it_came_from(self):
        for kind in ("changes", "rules_added", "failed_logins"):
            self.assertEqual(self.detail(kind)["total"],
                             self.activity("24h")["kpis"][kind], kind)

    def test_switch_tiles_open_into_switch_lists_not_log_entries(self):
        # The inventory list matches its tile: every account's for a super
        # admin, while "unsaved" stays the caller's own work list.
        self.assertEqual(len(self.detail("switches")["switches"]), 3)
        self.assertEqual([s["switch_label"]
                          for s in self.detail("unsaved")["switches"]], ["edge-b"])

    def test_the_inventory_list_names_the_owner_of_every_entry(self):
        # The same device registered by two people is two entries, so the
        # owner is the only thing telling them apart.
        self.db.add(Switch(id=6, ip_address="10.0.0.1", hostname="edge-a",
                           switch_type="nexus", owner_username="someone-else"))
        self.db.commit()
        rows = self.detail("switches")["switches"]
        same_device = [r for r in rows if r["ip_address"] == "10.0.0.1"]
        self.assertEqual(len(same_device), 2)
        self.assertEqual(sorted(r["owner"] for r in same_device),
                         ["boss", "someone-else"])

    def test_a_plain_admin_opens_only_their_own_inventory(self):
        admin = User(username="mina", hashed_password="x", role=ROLE_ADMIN)
        self.db.add(admin)
        self.db.add(Switch(id=7, ip_address="10.0.0.7", hostname="mina-a",
                           switch_type="ios", owner_username="mina"))
        self.db.commit()
        d = asyncio.run(main.dashboard_activity_detail(
            kind="switches", window="24h", cu=admin, db=self.db))
        self.assertEqual([s["switch_label"] for s in d["switches"]], ["mina-a"])

    def test_a_plain_admin_is_not_told_another_accounts_vpc_peer(self):
        # edge-a's peer is edge-b, which this admin does not own; naming it
        # would leak a hostname from somebody else's inventory.
        admin = User(username="mina", hashed_password="x", role=ROLE_ADMIN)
        self.db.add(admin)
        self.db.add(Switch(id=8, ip_address="10.0.0.8", hostname="mina-a",
                           switch_type="nexus", owner_username="mina",
                           vpc_peer_id=1))
        self.db.commit()
        d = asyncio.run(main.dashboard_activity_detail(
            kind="switches", window="24h", cu=admin, db=self.db))
        self.assertIsNone(d["switches"][0]["vpc_peer_label"])

    def test_an_unknown_detail_kind_is_rejected(self):
        with self.assertRaises(main.ValidationError):
            self.detail("everything")

    def test_presence_counts_only_recently_seen_accounts(self):
        # There is no session store, so "signed in" means recent traffic.
        self.assertEqual(self.activity("24h")["kpis"]["signed_in"], 0)
        self.boss.last_seen = datetime.utcnow()
        stale = User(username="ghost", hashed_password="x", role=ROLE_ADMIN,
                     last_seen=datetime.utcnow() - timedelta(hours=4))
        self.db.add(stale)
        self.db.commit()
        d = self.activity("24h")
        self.assertEqual(d["kpis"]["signed_in"], 1)
        self.assertEqual([u["username"] for u in d["signed_in"]], ["boss"])

    def test_unsaved_changes_are_listed_regardless_of_window(self):
        d = self.activity("1h")
        self.assertEqual([p["switch_label"] for p in d["pending_saves"]],
                         ["edge-b"])

    def test_health_lists_only_switches_the_caller_owns(self):
        d = asyncio.run(main.dashboard_health(self.boss, self.db))
        self.assertEqual([s["switch_label"] for s in d["switches"]],
                         ["edge-a", "edge-b"])

    def test_unscanned_switches_are_shown_as_gaps_not_omitted(self):
        d = asyncio.run(main.dashboard_health(self.boss, self.db))
        self.assertTrue(all(s["status"] == "never_scanned" for s in d["switches"]))
        self.assertEqual(d["totals"]["never_scanned_count"], 2)
        self.assertIsNone(d["last_collected_at"])

    def test_totals_ignore_switches_whose_fetch_failed(self):
        self.db.add_all([
            SwitchHealth(switch_id=1, collected_at=datetime.utcnow(),
                         status="ok", redundant_count=17, tcam_status="ok",
                         tcam_in_pct=77.06, tcam_out_pct=92.08),
            # Zeros here are an absence of data, not an absence of findings.
            SwitchHealth(switch_id=2, collected_at=datetime.utcnow(),
                         status="error", error="timed out", redundant_count=0),
        ])
        self.db.commit()
        t = asyncio.run(main.dashboard_health(self.boss, self.db))["totals"]
        self.assertEqual(t["redundant_count"], 17)
        self.assertEqual(t["error_count"], 1)
        self.assertEqual(t["scanned_count"], 2)
        self.assertEqual(t["worst_tcam_percent"], 92.08)

    def test_a_tcam_source_disagreeing_with_the_type_flags_a_mislabel(self):
        self.db.add(SwitchHealth(switch_id=1, collected_at=datetime.utcnow(),
                                 status="ok", tcam_status="ok",
                                 tcam_source="ios"))   # switch is typed nexus
        self.db.commit()
        d = asyncio.run(main.dashboard_health(self.boss, self.db))
        row = next(s for s in d["switches"] if s["switch_id"] == 1)
        self.assertTrue(row["type_mismatch"])
        self.assertEqual(d["totals"]["type_mismatch_count"], 1)

    def test_a_scan_refuses_to_run_twice_at_once(self):
        main._health_sweep_lock.acquire()
        try:
            with self.assertRaises(HTTPException) as caught:
                asyncio.run(main.dashboard_health_scan(
                    sch.DashboardScanRequest(), self.boss, self.db))
            self.assertEqual(caught.exception.status_code, 409)
        finally:
            main._health_sweep_lock.release()

    def test_the_lock_is_released_after_a_scan_fails(self):
        with self.assertRaises(HTTPException):
            asyncio.run(main.dashboard_health_scan(
                sch.DashboardScanRequest(switch_ids=[999]), self.boss, self.db))
        self.assertFalse(main._health_sweep_lock.locked())


class DashboardAccessTests(unittest.TestCase):

    def test_a_plain_admin_is_refused(self):
        admin = User(username="a", hashed_password="x", role=ROLE_ADMIN)
        with self.assertRaises(HTTPException) as caught:
            asyncio.run(require_super_admin(admin))
        self.assertEqual(caught.exception.status_code, 403)

    def test_a_super_admin_is_allowed(self):
        boss = User(username="b", hashed_password="x", role=ROLE_SUPER_ADMIN)
        self.assertIs(asyncio.run(require_super_admin(boss)), boss)


class VpcSyncTests(unittest.TestCase):
    """The pair is diffed from ACL data both switches already returned, so a
    sync check costs no extra round trips."""

    def rows(self):
        return [{"switch_id": 1, "status": "ok"}, {"switch_id": 2, "status": "ok"}]

    def test_identical_acls_are_in_sync_on_both_rows(self):
        rows = self.rows()
        acls = {"EDGE": ["10 permit ip any any"]}
        main._apply_vpc_sync(rows, {1: acls, 2: dict(acls)}, {}, {1: 2, 2: 1})
        for row in rows:
            self.assertEqual(row["vpc_sync_status"], "match")
            self.assertEqual(row["vpc_mismatch_count"], 0)

    def test_a_difference_is_reported_on_both_members(self):
        rows = self.rows()
        main._apply_vpc_sync(
            rows,
            {1: {"EDGE": ["10 permit ip any any"]},
             2: {"EDGE": ["10 permit ip any any", "20 permit tcp any any eq 22"]}},
            {}, {1: 2, 2: 1})
        for row in rows:
            self.assertEqual(row["vpc_sync_status"], "mismatch")
            self.assertEqual(row["vpc_mismatch_count"], 1)
            self.assertEqual(row["vpc_peer_id"], 3 - row["switch_id"])

    def test_a_peer_that_was_not_collected_leaves_the_row_alone(self):
        rows = self.rows()
        main._apply_vpc_sync(rows, {1: {"EDGE": []}}, {}, {1: 2, 2: 1})
        self.assertNotIn("vpc_sync_status", rows[0])

    def test_a_binding_difference_alone_puts_the_pair_out_of_sync(self):
        # Identical rules, but one switch applies the ACL to a different VLAN.
        # Diffing only the rules would call this pair in sync.
        rows = self.rows()
        acls = {"EDGE": ["10 permit ip any any"]}
        main._apply_vpc_sync(
            rows, {1: acls, 2: dict(acls)},
            {1: {"EDGE": [{"interface": "Vlan10", "direction": "in"}]},
             2: {"EDGE": [{"interface": "Vlan20", "direction": "in"}]}},
            {1: 2, 2: 1})
        for row in rows:
            self.assertEqual(row["vpc_sync_status"], "mismatch")
            self.assertEqual(row["vpc_mismatch_count"], 0)
            self.assertEqual(row["vpc_binding_mismatch_count"], 2)

    def test_a_direction_difference_counts_as_a_binding_mismatch(self):
        rows = self.rows()
        acls = {"EDGE": ["10 permit ip any any"]}
        main._apply_vpc_sync(
            rows, {1: acls, 2: dict(acls)},
            {1: {"EDGE": [{"interface": "Vlan10", "direction": "in"}]},
             2: {"EDGE": [{"interface": "Vlan10", "direction": "out"}]}},
            {1: 2, 2: 1})
        self.assertEqual(rows[0]["vpc_binding_mismatch_count"], 1)

    def test_non_vlan_bindings_are_ignored(self):
        # A VPC pair is only expected to agree on its SVIs.
        rows = self.rows()
        acls = {"EDGE": ["10 permit ip any any"]}
        main._apply_vpc_sync(
            rows, {1: acls, 2: dict(acls)},
            {1: {"EDGE": [{"interface": "Ethernet1/1", "direction": "in"}]},
             2: {"EDGE": []}},
            {1: 2, 2: 1})
        self.assertEqual(rows[0]["vpc_sync_status"], "match")

    def test_both_halves_are_reported_separately(self):
        rows = self.rows()
        main._apply_vpc_sync(
            rows,
            {1: {"EDGE": ["10 permit ip any any"]},
             2: {"EDGE": ["10 permit ip any any", "20 permit tcp any any eq 22"]}},
            {1: {"EDGE": [{"interface": "Vlan10", "direction": "in"}]},
             2: {"EDGE": [{"interface": "Vlan20", "direction": "in"}]}},
            {1: 2, 2: 1})
        self.assertEqual(rows[0]["vpc_mismatch_count"], 1)
        self.assertEqual(rows[0]["vpc_binding_mismatch_count"], 2)


class SweepIntegrationTests(unittest.TestCase):
    """Drives the real endpoint end to end with the switch layer faked out."""

    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:",
                                    connect_args={"check_same_thread": False})
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)
        self.db = self.Session()
        self.boss = User(username="boss", hashed_password="x",
                         role=ROLE_SUPER_ADMIN)
        self.db.add(self.boss)
        self.db.add_all([
            Switch(id=1, ip_address="10.0.0.1", hostname="edge-a",
                   switch_type="nexus", owner_username="boss", vpc_peer_id=2),
            Switch(id=2, ip_address="10.0.0.2", hostname="edge-b",
                   switch_type="nexus", owner_username="boss", vpc_peer_id=1),
        ])
        self.db.commit()

        self.invalidated = []
        self.saved = {}
        self.patches = [
            patch.object(main, "SessionLocal", self.Session),
            patch.object(hc.svc, "show", _RecordingShow(_replies())),
            patch.object(main.svc, "resolve_targets",
                         lambda ids, username, db: [self._target(ids[0])]),
            patch.object(main.ssh_manager, "has_session", lambda u, ip: False),
            patch.object(main.ssh_manager, "invalidate_session",
                         lambda u, ip: self.invalidated.append(ip)),
        ]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        self.db.close()

    def _target(self, switch_id):
        t = _FakeTarget("nexus")
        t.id = switch_id
        t.ip = f"10.0.0.{switch_id}"
        t.label = f"edge-{'ab'[switch_id - 1]}"
        return t

    def scan(self, **kwargs):
        return asyncio.run(main.dashboard_health_scan(
            sch.DashboardScanRequest(**kwargs), self.boss, self.db))

    def test_a_sweep_stores_a_snapshot_for_every_switch(self):
        d = self.scan()
        self.assertEqual(d["sweep"]["scanned"], 2)
        self.assertEqual(d["sweep"]["ok"], 2)
        stored = self.db.query(SwitchHealth).all()
        self.assertEqual({s.switch_id for s in stored}, {1, 2})
        self.assertTrue(all(s.redundant_count == 1 for s in stored))
        self.assertTrue(all(s.scanned_by == "boss" for s in stored))

    def test_the_stored_counts_are_what_the_get_returns(self):
        self.scan()
        d = asyncio.run(main.dashboard_health(self.boss, self.db))
        self.assertEqual(d["totals"]["redundant_count"], 2)
        self.assertEqual(d["totals"]["rules_with_dead_schedule"], 2)
        self.assertTrue(all(s["status"] == "ok" for s in d["switches"]))

    def test_a_matching_vpc_pair_is_recorded_on_both_switches(self):
        self.scan()
        stored = self.db.query(SwitchHealth).all()
        self.assertTrue(all(s.vpc_sync_status == "match" for s in stored))
        self.assertEqual({s.vpc_peer_id for s in stored}, {1, 2})
        self.assertTrue(all(s.vpc_binding_mismatch_count == 0 for s in stored))

    def test_sessions_the_sweep_opened_are_handed_back(self):
        # Sessions are never evicted, so without this a sweep would leave one
        # open connection and VTY line per switch, permanently.
        self.scan()
        self.assertEqual(sorted(self.invalidated), ["10.0.0.1", "10.0.0.2"])

    def test_a_second_sweep_updates_rather_than_duplicates(self):
        self.scan()
        self.scan()
        self.assertEqual(self.db.query(SwitchHealth).count(), 2)

    def test_scanning_a_subset_leaves_the_other_snapshot_alone(self):
        self.scan()
        first = {s.switch_id: s.collected_at
                 for s in self.Session().query(SwitchHealth).all()}
        self.scan(switch_ids=[1])
        after = {s.switch_id: s.collected_at
                 for s in self.Session().query(SwitchHealth).all()}
        self.assertEqual(after[2], first[2])

    def test_the_sweep_is_recorded_in_the_audit_log(self):
        self.scan()
        entry = self.db.query(AuditLog).filter(
            AuditLog.message.like("Ran a fleet health scan%")).first()
        self.assertIsNotNone(entry)
        self.assertEqual(entry.username, "boss")


class PresenceTests(unittest.TestCase):
    """Who counts as active, and what signing out does about it."""

    def setUp(self):
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        self.db = sessionmaker(bind=engine)()
        self.boss = User(username="boss", hashed_password="x",
                         role=ROLE_SUPER_ADMIN, last_seen=datetime.utcnow())
        self.db.add(self.boss)
        self.db.commit()

    def tearDown(self):
        self.db.close()

    def active(self):
        return [u["username"] for u in main._signed_in_users(self.db)]

    def test_a_recently_seen_account_is_active(self):
        self.assertEqual(self.active(), ["boss"])

    def test_signing_out_drops_the_account_immediately(self):
        # Sign-out is otherwise client-only, so without clearing last_seen the
        # account lingered on the dashboard for the whole idle window.
        asyncio.run(main.logout(self.boss, self.db))
        self.assertIsNone(self.boss.last_seen)
        self.assertEqual(self.active(), [])

    def test_signing_out_is_recorded(self):
        asyncio.run(main.logout(self.boss, self.db))
        entry = self.db.query(AuditLog).filter(
            AuditLog.message == "Signed out").first()
        self.assertIsNotNone(entry)
        self.assertEqual(entry.username, "boss")

    def test_an_account_never_seen_is_not_active(self):
        self.boss.last_seen = None
        self.db.commit()
        self.assertEqual(self.active(), [])

    def test_presence_expires_with_the_idle_window(self):
        self.boss.last_seen = datetime.utcnow() - timedelta(
            minutes=main.DEFAULT_PRESENCE_MINUTES + 1)
        self.db.commit()
        self.assertEqual(self.active(), [])

    def test_the_configured_idle_timeout_defines_the_window(self):
        settings_row = get_app_settings(self.db)
        settings_row.idle_timeout_minutes = 120
        self.db.commit()
        self.boss.last_seen = datetime.utcnow() - timedelta(minutes=60)
        self.db.commit()
        # Stale by the 15-minute default, still present under a 2-hour timeout.
        self.assertEqual(self.active(), ["boss"])

    def test_using_the_token_after_signing_out_marks_the_account_active_again(self):
        # There is no revocation list, so a still-valid token legitimately
        # brings the account back. Presence reflects traffic, not intent.
        asyncio.run(main.logout(self.boss, self.db))
        auth._touch_last_seen(self.db, self.boss)
        self.assertEqual(self.active(), ["boss"])


class TouchLastSeenTests(unittest.TestCase):

    def setUp(self):
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        self.db = sessionmaker(bind=engine)()
        self.user = User(username="u", hashed_password="x", role=ROLE_ADMIN)
        self.db.add(self.user)
        self.db.commit()

    def tearDown(self):
        self.db.close()

    def test_a_first_request_records_presence(self):
        auth._touch_last_seen(self.db, self.user)
        self.assertIsNotNone(self.user.last_seen)

    def test_writes_are_throttled(self):
        # SQLite takes one writer at a time; a write per request would be a
        # needless contention point for a minute-granular fact.
        auth._touch_last_seen(self.db, self.user)
        first = self.user.last_seen
        auth._touch_last_seen(self.db, self.user)
        self.assertEqual(self.user.last_seen, first)

    def test_a_stale_marker_is_refreshed(self):
        self.user.last_seen = datetime.utcnow() - timedelta(
            seconds=auth.LAST_SEEN_REFRESH_SECONDS + 5)
        self.db.commit()
        stale = self.user.last_seen
        auth._touch_last_seen(self.db, self.user)
        self.assertGreater(self.user.last_seen, stale)
