"""
Rules pinned to a schedule that can never fire again.

Reported separately from redundancy on purpose. A redundant rule is covered by
another, so removing it changes nothing; a dead-schedule rule matches nothing
at all and never will, and the fix is usually to renew the schedule rather
than delete the rule.
"""
import unittest
from datetime import datetime
import acl_parser

class DeadSchedule(unittest.TestCase):
    RULES = [
        "10 permit tcp any any eq 22 time-range MAINT-2024",
        "20 permit ip any any",
        "30 permit tcp any any eq 443 time-range NIGHTLY",
        "40 permit udp any any time-range maint-2024",
    ]
    TRS = [
        {"name": "MAINT-2024", "entries": ["absolute start 00:00 1 Jan 2024 end 23:59 31 Dec 2024"]},
        {"name": "NIGHTLY",    "entries": ["periodic daily 22:00 to 06:00"]},
    ]
    NOW = datetime(2026, 8, 26)

    def test_finds_only_the_expired_one(self):
        out = acl_parser.find_dead_schedule_rules(self.RULES, self.TRS, "nexus", {}, self.NOW)
        self.assertEqual([d["sequence"] for d in out], [10, 40],
                         "both rules on the expired range, matched case-insensitively")

    def test_periodic_is_not_dead(self):
        out = acl_parser.find_dead_schedule_rules(self.RULES, self.TRS, "nexus", {}, self.NOW)
        self.assertNotIn(30, [d["sequence"] for d in out],
                         "a nightly range is inactive by day, not expired")

    def test_carries_the_schedule_for_the_ui(self):
        out = acl_parser.find_dead_schedule_rules(self.RULES, self.TRS, "nexus", {}, self.NOW)
        self.assertEqual(out[0]["time_range"], "MAINT-2024")
        self.assertTrue(out[0]["entries"], "the UI shows why it is dead")

    def test_no_expired_ranges_means_no_work(self):
        self.assertEqual(
            acl_parser.find_dead_schedule_rules(self.RULES, [self.TRS[1]], "nexus", {}, self.NOW), [])

    def test_no_ranges_at_all(self):
        self.assertEqual(acl_parser.find_dead_schedule_rules(self.RULES, [], "nexus", {}, self.NOW), [])

if __name__ == "__main__":
    unittest.main(verbosity=2)
