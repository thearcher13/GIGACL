import unittest

import main


class AclConfigLinesTests(unittest.TestCase):
    def test_extracts_header_and_rule_lines(self):
        raw = """ip access-list extended EDGE
 10 permit tcp host 10.0.0.1 any eq 443
 20 deny ip any any
"""
        lines = main._acl_config_lines(raw, "ip access-list extended EDGE")
        self.assertEqual(lines, [
            "ip access-list extended EDGE",
            " 10 permit tcp host 10.0.0.1 any eq 443",
            " 20 deny ip any any",
        ])

    def test_includes_remarks(self):
        raw = """ip access-list extended EDGE
 10 remark allow web traffic
 20 permit tcp host 10.0.0.1 any eq 443
"""
        lines = main._acl_config_lines(raw, "ip access-list extended EDGE")
        self.assertIn(" 10 remark allow web traffic", lines)
        self.assertIn(" 20 permit tcp host 10.0.0.1 any eq 443", lines)

    def test_stops_at_next_unindented_line(self):
        raw = """ip access-list extended EDGE
 10 permit ip any any
!
ip access-list extended OTHER
 10 deny ip any any
"""
        lines = main._acl_config_lines(raw, "ip access-list extended EDGE")
        self.assertEqual(lines, [
            "ip access-list extended EDGE",
            " 10 permit ip any any",
        ])

    def test_missing_acl_returns_empty(self):
        raw = "!\n"
        lines = main._acl_config_lines(raw, "ip access-list extended MISSING")
        self.assertEqual(lines, [])

    def test_nxos_context_matches(self):
        raw = """ip access-list EDGE
  10 permit tcp any any eq 443
"""
        lines = main._acl_config_lines(raw, "ip access-list EDGE")
        self.assertEqual(lines, [
            "ip access-list EDGE",
            " 10 permit tcp any any eq 443",
        ])


class AclCtxTests(unittest.TestCase):
    def test_ios_extended(self):
        self.assertEqual(main._acl_ctx("EDGE", "ios", "extended"),
                         "ip access-list extended EDGE")

    def test_ios_standard(self):
        self.assertEqual(main._acl_ctx("EDGE", "ios", "standard"),
                         "ip access-list standard EDGE")

    def test_nxos_ignores_kind(self):
        self.assertEqual(main._acl_ctx("EDGE", "nexus", "standard"),
                         "ip access-list EDGE")


if __name__ == "__main__":
    unittest.main()
