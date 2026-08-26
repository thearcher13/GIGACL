import asyncio
import unittest
from unittest.mock import ANY, patch, call

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import main
import schemas as sch
from database import Base, User, Switch, ROLE_ADMIN
from validators import ValidationError, validate_vlan_interface


class ACLViewerWriteTests(unittest.TestCase):
    def setUp(self):
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        self.db = sessionmaker(bind=engine)()
        self.user = User(username="admin", hashed_password="x", role=ROLE_ADMIN)
        self.switch = Switch(id=7, ip_address="10.1.1.7", hostname="sw7",
                             switch_type="ios", owner_username="admin",
                             ssh_username="admin")
        self.db.add_all((self.user, self.switch))
        self.db.commit()

    def tearDown(self):
        self.db.close()

    def edit(self, replacement, original="10 permit ip host 10.0.0.1 any (3 matches)"):
        data = sch.RuleEditRequest(
            switch_id=7, acl_name="TEST",
            original_rule=original,
            new_rule=replacement)
        return asyncio.run(main.rule_edit(data, self.user, self.db))

    def apply(self, rule_syntax):
        data = sch.RuleApplyRequest(
            switch_id=7, acl_name="TEST", rule_syntax=rule_syntax,
            remark=None, remark_sequence=None)
        return asyncio.run(main.rule_apply(data, self.user, self.db))

    @patch("main.get_switch_and_password")
    @patch("main.svc.get_acl_kind")
    @patch("main.svc.get_acl_rules")
    @patch("main.svc.configure")
    def test_failed_edit_restores_original_rule(self, configure, get_rules, get_kind, get_switch):
        get_switch.return_value = (self.switch, "pw", None)
        get_kind.return_value = "extended"
        get_rules.return_value = (
            "", ["10 permit ip host 10.0.0.1 any (3 matches)"])
        configure.side_effect = [
            (False, "% Invalid command", "Invalid command"),
            (True, "restored", None),
        ]

        result = self.edit("10 permit tcp host 10.0.0.1 any eq 443")

        self.assertFalse(result["success"])
        self.assertIn("original rule was restored", result["message"].lower())
        self.assertEqual(configure.call_args_list[0], call(
            ANY, "admin",
            ["ip access-list extended TEST", "no 10",
             "10 permit tcp host 10.0.0.1 any eq 443"], timeout=45))
        self.assertEqual(configure.call_args_list[1], call(
            ANY, "admin",
            ["ip access-list extended TEST", "no 10",
             "10 permit ip host 10.0.0.1 any"], timeout=45))

    @patch("main.get_switch_and_password")
    @patch("main.svc.get_acl_kind")
    @patch("main.svc.get_acl_rules")
    @patch("main.svc.configure")
    def test_successful_edit_is_verified(self, configure, get_rules, get_kind, get_switch):
        get_switch.return_value = (self.switch, "pw", None)
        get_kind.return_value = "extended"
        get_rules.side_effect = [
            ("before", ["10 permit ip host 10.0.0.1 any"]),
            ("after", ["10 deny tcp host 10.0.0.1 any eq 23"]),
        ]
        configure.return_value = (True, "configured", None)

        data = sch.RuleEditRequest(
            switch_id=7, acl_name="TEST",
            original_rule="10 permit ip host 10.0.0.1 any",
            new_rule="10 deny tcp host 10.0.0.1 any eq 23")
        result = asyncio.run(main.rule_edit(data, self.user, self.db))

        self.assertTrue(result["success"])
        self.assertEqual(result["undo_commands"], [
            "ip access-list extended TEST", "no 10",
            "10 permit ip host 10.0.0.1 any"])

    def test_canonical_rule_strips_display_annotations(self):
        self.assertEqual(
            main._canonical_acl_rule("10 permit ip host 10.0.0.1 any (3 matches)"),
            main._canonical_acl_rule("10 permit ip host 10.0.0.1 any"))
        self.assertEqual(
            main._canonical_acl_rule(
                "permit object-group WEB_PORT host 172.30.201.191 "
                "host 172.30.48.119 time-range bagher.hosseini (inactive)"),
            main._canonical_acl_rule(
                "permit object-group WEB_PORT host 172.30.201.191 "
                "host 172.30.48.119 time-range bagher.hosseini"))

    @patch("main.get_switch_and_password")
    @patch("main.svc.get_acl_kind")
    @patch("main.svc.get_acl_rules")
    @patch("main.svc.configure")
    def test_edit_rollback_strips_inactive_marker_from_restore_command(
            self, configure, get_rules, get_kind, get_switch):
        # A rule tied to an inactive time-range shows "(inactive)" in `show`
        # output — that must never be replayed as literal CLI syntax.
        get_switch.return_value = (self.switch, "pw", None)
        get_kind.return_value = "extended"
        get_rules.return_value = (
            "", ["10 permit ip host 10.0.0.1 any time-range TR1 (inactive)"])
        configure.side_effect = [
            (False, "% Invalid command", "Invalid command"),
            (True, "restored", None),
        ]

        result = self.edit(
            "10 permit tcp host 10.0.0.1 any eq 443",
            original="10 permit ip host 10.0.0.1 any time-range TR1 (inactive)")

        self.assertFalse(result["success"])
        self.assertEqual(configure.call_args_list[1], call(
            ANY, "admin",
            ["ip access-list extended TEST", "no 10",
             "10 permit ip host 10.0.0.1 any time-range TR1"], timeout=45))

    @patch("main.get_switch_and_password")
    @patch("main.svc.get_acl_kind")
    @patch("main.svc.get_acl_rules")
    @patch("main.svc.configure")
    def test_apply_accepts_deny_rule(self, configure, get_rules, get_kind, get_switch):
        get_switch.return_value = (self.switch, "pw", None)
        get_kind.return_value = "extended"
        get_rules.side_effect = [
            ("", []),
            ("", ["60 deny ip 10.0.0.0 0.0.0.255 any"]),
        ]
        configure.return_value = (True, "configured", None)

        result = self.apply("60 deny ip 10.0.0.0 0.0.0.255 any")

        self.assertTrue(result["success"])
        self.assertEqual(configure.call_args_list[0], call(
            ANY, "admin",
            ["ip access-list extended TEST", "60 deny ip 10.0.0.0 0.0.0.255 any"]))

    @patch("main.get_switch_and_password")
    @patch("main.svc.get_acl_kind")
    @patch("main.svc.get_acl_rules")
    def test_apply_rejects_duplicate_sequence(self, get_rules, get_kind, get_switch):
        get_switch.return_value = (self.switch, "pw", None)
        get_kind.return_value = "extended"
        get_rules.return_value = ("", ["60 permit ip any any"])

        result = self.apply("60 deny ip 10.0.0.0 0.0.0.255 any")

        self.assertFalse(result["success"])
        self.assertIn("already exists", result["message"].lower())

    @patch("main.get_switch_and_password")
    @patch("main.svc.list_acl_names")
    @patch("main.svc.show")
    def test_attach_rejects_existing_acl_in_same_direction(
            self, show, list_names, get_switch):
        get_switch.return_value = (self.switch, "pw", None)
        list_names.return_value = ["TEST", "OTHER"]
        show.return_value = (
            "interface Vlan748\n ip access-group OTHER out\n")
        data = sch.ACLInterfaceUpdateRequest(
            switch_id=7, acl_name="TEST", interface="748",
            direction="out", action="attach")

        with self.assertRaisesRegex(ValidationError, "already has ACL 'OTHER'"):
            asyncio.run(main.update_acl_interface(data, self.user, self.db))

    def test_vlan_validation(self):
        self.assertEqual(validate_vlan_interface("748"), "Vlan748")
        self.assertEqual(validate_vlan_interface("vlan 20"), "Vlan20")
        with self.assertRaises(ValidationError):
            validate_vlan_interface("Vlan5000")


if __name__ == "__main__":
    unittest.main()
