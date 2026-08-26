import asyncio
import unittest
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import main
import schemas as sch
from database import Base, User, Switch, Template, ROLE_ADMIN
from validators import ValidationError


class AclCreateTests(unittest.TestCase):
    """Mocks switch_service the same way test_templates.py's
    ApplyTemplateTests does, since acl_create() needs a live-switch round
    trip for the existing-ACL-name and object-group/time-range checks."""

    def setUp(self):
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        self.db = sessionmaker(bind=engine)()
        self.owner = User(username="owner1", hashed_password="x", role=ROLE_ADMIN)
        self.db.add(self.owner)
        self.db.commit()
        self.db.refresh(self.owner)
        self.switch = Switch(ip_address="10.1.1.1", hostname="sw1",
                             switch_type="nexus", owner_username="owner1",
                             saved_password="enc", ssh_username="netadmin")
        self.ios_switch = Switch(ip_address="10.1.1.4", hostname="ios1",
                                 switch_type="ios", owner_username="owner1",
                                 saved_password="enc", ssh_username="netadmin")
        self.db.add_all((self.switch, self.ios_switch))
        self.db.commit()
        self.db.refresh(self.switch)
        self.db.refresh(self.ios_switch)

    def tearDown(self):
        self.db.close()

    def _create_template(self, switch_type="nexus", lines=None, acl_kind="extended"):
        lines = lines or ["permit tcp host 10.0.0.1 host 10.0.0.2 eq 22"]
        return asyncio.run(main.create_template(
            sch.TemplateCreate(name="T1", switch_type=switch_type, acl_kind=acl_kind,
                              direction="in", lines=lines, share_with=[]),
            self.owner, self.db))

    def _req(self, **overrides):
        payload = dict(acl_name="NEW-ACL", switch_id=self.switch.id,
                       switch_type="nexus", implicit_action="deny",
                       template_id=None, direction=None)
        payload.update(overrides)
        return sch.AclCreateRequest(**payload)

    def test_platform_mismatch_is_rejected(self):
        with patch("switch_utils.decrypt_password", return_value="pw"):
            with self.assertRaises(ValidationError):
                asyncio.run(main.acl_create(
                    self._req(switch_type="ios"), self.owner, self.db))

    def test_invalid_implicit_action_is_rejected(self):
        with patch("switch_utils.decrypt_password", return_value="pw"):
            with self.assertRaises(ValidationError):
                asyncio.run(main.acl_create(
                    self._req(implicit_action="allow"), self.owner, self.db))

    def test_duplicate_acl_name_is_rejected(self):
        with patch.object(main.svc, "list_acl_names", return_value=["NEW-ACL"]), \
             patch("switch_utils.decrypt_password", return_value="pw"):
            with self.assertRaises(ValidationError) as ctx:
                asyncio.run(main.acl_create(self._req(), self.owner, self.db))
            self.assertIn("already exists", str(ctx.exception))

    def test_duplicate_acl_name_check_is_case_insensitive(self):
        with patch.object(main.svc, "list_acl_names", return_value=["new-acl"]), \
             patch("switch_utils.decrypt_password", return_value="pw"):
            with self.assertRaises(ValidationError):
                asyncio.run(main.acl_create(self._req(), self.owner, self.db))

    def test_create_without_template_produces_only_the_implicit_rule(self):
        with patch.object(main.svc, "list_acl_names", return_value=[]), \
             patch.object(main.svc, "configure", return_value=(True, "ok", "")) as mock_configure, \
             patch("switch_utils.decrypt_password", return_value="pw"):
            result = asyncio.run(main.acl_create(
                self._req(implicit_action="permit"), self.owner, self.db))
            cmds = mock_configure.call_args[0][2]
        self.assertTrue(result["success"])
        self.assertEqual(cmds, ["ip access-list NEW-ACL", "999 permit ip any any"])
        self.assertEqual(result["undo_commands"], ["no ip access-list NEW-ACL"])

    def test_create_uses_ios_extended_context(self):
        with patch.object(main.svc, "list_acl_names", return_value=[]), \
             patch.object(main.svc, "configure", return_value=(True, "ok", "")) as mock_configure, \
             patch("switch_utils.decrypt_password", return_value="pw"):
            asyncio.run(main.acl_create(
                self._req(switch_id=self.ios_switch.id, switch_type="ios"),
                self.owner, self.db))
            cmds = mock_configure.call_args[0][2]
        self.assertEqual(cmds[0], "ip access-list extended NEW-ACL")

    def test_create_standard_ios_acl_uses_standard_context_and_implicit_line(self):
        with patch.object(main.svc, "list_acl_names", return_value=[]), \
             patch.object(main.svc, "configure", return_value=(True, "ok", "")) as mock_configure, \
             patch("switch_utils.decrypt_password", return_value="pw"):
            asyncio.run(main.acl_create(
                self._req(switch_id=self.ios_switch.id, switch_type="ios",
                          acl_kind="standard", implicit_action="deny"),
                self.owner, self.db))
            cmds = mock_configure.call_args[0][2]
        self.assertEqual(cmds, ["ip access-list standard NEW-ACL", "999 deny any"])

    def test_create_with_standard_template_seeds_standard_lines(self):
        created = self._create_template(switch_type="ios", acl_kind="standard",
                                        lines=["permit 10.0.0.0 0.0.0.255"])
        with patch.object(main.svc, "list_acl_names", return_value=[]), \
             patch.object(main.svc, "get_object_groups", return_value=[]), \
             patch.object(main.svc, "get_time_ranges", return_value=[]), \
             patch.object(main.svc, "configure", return_value=(True, "ok", "")) as mock_configure, \
             patch("switch_utils.decrypt_password", return_value="pw"):
            asyncio.run(main.acl_create(
                self._req(switch_id=self.ios_switch.id, switch_type="ios", acl_kind="standard",
                          implicit_action="permit", template_id=created["id"], direction="in"),
                self.owner, self.db))
            cmds = mock_configure.call_args[0][2]
        self.assertEqual(cmds, [
            "ip access-list standard NEW-ACL",
            "1 permit 10.0.0.0 0.0.0.255",
            "999 permit any",
        ])

    def test_standard_template_cannot_seed_an_extended_acl_create(self):
        created = self._create_template(switch_type="ios", acl_kind="standard",
                                        lines=["permit 10.0.0.0 0.0.0.255"])
        with patch.object(main.svc, "list_acl_names", return_value=[]), \
             patch("switch_utils.decrypt_password", return_value="pw"):
            with self.assertRaises(ValidationError) as ctx:
                asyncio.run(main.acl_create(
                    self._req(switch_id=self.ios_switch.id, switch_type="ios", acl_kind="extended",
                              template_id=created["id"], direction="in"),
                    self.owner, self.db))
            self.assertIn("standard template", str(ctx.exception))

    def test_nexus_ignores_requested_acl_kind(self):
        with patch.object(main.svc, "list_acl_names", return_value=[]), \
             patch.object(main.svc, "configure", return_value=(True, "ok", "")) as mock_configure, \
             patch("switch_utils.decrypt_password", return_value="pw"):
            asyncio.run(main.acl_create(
                self._req(acl_kind="standard", implicit_action="permit"),
                self.owner, self.db))
            cmds = mock_configure.call_args[0][2]
        self.assertEqual(cmds, ["ip access-list NEW-ACL", "999 permit ip any any"])

    def test_create_with_template_orders_lines_before_the_implicit_rule(self):
        created = self._create_template(lines=[
            "permit tcp host 10.0.0.1 host 10.0.0.2 eq 22",
            "permit tcp host 10.0.0.3 host 10.0.0.4 eq 23",
        ])
        with patch.object(main.svc, "list_acl_names", return_value=[]), \
             patch.object(main.svc, "get_object_groups", return_value=[]), \
             patch.object(main.svc, "get_time_ranges", return_value=[]), \
             patch.object(main.svc, "configure", return_value=(True, "ok", "")) as mock_configure, \
             patch("switch_utils.decrypt_password", return_value="pw"):
            result = asyncio.run(main.acl_create(
                self._req(template_id=created["id"], direction="in"),
                self.owner, self.db))
            cmds = mock_configure.call_args[0][2]
        self.assertTrue(result["success"])
        self.assertEqual(cmds, [
            "ip access-list NEW-ACL",
            "1 permit tcp host 10.0.0.1 host 10.0.0.2 eq 22",
            "2 permit tcp host 10.0.0.3 host 10.0.0.4 eq 23",
            "999 deny ip any any",
        ])

    def test_template_platform_mismatch_is_rejected(self):
        created = self._create_template(switch_type="ios")
        with patch.object(main.svc, "list_acl_names", return_value=[]), \
             patch("switch_utils.decrypt_password", return_value="pw"):
            with self.assertRaises(ValidationError):
                asyncio.run(main.acl_create(
                    self._req(template_id=created["id"], direction="in"),
                    self.owner, self.db))

    def test_missing_object_group_in_template_blocks_create(self):
        created = self._create_template(
            lines=["permit tcp addrgroup MISSING host 10.0.0.2 eq 22"])
        with patch.object(main.svc, "list_acl_names", return_value=[]), \
             patch.object(main.svc, "get_object_groups", return_value=[]), \
             patch.object(main.svc, "get_time_ranges", return_value=[]), \
             patch("switch_utils.decrypt_password", return_value="pw"):
            with self.assertRaises(ValidationError) as ctx:
                asyncio.run(main.acl_create(
                    self._req(template_id=created["id"], direction="in"),
                    self.owner, self.db))
            self.assertIn("MISSING", str(ctx.exception))

    def test_template_reversed_direction_is_used_when_requested(self):
        created = self._create_template(lines=[
            "permit tcp host 10.0.0.1 host 10.0.0.2 eq 22",
        ])
        with patch.object(main.svc, "list_acl_names", return_value=[]), \
             patch.object(main.svc, "get_object_groups", return_value=[]), \
             patch.object(main.svc, "get_time_ranges", return_value=[]), \
             patch.object(main.svc, "configure", return_value=(True, "ok", "")) as mock_configure, \
             patch("switch_utils.decrypt_password", return_value="pw"):
            asyncio.run(main.acl_create(
                self._req(template_id=created["id"], direction="out"),
                self.owner, self.db))
            cmds = mock_configure.call_args[0][2]
        self.assertEqual(cmds[1], "1 permit tcp host 10.0.0.2 eq 22 host 10.0.0.1")

    def test_preview_returns_commands_without_writing(self):
        with patch.object(main.svc, "list_acl_names", return_value=[]), \
             patch.object(main.svc, "configure") as mock_configure, \
             patch("switch_utils.decrypt_password", return_value="pw"):
            result = asyncio.run(main.acl_create_preview(
                self._req(implicit_action="permit"), self.owner, self.db))
            mock_configure.assert_not_called()
        self.assertEqual(result["commands"], ["ip access-list NEW-ACL", "999 permit ip any any"])
        self.assertEqual(result["acl_name"], "NEW-ACL")

    def test_preview_is_rejected_for_a_duplicate_acl_name_and_generates_nothing(self):
        with patch.object(main.svc, "list_acl_names", return_value=["NEW-ACL"]), \
             patch.object(main.svc, "configure") as mock_configure, \
             patch("switch_utils.decrypt_password", return_value="pw"):
            with self.assertRaises(ValidationError) as ctx:
                asyncio.run(main.acl_create_preview(self._req(), self.owner, self.db))
            mock_configure.assert_not_called()
        self.assertIn("already exists", str(ctx.exception))

    def test_preview_duplicate_check_is_case_insensitive(self):
        with patch.object(main.svc, "list_acl_names", return_value=["new-acl"]), \
             patch("switch_utils.decrypt_password", return_value="pw"):
            with self.assertRaises(ValidationError):
                asyncio.run(main.acl_create_preview(self._req(), self.owner, self.db))


if __name__ == "__main__":
    unittest.main()
