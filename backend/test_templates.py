import asyncio
import json
import unittest
from unittest.mock import patch

from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import acl_parser as ap
import main
import schemas as sch
from database import (Base, User, Switch, Template, TemplateShare,
                      ROLE_ADMIN, ROLE_SUPER_ADMIN, ROLE_USER)
from validators import ValidationError


class InferIosGroupKindsTests(unittest.TestCase):

    def test_protocol_position_is_a_port_group(self):
        kinds = ap._infer_ios_group_kinds("permit object-group MYSVC host 10.0.0.1 host 10.0.0.2")
        self.assertEqual(kinds, {"MYSVC": "port"})

    def test_address_position_is_an_address_group(self):
        kinds = ap._infer_ios_group_kinds("permit tcp object-group MYADDR host 10.0.0.2 eq 22")
        self.assertEqual(kinds, {"MYADDR": "address"})

    def test_both_positions_in_one_line(self):
        kinds = ap._infer_ios_group_kinds(
            "permit object-group MYSVC object-group SRC object-group DST")
        self.assertEqual(kinds, {"MYSVC": "port", "SRC": "address", "DST": "address"})

    def test_plain_line_has_no_groups(self):
        self.assertEqual(ap._infer_ios_group_kinds("permit tcp host 1.1.1.1 host 2.2.2.2"), {})


class ReverseTemplateLineTests(unittest.TestCase):

    def test_plain_line_reverses(self):
        self.assertEqual(
            ap.reverse_template_line("permit tcp host 10.0.0.1 host 10.0.0.2 eq 22", "nexus"),
            "permit tcp host 10.0.0.2 eq 22 host 10.0.0.1")

    def test_ios_object_group_line_returns_none(self):
        self.assertIsNone(ap.reverse_template_line(
            "permit tcp object-group MYADDR host 10.0.0.2 eq 22", "ios"))

    def test_ios_plain_line_still_reverses(self):
        self.assertEqual(
            ap.reverse_template_line("permit tcp host 10.0.0.1 eq 443 host 10.0.0.2", "ios"),
            "permit tcp host 10.0.0.2 host 10.0.0.1 eq 443")

    def test_nxos_addrgroup_reverses_without_real_group_data(self):
        self.assertEqual(
            ap.reverse_template_line("permit tcp addrgroup A portgroup P addrgroup B", "nexus"),
            "permit tcp addrgroup B addrgroup A portgroup P")

    def test_standard_acl_line_is_returned_unchanged(self):
        # No destination to swap with -- "reversing" a standard-ACL line is
        # a no-op, matching plan_acl_reversal()'s treatment of standard ACLs.
        self.assertEqual(
            ap.reverse_template_line("permit 10.0.0.0 0.0.0.255", "ios", "standard"),
            "permit 10.0.0.0 0.0.0.255")


class BuildReversedTemplateLinesTests(unittest.TestCase):

    def test_mixed_ios_template_skips_only_the_group_line(self):
        lines = [
            "permit tcp object-group MYADDR host 10.0.0.2 eq 22",
            "permit tcp host 10.0.0.5 host 10.0.0.6",
        ]
        reversed_lines, skipped = ap.build_reversed_template_lines(lines, "ios")
        self.assertEqual(skipped, 1)
        self.assertEqual(reversed_lines, ["permit tcp host 10.0.0.6 host 10.0.0.5"])

    def test_all_nxos_lines_reverse(self):
        lines = ["permit tcp host 1.1.1.1 host 2.2.2.2", "deny tcp host 3.3.3.3 host 4.4.4.4"]
        reversed_lines, skipped = ap.build_reversed_template_lines(lines, "nexus")
        self.assertEqual(skipped, 0)
        self.assertEqual(len(reversed_lines), 2)

    def test_standard_ios_lines_all_pass_through_unchanged(self):
        lines = ["permit 10.0.0.0 0.0.0.255", "deny host 10.0.0.5", "permit any"]
        reversed_lines, skipped = ap.build_reversed_template_lines(lines, "ios", "standard")
        self.assertEqual(skipped, 0)
        self.assertEqual(reversed_lines, lines)


class FirstEmptySequencesTests(unittest.TestCase):

    def test_empty_acl_starts_at_one(self):
        self.assertEqual(ap.first_empty_sequences([], 2), [1, 2])

    def test_fills_a_real_gap_before_appending_past_the_max(self):
        # 1 and 3 exist, 2 is a genuine gap -- must be used first.
        self.assertEqual(ap.first_empty_sequences([1, 3], 1), [2])

    def test_multiple_rules_fill_every_gap_before_appending(self):
        self.assertEqual(ap.first_empty_sequences([1, 4], 3), [2, 3, 5])

    def test_appends_past_the_max_once_gaps_are_exhausted(self):
        self.assertEqual(ap.first_empty_sequences([1, 2, 3], 2), [4, 5])

    def test_consecutive_existing_seqs_produce_no_early_gap(self):
        self.assertEqual(ap.first_empty_sequences([1, 2], 2), [3, 4])

    def test_low_numbers_below_existing_higher_seqs_are_used_first(self):
        # Existing rules start at 10 -- 1 through 9 are still genuinely
        # empty and must be filled before anything past the max.
        self.assertEqual(ap.first_empty_sequences([10, 20], 3), [1, 2, 3])


class TemplateEndpointTests(unittest.TestCase):
    """DB-backed tests using an in-memory SQLite session, mirroring the
    pattern in test_user_management.py's UsernameUpdateTests."""

    def setUp(self):
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        self.db = sessionmaker(bind=engine)()
        self.owner = User(username="owner1", hashed_password="x", role=ROLE_ADMIN)
        self.super_owner = User(username="superowner", hashed_password="x", role=ROLE_SUPER_ADMIN)
        self.other_admin = User(username="admin2", hashed_password="x", role=ROLE_ADMIN)
        self.plain_user = User(username="user1", hashed_password="x", role=ROLE_USER)
        self.db.add_all((self.owner, self.super_owner, self.other_admin, self.plain_user))
        self.db.commit()
        for u in (self.owner, self.super_owner, self.other_admin, self.plain_user):
            self.db.refresh(u)

    def tearDown(self):
        self.db.close()

    def _create(self, cu, name="MyTemplate", switch_type="nexus", direction="in",
               lines=None, share_with=None, acl_kind="extended"):
        lines = lines if lines is not None else ["permit tcp host 10.0.0.1 host 10.0.0.2 eq 22"]
        return asyncio.run(main.create_template(
            sch.TemplateCreate(name=name, switch_type=switch_type, acl_kind=acl_kind,
                              direction=direction, lines=lines, share_with=share_with or []),
            cu, self.db))

    def test_create_computes_reversed_lines_and_persists(self):
        result = self._create(self.owner)
        self.assertEqual(result["direction"], "in")
        self.assertEqual(result["reversed_lines"],
                         ["permit tcp host 10.0.0.2 eq 22 host 10.0.0.1"])
        self.assertEqual(result["skipped_reversal_count"], 0)
        self.assertTrue(result["is_owner"])
        row = self.db.query(Template).filter(Template.name == "MyTemplate").one()
        self.assertEqual(json.loads(row.lines), ["permit tcp host 10.0.0.1 host 10.0.0.2 eq 22"])

    def test_invalid_line_rejects_the_whole_create(self):
        with self.assertRaises(ValidationError):
            self._create(self.owner, lines=["this is not a valid rule"])
        self.assertEqual(self.db.query(Template).count(), 0)

    def test_permit_prefixed_but_structurally_invalid_line_is_rejected(self):
        # Starts with "permit " (passes the old, weak check) but the rest
        # isn't real Cisco ACL syntax at all — must still be rejected.
        with self.assertRaises(ValidationError) as ctx:
            self._create(self.owner, lines=["permit askjdklajd not a real rule"])
        self.assertIn("Line 1", str(ctx.exception))
        self.assertEqual(self.db.query(Template).count(), 0)

    def test_valid_ios_object_group_line_still_passes_validation(self):
        # A real, structurally valid IOS rule with a group reference must
        # NOT be rejected by the stricter parse check.
        result = self._create(self.owner, switch_type="ios",
                              lines=["permit tcp object-group MYADDR host 10.0.0.2 eq 22"])
        self.assertEqual(result["lines"], ["permit tcp object-group MYADDR host 10.0.0.2 eq 22"])

    def test_ios_standard_template_accepts_standard_syntax(self):
        result = self._create(self.owner, switch_type="ios", acl_kind="standard",
                              lines=["permit 10.0.0.0 0.0.0.255", "deny host 10.0.0.5"])
        self.assertEqual(result["acl_kind"], "standard")
        self.assertEqual(result["lines"], ["permit 10.0.0.0 0.0.0.255", "deny host 10.0.0.5"])
        # A standard-ACL line has nothing to reverse -- both directions
        # are the same content.
        self.assertEqual(result["reversed_lines"], result["lines"])
        self.assertEqual(result["skipped_reversal_count"], 0)

    def test_ios_standard_template_rejects_extended_syntax(self):
        with self.assertRaises(ValidationError) as ctx:
            self._create(self.owner, switch_type="ios", acl_kind="standard",
                        lines=["permit tcp host 10.0.0.1 host 10.0.0.2 eq 22"])
        self.assertIn("Line 1", str(ctx.exception))

    def test_ios_extended_template_rejects_standard_only_syntax(self):
        # No protocol/destination at all -- valid only as a standard rule.
        with self.assertRaises(ValidationError):
            self._create(self.owner, switch_type="ios", acl_kind="extended",
                        lines=["permit 10.0.0.0 0.0.0.255"])

    def test_nexus_template_forces_extended_regardless_of_requested_kind(self):
        result = self._create(self.owner, switch_type="nexus", acl_kind="standard")
        self.assertEqual(result["acl_kind"], "extended")

    def test_invalid_acl_kind_is_rejected(self):
        with self.assertRaises(ValidationError):
            self._create(self.owner, switch_type="ios", acl_kind="weird")

    def test_plain_admin_can_share_with_another_admin(self):
        result = self._create(self.owner, share_with=["admin2"])
        self.assertEqual(result["shared_with"], ["admin2"])
        share = self.db.query(TemplateShare).one()
        self.assertEqual(share.username, "admin2")

    def test_plain_admin_can_share_with_a_super_admin(self):
        result = self._create(self.owner, share_with=["superowner"])
        self.assertEqual(result["shared_with"], ["superowner"])

    def test_super_admin_share_with_non_admin_is_rejected(self):
        with self.assertRaises(ValidationError):
            self._create(self.super_owner, share_with=["user1"])

    def test_super_admin_share_with_nonexistent_user_is_rejected(self):
        with self.assertRaises(ValidationError):
            self._create(self.super_owner, share_with=["ghost"])

    def test_super_admin_share_with_valid_admin_creates_share_row(self):
        result = self._create(self.super_owner, share_with=["admin2"])
        self.assertEqual(result["shared_with"], ["admin2"])
        share = self.db.query(TemplateShare).one()
        self.assertEqual(share.username, "admin2")

    def test_shared_with_user_cannot_edit_or_delete(self):
        created = self._create(self.super_owner, share_with=["admin2"])
        with self.assertRaises(HTTPException) as ctx:
            asyncio.run(main.update_template(
                created["id"],
                sch.TemplateUpdate(name="Hacked", switch_type="nexus", direction="in",
                                  lines=["permit ip any any"]),
                self.other_admin, self.db))
        self.assertEqual(ctx.exception.status_code, 403)
        with self.assertRaises(HTTPException) as ctx2:
            asyncio.run(main.delete_template(created["id"], self.other_admin, self.db))
        self.assertEqual(ctx2.exception.status_code, 403)

    def test_name_collision_with_owners_own_template_is_rejected(self):
        self._create(self.owner, name="Dup")
        with self.assertRaises(ValidationError) as ctx:
            self._create(self.owner, name="Dup", lines=["permit ip any any"])
        self.assertIn("already have a template named", str(ctx.exception))

    def test_name_collision_with_a_share_recipients_own_template_is_rejected(self):
        # admin2 already owns a template called "Dup" -- sharing a new,
        # different "Dup" template with them must be rejected.
        self._create(self.other_admin, name="Dup")
        with self.assertRaises(ValidationError) as ctx:
            self._create(self.super_owner, name="Dup", share_with=["admin2"])
        self.assertIn("admin2", str(ctx.exception))
        self.assertIn("already has a template named", str(ctx.exception))

    def test_name_collision_with_a_share_recipients_shared_template_is_rejected(self):
        # admin2 already has "Dup" shared with them by super_owner; sharing
        # ANOTHER unrelated "Dup" template with admin2 (from a different
        # owner) must also be rejected.
        third_super = User(username="thirdsuper", hashed_password="x", role=ROLE_SUPER_ADMIN)
        self.db.add(third_super)
        self.db.commit()
        self.db.refresh(third_super)
        self._create(self.super_owner, name="Dup", share_with=["admin2"])
        with self.assertRaises(ValidationError):
            self._create(third_super, name="Dup", share_with=["admin2"])

    def test_ios_object_group_line_produces_skipped_count(self):
        result = self._create(self.owner, switch_type="ios",
                              lines=["permit tcp object-group MYADDR host 10.0.0.2 eq 22"])
        self.assertEqual(result["reversed_lines"], [])
        self.assertEqual(result["skipped_reversal_count"], 1)

    def test_list_shows_owned_and_shared_templates(self):
        self._create(self.super_owner, name="Owned", share_with=["admin2"])
        self._create(self.super_owner, name="NotShared")
        owner_list = asyncio.run(main.list_templates(self.super_owner, self.db))
        self.assertEqual({t["name"] for t in owner_list["templates"]}, {"Owned", "NotShared"})
        shared_list = asyncio.run(main.list_templates(self.other_admin, self.db))
        names = {t["name"] for t in shared_list["templates"]}
        self.assertEqual(names, {"Owned"})
        self.assertFalse(shared_list["templates"][0]["is_owner"])

    def test_non_owner_cannot_update(self):
        created = self._create(self.owner)
        with self.assertRaises(HTTPException) as ctx:
            asyncio.run(main.update_template(
                created["id"],
                sch.TemplateUpdate(name="Hacked", switch_type="nexus", direction="in",
                                  lines=["permit ip any any"]),
                self.other_admin, self.db))
        self.assertEqual(ctx.exception.status_code, 403)

    def test_owner_can_update_and_reversed_lines_recompute(self):
        created = self._create(self.owner)
        updated = asyncio.run(main.update_template(
            created["id"],
            sch.TemplateUpdate(name="Renamed", switch_type="nexus", direction="in",
                              lines=["permit tcp host 5.5.5.5 host 6.6.6.6 eq 80"]),
            self.owner, self.db))
        self.assertEqual(updated["name"], "Renamed")
        self.assertEqual(updated["reversed_lines"],
                         ["permit tcp host 6.6.6.6 eq 80 host 5.5.5.5"])

    def test_non_owner_cannot_delete(self):
        created = self._create(self.owner)
        with self.assertRaises(HTTPException) as ctx:
            asyncio.run(main.delete_template(created["id"], self.other_admin, self.db))
        self.assertEqual(ctx.exception.status_code, 403)

    def test_owner_can_delete_and_shares_are_cleaned_up(self):
        created = self._create(self.super_owner, share_with=["admin2"])
        asyncio.run(main.delete_template(created["id"], self.super_owner, self.db))
        self.assertEqual(self.db.query(Template).count(), 0)
        self.assertEqual(self.db.query(TemplateShare).count(), 0)

    def test_share_candidates_excludes_self_and_non_admins(self):
        result = asyncio.run(main.template_share_candidates(self.owner, self.db))
        usernames = {u["username"] for u in result["users"]}
        self.assertEqual(usernames, {"admin2", "superowner"})

    def test_username_rename_migrates_template_ownership_and_shares(self):
        created = self._create(self.super_owner, share_with=["admin2"])
        # A super admin can only rename themselves (existing app rule), so
        # the acting user here must be super_owner, not a different admin.
        asyncio.run(main.update_username(
            self.super_owner.id, sch.UsernameUpdate(username="renamedowner"),
            self.super_owner, self.db))
        row = self.db.query(Template).filter(Template.id == created["id"]).one()
        self.assertEqual(row.owner_username, "renamedowner")

    def test_deleting_owner_cascades_templates_and_shares(self):
        self._create(self.super_owner, share_with=["admin2"])
        acting_admin = User(username="root", hashed_password="x",
                           role=ROLE_SUPER_ADMIN, id=999)
        asyncio.run(main.delete_user(self.super_owner.id, acting_admin, self.db))
        self.assertEqual(self.db.query(Template).count(), 0)
        self.assertEqual(self.db.query(TemplateShare).count(), 0)


class ApplyTemplateTests(unittest.TestCase):
    """Mocks switch_service the same way test_vpc_sync.py's
    AclSeqMapForSyncFallbackTests does, since apply_template() needs a
    live-switch round trip for ACL kind / object-groups / time-ranges."""

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
        self.db.add(self.switch)
        self.db.commit()
        self.db.refresh(self.switch)

    def tearDown(self):
        self.db.close()

    def _create(self, switch_type="nexus", lines=None, acl_kind="extended"):
        lines = lines or ["permit tcp host 10.0.0.1 host 10.0.0.2 eq 22"]
        return asyncio.run(main.create_template(
            sch.TemplateCreate(name="T1", switch_type=switch_type, acl_kind=acl_kind,
                              direction="in", lines=lines, share_with=[]),
            self.owner, self.db))

    def test_platform_mismatch_is_rejected(self):
        created = self._create(switch_type="ios")
        with patch("switch_utils.decrypt_password", return_value="pw"):
            with self.assertRaises(ValidationError):
                asyncio.run(main.apply_template(
                    sch.TemplateApplyRequest(template_id=created["id"], switch_id=self.switch.id,
                                            acl_name="TEST", direction="in"),
                    self.owner, self.db))

    def test_standard_acl_is_rejected(self):
        created = self._create()
        with patch.object(main.svc, "get_acl_kind", return_value="standard"), \
             patch("switch_utils.decrypt_password", return_value="pw"):
            with self.assertRaises(ValidationError):
                asyncio.run(main.apply_template(
                    sch.TemplateApplyRequest(template_id=created["id"], switch_id=self.switch.id,
                                            acl_name="TEST", direction="in"),
                    self.owner, self.db))

    def test_standard_template_applies_to_a_standard_acl(self):
        ios_switch = Switch(ip_address="10.1.1.2", hostname="ios1",
                            switch_type="ios", owner_username="owner1",
                            saved_password="enc", ssh_username="netadmin")
        self.db.add(ios_switch)
        self.db.commit()
        self.db.refresh(ios_switch)
        created = self._create(switch_type="ios", acl_kind="standard",
                              lines=["permit 10.0.0.0 0.0.0.255"])
        with patch.object(main.svc, "get_acl_kind", return_value="standard"), \
             patch.object(main.svc, "get_object_groups", return_value=[]), \
             patch.object(main.svc, "get_time_ranges", return_value=[]), \
             patch.object(main.svc, "get_acl_rules", return_value=("", [])), \
             patch.object(main.svc, "configure", return_value=(True, "ok", "")) as mock_configure, \
             patch("switch_utils.decrypt_password", return_value="pw"):
            result = asyncio.run(main.apply_template(
                sch.TemplateApplyRequest(template_id=created["id"], switch_id=ios_switch.id,
                                        acl_name="TEST", direction="in"),
                self.owner, self.db))
            cmds = mock_configure.call_args[0][2]
        self.assertTrue(result["success"])
        self.assertEqual(cmds, ["ip access-list standard TEST", "1 permit 10.0.0.0 0.0.0.255"])

    def test_standard_template_cannot_apply_to_an_extended_acl(self):
        ios_switch = Switch(ip_address="10.1.1.3", hostname="ios2",
                            switch_type="ios", owner_username="owner1",
                            saved_password="enc", ssh_username="netadmin")
        self.db.add(ios_switch)
        self.db.commit()
        self.db.refresh(ios_switch)
        created = self._create(switch_type="ios", acl_kind="standard",
                              lines=["permit 10.0.0.0 0.0.0.255"])
        with patch.object(main.svc, "get_acl_kind", return_value="extended"), \
             patch("switch_utils.decrypt_password", return_value="pw"):
            with self.assertRaises(ValidationError) as ctx:
                asyncio.run(main.apply_template(
                    sch.TemplateApplyRequest(template_id=created["id"], switch_id=ios_switch.id,
                                            acl_name="TEST", direction="in"),
                    self.owner, self.db))
            self.assertIn("standard template", str(ctx.exception))

    def test_missing_object_group_blocks_apply(self):
        created = self._create(lines=["permit tcp addrgroup MISSING host 10.0.0.2 eq 22"])
        with patch.object(main.svc, "get_acl_kind", return_value="extended"), \
             patch.object(main.svc, "get_object_groups", return_value=[]), \
             patch.object(main.svc, "get_time_ranges", return_value=[]), \
             patch("switch_utils.decrypt_password", return_value="pw"):
            with self.assertRaises(ValidationError) as ctx:
                asyncio.run(main.apply_template(
                    sch.TemplateApplyRequest(template_id=created["id"], switch_id=self.switch.id,
                                            acl_name="TEST", direction="in"),
                    self.owner, self.db))
            self.assertIn("MISSING", str(ctx.exception))

    def test_successful_apply_assigns_first_empty_seqs_after_a_dense_run(self):
        created = self._create(lines=[
            "permit tcp host 10.0.0.1 host 10.0.0.2 eq 22",
            "permit tcp host 10.0.0.3 host 10.0.0.4 eq 23",
        ])
        with patch.object(main.svc, "get_acl_kind", return_value="extended"), \
             patch.object(main.svc, "get_object_groups", return_value=[]), \
             patch.object(main.svc, "get_time_ranges", return_value=[]), \
             patch.object(main.svc, "get_acl_rules",
                         return_value=("", ["1 permit ip any any", "2 deny ip any any"])), \
             patch.object(main.svc, "configure", return_value=(True, "ok", "")) as mock_configure, \
             patch("switch_utils.decrypt_password", return_value="pw"):
            result = asyncio.run(main.apply_template(
                sch.TemplateApplyRequest(template_id=created["id"], switch_id=self.switch.id,
                                        acl_name="TEST", direction="in"),
                self.owner, self.db))
            cmds = mock_configure.call_args[0][2]
        self.assertTrue(result["success"])
        self.assertEqual(cmds[1], "3 permit tcp host 10.0.0.1 host 10.0.0.2 eq 22")
        self.assertEqual(cmds[2], "4 permit tcp host 10.0.0.3 host 10.0.0.4 eq 23")
        self.assertEqual(result["undo_commands"][1:], ["no 3", "no 4"])

    def test_apply_fills_a_real_gap_between_existing_rules_first(self):
        # Existing rules jump 1 -> 3, leaving 2 genuinely empty — the
        # template's one line must land there, not appended past 3.
        created = self._create()
        with patch.object(main.svc, "get_acl_kind", return_value="extended"), \
             patch.object(main.svc, "get_object_groups", return_value=[]), \
             patch.object(main.svc, "get_time_ranges", return_value=[]), \
             patch.object(main.svc, "get_acl_rules",
                         return_value=("", ["1 permit ip any any", "3 deny ip any any"])), \
             patch.object(main.svc, "configure", return_value=(True, "ok", "")) as mock_configure, \
             patch("switch_utils.decrypt_password", return_value="pw"):
            asyncio.run(main.apply_template(
                sch.TemplateApplyRequest(template_id=created["id"], switch_id=self.switch.id,
                                        acl_name="TEST", direction="in"),
                self.owner, self.db))
            cmds = mock_configure.call_args[0][2]
        self.assertEqual(cmds[1], "2 permit tcp host 10.0.0.1 host 10.0.0.2 eq 22")

    def test_apply_fills_low_seqs_before_an_existing_higher_run(self):
        # Existing rules start at 10 -- 1..9 are still genuinely empty and
        # must be used before anything past the max.
        created = self._create()
        with patch.object(main.svc, "get_acl_kind", return_value="extended"), \
             patch.object(main.svc, "get_object_groups", return_value=[]), \
             patch.object(main.svc, "get_time_ranges", return_value=[]), \
             patch.object(main.svc, "get_acl_rules",
                         return_value=("", ["10 permit ip any any", "20 deny ip any any"])), \
             patch.object(main.svc, "configure", return_value=(True, "ok", "")) as mock_configure, \
             patch("switch_utils.decrypt_password", return_value="pw"):
            asyncio.run(main.apply_template(
                sch.TemplateApplyRequest(template_id=created["id"], switch_id=self.switch.id,
                                        acl_name="TEST", direction="in"),
                self.owner, self.db))
            cmds = mock_configure.call_args[0][2]
        self.assertEqual(cmds[1], "1 permit tcp host 10.0.0.1 host 10.0.0.2 eq 22")

    def test_preview_returns_commands_without_writing(self):
        created = self._create(lines=[
            "permit tcp host 10.0.0.1 host 10.0.0.2 eq 22",
            "permit tcp host 10.0.0.3 host 10.0.0.4 eq 23",
        ])
        with patch.object(main.svc, "get_acl_kind", return_value="extended"), \
             patch.object(main.svc, "get_object_groups", return_value=[]), \
             patch.object(main.svc, "get_time_ranges", return_value=[]), \
             patch.object(main.svc, "get_acl_rules",
                         return_value=("", ["1 permit ip any any"])), \
             patch.object(main.svc, "configure") as mock_configure, \
             patch("switch_utils.decrypt_password", return_value="pw"):
            result = asyncio.run(main.template_apply_preview(
                sch.TemplateApplyRequest(template_id=created["id"], switch_id=self.switch.id,
                                        acl_name="TEST", direction="in"),
                self.owner, self.db))
            mock_configure.assert_not_called()
        self.assertEqual(result["commands"][1], "2 permit tcp host 10.0.0.1 host 10.0.0.2 eq 22")
        self.assertEqual(result["commands"][2], "3 permit tcp host 10.0.0.3 host 10.0.0.4 eq 23")


if __name__ == "__main__":
    unittest.main()
