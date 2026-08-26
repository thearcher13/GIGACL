import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import main
import schemas as sch
from database import AuditLog, Base, Switch, User, ROLE_USER
from validators import ValidationError


class FakeTarget:
    def __init__(self, switch):
        self.id = switch.id
        self.ip = switch.ip_address
        self.label = switch.hostname or switch.ip_address
        self.type = (switch.switch_type or "ios").lower()
        self.is_nexus = self.type == "nexus"


class GlobalIpLookupTests(unittest.TestCase):
    def setUp(self):
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        self.db = sessionmaker(bind=engine)()
        self.user = User(username="viewer", hashed_password="x", role=ROLE_USER)
        self.db.add(self.user)
        self.db.add_all([
            Switch(ip_address="10.0.0.1", hostname="edge-a", switch_type="nexus",
                   owner_username="viewer", vpc_peer_id=2),
            Switch(ip_address="10.0.0.2", hostname="edge-b", switch_type="nexus",
                   owner_username="viewer", vpc_peer_id=1),
        ])
        self.db.commit()

    def tearDown(self):
        self.db.close()

    def test_global_lookup_returns_gateway_acl_and_writes_log(self):
        switches = {switch.id: switch for switch in self.db.query(Switch).all()}

        def resolve(ids, username, db):
            return [FakeTarget(switches[ids[0]])]

        def route(target, username, ip):
            return {"on_switch": target.id == 1,
                    "vlan": "Vlan100" if target.id == 1 else None,
                    "interface": None, "raw": "route output"}

        with patch.object(main.svc, "resolve_targets", side_effect=resolve), \
             patch.object(main.acls, "resolve_route", side_effect=route), \
             patch.object(main.svc, "get_interface_acls",
                          return_value=[{"acl_name": "CLIENTS", "direction": "in"}]), \
             patch.object(main.svc, "get_acl_rules",
                          return_value=("", ["10 permit ip any any"])):
            result = asyncio.run(main.check_ip_global(
                sch.GlobalIPACLCheckRequest(ip_address="192.168.1.25"),
                self.user, self.db))

        self.assertEqual(result["gateway_count"], 1)
        self.assertEqual(result["acl_switch_count"], 1)
        self.assertEqual(result["switches"][0]["acls"][0]["acl_name"], "CLIENTS")
        log = self.db.query(AuditLog).one()
        self.assertIn("Global IP ACL lookup", log.message)
        self.assertIn("192.168.1.25", log.message)

    def test_global_lookup_rejects_non_host_input(self):
        with self.assertRaises(ValidationError):
            asyncio.run(main.check_ip_global(
                sch.GlobalIPACLCheckRequest(ip_address="192.168.1.0/24"),
                self.user, self.db))

    def test_unsaved_state_matches_an_available_log_undo_action(self):
        switch = self.db.query(Switch).filter(Switch.id == 1).one()
        partial = AuditLog(
            username="viewer", switch_id=switch.id, message="Legacy change",
            level="SUCCESS", undo_commands='["no 10"]', undo_label=None)
        self.db.add(partial)
        self.db.commit()

        response = main._switch_out(switch, {switch.id: switch}, self.db)
        self.assertFalse(response.pending_changes)

        partial.undo_label = "remove rule 10"
        self.db.commit()
        response = main._switch_out(switch, {switch.id: switch}, self.db)
        self.assertTrue(response.pending_changes)

        partial.undo_commands = None
        partial.undo_label = None
        self.db.commit()
        response = main._switch_out(switch, {switch.id: switch}, self.db)
        self.assertFalse(response.pending_changes)

    def test_successful_save_creates_switch_specific_checkpoint_log(self):
        action = AuditLog(
            username="viewer", switch_id=1, message="Added rule 10",
            level="SUCCESS", undo_commands='["no 10"]',
            undo_label="remove rule 10")
        self.db.add(action)
        self.db.commit()
        target = SimpleNamespace(
            id=1, label="edge-a", enable_password=None)
        with patch.object(main.svc, "resolve_targets", return_value=[target]), \
             patch.object(main.svc, "run_with_confirm", return_value="Copy complete"), \
             patch.object(main.ssh_manager, "detect_switch_error", return_value=None):
            result = asyncio.run(main.save_config(
                sch.SaveConfigRequest(switch_ids=[1]), self.user, self.db))

        self.assertTrue(result["success"])
        saved = self.db.query(AuditLog).filter(
            AuditLog.message == "Saved configuration on edge-a").one()
        self.assertEqual(saved.switch_id, 1)
        self.db.refresh(action)
        self.assertEqual(action.undo_commands, '["no 10"]')
        switch = self.db.query(Switch).filter(Switch.id == 1).one()
        response = main._switch_out(switch, {switch.id: switch}, self.db)
        self.assertFalse(response.pending_changes)

    def test_log_undo_remains_available_after_save_and_marks_unsaved(self):
        switch = self.db.query(Switch).filter(Switch.id == 1).one()
        action = AuditLog(
            username="viewer", switch_id=switch.id, message="Added rule 10",
            level="SUCCESS", undo_commands='["ip access-list extended EDGE", "no 10"]',
            undo_label="remove rule 10")
        self.db.add(action)
        self.db.commit()
        self.db.add(AuditLog(
            username="viewer", switch_id=switch.id,
            message="Saved configuration on edge-a", level="SUCCESS"))
        self.db.commit()

        with patch("main.get_switch_and_password",
                   return_value=(switch, "password", None)), \
             patch.object(main.svc, "configure",
                          return_value=(True, "Undo complete", "")):
            result = asyncio.run(main.undo_from_log(
                sch.UndoFromLogRequest(log_id=action.id), self.user, self.db))

        self.assertIn("UNSAVED", result["message"])
        self.db.refresh(action)
        self.assertIsNone(action.undo_commands)
        self.assertIsNotNone(self.db.get(AuditLog, action.id))
        response = main._switch_out(switch, {switch.id: switch}, self.db)
        self.assertTrue(response.pending_changes)

    def test_undo_after_save_marks_switch_unsaved(self):
        switch = self.db.query(Switch).filter(Switch.id == 1).one()
        self.db.add(AuditLog(
            username="viewer", switch_id=switch.id,
            message="Saved configuration on edge-a", level="SUCCESS"))
        self.db.commit()

        with patch("main.get_switch_and_password",
                   return_value=(switch, "password", None)), \
             patch.object(main.svc, "configure",
                          return_value=(True, "Undo complete", "")):
            result = asyncio.run(main.undo(
                sch.UndoRequest(
                    switch_id=switch.id,
                    commands=["ip access-list extended EDGE", "no 10"],
                    label="remove rule 10"),
                self.user, self.db))

        self.assertIn("UNSAVED", result["message"])
        response = main._switch_out(switch, {switch.id: switch}, self.db)
        self.assertTrue(response.pending_changes)
        undo_log = self.db.query(AuditLog).filter(
            AuditLog.message == "Undid a saved change on edge-a").one()
        self.assertEqual(undo_log.switch_id, switch.id)

    def test_new_save_checkpoint_clears_post_save_undo_state(self):
        switch = self.db.query(Switch).filter(Switch.id == 1).one()
        self.db.add(AuditLog(
            username="viewer", switch_id=switch.id,
            message="Saved configuration on edge-a", level="SUCCESS"))
        self.db.commit()
        self.db.add(AuditLog(
            username="viewer", switch_id=switch.id,
            message="Undid a saved change on edge-a", level="WARN"))
        self.db.commit()
        response = main._switch_out(switch, {switch.id: switch}, self.db)
        self.assertTrue(response.pending_changes)

        self.db.add(AuditLog(
            username="viewer", switch_id=switch.id,
            message="Saved configuration on edge-a", level="SUCCESS"))
        self.db.commit()
        response = main._switch_out(switch, {switch.id: switch}, self.db)
        self.assertFalse(response.pending_changes)


if __name__ == "__main__":
    unittest.main()
