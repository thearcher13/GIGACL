import asyncio
import unittest
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import main
import schemas as sch
from database import Base, User, Switch, ROLE_ADMIN
from validators import ValidationError

IFACE_IN = """interface Vlan10
 ip address 10.0.0.1 255.255.255.0
 ip access-group EDGE in
"""
IFACE_OUT = """interface Vlan10
 ip address 10.0.0.1 255.255.255.0
 ip access-group EDGE out
"""
IFACE_BOTH = """interface Vlan10
 ip address 10.0.0.1 255.255.255.0
 ip access-group EDGE in
 ip access-group OTHER out
"""


class FlipAclInterfaceTests(unittest.TestCase):
    """Moving a binding between in and out. Both commands go in one config
    session so the interface is never left with no ACL at all."""

    def setUp(self):
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        self.db = sessionmaker(bind=engine)()
        self.owner = User(username="owner1", hashed_password="x", role=ROLE_ADMIN)
        self.db.add(self.owner)
        self.db.commit()
        self.db.refresh(self.owner)
        self.switch = Switch(ip_address="10.1.1.1", hostname="sw1",
                             switch_type="ios", owner_username="owner1",
                             saved_password="enc", ssh_username="netadmin")
        self.db.add(self.switch)
        self.db.commit()
        self.db.refresh(self.switch)

    def tearDown(self):
        self.db.close()

    def _req(self, direction="in", iface="Vlan10", acl="EDGE"):
        return sch.ACLInterfaceFlipRequest(
            switch_id=self.switch.id, acl_name=acl, interface=iface, direction=direction)

    def _run(self, show_side_effect, configure_result=(True, "ok", "")):
        with patch.object(main.svc, "show", side_effect=show_side_effect), \
             patch.object(main.svc, "configure", return_value=configure_result) as cfg, \
             patch("switch_utils.decrypt_password", return_value="pw"):
            result = asyncio.run(main.flip_acl_interface(self._req(), self.owner, self.db))
            return result, cfg

    def test_successful_flip_sends_remove_then_add_in_one_session(self):
        result, cfg = self._run([IFACE_IN, IFACE_OUT])
        self.assertTrue(result["success"])
        self.assertEqual(result["direction"], "out")
        cmds = cfg.call_args_list[0][0][2]
        self.assertEqual(cmds, ["interface Vlan10",
                                "no ip access-group EDGE in",
                                "ip access-group EDGE out"])

    def test_successful_flip_offers_the_reverse_as_undo(self):
        result, _ = self._run([IFACE_IN, IFACE_OUT])
        self.assertEqual(result["undo_commands"],
                         ["interface Vlan10",
                          "no ip access-group EDGE out",
                          "ip access-group EDGE in"])

    def test_flip_out_to_in(self):
        with patch.object(main.svc, "show", side_effect=[IFACE_OUT, IFACE_IN]), \
             patch.object(main.svc, "configure", return_value=(True, "ok", "")) as cfg, \
             patch("switch_utils.decrypt_password", return_value="pw"):
            result = asyncio.run(main.flip_acl_interface(
                self._req(direction="out"), self.owner, self.db))
        self.assertTrue(result["success"])
        self.assertEqual(cfg.call_args_list[0][0][2][1], "no ip access-group EDGE out")

    def test_missing_interface_sends_nothing(self):
        with patch.object(main.svc, "show", return_value="interface Vlan99 not found"), \
             patch.object(main.svc, "configure") as cfg, \
             patch("switch_utils.decrypt_password", return_value="pw"):
            with self.assertRaises(ValidationError):
                asyncio.run(main.flip_acl_interface(self._req(), self.owner, self.db))
            cfg.assert_not_called()

    def test_binding_not_present_in_that_direction_is_rejected(self):
        # Someone changed it underneath us; acting would be wrong.
        with patch.object(main.svc, "show", return_value=IFACE_OUT), \
             patch.object(main.svc, "configure") as cfg, \
             patch("switch_utils.decrypt_password", return_value="pw"):
            with self.assertRaises(ValidationError) as ctx:
                asyncio.run(main.flip_acl_interface(self._req(), self.owner, self.db))
            cfg.assert_not_called()
        self.assertIn("not applied", str(ctx.exception))

    def test_target_direction_occupied_by_another_acl_is_rejected(self):
        with patch.object(main.svc, "show", return_value=IFACE_BOTH), \
             patch.object(main.svc, "configure") as cfg, \
             patch("switch_utils.decrypt_password", return_value="pw"):
            with self.assertRaises(ValidationError) as ctx:
                asyncio.run(main.flip_acl_interface(self._req(), self.owner, self.db))
            cfg.assert_not_called()
        self.assertIn("OTHER", str(ctx.exception))

    def test_rejected_command_rolls_back(self):
        with patch.object(main.svc, "show", side_effect=[IFACE_IN]), \
             patch.object(main.svc, "configure",
                          return_value=(False, "out", "rejected")) as cfg, \
             patch("switch_utils.decrypt_password", return_value="pw"):
            result = asyncio.run(main.flip_acl_interface(self._req(), self.owner, self.db))
        self.assertFalse(result["success"])
        # Second configure call is the rollback.
        self.assertEqual(cfg.call_args_list[-1][0][2],
                         ["interface Vlan10",
                          "no ip access-group EDGE out",
                          "ip access-group EDGE in"])

    def test_unverified_change_rolls_back(self):
        # Switch accepted the command but the binding did not actually move.
        with patch.object(main.svc, "show", side_effect=[IFACE_IN, IFACE_IN]), \
             patch.object(main.svc, "configure", return_value=(True, "ok", "")) as cfg, \
             patch("switch_utils.decrypt_password", return_value="pw"):
            result = asyncio.run(main.flip_acl_interface(self._req(), self.owner, self.db))
        self.assertFalse(result["success"])
        self.assertEqual(len(cfg.call_args_list), 2)
        self.assertIn("restored", result["message"])

    def test_invalid_direction_is_rejected(self):
        with self.assertRaises(ValidationError):
            asyncio.run(main.flip_acl_interface(
                sch.ACLInterfaceFlipRequest(
                    switch_id=self.switch.id, acl_name="EDGE",
                    interface="Vlan10", direction="sideways"),
                self.owner, self.db))


if __name__ == "__main__":
    unittest.main()
