import asyncio
import unittest
from unittest.mock import patch

from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import main
import schemas as sch
import switch_service as svc
import ssh_manager
from database import (Base, Switch, User, ACCESS_READ, ACCESS_WRITE,
                      ROLE_USER, ROLE_ADMIN, ROLE_SUPER_ADMIN)
from switch_utils import encrypt_password
from validators import ValidationError


class _FakeSwitch:
    """Just enough of a Switch row for SwitchTarget's passthroughs."""

    def __init__(self, access_level=ACCESS_WRITE):
        self.id = 1
        self.ip_address = "10.0.0.1"
        self.hostname = "edge-a"
        self.switch_type = "ios"
        self.use_enable = False
        self.access_level = access_level


def _target(access_level=ACCESS_WRITE):
    return svc.SwitchTarget(_FakeSwitch(access_level), "pw", "amir")


class WriteAccessGuardTests(unittest.TestCase):
    """The guard sits where commands are actually sent, so no endpoint can
    forget it."""

    def test_a_write_switch_is_allowed(self):
        svc.require_write_access(_target(ACCESS_WRITE))   # must not raise

    def test_a_read_only_switch_is_refused(self):
        with self.assertRaises(svc.ReadOnlyAccessError) as caught:
            svc.require_write_access(_target(ACCESS_READ))
        self.assertIn("read-only", str(caught.exception))
        self.assertIn("edge-a", str(caught.exception))

    def test_a_missing_level_defaults_to_write(self):
        # Every switch that existed before this feature must keep working.
        t = _target(None)
        self.assertTrue(t.can_write)
        svc.require_write_access(t)

    def test_configure_refuses_before_opening_a_connection(self):
        with patch.object(ssh_manager, "run_config") as run_config:
            with self.assertRaises(svc.ReadOnlyAccessError):
                svc.configure(_target(ACCESS_READ), "amir", ["no 10"])
            run_config.assert_not_called()

    def test_saving_the_config_is_a_write(self):
        # It changes what the device boots with, so read-only must refuse it.
        with patch.object(ssh_manager, "run_command_with_confirm") as run:
            with self.assertRaises(svc.ReadOnlyAccessError):
                svc.run_with_confirm(_target(ACCESS_READ), "amir",
                                     "copy running-config startup-config")
            run.assert_not_called()

    def test_reads_are_unaffected(self):
        with patch.object(ssh_manager, "run_command", return_value="output"):
            self.assertEqual(
                svc.show(_target(ACCESS_READ), "amir", "show ip access-lists"),
                "output")


class GrantConflictTests(unittest.TestCase):
    """The three conflict cases, which behave deliberately differently."""

    def setUp(self):
        self.boss = User(username="boss", hashed_password="x",
                         role=ROLE_SUPER_ADMIN)
        self.peer = User(username="peer", hashed_password="x",
                         role=ROLE_SUPER_ADMIN)
        self.admin = User(username="admin1", hashed_password="x", role=ROLE_ADMIN)

    def conflict(self, existing, holder, overwrite=False):
        return main._conflict_for(existing, holder, self.boss, overwrite)

    def test_no_existing_row_is_never_a_conflict(self):
        self.assertIsNone(self.conflict(None, self.admin))

    def test_a_switch_the_holder_added_themselves_is_refused(self):
        row = Switch(ip_address="10.0.0.1", owner_username="admin1",
                     created_by=None)
        message = self.conflict(row, self.admin)
        self.assertIn("already added this switch themselves", message)
        self.assertIn("admin1", message)

    def test_confirming_does_not_override_someone_s_own_switch(self):
        # The one case that must never be taken over, whatever is confirmed.
        row = Switch(ip_address="10.0.0.1", owner_username="admin1",
                     created_by=None)
        self.assertIsNotNone(self.conflict(row, self.admin, overwrite=True))

    def test_another_super_admin_s_own_switch_is_refused(self):
        row = Switch(ip_address="10.0.0.1", owner_username="peer",
                     created_by=None)
        message = self.conflict(row, self.peer, overwrite=True)
        self.assertIn("super admin", message)

    def test_a_grant_from_another_super_admin_asks_for_confirmation(self):
        row = Switch(ip_address="10.0.0.1", owner_username="admin1",
                     created_by="someone-else")
        message = self.conflict(row, self.admin)
        self.assertIn("Confirm to take it over", message)

    def test_and_is_taken_over_once_confirmed(self):
        row = Switch(ip_address="10.0.0.1", owner_username="admin1",
                     created_by="someone-else")
        self.assertIsNone(self.conflict(row, self.admin, overwrite=True))

    def test_your_own_grant_is_yours_to_change(self):
        row = Switch(ip_address="10.0.0.1", owner_username="admin1",
                     created_by="boss")
        self.assertIsNone(self.conflict(row, self.admin))

    def test_your_own_switch_is_an_ordinary_update(self):
        row = Switch(ip_address="10.0.0.1", owner_username="boss",
                     created_by=None)
        self.assertIsNone(self.conflict(row, self.boss))


class AccessLevelTests(unittest.TestCase):

    def test_a_plain_user_can_only_ever_be_read_only(self):
        user = User(username="u", hashed_password="x", role=ROLE_USER)
        self.assertEqual(main._access_for(user, ACCESS_WRITE), ACCESS_READ)
        self.assertEqual(main._access_for(user, ACCESS_READ), ACCESS_READ)

    def test_an_admin_can_be_given_either(self):
        admin = User(username="a", hashed_password="x", role=ROLE_ADMIN)
        self.assertEqual(main._access_for(admin, ACCESS_WRITE), ACCESS_WRITE)
        self.assertEqual(main._access_for(admin, ACCESS_READ), ACCESS_READ)

    def test_the_default_is_write(self):
        admin = User(username="a", hashed_password="x", role=ROLE_ADMIN)
        self.assertEqual(main._access_for(admin, None), ACCESS_WRITE)

    def test_an_unknown_level_is_rejected(self):
        admin = User(username="a", hashed_password="x", role=ROLE_ADMIN)
        with self.assertRaises(ValidationError):
            main._access_for(admin, "admin")


class _Probe:
    """Stands in for the SSH probe, so no switch is contacted."""

    def __init__(self, failures=()):
        self.failures = set(failures)
        self.calls = []

    def __call__(self, ip, stype, ssh_username, password, use_enable,
                 enable_password):
        self.calls.append(ip)
        if ip in self.failures:
            raise ssh_manager.SSHError(f"Could not reach {ip}.")
        return f"host-{ip.replace('.', '-')}"


class BulkAddTests(unittest.TestCase):

    def setUp(self):
        engine = create_engine("sqlite:///:memory:",
                               connect_args={"check_same_thread": False})
        Base.metadata.create_all(engine)
        self.db = sessionmaker(bind=engine)()
        self.boss = User(username="boss", hashed_password="x",
                         role=ROLE_SUPER_ADMIN)
        self.admin = User(username="admin1", hashed_password="x", role=ROLE_ADMIN)
        self.plain = User(username="viewer", hashed_password="x", role=ROLE_USER)
        self.peer = User(username="peer", hashed_password="x",
                         role=ROLE_SUPER_ADMIN)
        self.db.add_all([self.boss, self.admin, self.plain, self.peer])
        self.db.commit()
        self.probe = _Probe()
        self.patches = [patch.object(main, "_probe_switch", self.probe),
                        patch.object(main.ssh_manager, "invalidate_session",
                                     lambda u, ip: None)]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        self.db.close()

    def add(self, caller=None, **kwargs):
        body = {"ip_addresses": ["10.0.0.1"], "switch_type": "ios",
                "ssh_password": "pw"}
        body.update(kwargs)
        return asyncio.run(main.bulk_add_switches(
            sch.SwitchBulkAdd(**body), caller or self.boss, self.db))

    def rows(self, username):
        return self.db.query(Switch).filter(
            Switch.owner_username == username).all()

    def test_adding_several_switches_for_yourself(self):
        d = self.add(ip_addresses=["10.0.0.1", "10.0.0.2", "10.0.0.3"])
        self.assertEqual(d["added"], 3)
        self.assertEqual(len(self.rows("boss")), 3)
        # A switch you add for yourself is your own, never a granted one.
        self.assertTrue(all(r.created_by is None for r in self.rows("boss")))
        self.assertTrue(all(r.access_level == ACCESS_WRITE
                            for r in self.rows("boss")))

    def test_each_ip_is_probed_once_however_many_people_it_is_for(self):
        self.add(ip_addresses=["10.0.0.1", "10.0.0.2"],
                 usernames=["admin1", "viewer"])
        self.assertEqual(sorted(self.probe.calls), ["10.0.0.1", "10.0.0.2"])

    def test_a_duplicate_ip_is_collapsed(self):
        d = self.add(ip_addresses=["10.0.0.1", "10.0.0.1"])
        self.assertEqual(d["added"], 1)
        self.assertEqual(len(self.probe.calls), 1)

    def test_one_unreachable_switch_does_not_stop_the_others(self):
        self.probe.failures.add("10.0.0.2")
        d = self.add(ip_addresses=["10.0.0.1", "10.0.0.2", "10.0.0.3"])
        self.assertEqual(d["added"], 2)
        self.assertEqual(d["failed"], 1)
        failed = [r for r in d["results"] if r["status"] == "error"]
        self.assertEqual(failed[0]["ip_address"], "10.0.0.2")
        self.assertIn("Could not reach", failed[0]["error"])

    def test_granting_to_others_records_the_granter_and_the_level(self):
        self.add(usernames=["admin1"], access_level=ACCESS_READ)
        row = self.rows("admin1")[0]
        self.assertEqual(row.created_by, "boss")
        self.assertEqual(row.access_level, ACCESS_READ)
        # Not added for the granter unless asked.
        self.assertEqual(self.rows("boss"), [])

    def test_include_self_adds_it_for_the_granter_too(self):
        self.add(usernames=["admin1"], access_level=ACCESS_READ,
                 include_self=True)
        mine = self.rows("boss")[0]
        self.assertEqual(len(mine.owner_username), len("boss"))
        # Your own copy is yours, and read-only never applies to it.
        self.assertIsNone(mine.created_by)
        self.assertEqual(mine.access_level, ACCESS_WRITE)

    def test_a_plain_user_is_forced_to_read_only(self):
        self.add(usernames=["viewer"], access_level=ACCESS_WRITE)
        self.assertEqual(self.rows("viewer")[0].access_level, ACCESS_READ)

    def test_only_a_super_admin_can_add_for_other_people(self):
        with self.assertRaises(HTTPException) as caught:
            self.add(caller=self.admin, usernames=["viewer"])
        self.assertEqual(caught.exception.status_code, 403)

    def test_an_admin_can_still_bulk_add_for_themselves(self):
        d = self.add(caller=self.admin, ip_addresses=["10.0.0.1", "10.0.0.2"])
        self.assertEqual(d["added"], 2)
        self.assertEqual(len(self.rows("admin1")), 2)

    def test_an_unknown_username_is_rejected(self):
        with self.assertRaises(ValidationError):
            self.add(usernames=["nobody"])

    def test_a_switch_the_target_added_themselves_is_skipped(self):
        self.db.add(Switch(ip_address="10.0.0.1", owner_username="admin1",
                           switch_type="ios", saved_password=encrypt_password("own")))
        self.db.commit()
        d = self.add(usernames=["admin1"])
        target = d["results"][0]["targets"][0]
        self.assertEqual(target["status"], "skipped")
        self.assertIn("already added this switch themselves", target["error"])
        self.assertEqual(d["skipped"], 1)
        self.assertEqual(d["added"], 0)

    def test_confirming_still_does_not_take_over_their_own_switch(self):
        self.db.add(Switch(ip_address="10.0.0.1", owner_username="admin1",
                           switch_type="ios"))
        self.db.commit()
        d = self.add(usernames=["admin1"], overwrite_granted=True)
        self.assertEqual(d["skipped"], 1)

    def test_another_super_admin_s_grant_needs_confirmation(self):
        self.db.add(Switch(ip_address="10.0.0.1", owner_username="admin1",
                           switch_type="ios", created_by="peer",
                           access_level=ACCESS_WRITE))
        self.db.commit()
        d = self.add(usernames=["admin1"], access_level=ACCESS_READ)
        self.assertEqual(d["skipped"], 1)
        self.assertIn("peer", d["results"][0]["targets"][0]["error"])
        # Unchanged until confirmed.
        self.assertEqual(self.rows("admin1")[0].access_level, ACCESS_WRITE)

    def test_and_is_taken_over_on_confirmation(self):
        self.db.add(Switch(ip_address="10.0.0.1", owner_username="admin1",
                           switch_type="ios", created_by="peer",
                           access_level=ACCESS_WRITE))
        self.db.commit()
        d = self.add(usernames=["admin1"], access_level=ACCESS_READ,
                     overwrite_granted=True)
        self.assertEqual(d["updated"], 1)
        row = self.rows("admin1")[0]
        self.assertEqual(row.created_by, "boss")
        self.assertEqual(row.access_level, ACCESS_READ)

    def test_one_blocked_person_does_not_stop_the_rest(self):
        self.db.add(Switch(ip_address="10.0.0.1", owner_username="admin1",
                           switch_type="ios"))
        self.db.commit()
        d = self.add(usernames=["admin1", "viewer"])
        statuses = {t["username"]: t["status"]
                    for t in d["results"][0]["targets"]}
        self.assertEqual(statuses, {"admin1": "skipped", "viewer": "added"})

    def test_too_many_ips_is_rejected(self):
        with self.assertRaises(ValidationError):
            self.add(ip_addresses=[f"10.0.0.{i}" for i in range(1, 60)])

    def test_a_bad_ip_is_rejected_before_anything_is_probed(self):
        with self.assertRaises(ValidationError):
            self.add(ip_addresses=["10.0.0.1", "not-an-ip"])
        self.assertEqual(self.probe.calls, [])

    def test_a_missing_password_is_rejected(self):
        with self.assertRaises(ValidationError):
            self.add(ssh_password="")

    def test_enable_requires_its_password(self):
        with self.assertRaises(ValidationError):
            self.add(use_enable=True)


class GrantedSwitchManagementTests(unittest.TestCase):

    def setUp(self):
        engine = create_engine("sqlite:///:memory:",
                               connect_args={"check_same_thread": False})
        Base.metadata.create_all(engine)
        self.db = sessionmaker(bind=engine)()
        self.boss = User(username="boss", hashed_password="x",
                         role=ROLE_SUPER_ADMIN)
        self.peer = User(username="peer", hashed_password="x",
                         role=ROLE_SUPER_ADMIN)
        self.admin = User(username="admin1", hashed_password="x", role=ROLE_ADMIN)
        self.db.add_all([self.boss, self.peer, self.admin])
        self.granted = Switch(ip_address="10.0.0.1", hostname="edge-a",
                              owner_username="admin1", switch_type="ios",
                              created_by="boss", access_level=ACCESS_WRITE)
        self.own = Switch(ip_address="10.0.0.2", hostname="edge-b",
                          owner_username="boss", switch_type="ios")
        self.db.add_all([self.granted, self.own])
        self.db.commit()
        self.patch = patch.object(main.ssh_manager, "invalidate_session",
                                  lambda u, ip: None)
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        self.db.close()

    def test_listing_shows_only_what_you_granted(self):
        d = asyncio.run(main.list_granted_switches(self.boss, self.db))
        self.assertEqual([s["ip_address"] for s in d["switches"]], ["10.0.0.1"])
        self.assertEqual(d["switches"][0]["owner_username"], "admin1")

    def test_another_super_admin_sees_none_of_it(self):
        d = asyncio.run(main.list_granted_switches(self.peer, self.db))
        self.assertEqual(d["switches"], [])

    def test_the_privilege_can_be_changed(self):
        asyncio.run(main.update_granted_switch(
            self.granted.id, sch.GrantedSwitchUpdate(access_level=ACCESS_READ),
            self.boss, self.db))
        self.assertEqual(self.granted.access_level, ACCESS_READ)

    def test_the_password_can_be_replaced(self):
        asyncio.run(main.update_granted_switch(
            self.granted.id, sch.GrantedSwitchUpdate(ssh_password="new"),
            self.boss, self.db))
        self.assertIsNotNone(self.granted.saved_password)

    def test_a_change_by_another_super_admin_is_refused(self):
        with self.assertRaises(HTTPException) as caught:
            asyncio.run(main.update_granted_switch(
                self.granted.id, sch.GrantedSwitchUpdate(access_level=ACCESS_READ),
                self.peer, self.db))
        self.assertEqual(caught.exception.status_code, 403)

    def test_your_own_switch_is_not_editable_through_this_route(self):
        with self.assertRaises(HTTPException) as caught:
            asyncio.run(main.update_granted_switch(
                self.own.id, sch.GrantedSwitchUpdate(access_level=ACCESS_READ),
                self.boss, self.db))
        self.assertEqual(caught.exception.status_code, 403)

    def test_a_no_op_update_reports_that_nothing_changed(self):
        d = asyncio.run(main.update_granted_switch(
            self.granted.id, sch.GrantedSwitchUpdate(), self.boss, self.db))
        self.assertFalse(d["changed"])

    def test_taking_the_switch_back(self):
        asyncio.run(main.delete_granted_switch(self.granted.id, self.boss, self.db))
        self.assertEqual(
            self.db.query(Switch).filter(Switch.owner_username == "admin1").count(), 0)

    def test_another_super_admin_cannot_take_it_back(self):
        with self.assertRaises(HTTPException) as caught:
            asyncio.run(main.delete_granted_switch(self.granted.id, self.peer, self.db))
        self.assertEqual(caught.exception.status_code, 403)


class GranteeClaimTests(unittest.TestCase):
    """A grant is a starting point, not a cage: the holder can take the switch
    over by proving their own credentials against it."""

    def setUp(self):
        engine = create_engine("sqlite:///:memory:",
                               connect_args={"check_same_thread": False})
        Base.metadata.create_all(engine)
        self.db = sessionmaker(bind=engine)()
        self.admin = User(username="admin1", hashed_password="x", role=ROLE_ADMIN)
        self.plain = User(username="viewer", hashed_password="x", role=ROLE_USER)
        self.db.add_all([self.admin, self.plain])
        self.granted = Switch(ip_address="10.0.0.1", hostname="edge-a",
                              owner_username="admin1", switch_type="ios",
                              created_by="boss", access_level=ACCESS_READ)
        self.own = Switch(ip_address="10.0.0.2", hostname="edge-b",
                          owner_username="admin1", switch_type="ios")
        self.db.add_all([self.granted, self.own])
        self.db.commit()

    def tearDown(self):
        self.db.close()

    def test_claiming_makes_it_the_holder_s_own_with_write_access(self):
        self.assertTrue(main._claim_if_granted(self.granted, self.admin))
        self.assertIsNone(self.granted.created_by)
        self.assertEqual(self.granted.access_level, ACCESS_WRITE)

    def test_a_standard_user_stays_read_only_after_claiming(self):
        # No write feature is available to that role, so write would be a lie.
        row = Switch(ip_address="10.0.0.3", owner_username="viewer",
                     created_by="boss", access_level=ACCESS_READ)
        main._claim_if_granted(row, self.plain)
        self.assertIsNone(row.created_by)
        self.assertEqual(row.access_level, ACCESS_READ)

    def test_claiming_a_switch_that_was_never_granted_does_nothing(self):
        self.assertFalse(main._claim_if_granted(self.own, self.admin))
        self.assertIsNone(self.own.created_by)

    def test_a_claimed_switch_leaves_the_granter_s_list(self):
        boss = User(username="boss", hashed_password="x", role=ROLE_SUPER_ADMIN)
        before = asyncio.run(main.list_granted_switches(boss, self.db))
        self.assertEqual(len(before["switches"]), 1)
        main._claim_if_granted(self.granted, self.admin)
        self.db.commit()
        after = asyncio.run(main.list_granted_switches(boss, self.db))
        self.assertEqual(after["switches"], [])

    def test_the_holder_can_remove_it_from_their_own_list(self):
        with patch.object(main.ssh_manager, "invalidate_session", lambda u, ip: None):
            asyncio.run(main.delete_switch(self.granted.id, self.admin, self.db))
        self.assertEqual(
            self.db.query(Switch).filter(Switch.id == self.granted.id).count(), 0)

    def test_the_holder_can_relabel_it_without_claiming_it(self):
        # Changing the location is not evidence of anything, so it must not
        # hand over write access by itself.
        self.granted.site = "part3"
        self.db.commit()
        self.assertEqual(self.granted.created_by, "boss")
        self.assertEqual(self.granted.access_level, ACCESS_READ)


class GrantedListVisibilityTests(unittest.TestCase):

    def setUp(self):
        engine = create_engine("sqlite:///:memory:",
                               connect_args={"check_same_thread": False})
        Base.metadata.create_all(engine)
        self.db = sessionmaker(bind=engine)()
        self.boss = User(username="boss", hashed_password="x",
                         role=ROLE_SUPER_ADMIN)
        self.db.add(self.boss)
        self.db.add_all([
            Switch(ip_address="10.0.0.1", hostname="a", owner_username="admin1",
                   switch_type="ios", created_by="boss", access_level=ACCESS_READ),
            Switch(ip_address="10.0.0.2", hostname="b", owner_username="admin1",
                   switch_type="ios", created_by="boss", access_level=ACCESS_WRITE),
            Switch(ip_address="10.0.0.3", hostname="c", owner_username="viewer",
                   switch_type="ios", created_by="boss", access_level=ACCESS_READ),
        ])
        self.db.commit()

    def tearDown(self):
        self.db.close()

    def test_the_list_is_ordered_so_it_can_be_grouped_by_holder(self):
        d = asyncio.run(main.list_granted_switches(self.boss, self.db))
        owners = [s["owner_username"] for s in d["switches"]]
        self.assertEqual(owners, sorted(owners))
        self.assertEqual(owners, ["admin1", "admin1", "viewer"])


class EffectiveAccessTests(unittest.TestCase):
    """A plain user has no write features anywhere, so a stored 'write' on
    one of their switches describes something they cannot do. What is
    reported has to be what the account can actually do."""

    def setUp(self):
        engine = create_engine("sqlite:///:memory:",
                               connect_args={"check_same_thread": False})
        Base.metadata.create_all(engine)
        self.db = sessionmaker(bind=engine)()
        self.boss = User(username="boss", hashed_password="x",
                         role=ROLE_SUPER_ADMIN)
        self.admin = User(username="admin1", hashed_password="x",
                          role=ROLE_ADMIN)
        # A plain user who registered a switch themselves: nothing forced the
        # column down, so it carries the schema's 'write' default.
        self.viewer = User(username="viewer", hashed_password="x",
                           role=ROLE_USER)
        self.db.add_all([self.boss, self.admin, self.viewer])
        self.db.add_all([
            Switch(id=1, ip_address="10.0.0.1", hostname="a",
                   owner_username="admin1", switch_type="ios",
                   created_by="boss", access_level=ACCESS_WRITE),
            Switch(id=2, ip_address="10.0.0.2", hostname="b",
                   owner_username="viewer", switch_type="ios",
                   access_level=ACCESS_WRITE),
            Switch(id=3, ip_address="10.0.0.3", hostname="c",
                   owner_username="admin1", switch_type="ios",
                   created_by="boss", access_level=ACCESS_READ),
        ])
        self.db.commit()

    def tearDown(self):
        self.db.close()

    def _dash(self, cu):
        d = asyncio.run(main.dashboard_activity_detail(
            kind="switches", window="24h", cu=cu, db=self.db))
        return {s["switch_label"]: s["access_level"] for s in d["switches"]}

    def test_the_dashboard_does_not_credit_a_plain_user_with_write_access(self):
        self.assertEqual(self._dash(self.boss)["b"], ACCESS_READ)

    def test_an_admins_own_level_is_left_alone(self):
        levels = self._dash(self.boss)
        self.assertEqual(levels["a"], ACCESS_WRITE)
        self.assertEqual(levels["c"], ACCESS_READ)

    def test_a_plain_user_is_not_told_they_can_write_to_their_own_switch(self):
        rows = asyncio.run(main.list_switches(self.viewer, self.db))
        self.assertEqual([r.access_level for r in rows], [ACCESS_READ])

    def test_an_admin_still_sees_their_real_level(self):
        rows = asyncio.run(main.list_switches(self.admin, self.db))
        self.assertEqual(sorted(r.access_level for r in rows),
                         [ACCESS_READ, ACCESS_WRITE])

    def test_the_granted_list_reports_what_the_holder_can_do(self):
        self.db.add(Switch(id=4, ip_address="10.0.0.4", hostname="d",
                           owner_username="viewer", switch_type="ios",
                           created_by="boss", access_level=ACCESS_WRITE))
        self.db.commit()
        d = asyncio.run(main.list_granted_switches(self.boss, self.db))
        levels = {s["hostname"]: s["access_level"] for s in d["switches"]}
        self.assertEqual(levels["d"], ACCESS_READ)
        self.assertEqual(levels["a"], ACCESS_WRITE)

    def test_a_switch_whose_owner_is_gone_keeps_its_stored_level(self):
        # No role to consult, so there is nothing to override it with.
        orphan = Switch(id=5, ip_address="10.0.0.5", hostname="e",
                        owner_username="deleted-account", switch_type="ios",
                        access_level=ACCESS_WRITE)
        self.assertEqual(main._effective_access(orphan, None), ACCESS_WRITE)

    def test_a_missing_level_still_defaults_to_write_for_an_admin(self):
        legacy = Switch(id=6, ip_address="10.0.0.6", hostname="f",
                        owner_username="admin1", switch_type="ios",
                        access_level=None)
        self.assertEqual(main._effective_access(legacy, ROLE_ADMIN), ACCESS_WRITE)
        self.assertEqual(main._effective_access(legacy, ROLE_USER), ACCESS_READ)

    def test_demoting_an_admin_takes_their_write_access_with_it(self):
        # The stored column is untouched by a role change, so the answer has
        # to come from the role — otherwise every demotion leaves a switch
        # advertising write access the account has just lost.
        self.assertEqual(self._dash(self.boss)["a"], ACCESS_WRITE)
        self.admin.role = ROLE_USER
        self.db.commit()
        self.assertEqual(self._dash(self.boss)["a"], ACCESS_READ)
        self.assertEqual(
            self.db.query(Switch).filter(Switch.id == 1).first().access_level,
            ACCESS_WRITE, "the stored grant is deliberately left alone")

    def test_promoting_a_user_gives_back_their_own_switch_s_write_access(self):
        # The other direction has to work too. A switch this account
        # registered itself, with its own credentials, is fully theirs once
        # the role allows writing — nothing needs to be repaired to restore it.
        self.assertEqual(self._dash(self.boss)["b"], ACCESS_READ)
        self.viewer.role = ROLE_ADMIN
        self.db.commit()
        self.assertEqual(self._dash(self.boss)["b"], ACCESS_WRITE)

    def test_write_carries_a_terminal_unless_it_is_withheld(self):
        self.assertTrue(main._terminal_for(ACCESS_WRITE, None))
        self.assertTrue(main._terminal_for(ACCESS_WRITE, True))
        self.assertFalse(main._terminal_for(ACCESS_WRITE, False))

    def test_read_only_never_carries_a_terminal_however_it_is_asked_for(self):
        # Ticking the box on a read-only grant cannot widen it: the terminal is
        # unrestricted access to the device, which is what read-only withholds.
        self.assertFalse(main._terminal_for(ACCESS_READ, True))
        self.assertFalse(main._terminal_for(ACCESS_READ, None))

    def test_losing_write_access_takes_the_terminal_with_it(self):
        sw = Switch(id=9, ip_address="10.0.0.9", hostname="h",
                    owner_username="admin1", switch_type="ios",
                    access_level=ACCESS_READ, terminal_access=True)
        self.assertFalse(main._effective_terminal(sw, ROLE_ADMIN))

    def test_a_plain_user_never_gets_a_terminal(self):
        sw = Switch(id=10, ip_address="10.0.0.10", hostname="i",
                    owner_username="viewer", switch_type="ios",
                    access_level=ACCESS_WRITE, terminal_access=True)
        self.assertFalse(main._effective_terminal(sw, ROLE_USER))

    def test_a_row_from_before_the_column_keeps_its_terminal(self):
        # Every write grant that predates the setting had one; reading the
        # missing value as "no" would take it away on upgrade.
        sw = Switch(id=11, ip_address="10.0.0.11", hostname="j",
                    owner_username="admin1", switch_type="ios",
                    access_level=ACCESS_WRITE, terminal_access=None)
        self.assertTrue(main._effective_terminal(sw, ROLE_ADMIN))

    def test_write_without_a_terminal_keeps_its_write_access(self):
        sw = Switch(id=12, ip_address="10.0.0.12", hostname="k",
                    owner_username="admin1", switch_type="ios",
                    access_level=ACCESS_WRITE, terminal_access=False)
        self.assertEqual(main._effective_access(sw, ROLE_ADMIN), ACCESS_WRITE)
        self.assertFalse(main._effective_terminal(sw, ROLE_ADMIN))

    def test_the_terminal_endpoint_refuses_a_grant_without_one(self):
        holder = User(username="noterm", hashed_password="x", role=ROLE_ADMIN)
        sw = Switch(id=13, ip_address="10.0.0.13", hostname="l",
                    owner_username="noterm", switch_type="ios",
                    created_by="boss", access_level=ACCESS_WRITE,
                    terminal_access=False)
        with self.assertRaises(HTTPException) as caught:
            main._require_terminal_access(sw, holder)
        self.assertEqual(caught.exception.status_code, 403)
        self.assertIn("terminal access", str(caught.exception.detail))
        sw.terminal_access = True
        main._require_terminal_access(sw, holder)   # must not raise

    def test_a_granted_read_only_switch_stays_read_only_after_promotion(self):
        # Promotion must not hand out write access the granter never gave:
        # that restriction is about whose password opened the switch, not
        # about the holder's role.
        self.db.add(Switch(id=7, ip_address="10.0.0.7", hostname="g",
                           owner_username="viewer", switch_type="ios",
                           created_by="boss", access_level=ACCESS_READ))
        self.db.commit()
        self.viewer.role = ROLE_ADMIN
        self.db.commit()
        self.assertEqual(self._dash(self.boss)["g"], ACCESS_READ)


if __name__ == "__main__":
    unittest.main()


class PreviewBlockingTests(unittest.TestCase):
    """A preview sends nothing to the device, so the guard inside configure()
    never sees it — yet it exists only to stage a change."""

    def test_resolve_targets_can_demand_write_access(self):
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        db = sessionmaker(bind=engine)()
        try:
            db.add(Switch(id=1, ip_address="10.0.0.1", hostname="edge-a",
                          owner_username="admin1", switch_type="ios",
                          access_level=ACCESS_READ,
                          saved_password=encrypt_password("pw")))
            db.commit()
            # A read is fine.
            targets = svc.resolve_targets([1], "admin1", db)
            self.assertEqual(len(targets), 1)
            # Staging a change is not.
            with self.assertRaises(svc.ReadOnlyAccessError):
                svc.resolve_targets([1], "admin1", db, require_write=True)
        finally:
            db.close()

    def test_every_preview_endpoint_demands_write_access(self):
        """Guards the enumeration itself: a new preview added without a guard
        fails here rather than silently shipping."""
        import inspect
        source = inspect.getsource(main)
        previews = [
            "rule_preview", "acl_sync_preview", "reverse_direction_preview",
            "template_apply_preview", "acl_create_preview", "tr_preview",
            "og_preview",
        ]
        for name in previews:
            start = source.index(f"async def {name}(")
            end = source.index("\n@app.", start)
            body = source[start:end]
            guarded = ("require_write=True" in body
                       or "require_write_access" in body
                       # These two delegate to a shared plan builder that is
                       # guarded once for both the preview and the apply.
                       or "_build_template_apply_plan" in body
                       or "_build_acl_create_plan" in body)
            self.assertTrue(guarded, f"{name} does not require write access")

    def test_the_shared_plan_builders_are_guarded(self):
        import inspect
        source = inspect.getsource(main)
        for name in ("_build_template_apply_plan", "_build_acl_create_plan"):
            start = source.index(f"async def {name}(")
            end = source.index("\n\n\n", start)
            self.assertIn("require_write_access", source[start:end], name)


class ThemeTests(unittest.TestCase):
    """The colour scheme lives on the account, not in one browser."""

    def setUp(self):
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        self.db = sessionmaker(bind=engine)()
        self.user = User(username="fresh", hashed_password="x", role=ROLE_ADMIN)
        self.db.add(self.user)
        self.db.commit()

    def tearDown(self):
        self.db.close()

    def _set(self, theme):
        import schemas as sch
        return asyncio.run(main.update_own_theme(
            sch.ThemeUpdate(theme=theme), cu=self.user, db=self.db))

    def test_a_new_account_starts_on_the_original_scheme(self):
        # 'dark' is the id the old localStorage value already carried, so an
        # account created before the column keeps the colours it had.
        self.assertEqual(self.user.theme, "dark")

    def test_the_choice_is_stored_against_the_account(self):
        r = self._set("glacier")
        self.assertTrue(r["changed"])
        self.db.refresh(self.user)
        self.assertEqual(self.user.theme, "glacier")

    def test_choosing_the_current_theme_reports_no_change(self):
        self._set("evermore")
        self.assertFalse(self._set("evermore")["changed"])

    def test_every_advertised_theme_is_accepted(self):
        # The picker offers exactly these; one the server rejects would be a
        # dead option in the UI.
        for theme in main.THEMES:
            self._set(theme)
            self.db.refresh(self.user)
            self.assertEqual(self.user.theme, theme)

    def test_a_retired_theme_is_moved_to_its_successor_not_forgotten(self):
        # Schemes that were offered and then replaced must not silently reset
        # to the default -- the account made a choice, and the nearest
        # surviving scheme honours it.
        from database import RETIRED_THEMES
        for old, new in RETIRED_THEMES.items():
            self.assertNotIn(old, main.THEMES, f"{old} should be retired")
            self.assertIn(new, main.THEMES, f"{new} should be its successor")

    def test_an_unknown_theme_is_refused(self):
        with self.assertRaises(main.ValidationError):
            self._set("hot-pink")

    def test_the_theme_is_reported_on_sign_in_and_on_restore(self):
        # Both paths, or a reload would disagree with a fresh sign-in.
        self.user.theme = "nord"
        self.db.commit()
        me = asyncio.run(main.me(cu=self.user))
        self.assertEqual(me["theme"], "nord")
        import schemas as sch
        self.assertEqual(sch.Token(access_token="t", token_type="bearer",
                                   role=ROLE_ADMIN, username="fresh",
                                   theme="nord").theme, "nord")


class MegaVisibilityTests(unittest.TestCase):
    """The mascot is opt-in: a new account should not have to work out how to
    dismiss something it never asked for."""

    def setUp(self):
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        self.db = sessionmaker(bind=engine)()

    def tearDown(self):
        self.db.close()

    def test_a_new_account_starts_with_it_hidden(self):
        user = User(username="fresh", hashed_password="x", role=ROLE_ADMIN)
        self.db.add(user)
        self.db.commit()
        self.assertFalse(user.mega_visible)

    def test_the_preference_is_stored_against_the_account(self):
        import schemas as sch
        user = User(username="fresh", hashed_password="x", role=ROLE_ADMIN)
        self.db.add(user)
        self.db.commit()
        asyncio.run(main.update_own_mega_visible(
            sch.MegaVisibleUpdate(visible=True), user, self.db))
        self.assertTrue(user.mega_visible)
        asyncio.run(main.update_own_mega_visible(
            sch.MegaVisibleUpdate(visible=False), user, self.db))
        self.assertFalse(user.mega_visible)

    def test_it_is_reported_on_sign_in_and_on_restore(self):
        user = User(username="fresh", hashed_password="x", role=ROLE_ADMIN,
                    mega_visible=True)
        self.db.add(user)
        self.db.commit()
        me = asyncio.run(main.me(user))
        self.assertTrue(me["mega_visible"])
        user.mega_visible = False
        self.assertFalse(asyncio.run(main.me(user))["mega_visible"])
