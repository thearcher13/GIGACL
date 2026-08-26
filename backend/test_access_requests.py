"""
Access requests: somebody without write access asking an admin to open a path.

The lifecycle is the interesting part -- who may raise one, who may see it,
what happens to it when it is answered, and what a role change does to it.
"""
import asyncio
import unittest

from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import main
import schemas as sch
from database import (Base, Switch, User, AccessRequest,
                      ACCESS_READ, ACCESS_WRITE,
                      ROLE_USER, ROLE_ADMIN, ROLE_SUPER_ADMIN,
                      REQUEST_PENDING, REQUEST_GRANTED, REQUEST_REJECTED,
                      REQUEST_CANCELLED)

run = asyncio.get_event_loop().run_until_complete


class _Base(unittest.TestCase):
    def setUp(self):
        engine = create_engine("sqlite:///:memory:",
                               connect_args={"check_same_thread": False})
        Base.metadata.create_all(engine)
        self.db = sessionmaker(bind=engine)()
        self.boss = User(username="boss", hashed_password="x", role=ROLE_SUPER_ADMIN)
        self.admin = User(username="admin1", hashed_password="x", role=ROLE_ADMIN)
        self.viewer = User(username="viewer", hashed_password="x", role=ROLE_USER)
        self.db.add_all([self.boss, self.admin, self.viewer])
        # The viewer holds a read-only copy; the admin holds a writable one of
        # the same physical device, which is how a request gets actioned.
        self.ro = Switch(ip_address="10.0.0.1", hostname="edge-a", switch_type="nexus",
                         owner_username="viewer", access_level=ACCESS_READ)
        self.rw = Switch(ip_address="10.0.0.1", hostname="edge-a", switch_type="nexus",
                         owner_username="admin1", access_level=ACCESS_WRITE)
        self.db.add_all([self.ro, self.rw])
        self.db.commit()

    def make(self, **kw):
        body = dict(switch_id=self.ro.id, src_ip="10.1.1.5", dst_ip="10.2.2.7",
                    protocol="tcp", port="443")
        body.update(kw)
        return run(main.create_access_request(
            sch.AccessRequestCreate(**body), self.viewer, self.db))


class RaisingTests(_Base):
    def test_a_read_only_holder_may_raise_one(self):
        out = self.make()
        self.assertEqual(len(out["requests"]), 1)
        r = self.db.query(AccessRequest).one()
        self.assertEqual(r.status, REQUEST_PENDING)
        self.assertEqual((r.src_ip, r.dst_ip, r.protocol, r.port),
                         ("10.1.1.5", "10.2.2.7", "tcp", "443"))

    def test_the_switch_is_recorded_by_name_as_well_as_id(self):
        """An admin who was never granted it still has to read the request."""
        self.make()
        r = self.db.query(AccessRequest).one()
        self.assertEqual(r.switch_ip, "10.0.0.1")
        self.assertEqual(r.switch_label, "edge-a")

    def test_someone_who_could_just_do_it_is_refused(self):
        with self.assertRaises(HTTPException) as caught:
            run(main.create_access_request(
                sch.AccessRequestCreate(switch_id=self.rw.id, src_ip="10.1.1.5",
                                        dst_ip="10.2.2.7", protocol="tcp"),
                self.admin, self.db))
        self.assertEqual(caught.exception.status_code, 400)
        self.assertIn("already have write access", caught.exception.detail)

    def test_a_switch_you_cannot_see_is_a_404(self):
        with self.assertRaises(HTTPException) as caught:
            run(main.create_access_request(
                sch.AccessRequestCreate(switch_id=self.rw.id, src_ip="10.1.1.5",
                                        dst_ip="10.2.2.7"),
                self.viewer, self.db))
        self.assertEqual(caught.exception.status_code, 404)


class VpcTests(_Base):
    def setUp(self):
        super().setUp()
        self.ro_peer = Switch(ip_address="10.0.0.2", hostname="edge-b",
                              switch_type="nexus", owner_username="viewer",
                              access_level=ACCESS_READ)
        self.db.add(self.ro_peer)
        self.db.commit()
        self.ro.vpc_peer_id = self.ro_peer.id
        self.ro_peer.vpc_peer_id = self.ro.id
        self.db.commit()

    def test_one_switch_by_default(self):
        self.make()
        self.assertEqual(self.db.query(AccessRequest).count(), 1)

    def test_including_the_peer_makes_two_standalone_rows(self):
        """Applied one at a time, so one row covering both could only ever be
        half-done."""
        out = self.make(include_peer=True)
        self.assertEqual(len(out["requests"]), 2)
        rows = self.db.query(AccessRequest).order_by(AccessRequest.id).all()
        self.assertEqual([r.switch_label for r in rows], ["edge-a", "edge-b"])
        self.assertTrue(all(r.status == REQUEST_PENDING for r in rows))
        self.assertEqual(len({r.id for r in rows}), 2)


class AdminViewTests(_Base):
    def test_an_admin_holding_the_switch_sees_it(self):
        self.make()
        rows = run(main.list_access_requests(self.admin, self.db))["requests"]
        self.assertEqual(len(rows), 1)

    def test_an_admin_without_the_switch_does_not_see_it(self):
        """A request they cannot act on is somebody else's job, and only
        clutters the queue."""
        outsider = User(username="elsewhere", hashed_password="x", role=ROLE_ADMIN)
        self.db.add(outsider); self.db.commit()
        self.make()
        self.assertEqual(run(main.list_access_requests(outsider, self.db))["requests"], [])

    def test_a_super_admin_sees_it_regardless(self):
        """Only they can see the whole inventory, so only they can tell that a
        request has nobody to answer it."""
        self.make()
        rows = run(main.list_access_requests(self.boss, self.db))["requests"]
        self.assertEqual(len(rows), 1)

    def test_you_never_see_your_own_requests(self):
        """You raised it because you could not action it."""
        self.ro.access_level = ACCESS_READ
        self.db.commit()
        run(main.create_access_request(
            sch.AccessRequestCreate(switch_id=self.ro.id, src_ip="10.1.1.5",
                                    dst_ip="10.2.2.7"), self.viewer, self.db))
        # viewer is a plain user, so promote a read-only admin to raise one
        selfish = User(username="selfish", hashed_password="x", role=ROLE_ADMIN)
        self.db.add(selfish)
        own = Switch(ip_address="10.9.9.9", hostname="own-a", switch_type="nexus",
                     owner_username="selfish", access_level=ACCESS_READ)
        self.db.add(own); self.db.commit()
        run(main.create_access_request(
            sch.AccessRequestCreate(switch_id=own.id, src_ip="1.1.1.1",
                                    dst_ip="2.2.2.2"), selfish, self.db))
        mine = [r for r in run(main.list_access_requests(selfish, self.db))["requests"]
                if r["requester"] == "selfish"]
        self.assertEqual(mine, [], "own requests must not appear in the queue")

    def test_an_admin_holding_the_switch_can_apply(self):
        self.make()
        row = run(main.list_access_requests(self.admin, self.db))["requests"][0]
        self.assertTrue(row["can_apply"])
        self.assertEqual(row["my_switch_id"], self.rw.id)
        self.assertIsNone(row["reason_blocked"])

    def test_a_super_admin_without_the_switch_is_told_why_not(self):
        """They see it -- they just cannot be the one to action it."""
        self.make()
        row = run(main.list_access_requests(self.boss, self.db))["requests"][0]
        self.assertFalse(row["can_apply"])
        self.assertIn("not in your inventory", row["reason_blocked"])

    def test_a_read_only_admin_does_not_see_it_at_all(self):
        """Read-only on the switch is the same as not holding it: they could
        not add the rule either way, so listing it only invites a dead end."""
        self.rw.access_level = ACCESS_READ
        self.db.commit()
        self.make()
        self.assertEqual(run(main.list_access_requests(self.admin, self.db))["requests"], [])


class ResolvingTests(_Base):
    def _one(self):
        self.make()
        return self.db.query(AccessRequest).one()

    def test_marking_done_removes_it_for_everyone(self):
        r = self._one()
        run(main.complete_access_request(r.id, sch.AccessRequestResolve(), self.admin, self.db))
        self.db.refresh(r)
        self.assertEqual(r.status, REQUEST_GRANTED)
        self.assertEqual(r.resolved_by, "admin1")
        self.assertEqual(run(main.list_access_requests(self.boss, self.db))["requests"], [])

    def test_the_log_says_marked_done_not_granted(self):
        """The app cannot see whether the rule was actually added, only that
        an admin is finished with it."""
        from database import AuditLog
        r = self._one()
        run(main.complete_access_request(r.id, sch.AccessRequestResolve(), self.admin, self.db))
        msg = self.db.query(AuditLog).filter(
            AuditLog.username == "admin1").order_by(AuditLog.id.desc()).first().message
        self.assertIn("Marked done", msg)
        self.assertNotIn("Granted", msg)

    def test_dismissing_records_who_and_why(self):
        r = self._one()
        run(main.dismiss_access_request(
            r.id, sch.AccessRequestResolve(note="Use the VPN instead"), self.admin, self.db))
        self.db.refresh(r)
        self.assertEqual(r.status, REQUEST_REJECTED)
        self.assertEqual(r.resolved_by, "admin1")
        self.assertEqual(r.resolution_note, "Use the VPN instead")

    def test_it_can_only_be_answered_once(self):
        r = self._one()
        run(main.complete_access_request(r.id, sch.AccessRequestResolve(), self.admin, self.db))
        with self.assertRaises(HTTPException) as caught:
            run(main.dismiss_access_request(r.id, sch.AccessRequestResolve(),
                                            self.boss, self.db))
        self.assertEqual(caught.exception.status_code, 400)

    def test_resolving_reopens_the_unseen_flag(self):
        """Which is what raises the toast on the requester's next load."""
        r = self._one()
        r.seen_by_requester = True
        self.db.commit()
        run(main.complete_access_request(r.id, sch.AccessRequestResolve(), self.admin, self.db))
        self.db.refresh(r)
        self.assertFalse(r.seen_by_requester)


class RequesterTests(_Base):
    def test_they_see_their_own_and_the_unseen_count(self):
        self.make()
        r = self.db.query(AccessRequest).one()
        run(main.complete_access_request(r.id, sch.AccessRequestResolve(), self.admin, self.db))
        out = run(main.my_access_requests(self.viewer, self.db))
        self.assertEqual(len(out["requests"]), 1)
        self.assertEqual(out["unseen"], 1)
        self.assertEqual(out["unseen_granted"], 1)
        self.assertEqual(out["unseen_rejected"], 0)

    def test_marking_seen_clears_the_toast(self):
        self.make()
        r = self.db.query(AccessRequest).one()
        run(main.dismiss_access_request(r.id, sch.AccessRequestResolve(), self.admin, self.db))
        run(main.mark_requests_seen(self.viewer, self.db))
        self.assertEqual(run(main.my_access_requests(self.viewer, self.db))["unseen"], 0)

    def test_they_can_edit_the_remark_while_it_is_pending(self):
        self.make()
        r = self.db.query(AccessRequest).one()
        run(main.edit_access_request(r.id, sch.AccessRequestRemark(remark="urgent"),
                                     self.viewer, self.db))
        self.db.refresh(r)
        self.assertEqual(r.remark, "urgent")

    def test_they_cannot_edit_one_that_was_answered(self):
        self.make()
        r = self.db.query(AccessRequest).one()
        run(main.complete_access_request(r.id, sch.AccessRequestResolve(), self.admin, self.db))
        with self.assertRaises(HTTPException):
            run(main.edit_access_request(r.id, sch.AccessRequestRemark(remark="late"),
                                         self.viewer, self.db))

    def test_cancelling_takes_it_off_the_admin_list(self):
        self.make()
        r = self.db.query(AccessRequest).one()
        run(main.cancel_access_request(r.id, self.viewer, self.db))
        self.db.refresh(r)
        self.assertEqual(r.status, REQUEST_CANCELLED)
        self.assertEqual(run(main.list_access_requests(self.admin, self.db))["requests"], [])

    def test_one_person_cannot_touch_anothers(self):
        self.make()
        r = self.db.query(AccessRequest).one()
        other = User(username="someone", hashed_password="x", role=ROLE_USER)
        self.db.add(other); self.db.commit()
        with self.assertRaises(HTTPException) as caught:
            run(main.cancel_access_request(r.id, other, self.db))
        self.assertEqual(caught.exception.status_code, 404)


class RoleChangeTests(_Base):
    """A role change rewrites what the whole UI offers, so it will not happen
    underneath a live session."""

    def test_refused_while_the_target_is_still_signed_in(self):
        from datetime import datetime
        self.viewer.last_seen = datetime.utcnow()
        self.db.commit()
        with self.assertRaises(HTTPException) as caught:
            run(main.update_role(self.viewer.id, sch.RoleUpdate(role=ROLE_ADMIN),
                                 self.boss, self.db))
        self.assertEqual(caught.exception.status_code, 409)
        self.assertIn("still signed in", caught.exception.detail)
        self.db.refresh(self.viewer)
        self.assertEqual(self.viewer.role, ROLE_USER, "the role must not have moved")

    def test_allowed_once_they_are_gone(self):
        from datetime import datetime, timedelta
        self.viewer.last_seen = datetime.utcnow() - timedelta(days=1)
        self.db.commit()
        run(main.update_role(self.viewer.id, sch.RoleUpdate(role=ROLE_ADMIN),
                             self.boss, self.db))
        self.db.refresh(self.viewer)
        self.assertEqual(self.viewer.role, ROLE_ADMIN)

    def test_demotion_drops_template_shares(self):
        """Templates are an admin feature and can only be shared with admins,
        so the share cannot outlive the role."""
        from database import Template, TemplateShare
        tpl = Template(name="std", owner_username="boss", switch_type="nexus",
                       direction="in", lines="[]", reversed_lines="[]")
        self.db.add(tpl); self.db.commit()
        self.db.add(TemplateShare(template_id=tpl.id, username="admin1"))
        self.db.commit()
        from datetime import datetime, timedelta
        self.admin.last_seen = datetime.utcnow() - timedelta(days=1)
        self.db.commit()
        run(main.update_role(self.admin.id, sch.RoleUpdate(role=ROLE_USER),
                             self.boss, self.db))
        left = self.db.query(TemplateShare).filter(
            TemplateShare.username == "admin1").count()
        self.assertEqual(left, 0)

    def test_promotion_leaves_shares_alone(self):
        from database import Template, TemplateShare
        tpl = Template(name="std2", owner_username="boss", switch_type="nexus",
                       direction="in", lines="[]", reversed_lines="[]")
        self.db.add(tpl); self.db.commit()
        self.db.add(TemplateShare(template_id=tpl.id, username="admin1"))
        self.db.commit()
        from datetime import datetime, timedelta
        self.viewer.last_seen = datetime.utcnow() - timedelta(days=1)
        self.db.commit()
        run(main.update_role(self.viewer.id, sch.RoleUpdate(role=ROLE_ADMIN),
                             self.boss, self.db))
        self.assertEqual(self.db.query(TemplateShare).count(), 1)

    def test_a_promoted_user_keeps_the_requests_they_raised(self):
        """They stop being theirs to see as a requester, but the history and
        the admin queue are unaffected."""
        self.make()
        from datetime import datetime, timedelta
        self.viewer.last_seen = datetime.utcnow() - timedelta(days=1)
        self.db.commit()
        run(main.update_role(self.viewer.id, sch.RoleUpdate(role=ROLE_ADMIN),
                             self.boss, self.db))
        self.assertEqual(len(run(main.list_access_requests(self.admin, self.db))["requests"]), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
