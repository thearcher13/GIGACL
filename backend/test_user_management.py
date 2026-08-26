import asyncio
import unittest

from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import main
import schemas as sch
from database import (Base, User, Switch, SiteLabel, AuditLog,
                      ROLE_SUPER_ADMIN, ROLE_USER)
from validators import ValidationError


class UsernameUpdateTests(unittest.TestCase):
    def setUp(self):
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        self.db = sessionmaker(bind=engine)()
        self.actor = User(username="rootadmin", hashed_password="x",
                          role=ROLE_SUPER_ADMIN)
        self.target = User(username="oldname", hashed_password="x",
                           role=ROLE_USER)
        self.db.add_all((self.actor, self.target))
        self.db.commit()
        self.db.refresh(self.actor)
        self.db.refresh(self.target)

    def tearDown(self):
        self.db.close()

    def rename(self, user_id, username):
        return asyncio.run(main.update_username(
            user_id, sch.UsernameUpdate(username=username),
            self.actor, self.db))

    def test_rename_migrates_username_owned_records(self):
        self.db.add(Switch(
            ip_address="10.0.0.1", owner_username="oldname",
            ssh_username="network-login"))
        self.db.add(SiteLabel(name="Lab", owner_username="oldname"))
        self.db.add(AuditLog(
            username="oldname", message="Prior action", level="INFO"))
        self.db.commit()

        result = self.rename(self.target.id, "newname")

        self.assertTrue(result["changed"])
        self.assertEqual(self.db.get(User, self.target.id).username, "newname")
        switch = self.db.query(Switch).one()
        self.assertEqual(switch.owner_username, "newname")
        self.assertEqual(switch.ssh_username, "network-login")
        self.assertEqual(self.db.query(SiteLabel).one().owner_username,
                         "newname")
        prior = self.db.query(AuditLog).filter(
            AuditLog.message == "Prior action").one()
        self.assertEqual(prior.username, "newname")

    def test_case_insensitive_collision_is_rejected(self):
        self.db.add(User(username="Existing", hashed_password="x",
                         role=ROLE_USER))
        self.db.commit()
        with self.assertRaisesRegex(ValidationError, "already exists"):
            self.rename(self.target.id, "existing")

    def test_current_account_can_rename_itself(self):
        result = self.rename(self.actor.id, "renamedadmin")
        self.assertTrue(result["changed"])
        self.assertEqual(self.db.get(User, self.actor.id).username, "renamedadmin")
        # A fresh token is issued since the signed-in token's subject is stale.
        self.assertIn("token", result)

    def test_cannot_rename_another_super_admin(self):
        other_super = User(username="othersuper", hashed_password="x",
                           role=ROLE_SUPER_ADMIN)
        self.db.add(other_super)
        self.db.commit()
        self.db.refresh(other_super)
        with self.assertRaises(HTTPException) as raised:
            self.rename(other_super.id, "renamed")
        self.assertEqual(raised.exception.status_code, 403)


if __name__ == "__main__":
    unittest.main()
