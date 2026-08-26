import asyncio
import unittest

from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import main
import schemas as sch
from database import Base, User, get_app_settings, ROLE_SUPER_ADMIN, ROLE_ADMIN
from validators import ValidationError, validate_idle_timeout_minutes


class GetAppSettingsTests(unittest.TestCase):
    def setUp(self):
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        self.db = sessionmaker(bind=engine)()

    def tearDown(self):
        self.db.close()

    def test_creates_row_with_default_never(self):
        row = get_app_settings(self.db)
        self.assertEqual(row.idle_timeout_minutes, 0)

    def test_returns_same_row_on_repeat_calls(self):
        first = get_app_settings(self.db)
        first.idle_timeout_minutes = 15
        self.db.commit()
        second = get_app_settings(self.db)
        self.assertEqual(second.idle_timeout_minutes, 15)
        self.assertEqual(self.db.query(type(first)).count(), 1)


class ValidateIdleTimeoutMinutesTests(unittest.TestCase):
    def test_accepts_every_allowed_value(self):
        for n in (0, 1, 5, 10, 15, 20, 30, 60, 120):
            self.assertEqual(validate_idle_timeout_minutes(n), n)

    def test_rejects_disallowed_value(self):
        with self.assertRaises(ValidationError):
            validate_idle_timeout_minutes(45)

    def test_rejects_non_numeric(self):
        with self.assertRaises(ValidationError):
            validate_idle_timeout_minutes("never")


class UpdateIdleTimeoutEndpointTests(unittest.TestCase):
    def setUp(self):
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        self.db = sessionmaker(bind=engine)()
        self.super_admin = User(username="root", hashed_password="x",
                                role=ROLE_SUPER_ADMIN)
        self.admin = User(username="regular-admin", hashed_password="x",
                          role=ROLE_ADMIN)
        self.db.add_all((self.super_admin, self.admin))
        self.db.commit()
        self.db.refresh(self.super_admin)
        self.db.refresh(self.admin)

    def tearDown(self):
        self.db.close()

    def update(self, actor, minutes):
        return asyncio.run(main.update_idle_timeout(
            sch.IdleTimeoutUpdate(idle_timeout_minutes=minutes), actor, self.db))

    def test_super_admin_can_set_value(self):
        result = self.update(self.super_admin, 30)
        self.assertEqual(result["idle_timeout_minutes"], 30)
        self.assertEqual(get_app_settings(self.db).idle_timeout_minutes, 30)

    def test_rejects_disallowed_value(self):
        with self.assertRaises(ValidationError):
            self.update(self.super_admin, 45)

    def test_value_persists_and_is_readable_via_meta(self):
        self.update(self.super_admin, 60)
        meta = asyncio.run(main.meta(self.super_admin, self.db))
        self.assertEqual(meta["idle_timeout_minutes"], 60)


if __name__ == "__main__":
    unittest.main()
