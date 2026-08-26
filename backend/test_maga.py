import asyncio
import unittest

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import main
import schemas as sch
from database import AuditLog, Base, User, ROLE_USER
from validators import ValidationError


class MegaSelectionTests(unittest.TestCase):
    def setUp(self):
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        self.db = sessionmaker(bind=engine)()
        self.user = User(username="viewer", hashed_password="x", role=ROLE_USER)
        self.db.add(self.user)
        self.db.commit()
        self.db.refresh(self.user)

    def tearDown(self):
        self.db.close()

    def choose(self, mega):
        return asyncio.run(main.update_own_mega(
            sch.MegaUpdate(mega=mega), self.user, self.db))

    def test_regular_user_can_choose_own_maga(self):
        result = self.choose("orbit")
        self.assertTrue(result["changed"])
        self.assertEqual(result["mega"], "orbit")
        self.assertEqual(self.db.get(User, self.user.id).mega, "orbit")
        self.assertEqual(self.db.query(AuditLog).count(), 0)

    def test_same_maga_is_noop(self):
        result = self.choose("byte")
        self.assertFalse(result["changed"])

    def test_unknown_maga_is_rejected(self):
        with self.assertRaisesRegex(ValidationError, "valid Mega"):
            self.choose("not-real")

    def test_every_mega_the_picker_offers_is_accepted(self):
        """The frontend draws one option per id in MEGA_TYPES, so an id the
        picker can show but the server refuses is a dead tile."""
        for mega in main.MEGA_TYPES:
            with self.subTest(mega=mega):
                self.user.mega = "byte" if mega != "byte" else "orbit"
                self.db.commit()
                self.assertEqual(self.choose(mega)["mega"], mega)


if __name__ == "__main__":
    unittest.main()
