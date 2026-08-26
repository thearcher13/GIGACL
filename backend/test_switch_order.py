import asyncio
import unittest

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import main
import schemas as sch
from database import Base, User, Switch, SiteLabel, ROLE_USER
from validators import ValidationError


class SwitchOrderTests(unittest.TestCase):
    def setUp(self):
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        self.db = sessionmaker(bind=engine)()
        self.user = User(username="operator", hashed_password="x", role=ROLE_USER)
        self.other = User(username="other", hashed_password="x", role=ROLE_USER)
        self.db.add_all((self.user, self.other))
        self.db.flush()
        self.first = Switch(ip_address="10.0.0.1", hostname="first",
                            site="site1", owner_username=self.user.username)
        self.second = Switch(ip_address="10.0.0.2", hostname="second",
                             site="site2", owner_username=self.user.username)
        self.foreign = Switch(ip_address="10.0.0.3", hostname="foreign",
                              site="site1", owner_username=self.other.username)
        self.db.add_all((self.first, self.second, self.foreign,
                         SiteLabel(name="lab", owner_username=self.user.username)))
        self.db.commit()
        for row in (self.user, self.first, self.second, self.foreign):
            self.db.refresh(row)

    def tearDown(self):
        self.db.close()

    def save(self, labels, switch_ids):
        return asyncio.run(main.update_switch_order(
            sch.SwitchOrderUpdate(labels=labels, switch_ids=switch_ids),
            self.user, self.db))

    def test_order_is_persisted_and_returned_by_meta(self):
        result = self.save(
            ["lab", "site2", "site1", ""],
            [self.second.id, self.first.id])

        self.assertEqual(result["labels"][:4], ["lab", "site2", "site1", ""])
        self.assertEqual(result["switch_ids"], [self.second.id, self.first.id])
        metadata = asyncio.run(main.meta(self.user, self.db))
        self.assertEqual(metadata["switch_layout"]["labels"], result["labels"])
        self.assertEqual(metadata["switch_layout"]["switch_ids"], result["switch_ids"])

    def test_foreign_switch_cannot_be_added_to_order(self):
        with self.assertRaisesRegex(ValidationError, "do not own"):
            self.save(["site1"], [self.foreign.id])

    def test_unknown_label_is_rejected(self):
        with self.assertRaisesRegex(ValidationError, "not one of your locations"):
            self.save(["unknown-lab"], [self.first.id])


if __name__ == "__main__":
    unittest.main()
