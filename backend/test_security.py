import asyncio
import base64
import unittest
from datetime import datetime, timedelta
from unittest.mock import patch

from cryptography.fernet import Fernet
from fastapi import HTTPException
from jose import jwt
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import auth
import crypto
import main
from config import settings
from database import Base, Switch, User, ROLE_ADMIN, ROLE_SUPER_ADMIN


class SecretKeyTests(unittest.TestCase):
    """The value that shipped in the repository must never be accepted as a
    real secret, because it signed tokens and encrypted every credential."""

    def test_the_shipped_placeholder_is_rejected(self):
        self.assertTrue(crypto.is_insecure_secret(crypto.LEGACY_SECRET))

    def test_blank_and_short_secrets_are_rejected(self):
        for value in (None, "", "   ", "tooshort", "x" * 31):
            self.assertTrue(crypto.is_insecure_secret(value), repr(value))

    def test_a_generated_secret_is_accepted(self):
        self.assertFalse(crypto.is_insecure_secret(crypto.generate_secret()))

    def test_generated_secrets_are_unique(self):
        self.assertEqual(len({crypto.generate_secret() for _ in range(50)}), 50)


class KeyDerivationTests(unittest.TestCase):

    def setUp(self):
        self.secret = crypto.generate_secret()

    def test_signing_and_credential_keys_differ(self):
        # Domain separation: a leaked signing key must not decrypt passwords.
        signing = crypto.signing_key(self.secret)
        credential = crypto._derive(self.secret, crypto._INFO_CREDENTIALS).decode()
        self.assertNotEqual(signing, credential)

    def test_the_signing_key_is_not_the_raw_secret(self):
        self.assertNotEqual(crypto.signing_key(self.secret), self.secret)

    def test_the_whole_secret_contributes(self):
        # The old scheme used only the first 32 bytes, so two secrets sharing
        # a prefix produced an identical key.
        a = "x" * 32 + "aaaaaaaa"
        b = "x" * 32 + "bbbbbbbb"
        self.assertNotEqual(crypto.signing_key(a), crypto.signing_key(b))
        self.assertNotEqual(crypto.encrypt_password(a, "p"),
                            crypto.encrypt_password(b, "p"))

    def test_derivation_is_deterministic(self):
        self.assertEqual(crypto.signing_key(self.secret),
                         crypto.signing_key(self.secret))


class CredentialEncryptionTests(unittest.TestCase):

    def setUp(self):
        self.secret = crypto.generate_secret()

    def legacy_token(self, plain):
        key = crypto.LEGACY_SECRET.encode()[:32].ljust(32, b"0")
        return Fernet(base64.urlsafe_b64encode(key)).encrypt(
            plain.encode()).decode()

    def test_round_trip(self):
        token = crypto.encrypt_password(self.secret, "hunter2")
        self.assertEqual(crypto.decrypt_password(self.secret, token), "hunter2")

    def test_a_value_written_under_the_old_scheme_still_reads(self):
        # Without this an existing database becomes unusable the moment the
        # key changes.
        token = self.legacy_token("old-pw")
        self.assertEqual(crypto.decrypt_password(self.secret, token), "old-pw")

    def test_old_values_are_identified_for_re_encryption(self):
        self.assertTrue(
            crypto.is_legacy_ciphertext(self.secret, self.legacy_token("x")))
        self.assertFalse(crypto.is_legacy_ciphertext(
            self.secret, crypto.encrypt_password(self.secret, "x")))

    def test_a_different_secret_cannot_read_the_ciphertext(self):
        token = crypto.encrypt_password(self.secret, "hunter2")
        with self.assertRaises(Exception):
            crypto.decrypt_password(crypto.generate_secret(), token)


class ReEncryptionTests(unittest.TestCase):
    """The one-off pass that moves stored credentials onto the new key."""

    def setUp(self):
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        self.db = sessionmaker(bind=engine)()
        self.secret = crypto.generate_secret()
        key = crypto.LEGACY_SECRET.encode()[:32].ljust(32, b"0")
        self.old = Fernet(base64.urlsafe_b64encode(key))
        self.db.add_all([
            Switch(id=1, ip_address="10.0.0.1", owner_username="a",
                   saved_password=self.old.encrypt(b"pw-one").decode(),
                   saved_enable_password=self.old.encrypt(b"en-one").decode()),
            Switch(id=2, ip_address="10.0.0.2", owner_username="a",
                   saved_password=self.old.encrypt(b"pw-two").decode()),
            Switch(id=3, ip_address="10.0.0.3", owner_username="a"),
        ])
        self.db.commit()

    def tearDown(self):
        self.db.close()

    def run_pass(self):
        with patch.object(settings, "SECRET_KEY", self.secret):
            return main._reencrypt_stored_credentials(self.db)

    def test_every_stored_credential_is_moved(self):
        self.assertEqual(self.run_pass(), 3)

    def test_the_plaintext_is_unchanged(self):
        self.run_pass()
        with patch.object(settings, "SECRET_KEY", self.secret):
            rows = {r.id: r for r in self.db.query(Switch).all()}
            self.assertEqual(
                crypto.decrypt_password(self.secret, rows[1].saved_password), "pw-one")
            self.assertEqual(
                crypto.decrypt_password(self.secret, rows[1].saved_enable_password),
                "en-one")
            self.assertEqual(
                crypto.decrypt_password(self.secret, rows[2].saved_password), "pw-two")

    def test_nothing_is_left_on_the_published_key(self):
        self.run_pass()
        for row in self.db.query(Switch).all():
            for token in (row.saved_password, row.saved_enable_password):
                if token:
                    self.assertFalse(
                        crypto.is_legacy_ciphertext(self.secret, token))

    def test_running_it_twice_is_a_no_op(self):
        self.run_pass()
        self.assertEqual(self.run_pass(), 0)

    def test_a_switch_without_a_password_is_untouched(self):
        self.run_pass()
        row = self.db.query(Switch).filter(Switch.id == 3).first()
        self.assertIsNone(row.saved_password)

    def test_an_unreadable_value_is_left_alone_rather_than_destroyed(self):
        row = self.db.query(Switch).filter(Switch.id == 2).first()
        row.saved_password = "not-a-fernet-token"
        self.db.commit()
        self.run_pass()
        self.assertEqual(
            self.db.query(Switch).filter(Switch.id == 2).first().saved_password,
            "not-a-fernet-token")


class TokenRevocationTests(unittest.TestCase):
    """A role change or password reset used to leave the old token working
    for up to eight hours."""

    def setUp(self):
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        self.db = sessionmaker(bind=engine)()
        self.user = User(username="amir", hashed_password="x", role=ROLE_ADMIN)
        self.db.add(self.user)
        self.db.commit()

    def tearDown(self):
        self.db.close()

    def resolve(self, token):
        return asyncio.run(auth.get_current_user(token, self.db))

    def token_for(self, user, issued_at=None):
        token = auth.create_access_token({"sub": user.username, "role": user.role})
        if issued_at is None:
            return token
        claims = jwt.decode(token, crypto.signing_key(settings.SECRET_KEY),
                            algorithms=[settings.ALGORITHM])
        claims["iat"] = int(issued_at.timestamp())
        return jwt.encode(claims, crypto.signing_key(settings.SECRET_KEY),
                          algorithm=settings.ALGORITHM)

    def test_a_fresh_token_is_accepted(self):
        self.assertIs(self.resolve(self.token_for(self.user)), self.user)

    def test_a_token_issued_before_revocation_is_refused(self):
        stale = self.token_for(self.user,
                               issued_at=datetime.utcnow() - timedelta(hours=1))
        auth.revoke_tokens(self.db, self.user)
        with self.assertRaises(HTTPException) as caught:
            self.resolve(stale)
        self.assertEqual(caught.exception.status_code, 401)

    def test_a_token_issued_after_revocation_is_accepted(self):
        auth.revoke_tokens(self.db, self.user)
        self.assertIs(self.resolve(self.token_for(self.user)), self.user)

    def test_accounts_that_never_revoked_are_unaffected(self):
        self.assertIsNone(self.user.tokens_valid_from)
        old = self.token_for(self.user,
                             issued_at=datetime.utcnow() - timedelta(hours=6))
        self.assertIs(self.resolve(old), self.user)

    def test_a_token_without_an_issue_time_is_refused_after_revocation(self):
        claims = {"sub": self.user.username, "role": self.user.role,
                  "exp": datetime.utcnow() + timedelta(hours=1)}
        forged = jwt.encode(claims, crypto.signing_key(settings.SECRET_KEY),
                            algorithm=settings.ALGORITHM)
        auth.revoke_tokens(self.db, self.user)
        with self.assertRaises(HTTPException):
            self.resolve(forged)

    def test_revoking_one_account_does_not_touch_another(self):
        other = User(username="mina", hashed_password="x", role=ROLE_ADMIN)
        self.db.add(other)
        self.db.commit()
        token = self.token_for(other,
                               issued_at=datetime.utcnow() - timedelta(hours=1))
        auth.revoke_tokens(self.db, self.user)
        self.assertIs(self.resolve(token), other)


class TokenSigningTests(unittest.TestCase):

    def test_a_token_signed_with_the_published_secret_is_refused(self):
        # The exact forgery the old scheme allowed: anyone with the repo could
        # mint an administrator token.
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        db = sessionmaker(bind=engine)()
        try:
            db.add(User(username="admin", hashed_password="x",
                        role=ROLE_SUPER_ADMIN))
            db.commit()
            forged = jwt.encode(
                {"sub": "admin", "role": ROLE_SUPER_ADMIN,
                 "exp": datetime.utcnow() + timedelta(hours=1),
                 "iat": datetime.utcnow()},
                crypto.LEGACY_SECRET, algorithm=settings.ALGORITHM)
            with self.assertRaises(HTTPException) as caught:
                asyncio.run(auth.get_current_user(forged, db))
            self.assertEqual(caught.exception.status_code, 401)
        finally:
            db.close()


class DefaultAdminTests(unittest.TestCase):

    def setUp(self):
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        self.db = sessionmaker(bind=engine)()

    def tearDown(self):
        self.db.close()

    def test_the_seeded_account_uses_the_documented_password(self):
        auth.ensure_admin_exists(self.db)
        self.assertTrue(auth.uses_default_admin_password(self.db))
        admin = auth.get_user(self.db, "admin")
        self.assertEqual(admin.role, ROLE_SUPER_ADMIN)

    def test_the_seeded_password_deliberately_fails_the_app_s_own_rules(self):
        # So it cannot quietly become a permanent password.
        self.assertIsNotNone(auth.validate_password(auth.DEFAULT_ADMIN_PASSWORD))

    def test_changing_it_clears_the_warning(self):
        auth.ensure_admin_exists(self.db)
        admin = auth.get_user(self.db, "admin")
        admin.hashed_password = auth.get_password_hash("A-real-Password-1!")
        self.db.commit()
        self.assertFalse(auth.uses_default_admin_password(self.db))

    def test_seeding_does_not_run_when_accounts_already_exist(self):
        self.db.add(User(username="someone", hashed_password="x",
                         role=ROLE_ADMIN))
        self.db.commit()
        auth.ensure_admin_exists(self.db)
        self.assertIsNone(auth.get_user(self.db, "admin"))


class NoPublishedCredentialsTests(unittest.TestCase):
    """Nothing that runs should print a working credential."""

    def test_the_startup_scripts_do_not_announce_the_password(self):
        from pathlib import Path
        root = Path(__file__).resolve().parent.parent
        for name in ("start.sh", "start.bat"):
            text = (root / name).read_text()
            self.assertNotIn("Admin@Giga2026", text, name)
            self.assertNotIn(auth.DEFAULT_ADMIN_PASSWORD + '"', text, name)

    def test_seeding_does_not_print_the_password(self):
        import inspect
        source = inspect.getsource(auth.ensure_admin_exists)
        self.assertNotIn(f'/ {auth.DEFAULT_ADMIN_PASSWORD}', source)
        self.assertNotIn("Admin@Giga2026", source)


if __name__ == "__main__":
    unittest.main()


class ConfigPathTests(unittest.TestCase):
    """The bug that nearly orphaned every stored credential: .env was looked
    up relative to the working directory, and start.sh runs from backend/."""

    def test_the_env_file_is_resolved_absolutely(self):
        import config
        self.assertTrue(config.ENV_PATH.is_absolute())
        self.assertEqual(config.ENV_PATH.name, ".env")
        self.assertEqual(config.ENV_PATH, crypto.ENV_FILE)

    def test_it_sits_beside_the_startup_script_not_inside_backend(self):
        import config
        self.assertTrue((config.ENV_PATH.parent / "start.sh").exists())

    def test_no_usable_secret_ships_as_a_default(self):
        # A default that works is a default that stays in production.
        import inspect
        source = inspect.getsource(__import__("config"))
        self.assertNotIn(crypto.LEGACY_SECRET, source)
        self.assertIn('SECRET_KEY: str = ""', source)


class OrphanGuardTests(unittest.TestCase):

    def setUp(self):
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        self.Session = sessionmaker(bind=engine)
        self.db = self.Session()

    def tearDown(self):
        self.db.close()

    def test_it_refuses_to_rotate_over_unreadable_credentials(self):
        # A password encrypted with a key nobody has any more.
        lost = crypto.encrypt_password(crypto.generate_secret(), "pw")
        self.db.add(Switch(ip_address="10.0.0.1", owner_username="a",
                           saved_password=lost))
        self.db.commit()
        with patch.object(main, "SessionLocal", self.Session), \
             patch.object(settings, "SECRET_KEY", ""):
            with self.assertRaises(RuntimeError) as caught:
                main._guard_against_orphaning_credentials()
        self.assertIn("permanently unrecoverable", str(caught.exception))

    def test_it_allows_rotation_when_everything_is_still_readable(self):
        key = crypto.LEGACY_SECRET.encode()[:32].ljust(32, b"0")
        legacy = Fernet(base64.urlsafe_b64encode(key)).encrypt(b"pw").decode()
        self.db.add(Switch(ip_address="10.0.0.1", owner_username="a",
                           saved_password=legacy))
        self.db.commit()
        with patch.object(main, "SessionLocal", self.Session), \
             patch.object(settings, "SECRET_KEY", ""):
            main._guard_against_orphaning_credentials()   # must not raise

    def test_it_does_nothing_once_a_real_key_is_loaded(self):
        with patch.object(settings, "SECRET_KEY", crypto.generate_secret()):
            main._guard_against_orphaning_credentials()   # must not raise
