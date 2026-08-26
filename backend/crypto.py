"""
Key management and credential encryption.

Two things used to share one hard-coded string: the JWT signing key and the
key that encrypts every stored switch password. That string shipped in the
repository, so anyone holding a copy could both mint an administrator token
and decrypt every credential in the database.

This module fixes that in three ways:

  · the root secret is generated once, at random, and kept out of git;
  · signing and encryption use *separate* keys derived from it, so rotating
    one does not force the other;
  · derivation is HKDF rather than truncate-and-pad, so the whole secret
    contributes and a short one is not silently padded with zeros.

`decrypt_password` still understands the old scheme, so a database written
before this change keeps working until the one-off re-encryption runs.
"""
import base64
import os
import secrets
from pathlib import Path
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# The value that shipped in config.py. Anything encrypted while it was in use
# has to stay readable long enough to be re-encrypted, and it must never be
# accepted as a real secret again.
LEGACY_SECRET = "giga-acl-secret-key-change-in-production-2024"

ENV_FILE = Path(__file__).resolve().parent.parent / ".env"

# Domain separation: the same root secret produces unrelated keys for
# unrelated jobs, so a key used for one purpose is useless for the other.
_INFO_SIGNING = b"gigacl.jwt.signing.v1"
_INFO_CREDENTIALS = b"gigacl.credentials.v1"


def generate_secret() -> str:
    return secrets.token_urlsafe(48)


def is_insecure_secret(value: Optional[str]) -> bool:
    return not value or value.strip() == LEGACY_SECRET or len(value.strip()) < 32


def ensure_secret_key(settings) -> bool:
    """
    Replace the shipped placeholder with a real, persisted secret.

    Returns True when a new key was generated. Persisting matters more than
    it might look: a key held only in memory would change on every restart
    and take every stored switch password with it.
    """
    if not is_insecure_secret(settings.SECRET_KEY):
        return False

    generated = generate_secret()
    _persist_secret(generated)
    settings.SECRET_KEY = generated
    return True


def _persist_secret(value: str):
    """Write SECRET_KEY into .env, leaving any other settings there intact."""
    lines = []
    if ENV_FILE.exists():
        lines = [ln for ln in ENV_FILE.read_text().splitlines()
                 if not ln.strip().startswith("SECRET_KEY=")]
    lines.append(f"SECRET_KEY={value}")
    try:
        ENV_FILE.write_text("\n".join(lines) + "\n")
        os.chmod(ENV_FILE, 0o600)
    except OSError as e:
        raise RuntimeError(
            f"Could not write the generated secret key to {ENV_FILE}: {e}\n"
            "Set SECRET_KEY yourself before starting again — a key that is "
            "not persisted would change on every restart and make every "
            "stored switch password unreadable."
        ) from e


def _derive(secret: str, info: bytes) -> bytes:
    """One 32-byte key per purpose, urlsafe-base64 encoded for Fernet."""
    raw = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
               info=info).derive(secret.encode())
    return base64.urlsafe_b64encode(raw)


def signing_key(secret: str) -> str:
    """The JWT signing key. Never the raw secret, so a leaked token signature
    reveals nothing about the credential key."""
    return _derive(secret, _INFO_SIGNING).decode()


def _credential_fernet(secret: str) -> Fernet:
    return Fernet(_derive(secret, _INFO_CREDENTIALS))


def _legacy_fernet() -> Fernet:
    """The original scheme: the first 32 bytes of the secret, zero-padded."""
    key_bytes = LEGACY_SECRET.encode()[:32].ljust(32, b"0")
    return Fernet(base64.urlsafe_b64encode(key_bytes))


def encrypt_password(secret: str, password: str) -> str:
    return _credential_fernet(secret).encrypt(password.encode()).decode()


def decrypt_password(secret: str, token: str) -> str:
    """
    Decrypt with the current key, falling back to the old scheme.

    The fallback is what lets an existing database keep working before the
    re-encryption pass has run, and what lets that pass read the old values
    in the first place.
    """
    try:
        return _credential_fernet(secret).decrypt(token.encode()).decode()
    except InvalidToken:
        return _legacy_fernet().decrypt(token.encode()).decode()


def is_legacy_ciphertext(secret: str, token: str) -> bool:
    """Whether this value still needs re-encrypting."""
    if not token:
        return False
    try:
        _credential_fernet(secret).decrypt(token.encode())
        return False
    except InvalidToken:
        return True
