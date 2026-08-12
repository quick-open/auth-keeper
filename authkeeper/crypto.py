r"""Passphrase-encrypted vault storage for AuthKeeper.

The on-disk vault is a small JSON *envelope* whose only interesting field is an
opaque ``ciphertext``.  The real payload -- the JSON list of accounts, each
holding a TOTP/HOTP ``secret`` -- is encrypted with **AES-256-GCM** using a key
derived from the master passphrase with **scrypt** (via ``cryptography``) and a
fresh random 16-byte salt.  A fresh random 12-byte nonce is used on every write.

Guarantees this module is responsible for:
  * A secret is *never* written to disk in plaintext -- only inside the GCM
    ciphertext.  The envelope is safe to back up or sync.
  * A wrong passphrase (or any tampering) fails the GCM authentication tag and
    is reported as a clean :class:`AuthKeeperError` -- we never return partial
    or garbage plaintext, and nothing about the payload leaks.

Public API::

    create_vault(path, passphrase)              -> vault dict (empty accounts)
    load_vault(path, passphrase)                -> vault dict
    save_vault(path, vault, passphrase)         -> None

100% AI-built, open source, published on QuickOpen (quickopen.ai).
"""

from __future__ import annotations

import base64
import json
import os
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .errors import AuthKeeperError

# --- format constants -------------------------------------------------------

FORMAT = "authkeeper-vault"
FORMAT_VERSION = 1

# scrypt cost parameters.  N must be a power of two; these give a strong,
# interactive-latency KDF.  They are stored in the envelope so a vault written
# with different parameters still loads.
SCRYPT_N = 1 << 15   # 32768
SCRYPT_R = 8
SCRYPT_P = 1

SALT_BYTES = 16
NONCE_BYTES = 12
KEY_BYTES = 32       # AES-256


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(text: str) -> bytes:
    try:
        return base64.b64decode(text.encode("ascii"), validate=True)
    except Exception as exc:  # noqa: BLE001 - normalise to our error type
        raise AuthKeeperError("Vault file is corrupt (bad base64).") from exc


def derive_key(passphrase, salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P):
    """Derive a 32-byte AES key from *passphrase* and *salt* using scrypt."""
    if not isinstance(passphrase, str) or passphrase == "":
        raise AuthKeeperError("A non-empty master passphrase is required.")
    kdf = Scrypt(salt=salt, length=KEY_BYTES, n=n, r=r, p=p)
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt_payload(payload, passphrase, salt=None, nonce=None,
                    n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P):
    """Encrypt *payload* (a JSON-serialisable object) into an envelope dict.

    A fresh random salt and nonce are used unless supplied (supplying them is
    only for deterministic tests).  Never call this with a reused salt+nonce
    pair on real data.
    """
    if salt is None:
        salt = secrets.token_bytes(SALT_BYTES)
    if nonce is None:
        nonce = secrets.token_bytes(NONCE_BYTES)
    key = derive_key(passphrase, salt, n=n, r=r, p=p)
    plaintext = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    return {
        "format": FORMAT,
        "version": FORMAT_VERSION,
        "kdf": "scrypt",
        "n": n, "r": r, "p": p,
        "salt": _b64e(salt),
        "nonce": _b64e(nonce),
        "ciphertext": _b64e(ciphertext),
    }


def decrypt_envelope(envelope, passphrase):
    """Return the decrypted payload object from an envelope dict.

    Raises :class:`AuthKeeperError` (with a generic message) on a wrong
    passphrase, tampering, or a malformed envelope -- never leaking plaintext.
    """
    if not isinstance(envelope, dict) or envelope.get("format") != FORMAT:
        raise AuthKeeperError("Not an AuthKeeper vault file.")
    try:
        salt = _b64d(envelope["salt"])
        nonce = _b64d(envelope["nonce"])
        ciphertext = _b64d(envelope["ciphertext"])
        n = int(envelope.get("n", SCRYPT_N))
        r = int(envelope.get("r", SCRYPT_R))
        p = int(envelope.get("p", SCRYPT_P))
    except (KeyError, TypeError, ValueError) as exc:
        raise AuthKeeperError("Vault file is corrupt or incomplete.") from exc
    key = derive_key(passphrase, salt, n=n, r=r, p=p)
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
    except InvalidTag:
        # Wrong passphrase OR tampered ciphertext.  Identical, generic message;
        # we deliberately reveal nothing about which, and no partial plaintext.
        raise AuthKeeperError(
            "Wrong passphrase or the vault is corrupt.") from None
    try:
        return json.loads(plaintext.decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise AuthKeeperError("Vault contents are unreadable.") from exc


# --- file-level API ---------------------------------------------------------

def _read_envelope(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError as exc:
        raise AuthKeeperError(f"Vault not found: {path}") from exc
    except (OSError, ValueError) as exc:
        raise AuthKeeperError(f"Could not read vault: {exc}") from exc
    if not isinstance(data, dict):
        raise AuthKeeperError("Not an AuthKeeper vault file.")
    return data


def _empty_vault():
    return {"version": FORMAT_VERSION, "accounts": []}


def create_vault(path, passphrase):
    """Create a new, empty encrypted vault at *path* and return the vault dict.

    Refuses to overwrite an existing file.
    """
    if os.path.exists(path):
        raise AuthKeeperError(f"A file already exists at {path}.")
    vault = _empty_vault()
    save_vault(path, vault, passphrase)
    return vault


def load_vault(path, passphrase):
    """Decrypt and return the vault dict at *path*.

    A wrong passphrase raises a clean :class:`AuthKeeperError` and reveals
    nothing about the contents.
    """
    envelope = _read_envelope(path)
    payload = decrypt_envelope(envelope, passphrase)
    if not isinstance(payload, dict) or not isinstance(
            payload.get("accounts"), list):
        raise AuthKeeperError("Vault contents are malformed.")
    payload.setdefault("version", FORMAT_VERSION)
    return payload


def save_vault(path, vault, passphrase, salt=None, nonce=None,
               n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P):
    """Encrypt *vault* and write it to *path* atomically.

    ``salt``/``nonce`` overrides exist only for deterministic tests.
    """
    if not isinstance(vault, dict) or not isinstance(
            vault.get("accounts"), list):
        raise AuthKeeperError("Refusing to save a malformed vault.")
    envelope = encrypt_payload(vault, passphrase, salt=salt, nonce=nonce,
                               n=n, r=r, p=p)
    directory = os.path.dirname(os.path.abspath(path))
    try:
        os.makedirs(directory, exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(envelope, fh, separators=(",", ":"))
        os.replace(tmp, path)
    except OSError as exc:
        raise AuthKeeperError(f"Could not write vault: {exc}") from exc
