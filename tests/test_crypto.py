"""Vault encryption: round-trip, wrong-passphrase safety, no plaintext on disk."""

from __future__ import annotations

import pytest

from authkeeper import crypto, vault
from authkeeper.errors import AuthKeeperError

from .conftest import FAST_KDF, PASSPHRASE, SAMPLE_SECRET, SAMPLE_URI


def test_create_and_load_roundtrip(vault_path):
    v = crypto.create_vault(vault_path, PASSPHRASE)
    assert v == {"version": 1, "accounts": []}
    vault.import_uri(v, SAMPLE_URI)
    crypto.save_vault(vault_path, v, PASSPHRASE, **FAST_KDF)

    loaded = crypto.load_vault(vault_path, PASSPHRASE)
    assert len(loaded["accounts"]) == 1
    acc = loaded["accounts"][0]
    assert acc["issuer"] == "GitHub"
    assert acc["label"] == "alice@example.com"
    assert acc["secret"] == SAMPLE_SECRET


def test_create_refuses_overwrite(vault_path):
    crypto.create_vault(vault_path, PASSPHRASE)
    with pytest.raises(AuthKeeperError):
        crypto.create_vault(vault_path, PASSPHRASE)


def test_wrong_passphrase_raises_and_reveals_nothing(vault_path):
    v = crypto.create_vault(vault_path, PASSPHRASE)
    vault.import_uri(v, SAMPLE_URI)
    crypto.save_vault(vault_path, v, PASSPHRASE, **FAST_KDF)

    with pytest.raises(AuthKeeperError) as excinfo:
        crypto.load_vault(vault_path, "not the passphrase")
    # The error is generic and leaks neither the secret nor the label.
    message = str(excinfo.value)
    assert SAMPLE_SECRET not in message
    assert "alice@example.com" not in message


def test_vault_file_contains_no_plaintext_secret(vault_path):
    v = crypto.create_vault(vault_path, PASSPHRASE)
    vault.import_uri(v, SAMPLE_URI)
    crypto.save_vault(vault_path, v, PASSPHRASE, **FAST_KDF)

    with open(vault_path, "rb") as fh:
        raw = fh.read()
    # The base32 secret must never appear in the on-disk bytes, in any casing.
    assert SAMPLE_SECRET.encode() not in raw
    assert SAMPLE_SECRET.lower().encode() not in raw
    assert b"alice@example.com" not in raw
    assert b"GitHub" not in raw


def test_tampered_ciphertext_raises(vault_path):
    v = crypto.create_vault(vault_path, PASSPHRASE)
    vault.import_uri(v, SAMPLE_URI)
    crypto.save_vault(vault_path, v, PASSPHRASE, **FAST_KDF)

    import json
    with open(vault_path) as fh:
        env = json.load(fh)
    env["ciphertext"] = env["ciphertext"][:-4] + "AAAA"
    with open(vault_path, "w") as fh:
        json.dump(env, fh)
    with pytest.raises(AuthKeeperError):
        crypto.load_vault(vault_path, PASSPHRASE)


def test_load_missing_vault_raises(tmp_path):
    with pytest.raises(AuthKeeperError):
        crypto.load_vault(str(tmp_path / "nope.akv"), PASSPHRASE)
