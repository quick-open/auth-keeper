"""Accounts store: URI parsing, CRUD, search, and encrypted backup round-trip."""

from __future__ import annotations

import pytest

from authkeeper import crypto, vault
from authkeeper.errors import AuthKeeperError

from .conftest import FAST_KDF, PASSPHRASE, SAMPLE_SECRET, SAMPLE_URI


def _new_vault():
    return {"version": 1, "accounts": []}


def test_import_uri_parses_issuer_label_secret():
    v = _new_vault()
    acc = vault.import_uri(v, SAMPLE_URI)
    assert acc["issuer"] == "GitHub"
    assert acc["label"] == "alice@example.com"
    assert acc["secret"] == SAMPLE_SECRET
    assert acc["digits"] == 6
    assert acc["period"] == 30
    assert acc["algorithm"] == "SHA1"
    assert acc["type"] == "totp"
    assert len(vault.accounts(v)) == 1


def test_parse_uri_query_issuer_overrides_path():
    uri = ("otpauth://totp/Example%20Corp:bob?secret=" + SAMPLE_SECRET +
           "&issuer=RealIssuer")
    acc = vault.parse_uri(uri)
    assert acc["issuer"] == "RealIssuer"
    assert acc["label"] == "bob"


def test_parse_hotp_uri_counter():
    uri = "otpauth://hotp/Acme:carol?secret=" + SAMPLE_SECRET + "&counter=5"
    acc = vault.parse_uri(uri)
    assert acc["type"] == "hotp"
    assert acc["counter"] == 5


def test_parse_uri_rejects_non_otpauth():
    with pytest.raises(AuthKeeperError):
        vault.parse_uri("https://example.com/?secret=ABC")


def test_parse_uri_rejects_bad_secret():
    with pytest.raises(AuthKeeperError):
        vault.parse_uri("otpauth://totp/X:y?secret=not!base32!")


def test_add_update_delete_and_get():
    v = _new_vault()
    acc = vault.add(v, issuer="AWS", label="root", secret=SAMPLE_SECRET)
    aid = acc["id"]
    assert vault.get(v, aid)["issuer"] == "AWS"

    vault.update(v, aid, label="admin", digits=8)
    got = vault.get(v, aid)
    assert got["label"] == "admin"
    assert got["digits"] == 8
    assert got["secret"] == SAMPLE_SECRET  # unchanged

    vault.delete(v, aid)
    with pytest.raises(AuthKeeperError):
        vault.get(v, aid)


def test_search_matches_issuer_and_label():
    v = _new_vault()
    vault.add(v, issuer="GitHub", label="alice", secret=SAMPLE_SECRET)
    vault.add(v, issuer="GitLab", label="bob", secret=SAMPLE_SECRET)
    vault.add(v, issuer="AWS", label="alice-ops", secret=SAMPLE_SECRET)
    assert len(vault.search(v, "git")) == 2
    assert len(vault.search(v, "alice")) == 2
    assert len(vault.search(v, "")) == 3
    assert vault.search(v, "nope") == []


def test_hotp_counter_increments():
    v = _new_vault()
    acc = vault.add(v, issuer="Acme", label="c", secret=SAMPLE_SECRET,
                    type="hotp", counter=0)
    assert vault.increment_counter(v, acc["id"]) == 1
    assert vault.increment_counter(v, acc["id"]) == 2
    assert vault.get(v, acc["id"])["counter"] == 2


def test_increment_counter_rejects_totp():
    v = _new_vault()
    acc = vault.add(v, issuer="T", label="t", secret=SAMPLE_SECRET, type="totp")
    with pytest.raises(AuthKeeperError):
        vault.increment_counter(v, acc["id"])


def test_encrypted_export_import_roundtrip(tmp_path):
    src = _new_vault()
    vault.import_uri(src, SAMPLE_URI)
    vault.add(src, issuer="AWS", label="root", secret=SAMPLE_SECRET)
    backup = str(tmp_path / "backup.akv")
    vault.export_encrypted(src, backup, PASSPHRASE)

    dest = _new_vault()
    imported = vault.import_backup(dest, backup, PASSPHRASE)
    assert len(imported) == 2
    assert len(vault.accounts(dest)) == 2
    issuers = {a["issuer"] for a in vault.accounts(dest)}
    assert issuers == {"GitHub", "AWS"}


def test_import_backup_regenerates_colliding_ids(tmp_path):
    src = _new_vault()
    acc = vault.add(src, issuer="X", label="y", secret=SAMPLE_SECRET)
    backup = str(tmp_path / "b.akv")
    vault.export_encrypted(src, backup, PASSPHRASE)
    # Destination already holds an account with the SAME id.
    dest = {"version": 1, "accounts": [dict(acc)]}
    vault.import_backup(dest, backup, PASSPHRASE)
    ids = [a["id"] for a in vault.accounts(dest)]
    assert len(ids) == 2
    assert len(set(ids)) == 2  # no duplicate ids


def test_plaintext_export_requires_confirm(tmp_path):
    v = _new_vault()
    vault.import_uri(v, SAMPLE_URI)
    out = str(tmp_path / "plain.txt")
    with pytest.raises(AuthKeeperError):
        vault.export_plaintext(v, out, confirm=False)
    # With explicit confirmation the secret IS written (that is the risk).
    vault.export_plaintext(v, out, confirm=True)
    with open(out) as fh:
        text = fh.read()
    assert SAMPLE_SECRET in text
    assert text.startswith("otpauth://totp/")


def test_to_uri_roundtrips_through_parse():
    v = _new_vault()
    acc = vault.add(v, issuer="GitHub", label="alice", secret=SAMPLE_SECRET,
                    digits=8, algorithm="SHA256")
    uri = vault.to_uri(acc)
    back = vault.parse_uri(uri)
    assert back["issuer"] == "GitHub"
    assert back["label"] == "alice"
    assert back["secret"] == SAMPLE_SECRET
    assert back["digits"] == 8
    assert back["algorithm"] == "SHA256"
