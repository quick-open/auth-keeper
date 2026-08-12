"""QR provisioning/render and headless-safe GUI import."""

from __future__ import annotations

import os

import pytest

from authkeeper import qr, vault
from authkeeper.errors import AuthKeeperError

from .conftest import SAMPLE_SECRET


def test_provisioning_uri_roundtrips():
    v = {"version": 1, "accounts": []}
    acc = vault.add(v, issuer="GitHub", label="alice", secret=SAMPLE_SECRET)
    uri = qr.provisioning_uri(acc)
    assert uri.startswith("otpauth://totp/")
    parsed = vault.parse_uri(uri)
    assert parsed["secret"] == SAMPLE_SECRET
    assert parsed["issuer"] == "GitHub"


def test_render_png_writes_a_file(tmp_path):
    v = {"version": 1, "accounts": []}
    acc = vault.add(v, issuer="GitHub", label="alice", secret=SAMPLE_SECRET)
    out = str(tmp_path / "qr.png")
    qr.render_png(acc, out)
    assert os.path.exists(out)
    with open(out, "rb") as fh:
        assert fh.read(8) == b"\x89PNG\r\n\x1a\n"  # PNG magic


def test_render_data_uri():
    v = {"version": 1, "accounts": []}
    acc = vault.add(v, issuer="X", label="y", secret=SAMPLE_SECRET)
    data = qr.render_data_uri(acc)
    assert data.startswith("data:image/png;base64,")


def test_decode_missing_file_raises():
    with pytest.raises(AuthKeeperError):
        qr.decode_image("/nonexistent/definitely-not-here.png")


def test_gui_imports_cleanly_and_is_side_effect_free():
    # Importing the GUI module must not create a Tk root or need a display.
    from authkeeper import gui
    assert hasattr(gui, "main")
    assert gui.group_code("123456") == "123 456"
    assert gui.group_code("12345678") == "1234 5678"


def test_gui_main_headless_returns_int(monkeypatch):
    # With no display, main() should degrade gracefully and return 0.
    from authkeeper import gui
    monkeypatch.delenv("DISPLAY", raising=False)
    rc = gui.main()
    assert rc == 0
