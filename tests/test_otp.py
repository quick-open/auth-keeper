"""OTP generation: RFC-6238 vector, time_remaining, HOTP, and verify."""

from __future__ import annotations

import pyotp
import pytest

from authkeeper import otp, vault
from authkeeper.errors import AuthKeeperError

from .conftest import RFC6238_SECRET, SAMPLE_SECRET


def _totp_account(secret=RFC6238_SECRET, digits=8, period=30, algorithm="SHA1"):
    return {"id": "x", "issuer": "RFC", "label": "6238", "secret": secret,
            "digits": digits, "period": period, "algorithm": algorithm,
            "type": "totp", "counter": 0}


def test_totp_matches_rfc6238_vector():
    # RFC-6238 Appendix B, SHA1 seed, T = 59s -> code "94287082".
    acc = _totp_account()
    assert otp.code(acc, at=59) == "94287082"


def test_totp_matches_pyotp_reference():
    acc = _totp_account(secret=SAMPLE_SECRET, digits=6)
    expected = pyotp.TOTP(SAMPLE_SECRET).at(1234567890)
    assert otp.code(acc, at=1234567890) == expected


def test_time_remaining_is_deterministic():
    # At t=59 with a 30s step, 1 second remains in the current window.
    assert otp.time_remaining(30, at=59) == 1
    assert otp.time_remaining(30, at=45) == 15
    assert otp.time_remaining(30, at=30) == 30


def test_time_remaining_rejects_bad_period():
    with pytest.raises(AuthKeeperError):
        otp.time_remaining(0, at=10)


def test_hotp_code_advances_with_counter():
    acc = {"id": "h", "issuer": "A", "label": "b", "secret": SAMPLE_SECRET,
           "digits": 6, "period": 30, "algorithm": "SHA1", "type": "hotp",
           "counter": 0}
    c0 = otp.code(acc, counter=0)
    c1 = otp.code(acc, counter=1)
    assert c0 == pyotp.HOTP(SAMPLE_SECRET).at(0)
    assert c1 == pyotp.HOTP(SAMPLE_SECRET).at(1)
    assert c0 != c1


def test_hotp_code_uses_stored_counter():
    v = {"version": 1, "accounts": []}
    acc = vault.add(v, issuer="A", label="b", secret=SAMPLE_SECRET,
                    type="hotp", counter=0)
    first = otp.code(acc)
    vault.increment_counter(v, acc["id"])
    second = otp.code(acc)
    assert first == pyotp.HOTP(SAMPLE_SECRET).at(0)
    assert second == pyotp.HOTP(SAMPLE_SECRET).at(1)


def test_verify_totp_true_and_false():
    acc = _totp_account(secret=SAMPLE_SECRET, digits=6)
    good = otp.code(acc, at=1000)
    assert otp.verify(acc, good, at=1000) is True
    assert otp.verify(acc, "000000", at=1000) in (True, False)  # bounded
    assert otp.verify(acc, "", at=1000) is False


def test_code_bad_secret_raises_clean_error():
    acc = _totp_account(secret="", digits=6)
    with pytest.raises(AuthKeeperError):
        otp.code(acc, at=0)
