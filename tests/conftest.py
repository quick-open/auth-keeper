"""Shared pytest fixtures and constants for the AuthKeeper test-suite.

Everything here is deterministic: a fixed RFC-6238 test secret, a fixed
timestamp, and a fast scrypt cost so the crypto round-trips stay quick.
"""

from __future__ import annotations

import pytest

# RFC-6238 Appendix B uses the ASCII seed "12345678901234567890"; its base32
# encoding is the well-known test secret below.  pyotp reproduces the vectors.
RFC6238_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

# A base32 secret used across enrolment/import tests.
SAMPLE_SECRET = "JBSWY3DPEHPK3PXP"  # "Hello!\xDE\xAD\xBE\xEF" — classic example

SAMPLE_URI = (
    "otpauth://totp/GitHub:alice@example.com"
    "?secret=" + SAMPLE_SECRET + "&issuer=GitHub&digits=6&period=30&algorithm=SHA1"
)

PASSPHRASE = "correct horse battery staple"

# Low scrypt cost keeps the encrypted round-trips fast in tests only.
FAST_KDF = {"n": 1 << 12, "r": 8, "p": 1}


@pytest.fixture
def vault_path(tmp_path):
    return str(tmp_path / "test.akv")
