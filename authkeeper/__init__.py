"""authkeeper -- an offline, encrypted 2FA / TOTP authenticator library.

A password-encrypted local vault (scrypt + AES-256-GCM) of TOTP/HOTP accounts,
plus generation, otpauth import/export and QR helpers.  Secrets never leave the
device and are never written in plaintext.  The CLI (``python -m authkeeper``)
and the tkinter GUI both build on this module::

    from authkeeper import crypto, vault, otp
    v = crypto.create_vault("my.akv", "correct horse battery staple")
    vault.import_uri(v, "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP")
    crypto.save_vault("my.akv", v, "correct horse battery staple")

100% AI-built, open source, published on QuickOpen (quickopen.ai).
"""

from __future__ import annotations

from . import crypto, otp, qr, vault
from .errors import AuthKeeperError

__version__ = "1.1.0"

__all__ = [
    "AuthKeeperError",
    "crypto",
    "vault",
    "otp",
    "qr",
    "__version__",
]
