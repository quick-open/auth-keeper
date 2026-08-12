r"""One-time-password generation on top of :mod:`pyotp`.

Thin, well-defined wrappers around ``pyotp`` that speak our *account* dicts
(see :mod:`authkeeper.vault`).  Everything that needs "the current time" accepts
an explicit ``at`` (a unix timestamp) so behaviour is fully deterministic in
tests -- pass a fixed timestamp to reproduce an RFC-6238 test vector exactly.

Public API::

    code(account, at=None)          -> str   (TOTP at a time / HOTP by counter)
    time_remaining(period, at=None) -> int   (seconds until the next TOTP step)
    verify(account, code, at=None)  -> bool

100% AI-built, open source, published on QuickOpen (quickopen.ai).
"""

from __future__ import annotations

import hashlib
import time

import pyotp

from .errors import AuthKeeperError

# Map the OTP ``algorithm`` field to a hashlib constructor pyotp accepts.
_DIGESTS = {
    "SHA1": hashlib.sha1,
    "SHA256": hashlib.sha256,
    "SHA512": hashlib.sha512,
}


def _digest_for(account):
    algo = str(account.get("algorithm", "SHA1")).upper()
    digest = _DIGESTS.get(algo)
    if digest is None:
        raise AuthKeeperError(f"Unsupported algorithm: {algo!r}")
    return digest


def _secret_of(account):
    secret = (account or {}).get("secret")
    if not secret:
        raise AuthKeeperError("Account has no secret.")
    return secret


def _totp(account):
    return pyotp.TOTP(
        _secret_of(account),
        digits=int(account.get("digits", 6)),
        interval=int(account.get("period", 30)),
        digest=_digest_for(account),
    )


def _hotp(account):
    return pyotp.HOTP(
        _secret_of(account),
        digits=int(account.get("digits", 6)),
        digest=_digest_for(account),
    )


def code(account, at=None, counter=None):
    """Return the current OTP for *account*.

    For a TOTP account the code is computed at unix time ``at`` (or now).  For a
    HOTP account it is computed at ``counter`` (or the account's stored
    counter).  The base32 secret is validated here; a malformed secret raises
    :class:`AuthKeeperError` rather than a low-level binascii error.
    """
    kind = str(account.get("type", "totp")).lower()
    try:
        if kind == "hotp":
            c = account.get("counter", 0) if counter is None else counter
            return _hotp(account).at(int(c))
        moment = time.time() if at is None else at
        return _totp(account).at(moment)
    except AuthKeeperError:
        raise
    except Exception as exc:  # noqa: BLE001 - e.g. bad base32 secret
        raise AuthKeeperError(f"Could not generate a code: {exc}") from exc


def time_remaining(period, at=None):
    """Seconds until the current TOTP step ends (1..period)."""
    try:
        period = int(period)
        if period <= 0:
            raise ValueError
    except (TypeError, ValueError) as exc:
        raise AuthKeeperError("Period must be a positive integer.") from exc
    now = time.time() if at is None else at
    return period - int(now) % period


def verify(account, candidate, at=None, valid_window=0):
    """Return True if *candidate* matches *account*'s current code.

    TOTP is checked at ``at`` (or now) with an optional ``valid_window`` of
    adjacent steps; HOTP is checked against the stored counter.
    """
    candidate = (candidate or "").strip()
    if not candidate:
        return False
    kind = str(account.get("type", "totp")).lower()
    try:
        if kind == "hotp":
            return bool(_hotp(account).verify(
                candidate, int(account.get("counter", 0))))
        moment = time.time() if at is None else at
        return bool(_totp(account).verify(
            candidate, for_time=moment, valid_window=valid_window))
    except AuthKeeperError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise AuthKeeperError(f"Could not verify a code: {exc}") from exc
