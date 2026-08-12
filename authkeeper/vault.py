r"""The in-memory accounts store and its (de)serialisation helpers.

A *vault* is the dict returned by :mod:`authkeeper.crypto` -- ``{"version": 1,
"accounts": [account, ...]}``.  An *account* is a plain dict::

    {
      "id":        "<uuid hex>",     # stable local id
      "issuer":    "GitHub",          # service name (may be "")
      "label":     "alice@example",   # account name (may be "")
      "secret":    "JBSWY3DPEHPK3PXP",# base32, no padding/spaces
      "digits":    6,
      "period":    30,                # TOTP step seconds
      "algorithm": "SHA1",            # SHA1 | SHA256 | SHA512
      "type":      "totp",            # totp | hotp
      "counter":   0,                 # hotp only
    }

This module never touches disk or crypto directly; it only shapes accounts and
parses/produces ``otpauth://`` URIs.  Encrypted backups round-trip through
:mod:`authkeeper.crypto`; a *plaintext* export is available only behind an
explicit confirmation flag because it writes secrets in the clear.

100% AI-built, open source, published on QuickOpen (quickopen.ai).
"""

from __future__ import annotations

import base64
import re
import uuid
from urllib.parse import parse_qs, quote, unquote, urlencode, urlparse

from . import crypto
from .errors import AuthKeeperError

VALID_TYPES = ("totp", "hotp")
VALID_ALGORITHMS = ("SHA1", "SHA256", "SHA512")
VALID_DIGITS = (6, 7, 8)


# --- helpers ----------------------------------------------------------------

def _normalise_secret(secret):
    """Upper-case, strip spaces/padding, and validate a base32 secret."""
    if not secret:
        raise AuthKeeperError("A base32 secret is required.")
    cleaned = re.sub(r"\s+", "", str(secret)).upper().rstrip("=")
    if not cleaned:
        raise AuthKeeperError("A base32 secret is required.")
    try:
        # Validate by decoding a padded copy; raises on non-base32 input.
        base64.b32decode(cleaned + "=" * (-len(cleaned) % 8))
    except Exception as exc:  # noqa: BLE001
        raise AuthKeeperError("Secret is not valid base32.") from exc
    return cleaned


def _coerce_account(issuer="", label="", secret="", digits=6, period=30,
                    algorithm="SHA1", type="totp", counter=0, id=None):
    kind = str(type or "totp").lower()
    if kind not in VALID_TYPES:
        raise AuthKeeperError(f"Unsupported OTP type: {type!r}")
    algo = str(algorithm or "SHA1").upper()
    if algo not in VALID_ALGORITHMS:
        raise AuthKeeperError(f"Unsupported algorithm: {algorithm!r}")
    try:
        digits = int(digits)
        period = int(period)
        counter = int(counter)
    except (TypeError, ValueError) as exc:
        raise AuthKeeperError("digits/period/counter must be integers.") from exc
    if digits not in VALID_DIGITS:
        raise AuthKeeperError("digits must be 6, 7 or 8.")
    if period <= 0:
        raise AuthKeeperError("period must be a positive integer.")
    return {
        "id": id or uuid.uuid4().hex,
        "issuer": (issuer or "").strip(),
        "label": (label or "").strip(),
        "secret": _normalise_secret(secret),
        "digits": digits,
        "period": period,
        "algorithm": algo,
        "type": kind,
        "counter": counter,
    }


def accounts(vault):
    """Return the account list (validated to be a list)."""
    items = (vault or {}).get("accounts")
    if not isinstance(items, list):
        raise AuthKeeperError("Vault has no accounts list.")
    return items


def get(vault, account_id):
    for acc in accounts(vault):
        if acc.get("id") == account_id:
            return acc
    raise AuthKeeperError(f"No account with id {account_id!r}.")


def display_name(account):
    """A human label like ``Issuer (label)`` / ``Issuer`` / ``label``."""
    issuer = (account.get("issuer") or "").strip()
    label = (account.get("label") or "").strip()
    if issuer and label:
        return f"{issuer} ({label})"
    return issuer or label or "(unnamed)"


# --- CRUD -------------------------------------------------------------------

def add(vault, issuer="", label="", secret="", digits=6, period=30,
        algorithm="SHA1", type="totp", counter=0):
    """Build, append and return a new account."""
    acc = _coerce_account(issuer=issuer, label=label, secret=secret,
                          digits=digits, period=period, algorithm=algorithm,
                          type=type, counter=counter)
    accounts(vault).append(acc)
    return acc


def add_account(vault, account):
    """Append a fully-formed (re-validated) account dict; returns it."""
    acc = _coerce_account(**{k: account.get(k) for k in (
        "issuer", "label", "secret", "digits", "period", "algorithm",
        "type", "counter", "id") if k in account})
    accounts(vault).append(acc)
    return acc


def update(vault, account_id, **fields):
    """Update mutable fields of an account; returns the updated account."""
    acc = get(vault, account_id)
    merged = dict(acc)
    merged.update({k: v for k, v in fields.items() if v is not None})
    merged["id"] = account_id
    fresh = _coerce_account(**{k: merged.get(k) for k in (
        "issuer", "label", "secret", "digits", "period", "algorithm",
        "type", "counter", "id")})
    acc.clear()
    acc.update(fresh)
    return acc


def delete(vault, account_id):
    """Remove an account by id; raises if not present."""
    items = accounts(vault)
    for i, acc in enumerate(items):
        if acc.get("id") == account_id:
            del items[i]
            return True
    raise AuthKeeperError(f"No account with id {account_id!r}.")


def increment_counter(vault, account_id):
    """Advance a HOTP account's counter and return the new value."""
    acc = get(vault, account_id)
    if str(acc.get("type", "totp")).lower() != "hotp":
        raise AuthKeeperError("Only HOTP accounts have a counter.")
    acc["counter"] = int(acc.get("counter", 0)) + 1
    return acc["counter"]


def search(vault, query):
    """Case-insensitive substring match over issuer + label."""
    q = (query or "").strip().lower()
    if not q:
        return list(accounts(vault))
    return [a for a in accounts(vault)
            if q in (a.get("issuer", "") + " " + a.get("label", "")).lower()]


# --- otpauth:// URIs --------------------------------------------------------

def parse_uri(uri):
    """Parse an ``otpauth://`` URI into a validated account dict.

    Handles the ``Issuer:label`` convention in the path plus the ``issuer``,
    ``secret``, ``digits``, ``period``, ``algorithm`` and ``counter`` query
    parameters.  Raises :class:`AuthKeeperError` on anything malformed.
    """
    if not uri or not str(uri).strip():
        raise AuthKeeperError("Empty otpauth URI.")
    parsed = urlparse(str(uri).strip())
    if parsed.scheme.lower() != "otpauth":
        raise AuthKeeperError("Not an otpauth:// URI.")
    kind = (parsed.netloc or parsed.hostname or "").lower()
    if kind not in VALID_TYPES:
        raise AuthKeeperError("otpauth URI must be of type totp or hotp.")

    # Path is "/Issuer:label" or "/label"; both parts are percent-encoded.
    raw_label = unquote(parsed.path.lstrip("/"))
    path_issuer, label = "", raw_label
    if ":" in raw_label:
        path_issuer, label = raw_label.split(":", 1)
    label = label.strip()
    path_issuer = path_issuer.strip()

    params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
    secret = params.get("secret", "")
    if not secret:
        raise AuthKeeperError("otpauth URI has no secret.")
    issuer = (params.get("issuer") or path_issuer or "").strip()

    counter = params.get("counter", 0)
    if kind == "hotp" and "counter" not in params:
        # RFC recommends an explicit counter; default to 0 if omitted.
        counter = 0

    return _coerce_account(
        issuer=issuer,
        label=label,
        secret=secret,
        digits=params.get("digits", 6),
        period=params.get("period", 30),
        algorithm=params.get("algorithm", "SHA1"),
        type=kind,
        counter=counter,
    )


def import_uri(vault, uri):
    """Parse *uri* and append the resulting account; returns it."""
    acc = parse_uri(uri)
    accounts(vault).append(acc)
    return acc


def to_uri(account):
    """Render an account as a canonical ``otpauth://`` URI (contains the secret)."""
    kind = str(account.get("type", "totp")).lower()
    issuer = (account.get("issuer") or "").strip()
    label = (account.get("label") or "").strip()
    name = f"{issuer}:{label}" if issuer and label else (label or issuer or "AuthKeeper")
    query = {
        "secret": account.get("secret", ""),
        "algorithm": str(account.get("algorithm", "SHA1")).upper(),
        "digits": int(account.get("digits", 6)),
    }
    if issuer:
        query["issuer"] = issuer
    if kind == "hotp":
        query["counter"] = int(account.get("counter", 0))
    else:
        query["period"] = int(account.get("period", 30))
    return f"otpauth://{kind}/{quote(name)}?{urlencode(query)}"


# --- backups / export -------------------------------------------------------

def export_encrypted(vault, out_path, passphrase):
    """Write an encrypted backup (same format as the vault) to *out_path*."""
    crypto.save_vault(out_path, {"version": crypto.FORMAT_VERSION,
                                 "accounts": list(accounts(vault))}, passphrase)
    return out_path


def import_backup(vault, backup_path, passphrase, merge=True):
    """Load an encrypted backup and merge its accounts into *vault*.

    Ids that collide with existing accounts are regenerated so nothing is
    silently overwritten.  Returns the list of imported accounts.
    """
    loaded = crypto.load_vault(backup_path, passphrase)
    existing_ids = {a.get("id") for a in accounts(vault)}
    imported = []
    target = accounts(vault) if merge else []
    for raw in accounts(loaded):
        acc = _coerce_account(**{k: raw.get(k) for k in (
            "issuer", "label", "secret", "digits", "period", "algorithm",
            "type", "counter", "id") if k in raw})
        if acc["id"] in existing_ids:
            acc["id"] = uuid.uuid4().hex
        existing_ids.add(acc["id"])
        target.append(acc)
        imported.append(acc)
    if not merge:
        vault["accounts"] = target
    return imported


def export_plaintext(vault, out_path, confirm=False):
    r"""Write a plaintext ``otpauth://`` export -- ONE line per account.

    .. warning::
       This writes every secret **in the clear**.  Anyone who reads the file
       can clone your 2FA.  It is refused unless *confirm* is explicitly True.
    """
    if not confirm:
        raise AuthKeeperError(
            "Refusing to write secrets in plaintext without an explicit "
            "confirmation (pass --yes / confirm=True).")
    lines = [to_uri(a) for a in accounts(vault)]
    try:
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + ("\n" if lines else ""))
    except OSError as exc:
        raise AuthKeeperError(f"Could not write export: {exc}") from exc
    return out_path
