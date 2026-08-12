r"""Command-line interface: ``python -m authkeeper <command> ...``.

Every command works on one encrypted vault (``--vault PATH``) and needs the
master passphrase, taken from ``--passphrase`` or an interactive prompt (never
echoed).  Commands::

    init                                   create a new empty vault
    add   --uri "otpauth://..."            enrol from a provisioning URI
    add   --issuer I --label L --secret S  enrol from fields
    list                                   list accounts (no secrets shown)
    code  <id>                             print the current OTP for an account
    remove <id>                            delete an account
    export --encrypted OUT                 write an encrypted backup
    export --plain OUT --yes               write a PLAINTEXT otpauth export
    import <backup>                        merge an encrypted backup in

Any :class:`AuthKeeperError` is printed to stderr and the process exits 1 --
never a traceback.

100% AI-built, open source, published on QuickOpen (quickopen.ai).
"""

from __future__ import annotations

import argparse
import getpass
import sys

from . import crypto, otp, vault
from .errors import AuthKeeperError

APP_NAME = "AuthKeeper"


# --- passphrase handling ----------------------------------------------------

def _get_passphrase(args, confirm=False, prompt="Master passphrase: "):
    """Return the passphrase from ``--passphrase`` or an interactive prompt."""
    if getattr(args, "passphrase", None):
        return args.passphrase
    if not sys.stdin or not sys.stdin.isatty():
        raise AuthKeeperError(
            "No passphrase given and no interactive terminal to prompt "
            "(use --passphrase).")
    try:
        pw = getpass.getpass(prompt)
        if confirm:
            again = getpass.getpass("Confirm passphrase: ")
            if pw != again:
                raise AuthKeeperError("Passphrases did not match.")
    except (EOFError, KeyboardInterrupt) as exc:
        raise AuthKeeperError("Passphrase entry cancelled.") from exc
    if not pw:
        raise AuthKeeperError("A non-empty passphrase is required.")
    return pw


def _load(args):
    return crypto.load_vault(args.vault, _get_passphrase(args))


# --- command handlers -------------------------------------------------------

def cmd_init(a):
    pw = _get_passphrase(a, confirm=True)
    crypto.create_vault(a.vault, pw)
    print(f"Created encrypted vault: {a.vault}")


def cmd_add(a):
    pw = _get_passphrase(a)
    v = crypto.load_vault(a.vault, pw)
    if a.uri:
        acc = vault.import_uri(v, a.uri)
    else:
        if not a.secret:
            raise AuthKeeperError(
                "Provide --uri, or --secret together with --issuer/--label.")
        acc = vault.add(v, issuer=a.issuer or "", label=a.label or "",
                        secret=a.secret, digits=a.digits, period=a.period,
                        algorithm=a.algorithm, type=a.type,
                        counter=a.counter or 0)
    crypto.save_vault(a.vault, v, pw)
    print(f"Added {vault.display_name(acc)}  [id {acc['id']}]")


def cmd_list(a):
    v = _load(a)
    items = vault.accounts(v)
    if not items:
        print("(no accounts yet)")
        return
    for acc in items:
        kind = acc.get("type", "totp").upper()
        print(f"{acc['id']}  {vault.display_name(acc):32.32s}  "
              f"{kind} {acc.get('digits', 6)}d/{acc.get('period', 30)}s "
              f"{acc.get('algorithm', 'SHA1')}")


def cmd_code(a):
    v = _load(a)
    acc = vault.get(v, a.id)
    value = otp.code(acc)
    remaining = ""
    if str(acc.get("type", "totp")).lower() == "totp":
        remaining = f"  (valid {otp.time_remaining(acc.get('period', 30))}s)"
    print(f"{value}{remaining}")
    if str(acc.get("type", "totp")).lower() == "hotp":
        # HOTP codes are single-use: advance and persist the counter.
        vault.increment_counter(v, a.id)
        crypto.save_vault(a.vault, v, _get_passphrase(a))


def cmd_remove(a):
    pw = _get_passphrase(a)
    v = crypto.load_vault(a.vault, pw)
    acc = vault.get(v, a.id)
    name = vault.display_name(acc)
    vault.delete(v, a.id)
    crypto.save_vault(a.vault, v, pw)
    print(f"Removed {name}  [id {a.id}]")


def cmd_export(a):
    v = _load(a)
    if a.plain:
        vault.export_plaintext(v, a.plain, confirm=a.yes)
        print(f"WROTE PLAINTEXT SECRETS to {a.plain} -- protect or delete it.")
    elif a.encrypted:
        pw = _get_passphrase(a)
        vault.export_encrypted(v, a.encrypted, pw)
        print(f"Wrote encrypted backup: {a.encrypted}")
    else:
        raise AuthKeeperError("Choose --encrypted OUT or --plain OUT --yes.")


def cmd_import(a):
    pw = _get_passphrase(a)
    v = crypto.load_vault(a.vault, pw)
    backup_pw = a.backup_passphrase or pw
    imported = vault.import_backup(v, a.backup, backup_pw)
    crypto.save_vault(a.vault, v, pw)
    print(f"Imported {len(imported)} account(s) from {a.backup}")


# --- parser -----------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(
        prog="authkeeper",
        description="Offline, encrypted 2FA / TOTP authenticator.")
    parser.add_argument("--vault", required=True, metavar="PATH",
                        help="path to the encrypted vault file")
    parser.add_argument("--passphrase", metavar="PW",
                        help="master passphrase (omit to be prompted)")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="create a new empty encrypted vault").set_defaults(
        func=cmd_init)

    p_add = sub.add_parser("add", help="add an account")
    p_add.add_argument("--uri", help='otpauth:// provisioning URI')
    p_add.add_argument("--issuer", help="service name, e.g. GitHub")
    p_add.add_argument("--label", help="account name, e.g. alice@example.com")
    p_add.add_argument("--secret", help="base32 shared secret")
    p_add.add_argument("--digits", type=int, default=6, choices=(6, 7, 8))
    p_add.add_argument("--period", type=int, default=30)
    p_add.add_argument("--algorithm", default="SHA1",
                       choices=("SHA1", "SHA256", "SHA512"))
    p_add.add_argument("--type", default="totp", choices=("totp", "hotp"))
    p_add.add_argument("--counter", type=int, default=0,
                       help="initial HOTP counter")
    p_add.set_defaults(func=cmd_add)

    sub.add_parser("list", help="list accounts").set_defaults(func=cmd_list)

    p_code = sub.add_parser("code", help="print the current code for an account")
    p_code.add_argument("id", help="account id (see 'list')")
    p_code.set_defaults(func=cmd_code)

    p_rm = sub.add_parser("remove", help="delete an account")
    p_rm.add_argument("id", help="account id (see 'list')")
    p_rm.set_defaults(func=cmd_remove)

    p_exp = sub.add_parser("export", help="export a backup")
    p_exp.add_argument("--encrypted", metavar="OUT",
                       help="write an encrypted backup")
    p_exp.add_argument("--plain", metavar="OUT",
                       help="write a PLAINTEXT otpauth export (needs --yes)")
    p_exp.add_argument("--yes", action="store_true",
                       help="confirm writing secrets in plaintext")
    p_exp.set_defaults(func=cmd_export)

    p_imp = sub.add_parser("import", help="merge an encrypted backup")
    p_imp.add_argument("backup", help="path to an encrypted backup file")
    p_imp.add_argument("--backup-passphrase", dest="backup_passphrase",
                       help="passphrase for the backup (defaults to the "
                            "vault passphrase)")
    p_imp.set_defaults(func=cmd_import)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except AuthKeeperError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
