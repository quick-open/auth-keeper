# AuthKeeper

A fast, **offline**, **100% open-source** 2FA / TOTP authenticator for Windows. Nothing is uploaded anywhere. Built entirely by AI with human testing and guidance, and published on [QuickOpen](https://quickopen.ai/projects/auth-keeper).

> **100% AI-built and open source.** Apache-2.0.

## What it does

Store and generate TOTP/HOTP two-factor codes in a password-encrypted local vault. Enroll accounts by pasting an otpauth URI or scanning a QR image, see live rotating codes, and export/import an encrypted backup. Your secrets never leave the device — a desktop authenticator that you actually own.

## Install

Download **`AuthKeeper-Setup.exe`** from the [QuickOpen page](https://quickopen.ai/projects/auth-keeper) or the [GitHub release](https://github.com/quickpod/auth-keeper/releases/latest) and double-click it. It installs per-user, adds Desktop and Start Menu shortcuts, and can optionally trust the QuickOpen Root CA. Authenticode-signed by the QuickOpen Code Signing CA — verify at [quickopen.ai/trust](https://quickopen.ai/trust).

## Run from source

```sh
pip install -r requirements.txt
python auth_keeper_app.py          # GUI
python -m authkeeper --help    # CLI
```


## Features

- **Encrypted local vault.** Accounts live in a single file encrypted with **AES-256-GCM** under a key derived from your master passphrase with **scrypt** (random per-vault salt, random per-write nonce). Secrets are never written in plaintext, and a wrong passphrase fails cleanly with no partial leak.
- **TOTP and HOTP.** RFC-6238 time-based codes and RFC-4226 counter-based codes, with configurable digits (6/7/8), period, and algorithm (SHA1/SHA256/SHA512).
- **Easy enrolment.** Paste an `otpauth://` provisioning URI, type the fields by hand, or open a QR image (best-effort decode via OpenCV/pyzbar when present; otherwise paste the URI).
- **Live desktop GUI.** Unlock screen → searchable list of accounts, each with its live code and a countdown toward the next rotation; Copy, Delete, Share-as-QR, Lock, and dark/light mode.
- **Share to another device.** Render any account as a scannable `otpauth://` QR (via segno).
- **Backup & restore.** Export an encrypted backup (same format) and import/merge it back — colliding ids are regenerated so nothing is overwritten. A plaintext `otpauth://` export is available too, but only behind an explicit confirmation because it writes secrets in the clear.
- **Offline and private.** Nothing is uploaded anywhere; the passphrase and decrypted vault live in memory only and are dropped on Lock/exit. The config file (theme, recent vault paths) never holds secrets.

## CLI examples

Every command takes `--vault PATH` and the master passphrase (from `--passphrase`, or an interactive prompt if omitted):

```sh
# Create a new encrypted vault (prompts for the passphrase twice)
python -m authkeeper --vault my.akv init

# Add an account from an otpauth:// URI, or from explicit fields
python -m authkeeper --vault my.akv add --uri "otpauth://totp/GitHub:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"
python -m authkeeper --vault my.akv add --issuer AWS --label root --secret JBSWY3DPEHPK3PXP

# List accounts and print a live code
python -m authkeeper --vault my.akv list
python -m authkeeper --vault my.akv code <id>

# Remove an account
python -m authkeeper --vault my.akv remove <id>

# Encrypted backup / restore, and (risky) plaintext export
python -m authkeeper --vault my.akv export --encrypted backup.akv
python -m authkeeper --vault my.akv import backup.akv
python -m authkeeper --vault my.akv export --plain secrets.txt --yes
```

Any error exits non-zero with a one-line `error: …` message (never a traceback).

## License

Apache-2.0 — see [LICENSE](LICENSE). A 100% AI-built project published on QuickOpen.
