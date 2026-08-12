#!/usr/bin/env python3
r"""AuthKeeper -- an Aura (QuickOpen design system) GUI on the ``authkeeper`` API.

A single Aura window with a **Vault** section that swaps between an *unlock*
panel (pick a vault file + type the master passphrase) and, on success, the
live *accounts* view -- a searchable list where each account shows its
issuer/label, the ticking 6-digit code and a countdown toward the next
rotation.  A **Backup** section takes/imports encrypted backups and an
**About** section carries the credits.  Enrol by pasting an ``otpauth://`` URI,
typing the fields, or opening a QR image; Copy a code, Delete an account, and
Lock to wipe the passphrase and vault back out of memory.

Design goals baked in here (mirrors the QuickOpen house style):
  * built on the vendored ``authkeeper/aura.py`` design system, which layers the
    quickopen.ai look (deep space + light) over CustomTkinter.  Runtime deps:
    ``customtkinter`` (+ ``darkdetect``) -- declared in requirements.txt; the
    PyInstaller build adds ``--collect-all customtkinter``.
  * All disk/crypto work (unlock, save, backup) runs on a background thread so
    the window stays responsive; results marshal back with ``self.after`` and
    surface in the Aura status bar (never a raw traceback -- only the
    ``AuthKeeperError`` text).
  * Importing this module does nothing.  Only :func:`main` builds a root window,
    and it degrades gracefully (prints a note, returns 0) with no display or
    with customtkinter missing.
  * Frozen-exe safe: bundled assets resolve via ``sys._MEIPASS`` / the exe
    directory when ``sys.frozen`` is set -- never ``__file__``.
  * Secrets stay in memory only: the passphrase and decrypted vault are dropped
    on Lock and on close; the config file holds paths and theme only.

100% AI-built, open source, published on QuickOpen (quickopen.ai).
"""

from __future__ import annotations

import os
import sys
import threading

# NOTE: tkinter/customtkinter are imported lazily inside main()/build_app so
# that merely importing this module (e.g. during packaging or on a headless CI
# box) never fails.

APP_NAME = "AuthKeeper"
APP_VERSION = "1.0.0"
WINDOW_TITLE = "AuthKeeper — by QuickOpen (quickopen.ai)"
PROJECT_URL = "https://quickopen.ai"
# publish/specs/auth-keeper.json icon accent is near-black (#0f1115); the Aura
# UI-accent registry overrides it to this amber so buttons/pills/codes read.
ACCENT = "#e0a63a"

VAULT_TYPES = [("AuthKeeper vault", "*.akv *.vault *.json"), ("All files", "*.*")]
IMAGE_TYPES = [
    ("Images", "*.png *.jpg *.jpeg *.bmp *.gif *.tif *.tiff"),
    ("All files", "*.*"),
]


# ---------------------------------------------------------------------------
# Asset / frozen handling
# ---------------------------------------------------------------------------
def asset_path(name):
    """Locate a bundled asset from source OR a PyInstaller one-file build.

    For a frozen exe we look only at ``sys._MEIPASS`` and the executable's own
    directory (never ``__file__``).  From source we also consult the package
    dir, the repo root and the CWD.  Returns an absolute path or ``None``.
    """
    roots = []
    if getattr(sys, "frozen", False):
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            roots.append(meipass)
        roots.append(os.path.dirname(os.path.abspath(sys.executable)))
    else:
        here = os.path.dirname(os.path.abspath(__file__))
        roots += [here, os.path.dirname(here), os.getcwd()]
    for root in roots:
        candidate = os.path.join(root, name)
        if os.path.exists(candidate):
            return candidate
    return None


def open_with_default_app(path):
    """Open a file/URL with the OS default application, guarded."""
    try:
        if hasattr(os, "startfile"):
            os.startfile(path)                # noqa: S606
        elif sys.platform == "darwin":
            import subprocess
            subprocess.Popen(["open", path])
        else:
            import subprocess
            subprocess.Popen(["xdg-open", path])
        return True
    except Exception:
        return False


def group_code(code):
    """Render "123456" as "123 456" for readability."""
    code = str(code)
    if len(code) == 6:
        return code[:3] + " " + code[3:]
    if len(code) == 8:
        return code[:4] + " " + code[4:]
    mid = len(code) // 2
    return code[:mid] + " " + code[mid:]


# ---------------------------------------------------------------------------
# The app (built lazily; tkinter/customtkinter imported only inside build_app)
# ---------------------------------------------------------------------------
def build_app():
    """Construct and return the App class bound to live GUI imports.

    Kept inside a function so this module imports cleanly without a display
    (and without customtkinter installed).
    """
    import tkinter as tk
    from tkinter import filedialog, messagebox
    import customtkinter as ctk

    from . import aura, crypto, guiconfig, otp, qr, vault
    from .errors import AuthKeeperError

    # A tuple text_color auto-switches with the Aura (light, dark) theme.
    DANGER = (aura.TOKENS["light"]["danger"], aura.TOKENS["dark"]["danger"])
    MONO = "Consolas" if os.name == "nt" else "DejaVu Sans Mono"

    # -- the main window --------------------------------------------------

    class App(aura.AuraApp):
        def __init__(self):
            super().__init__(
                title=WINDOW_TITLE, app_name=APP_NAME, accent=ACCENT,
                theme=guiconfig.get_theme(),
                icon_png=asset_path("auth-keeper.png"), version=APP_VERSION,
                tagline="offline · encrypted",
                on_theme_change=guiconfig.set_theme,
                size=(940, 660), min_size=(760, 540))

            self._busy = False
            self._img_refs_gui = []     # keep PhotoImage refs alive (icon)

            # --- vault session state (secrets live only here, in memory) ----
            self._vault_path = None
            self._passphrase = None
            self._vault = None
            self._rows = []             # per-account live widgets on the list
            self._filter = ""
            self._tick_job = None
            self._vault_frame = None    # content host for the Vault section
            self._code_font = ctk.CTkFont(family=MONO, size=22, weight="bold")

            self._set_icon()
            self._build_menu()

            # A Lock action lives in the header, shown only while unlocked.
            self._lock_btn = aura.AuraButton(
                self.header_actions, "Lock", kind="secondary", height=30,
                command=self.lock)

            self.add_section("vault", "Vault", "⛁", self._build_vault_section)
            self.add_section("backup", "Backup", "⇅", self._build_backup_section)
            self.add_section("about", "About", "ℹ", self._build_about)
            self.show("vault")

            self.protocol("WM_DELETE_WINDOW", self._on_close)

        # ---- assets / icon
        def _set_icon(self):
            try:
                ico = asset_path("auth-keeper.ico")
                if ico and os.name == "nt":
                    self.iconbitmap(ico)
                    return
            except Exception:
                pass
            try:
                png = asset_path("auth-keeper.png")
                if png:
                    img = tk.PhotoImage(file=png)
                    self._img_refs_gui.append(img)
                    self.iconphoto(True, img)
            except Exception:
                pass  # icon is cosmetic; never block launch

        # ---- menu (native menus stay; theme also lives in the sidebar toggle)
        def _build_menu(self):
            bar = tk.Menu(self)
            filem = tk.Menu(bar, tearoff=0)
            filem.add_command(label="Open vault…", command=self._menu_open_vault)
            filem.add_command(label="Lock vault", command=self.lock)
            filem.add_separator()
            filem.add_command(label="Exit", command=self._on_close)
            bar.add_cascade(label="File", menu=filem)

            viewm = tk.Menu(bar, tearoff=0)
            viewm.add_command(
                label="Toggle dark mode",
                command=lambda: self.set_theme(
                    "light" if self.theme == "dark" else "dark"))
            bar.add_cascade(label="View", menu=viewm)

            helpm = tk.Menu(bar, tearoff=0)
            helpm.add_command(label="About", command=lambda: self.show("about"))
            helpm.add_command(label="Open project page (quickopen.ai)",
                              command=lambda: open_with_default_app(PROJECT_URL))
            bar.add_cascade(label="Help", menu=helpm)
            self.configure(menu=bar)

        def _menu_open_vault(self):
            self.lock()
            p = filedialog.askopenfilename(title="Open a vault",
                                           filetypes=VAULT_TYPES)
            if p and hasattr(self, "_path_var"):
                self._path_var.set(p)

        # ---- status helpers (thin proxies onto the Aura status bar)
        def _set_status(self, text, kind="idle"):
            self.set_status(text, kind)

        def _show_error(self, message):
            self.set_error(message)

        def _show_ok(self, message):
            self.set_success(message)

        # ---- background operation runner
        def _bg(self, work, on_ok, button=None, busy="Working…"):
            """Run ``work()`` off the UI thread; call ``on_ok(result)`` back on it.

            Errors surface in the status bar (AuthKeeperError message, or a
            generic note), never as a traceback.  Refuses a second op while busy.
            """
            if self._busy:
                self._show_error("Please wait — an operation is already running.")
                return
            self._busy = True
            if button is not None:
                try:
                    button.state(["disabled"])
                except Exception:
                    pass
            self._set_status(busy, kind="working")

            def run():
                try:
                    res, err = work(), None
                except AuthKeeperError as ex:
                    res, err = None, str(ex)
                except Exception as ex:  # never leak a traceback
                    res, err = None, f"Unexpected error: {ex}"
                self.after(0, lambda: finish(res, err))

            def finish(res, err):
                self._busy = False
                if button is not None:
                    try:
                        button.state(["!disabled"])
                    except Exception:
                        pass
                if err is not None:
                    self._show_error(err)
                    return
                try:
                    on_ok(res)
                except Exception as ex:
                    self._show_error(f"Post-processing error: {ex}")

            threading.Thread(target=run, daemon=True).start()

        # =====================================================================
        # VAULT section  (unlock panel  <->  live accounts view)
        # =====================================================================
        def _build_vault_section(self, frame):
            self._vault_frame = frame
            self._render_vault_screen()

        def _clear_vault_frame(self):
            if self._vault_frame is not None:
                for child in self._vault_frame.winfo_children():
                    child.destroy()
            self._rows = []

        def _render_vault_screen(self):
            self._clear_vault_frame()
            if self._vault is None:
                self._show_unlock()
            else:
                self._show_vault()

        # ---- unlock panel ---------------------------------------------------
        def _show_unlock(self):
            self._stop_tick()
            self._clear_vault_frame()
            try:
                self._lock_btn.pack_forget()
            except Exception:
                pass
            self._set_status("Locked")

            wrap = ctk.CTkFrame(self._vault_frame, fg_color="transparent")
            wrap.pack(fill="both", expand=True)

            card = aura.Card(wrap, title="Unlock your vault")
            card.pack(anchor="n", pady=(4, 0))
            aura.Caption(
                card.body, wraplength=440,
                text="Everything is stored locally and encrypted with your "
                     "master passphrase (scrypt + AES-256-GCM). Nothing is "
                     "uploaded anywhere.").pack(anchor="w", pady=(0, 12))

            form = ctk.CTkFrame(card.body, fg_color="transparent")
            form.pack(fill="x")
            form.columnconfigure(1, weight=1)

            aura.Caption(form, "Vault file").grid(row=0, column=0, sticky="w",
                                                  padx=(0, 10), pady=5)
            self._path_var = tk.StringVar(value=self._default_vault_path())
            ent = aura.AuraEntry(form, textvariable=self._path_var, width=320)
            ent.grid(row=0, column=1, sticky="ew", pady=5)
            aura.AuraButton(form, "Browse…", kind="secondary", height=30,
                            command=self._browse_vault).grid(
                row=0, column=2, padx=(8, 0))

            aura.Caption(form, "Passphrase").grid(row=1, column=0, sticky="w",
                                                  padx=(0, 10), pady=5)
            self._pw_var = tk.StringVar()
            pw = aura.AuraEntry(form, textvariable=self._pw_var, show="•",
                                width=320)
            pw.grid(row=1, column=1, columnspan=2, sticky="ew", pady=5)
            pw.bind("<Return>", lambda _e: self._do_unlock())

            btns = ctk.CTkFrame(card.body, fg_color="transparent")
            btns.pack(fill="x", pady=(14, 0))
            self._unlock_btn = aura.AuraButton(btns, "Unlock", kind="primary",
                                               command=self._do_unlock)
            self._unlock_btn.pack(side="left")
            aura.AuraButton(btns, "Create new vault…", kind="secondary",
                            command=self._do_create).pack(side="left", padx=8)

            recent = guiconfig.get_recent()
            if recent:
                rc = aura.Card(wrap, title="Recent vaults")
                rc.pack(fill="x", pady=(14, 0))
                for path in recent[:5]:
                    exists = os.path.exists(path)
                    txt = path if exists else path + "   (missing)"
                    b = aura.AuraButton(
                        rc.body, txt, kind="ghost",
                        command=(lambda pp=path: self._path_var.set(pp)))
                    if not exists:
                        b.state(["disabled"])
                    b.pack(anchor="w", pady=1, fill="x")

            def _focus_first():
                try:
                    target = pw if self._path_var.get() else ent
                    if target.winfo_exists():
                        target.focus_set()
                except Exception:
                    pass  # screen may have been swapped already

            self.after(60, _focus_first)

        def _default_vault_path(self):
            recent = guiconfig.get_recent()
            if recent and os.path.exists(recent[0]):
                return recent[0]
            return os.path.join(guiconfig.config_dir(), "vault.akv")

        def _browse_vault(self):
            p = filedialog.askopenfilename(title="Open a vault",
                                           filetypes=VAULT_TYPES)
            if p:
                self._path_var.set(p)

        def _do_unlock(self):
            path = self._path_var.get().strip()
            pw = self._pw_var.get()
            if not path:
                self._show_error("Choose a vault file.")
                return
            if not os.path.exists(path):
                self._show_error("That vault file does not exist — "
                                 "use “Create new vault…”.")
                return
            if not pw:
                self._show_error("Enter your passphrase.")
                return
            self._bg(lambda: crypto.load_vault(path, pw),
                     lambda v: self._on_unlocked(path, pw, v),
                     button=self._unlock_btn, busy="Unlocking…")

        def _do_create(self):
            p = filedialog.asksaveasfilename(
                title="Create a new vault", defaultextension=".akv",
                filetypes=VAULT_TYPES, initialfile="vault.akv")
            if not p:
                return
            dlg = _PassphraseDialog(self, create=True)
            self.wait_window(dlg.top)
            if not dlg.result:
                return
            pw = dlg.result
            self._bg(lambda: crypto.create_vault(p, pw),
                     lambda v: self._on_unlocked(p, pw, v),
                     busy="Creating…")

        def _on_unlocked(self, path, passphrase, vault_dict):
            self._vault_path = path
            self._passphrase = passphrase
            self._vault = vault_dict
            guiconfig.add_recent(path)
            self._filter = ""
            self.show("vault")
            self._render_vault_screen()
            n = len(vault.accounts(vault_dict))
            self._show_ok(f"Unlocked — {n} account(s).")

        # ---- live accounts view --------------------------------------------
        def _show_vault(self):
            self._clear_vault_frame()
            try:
                self._lock_btn.pack(side="right")
            except Exception:
                pass
            self._set_status("Unlocked", kind="ok")

            # toolbar
            tools = ctk.CTkFrame(self._vault_frame, fg_color="transparent")
            tools.pack(fill="x")
            aura.AuraButton(tools, "Add account", kind="primary",
                            command=self._add_dialog).pack(side="left")

            # search — placeholder needs NO textvariable (they're exclusive),
            # so read as-you-type via <KeyRelease>.
            sf = ctk.CTkFrame(self._vault_frame, fg_color="transparent")
            sf.pack(fill="x", pady=(12, 8))
            self._search_entry = aura.AuraEntry(sf, placeholder="Search accounts…")
            if self._filter:
                self._search_entry.insert(0, self._filter)
            self._search_entry.pack(side="left", fill="x", expand=True)
            self._search_entry.bind("<KeyRelease>", lambda _e: self._on_search())

            # scrollable account list
            self._list = ctk.CTkScrollableFrame(self._vault_frame,
                                                fg_color="transparent")
            self._list.pack(fill="both", expand=True)

            self._render_accounts()
            self._start_tick()

        def _on_search(self):
            self._filter = self._search_entry.get().strip()
            self._render_accounts()

        def _render_accounts(self):
            if self._vault is None or not hasattr(self, "_list"):
                return
            for child in self._list.winfo_children():
                child.destroy()
            self._rows = []
            try:
                items = vault.search(self._vault, self._filter)
            except AuthKeeperError:
                items = []
            if not items:
                msg = ("No accounts yet — click “Add account”."
                       if not self._filter else "No accounts match your search.")
                aura.Caption(self._list, msg).pack(anchor="w", pady=20, padx=4)
                return
            for acc in items:
                self._build_row(acc)
            self._refresh_codes()

        def _build_row(self, acc):
            card = aura.Card(self._list, padding=14)
            card.pack(fill="x", pady=5, padx=2)

            left = ctk.CTkFrame(card.body, fg_color="transparent")
            left.pack(side="left", fill="x", expand=True)
            aura.Heading(left, vault.display_name(acc)).pack(anchor="w")
            kind = acc.get("type", "totp").upper()
            aura.Caption(
                left, text=f"{kind} · {acc.get('digits', 6)} digits · "
                           f"{acc.get('algorithm', 'SHA1')}").pack(anchor="w")

            code_var = tk.StringVar(value="------")
            ctk.CTkLabel(left, textvariable=code_var, font=self._code_font,
                         text_color=aura._pair("accent"), anchor="w").pack(
                anchor="w", pady=(6, 0))

            is_totp = str(acc.get("type", "totp")).lower() == "totp"
            prog = None
            remain_var = tk.StringVar(value="")
            if is_totp:
                prog = aura.ProgressBar(left, width=220)
                prog.pack(anchor="w", pady=(6, 2))
                aura.Caption(left, textvariable=remain_var).pack(anchor="w")

            right = ctk.CTkFrame(card.body, fg_color="transparent")
            right.pack(side="right")
            aura.AuraButton(right, "Copy", kind="secondary", height=30,
                            command=lambda a=acc: self._copy_code(a)).pack(
                fill="x")
            if not is_totp:
                aura.AuraButton(right, "Next", kind="secondary", height=28,
                                command=lambda a=acc: self._hotp_next(a)).pack(
                    fill="x", pady=(6, 0))
            aura.AuraButton(right, "Share QR…", kind="ghost", height=28,
                            command=lambda a=acc: self._share_qr(a)).pack(
                fill="x", pady=(6, 0))
            aura.AuraButton(right, "Delete", kind="danger", height=28,
                            command=lambda a=acc: self._delete(a)).pack(
                fill="x", pady=(6, 0))

            self._rows.append({
                "acc": acc, "code_var": code_var, "prog": prog,
                "remain_var": remain_var, "totp": is_totp,
            })

        # ---- live refresh (the ticking OTP countdown)
        def _start_tick(self):
            self._stop_tick()
            self._tick()

        def _stop_tick(self):
            if self._tick_job is not None:
                try:
                    self.after_cancel(self._tick_job)
                except Exception:
                    pass
                self._tick_job = None

        def _tick(self):
            self._refresh_codes()
            self._tick_job = self.after(1000, self._tick)

        def _refresh_codes(self):
            for row in self._rows:
                acc = row["acc"]
                try:
                    row["code_var"].set(group_code(otp.code(acc)))
                except AuthKeeperError:
                    row["code_var"].set("error")
                    continue
                if row["totp"] and row["prog"] is not None:
                    period = int(acc.get("period", 30))
                    remaining = otp.time_remaining(period)
                    try:
                        # ProgressBar is a 0..1 scale (not maximum/value).
                        row["prog"].set(remaining / max(1, period))
                    except Exception:
                        pass
                    row["remain_var"].set(f"{remaining}s until refresh")

        # ---- actions
        def _copy_code(self, acc):
            try:
                code = otp.code(acc)
            except AuthKeeperError as ex:
                self._show_error(str(ex))
                return
            try:
                self.clipboard_clear()
                self.clipboard_append(code)
            except Exception:
                pass
            self._show_ok(f"Copied {vault.display_name(acc)} code to clipboard.")

        def _hotp_next(self, acc):
            try:
                vault.increment_counter(self._vault, acc["id"])
            except AuthKeeperError as ex:
                self._show_error(str(ex))
                return
            self._save(lambda: self._refresh_codes(),
                       ok="Advanced HOTP counter.")

        def _delete(self, acc):
            if not messagebox.askyesno(
                    "Delete account",
                    f"Delete “{vault.display_name(acc)}”?\n\n"
                    "This removes the secret from your vault. If you have no "
                    "other copy you may lose access to that account.",
                    parent=self):
                return
            try:
                vault.delete(self._vault, acc["id"])
            except AuthKeeperError as ex:
                self._show_error(str(ex))
                return
            self._save(lambda: self._render_accounts(),
                       ok=f"Deleted {vault.display_name(acc)}.")

        def _save(self, on_ok, ok="Saved."):
            """Persist the current vault to disk on a background thread."""
            path, pw, v = self._vault_path, self._passphrase, self._vault
            if not path or pw is None or v is None:
                self._show_error("No vault is open.")
                return
            self._bg(lambda: crypto.save_vault(path, v, pw),
                     lambda _r: (on_ok(), self._show_ok(ok)), busy="Saving…")

        def _add_dialog(self):
            dlg = _AddDialog(self, qr, vault)
            self.wait_window(dlg.top)
            if not dlg.result:
                return
            try:
                if dlg.result.get("uri"):
                    vault.import_uri(self._vault, dlg.result["uri"])
                else:
                    vault.add(self._vault, **dlg.result["fields"])
            except AuthKeeperError as ex:
                self._show_error(str(ex))
                return
            self._save(lambda: self._render_accounts(), ok="Account added.")

        def _share_qr(self, acc):
            p = filedialog.asksaveasfilename(
                title="Save QR image", defaultextension=".png",
                filetypes=[("PNG image", "*.png"), ("All files", "*.*")],
                initialfile=f"{vault.display_name(acc)}.png".replace("/", "_"))
            if not p:
                return
            self._bg(lambda: qr.render_png(acc, p),
                     lambda _r: (open_with_default_app(p),
                                 self._show_ok(f"Wrote QR image → {p}")),
                     busy="Rendering QR…")

        # =====================================================================
        # BACKUP section
        # =====================================================================
        def _build_backup_section(self, frame):
            card = aura.Card(frame, title="Encrypted backup")
            card.pack(fill="x")
            aura.Caption(
                card.body, wraplength=520,
                text="Export every account to a passphrase-encrypted backup "
                     "file (same scrypt + AES-256-GCM format as the vault), or "
                     "restore accounts from one. Unlock your vault first.").pack(
                anchor="w", pady=(0, 12))
            row = ctk.CTkFrame(card.body, fg_color="transparent")
            row.pack(fill="x")
            aura.AuraButton(row, "Back up…", kind="primary",
                            command=self._backup).pack(side="left")
            aura.AuraButton(row, "Restore…", kind="secondary",
                            command=self._restore).pack(side="left", padx=(8, 0))

        def _backup(self):
            if self._vault is None:
                self._show_error("Unlock your vault first.")
                return
            p = filedialog.asksaveasfilename(
                title="Save encrypted backup", defaultextension=".akv",
                filetypes=VAULT_TYPES, initialfile="authkeeper-backup.akv")
            if not p:
                return
            v, pw = self._vault, self._passphrase
            self._bg(lambda: vault.export_encrypted(v, p, pw),
                     lambda _r: self._show_ok(f"Encrypted backup → {p}"),
                     busy="Backing up…")

        def _restore(self):
            if self._vault is None:
                self._show_error("Unlock your vault first.")
                return
            p = filedialog.askopenfilename(title="Restore from backup",
                                           filetypes=VAULT_TYPES)
            if not p:
                return
            dlg = _PassphraseDialog(self, create=False,
                                    prompt="Backup passphrase "
                                           "(blank = this vault's):")
            self.wait_window(dlg.top)
            if dlg.cancelled:
                return
            backup_pw = dlg.result or self._passphrase
            v = self._vault

            def work():
                imported = vault.import_backup(v, p, backup_pw)
                return len(imported)

            self._bg(work,
                     lambda n: (self.show("vault"),
                                self._save(lambda: self._render_accounts(),
                                           ok=f"Restored {n} account(s).")),
                     busy="Restoring…")

        # =====================================================================
        # ABOUT section
        # =====================================================================
        def _build_about(self, frame):
            card = aura.Card(frame, title="About AuthKeeper")
            card.pack(fill="x")
            aura.Heading(card.body, APP_NAME).pack(anchor="w")
            aura.Caption(card.body, f"Version {APP_VERSION}").pack(
                anchor="w", pady=(0, 10))
            ctk.CTkLabel(
                card.body, font=aura.font(), justify="left", anchor="w",
                wraplength=520,
                text="A fast, fully-offline 2FA / TOTP authenticator with a "
                     "passphrase-encrypted local vault (scrypt + AES-256-GCM). "
                     "Enrol by pasting an otpauth:// URI or opening a QR image, "
                     "watch codes rotate live, and take encrypted backups.\n\n"
                     "100% AI-built, open source, published on QuickOpen. Your "
                     "secrets never leave the device.").pack(anchor="w")
            aura.Caption(
                card.body,
                "Licensed under Apache-2.0. Built on pyotp, cryptography, "
                "segno, Pillow and CustomTkinter (MIT).").pack(
                anchor="w", pady=(10, 4))
            aura.AuraButton(card.body, "Project page: quickopen.ai",
                            kind="ghost",
                            command=lambda: open_with_default_app(
                                PROJECT_URL)).pack(anchor="w", pady=(6, 0))

        # ---- lock / close
        def lock(self):
            """Drop the passphrase and decrypted vault from memory."""
            self._stop_tick()
            self._passphrase = None
            self._vault = None
            self._vault_path = None
            self._rows = []
            self.show("vault")
            self._render_vault_screen()
            self._show_ok("Locked. Your vault is encrypted on disk.")

        def _on_close(self):
            self._stop_tick()
            self._passphrase = None
            self._vault = None
            self.destroy()

    # -- dialogs ----------------------------------------------------------

    class _PassphraseDialog:
        """Modal passphrase prompt; ``create`` requires a confirmation field."""

        def __init__(self, app, create=False, prompt="Master passphrase:"):
            self.result = None
            self.cancelled = False
            self.top = top = ctk.CTkToplevel(app)
            top.title("Create vault" if create else "Passphrase")
            top.resizable(False, False)
            frm = ctk.CTkFrame(top, fg_color="transparent")
            frm.pack(fill="both", expand=True, padx=18, pady=18)

            aura.Heading(frm, prompt).pack(anchor="w", pady=(0, 6))
            self._pw = aura.AuraEntry(frm, show="•", width=300)
            self._pw.pack(fill="x", pady=(0, 6))
            self._create = create
            self._pw2 = None
            if create:
                aura.Caption(frm, "Confirm passphrase").pack(anchor="w")
                self._pw2 = aura.AuraEntry(frm, show="•", width=300)
                self._pw2.pack(fill="x", pady=(0, 6))
                aura.Caption(
                    frm, wraplength=300,
                    text="There is no recovery — if you forget this passphrase "
                         "the vault cannot be opened.").pack(anchor="w",
                                                             pady=(0, 6))
            self._err = ctk.CTkLabel(frm, text="", font=aura.font(role="caption"),
                                     text_color=DANGER, anchor="w")
            self._err.pack(anchor="w")
            btns = ctk.CTkFrame(frm, fg_color="transparent")
            btns.pack(fill="x", pady=(10, 0))
            aura.AuraButton(btns, "OK", kind="primary",
                            command=self._ok).pack(side="right")
            aura.AuraButton(btns, "Cancel", kind="secondary",
                            command=self._cancel).pack(side="right", padx=6)
            self._pw.bind("<Return>", lambda _e: self._ok())
            top.bind("<Escape>", lambda _e: self._cancel())
            top.transient(app)
            top.grab_set()
            app.after(80, self._pw.focus_set)

        def _ok(self):
            pw = self._pw.get()
            if not pw:
                self._err.configure(text="Enter a passphrase.")
                return
            if self._create and pw != self._pw2.get():
                self._err.configure(text="Passphrases do not match.")
                return
            self.result = pw
            self.top.destroy()

        def _cancel(self):
            self.cancelled = True
            self.result = None
            self.top.destroy()

    class _AddDialog:
        """Add an account: paste otpauth URI, type fields, or open a QR image."""

        def __init__(self, app, qr_mod, vault_mod):
            self.app = app
            self.qr = qr_mod
            self.vault = vault_mod
            self.result = None
            self.top = top = ctk.CTkToplevel(app)
            top.title("Add account")
            top.geometry("480x500")
            frm = ctk.CTkFrame(top, fg_color="transparent")
            frm.pack(fill="both", expand=True, padx=18, pady=18)

            aura.SectionLabel(frm, "Paste an otpauth:// URI").pack(anchor="w")
            self._uri = aura.AuraEntry(frm, placeholder="otpauth://totp/…")
            self._uri.pack(fill="x", pady=(4, 4))
            aura.AuraButton(frm, "Open a QR image…", kind="ghost",
                            command=self._open_qr).pack(anchor="w", pady=(0, 8))

            sep = ctk.CTkFrame(frm, height=1, fg_color=aura._pair("border"))
            sep.pack(fill="x", pady=6)
            aura.SectionLabel(frm, "Or enter the details manually").pack(
                anchor="w", pady=(4, 6))

            grid = ctk.CTkFrame(frm, fg_color="transparent")
            grid.pack(fill="x")
            grid.columnconfigure(1, weight=1)

            def field(r, text):
                aura.Caption(grid, text).grid(row=r, column=0, sticky="w",
                                              padx=(0, 10), pady=4)
                ent = aura.AuraEntry(grid)
                ent.grid(row=r, column=1, sticky="ew", pady=4)
                return ent

            self._issuer = field(0, "Issuer")
            self._label = field(1, "Label")
            self._secret = field(2, "Secret")

            aura.Caption(grid, "Digits").grid(row=3, column=0, sticky="w",
                                              padx=(0, 10), pady=4)
            self._digits = aura.AuraCombo(grid, values=["6", "7", "8"],
                                          state="readonly", width=90)
            self._digits.set("6")
            self._digits.grid(row=3, column=1, sticky="w", pady=4)

            aura.Caption(grid, "Period").grid(row=4, column=0, sticky="w",
                                              padx=(0, 10), pady=4)
            self._period = aura.AuraEntry(grid, width=90)
            self._period.insert(0, "30")
            self._period.grid(row=4, column=1, sticky="w", pady=4)

            aura.Caption(grid, "Algorithm").grid(row=5, column=0, sticky="w",
                                                 padx=(0, 10), pady=4)
            self._algorithm = aura.AuraCombo(
                grid, values=["SHA1", "SHA256", "SHA512"], state="readonly",
                width=120)
            self._algorithm.set("SHA1")
            self._algorithm.grid(row=5, column=1, sticky="w", pady=4)

            aura.Caption(grid, "Type").grid(row=6, column=0, sticky="w",
                                            padx=(0, 10), pady=4)
            self._type = aura.AuraCombo(grid, values=["totp", "hotp"],
                                        state="readonly", width=120)
            self._type.set("totp")
            self._type.grid(row=6, column=1, sticky="w", pady=4)

            self._err = ctk.CTkLabel(frm, text="", font=aura.font(role="caption"),
                                     text_color=DANGER, anchor="w")
            self._err.pack(anchor="w", pady=(8, 0))
            btns = ctk.CTkFrame(frm, fg_color="transparent")
            btns.pack(fill="x", pady=(6, 0))
            aura.AuraButton(btns, "Add", kind="primary",
                            command=self._ok).pack(side="right")
            aura.AuraButton(btns, "Cancel", kind="secondary",
                            command=self.top.destroy).pack(side="right", padx=6)
            top.transient(app)
            top.grab_set()

        @staticmethod
        def _fill(entry, text):
            entry.delete(0, "end")
            if text:
                entry.insert(0, text)

        def _open_qr(self):
            p = filedialog.askopenfilename(title="Open a QR image",
                                           filetypes=IMAGE_TYPES)
            if not p:
                return
            try:
                uri = self.qr.decode_image(p)
                self._fill(self._uri, uri)
                self._err.configure(text="")
            except AuthKeeperError as ex:
                self._err.configure(text=str(ex))

        def _ok(self):
            uri = self._uri.get().strip()
            if uri:
                # validate before accepting
                try:
                    self.vault.parse_uri(uri)
                except AuthKeeperError as ex:
                    self._err.configure(text=str(ex))
                    return
                self.result = {"uri": uri}
                self.top.destroy()
                return
            if not self._secret.get().strip():
                self._err.configure(text="Paste a URI or enter a secret.")
                return
            try:
                fields = {
                    "issuer": self._issuer.get(),
                    "label": self._label.get(),
                    "secret": self._secret.get(),
                    "digits": int(self._digits.get()),
                    "period": int(self._period.get() or 30),
                    "algorithm": self._algorithm.get(),
                    "type": self._type.get(),
                }
            except ValueError:
                self._err.configure(text="Digits and period must be numbers.")
                return
            self.result = {"fields": fields}
            self.top.destroy()

    return App


def main():
    """Entry point: build the root window and run.  Degrades on headless hosts.

    Importing this module does nothing; only this function creates a Tk root.
    With no display (e.g. a server) or without customtkinter installed, it
    prints a friendly note and returns 0 instead of raising.
    """
    try:
        import tkinter as tk
    except Exception as exc:  # tkinter missing entirely
        print(f"{APP_NAME}: a graphical environment with tkinter is required "
              f"to run the GUI ({exc}).")
        return 0

    try:
        App = build_app()
        app = App()
    except ImportError as exc:
        print(f"{APP_NAME}: the GUI needs the 'customtkinter' package "
              f"({exc}). Install it with:  pip install customtkinter")
        return 0
    except tk.TclError as exc:
        # Typically "no display name and no $DISPLAY environment variable".
        print(f"{APP_NAME}: no graphical display available — cannot start the "
              f"GUI here ({exc}). This app is intended for the Windows desktop.")
        return 0
    except Exception as exc:
        print(f"{APP_NAME}: could not start the GUI ({exc}).")
        return 1

    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
