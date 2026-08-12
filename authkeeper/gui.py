#!/usr/bin/env python3
r"""AuthKeeper -- a pure-stdlib tkinter GUI on top of the ``authkeeper`` API.

A single main window with two screens: an **unlock** screen (pick a vault file
and type the master passphrase) that swaps, on success, to the **vault** screen
-- a searchable list of accounts, each showing its issuer/label, the live
6-digit code and a countdown progress toward the next rotation.  Enrol by
pasting an ``otpauth://`` URI, typing the fields, or opening a QR image; Copy a
code, Delete an account, take an encrypted Backup / Restore, and Lock to wipe
the passphrase and vault back out of memory.

Design goals baked in here (mirrors the QuickOpen house style):
  * pure standard-library tkinter/ttk -- NO third-party GUI deps.  Dark mode is
    a ttk-style + palette swap.  Every vault/crypto call goes through the tested
    ``authkeeper`` core; the UI never re-implements OTP or crypto logic.
  * All disk/crypto work (unlock, save, backup) runs on a background thread so
    the window stays responsive; results marshal back with ``self.after`` and
    surface inline (never a raw traceback -- only the ``AuthKeeperError`` text).
  * Importing this module does nothing.  Only :func:`main` builds a root window,
    and it degrades gracefully (prints a note, returns 0) with no display.
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

# NOTE: tkinter is imported lazily inside main()/build_app so that merely
# importing this module (e.g. during packaging or on a headless CI box) never
# fails.

APP_NAME = "AuthKeeper"
APP_VERSION = "1.0.0"
WINDOW_TITLE = "AuthKeeper — by QuickOpen (quickopen.ai)"
PROJECT_URL = "https://quickopen.ai"

VAULT_TYPES = [("AuthKeeper vault", "*.akv *.vault *.json"), ("All files", "*.*")]
IMAGE_TYPES = [
    ("Images", "*.png *.jpg *.jpeg *.bmp *.gif *.tif *.tiff"),
    ("All files", "*.*"),
]

# ---- colour palettes (mirror the QuickOpen palette) -------------------------
PALETTES = {
    "light": {
        "bg": "#f5f7fa", "surface": "#ffffff", "text": "#141820",
        "muted": "#5b6472", "primary": "#2f5fe0", "primary_hi": "#2450c8",
        "entry": "#ffffff", "border": "#d5dae2", "sel": "#2f5fe0",
        "sel_fg": "#ffffff", "trough": "#e2e7ef", "ok": "#1f7a3d",
        "err": "#c0392b",
    },
    "dark": {
        "bg": "#0f1115", "surface": "#1a1e24", "text": "#f1f3f7",
        "muted": "#9aa4b2", "primary": "#5b86f7", "primary_hi": "#7098ff",
        "entry": "#1a1e24", "border": "#2a2f38", "sel": "#5b86f7",
        "sel_fg": "#0f1115", "trough": "#2a2f38", "ok": "#5bd68a",
        "err": "#ff6b5e",
    },
}


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
# The app (built lazily; tkinter imported only inside build_app/main)
# ---------------------------------------------------------------------------
def build_app():
    """Construct and return the App class bound to a live tkinter import.

    Kept inside a function so this module imports cleanly without a display.
    """
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk

    from . import crypto, guiconfig, otp, qr, vault
    from .errors import AuthKeeperError

    FONT = "Segoe UI"
    MONO = "Consolas"

    # -- the main window --------------------------------------------------

    class App(tk.Tk):
        def __init__(self):
            super().__init__()
            self.title(WINDOW_TITLE)
            self.geometry("760x620")
            self.minsize(620, 480)

            self.theme = guiconfig.get_theme()
            self._busy = False
            self._tracked = []          # (tk_widget, role) for manual re-theming
            self._img_refs = []         # keep PhotoImage refs alive

            # --- vault session state (secrets live only here, in memory) ----
            self._vault_path = None
            self._passphrase = None
            self._vault = None
            self._rows = []             # per-account live widgets on the list
            self._filter = ""
            self._tick_job = None

            self._set_icon()
            self._build_menu()
            self._build_chrome()
            self._apply_theme()
            self.protocol("WM_DELETE_WINDOW", self._on_close)
            self._show_unlock()

        # ---- assets / icon
        def _set_icon(self):
            try:
                ico = asset_path("auth-keeper.ico")
                if ico:
                    self.iconbitmap(ico)
                    return
            except Exception:
                pass
            try:
                png = asset_path("auth-keeper.png")
                if png:
                    img = tk.PhotoImage(file=png)
                    self._img_refs.append(img)
                    self.iconphoto(True, img)
            except Exception:
                pass  # icon is cosmetic; never block launch

        # ---- theming
        def track(self, widget, role):
            self._tracked.append((widget, role))

        def _pal(self):
            return PALETTES[self.theme]

        def _apply_theme(self):
            p = self._pal()
            style = ttk.Style(self)
            try:
                style.theme_use("clam")
            except Exception:
                pass
            self.configure(bg=p["bg"])
            style.configure(".", background=p["bg"], foreground=p["text"],
                            fieldbackground=p["entry"], bordercolor=p["border"],
                            font=(FONT, 10))
            style.configure("TFrame", background=p["bg"])
            style.configure("Sidebar.TFrame", background=p["surface"])
            style.configure("Card.TFrame", background=p["surface"])
            style.configure("TLabel", background=p["bg"], foreground=p["text"])
            style.configure("Card.TLabel", background=p["surface"],
                            foreground=p["text"])
            style.configure("CardMuted.TLabel", background=p["surface"],
                            foreground=p["muted"])
            style.configure("Code.TLabel", background=p["surface"],
                            foreground=p["primary"], font=(MONO, 22, "bold"))
            style.configure("Muted.TLabel", background=p["bg"], foreground=p["muted"])
            style.configure("Header.TLabel", background=p["bg"], foreground=p["text"],
                            font=(FONT, 16, "bold"))
            style.configure("Sub.TLabel", background=p["bg"], foreground=p["muted"],
                            font=(FONT, 10))
            style.configure("Brand.TLabel", background=p["surface"],
                            foreground=p["text"], font=(FONT, 12, "bold"))
            style.configure("Status.TLabel", background=p["surface"],
                            foreground=p["muted"])
            style.configure("TButton", background=p["surface"], foreground=p["text"],
                            bordercolor=p["border"], focuscolor=p["surface"],
                            padding=(10, 5))
            style.map("TButton",
                      background=[("active", p["trough"]), ("disabled", p["bg"])],
                      foreground=[("disabled", p["muted"])])
            style.configure("Accent.TButton", background=p["primary"],
                            foreground="#ffffff", padding=(12, 6))
            style.map("Accent.TButton",
                      background=[("active", p["primary_hi"]),
                                  ("disabled", p["border"])],
                      foreground=[("disabled", p["muted"])])
            style.configure("Toggle.TButton", background=p["surface"],
                            foreground=p["text"], padding=(8, 4))
            style.configure("Card.TButton", background=p["surface"],
                            foreground=p["text"], padding=(8, 4))
            for name in ("TEntry", "TSpinbox"):
                style.configure(name, fieldbackground=p["entry"], foreground=p["text"],
                                insertcolor=p["text"], bordercolor=p["border"])
            style.configure("TCombobox", fieldbackground=p["entry"],
                            foreground=p["text"], background=p["surface"],
                            arrowcolor=p["text"])
            style.map("TCombobox", fieldbackground=[("readonly", p["entry"])],
                      foreground=[("readonly", p["text"])])
            style.configure("TCheckbutton", background=p["bg"], foreground=p["text"])
            style.map("TCheckbutton", background=[("active", p["bg"])])
            style.configure("TRadiobutton", background=p["bg"], foreground=p["text"])
            style.map("TRadiobutton", background=[("active", p["bg"])])
            style.configure("TLabelframe", background=p["bg"], foreground=p["text"],
                            bordercolor=p["border"])
            style.configure("TLabelframe.Label", background=p["bg"],
                            foreground=p["muted"])
            style.configure("Countdown.Horizontal.TProgressbar",
                            troughcolor=p["trough"], background=p["primary"],
                            bordercolor=p["border"], lightcolor=p["primary"],
                            darkcolor=p["primary"])
            style.configure("TScrollbar", background=p["surface"],
                            troughcolor=p["bg"], bordercolor=p["border"],
                            arrowcolor=p["text"])
            style.configure("TSeparator", background=p["border"])

            for widget, role in list(self._tracked):
                try:
                    if role == "canvas":
                        widget.configure(bg=p["bg"], highlightthickness=0)
                    elif role == "listframe":
                        widget.configure(bg=p["bg"])
                except Exception:
                    pass

        def toggle_theme(self):
            self.theme = "dark" if self.theme == "light" else "light"
            guiconfig.set_theme(self.theme)
            self._apply_theme()
            self._theme_btn.configure(
                text="☀ Light mode" if self.theme == "dark" else "🌙 Dark mode")
            # rebuild whichever screen is showing so new tk widgets get themed
            if self._vault is not None:
                self._render_accounts()

        # ---- menu
        def _build_menu(self):
            bar = tk.Menu(self)
            filem = tk.Menu(bar, tearoff=0)
            filem.add_command(label="Open vault…", command=self._menu_open_vault)
            filem.add_command(label="Lock vault", command=self.lock)
            filem.add_separator()
            filem.add_command(label="Exit", command=self._on_close)
            bar.add_cascade(label="File", menu=filem)

            viewm = tk.Menu(bar, tearoff=0)
            viewm.add_command(label="Toggle dark mode", command=self.toggle_theme)
            bar.add_cascade(label="View", menu=viewm)

            helpm = tk.Menu(bar, tearoff=0)
            helpm.add_command(label="About", command=self._about)
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

        # ---- chrome: brand bar, swappable container, result bar
        def _build_chrome(self):
            top = ttk.Frame(self, style="Sidebar.TFrame", padding=(12, 8))
            top.pack(fill="x", side="top")
            ttk.Label(top, text="AuthKeeper", style="Brand.TLabel").pack(side="left")
            ttk.Label(top, style="Status.TLabel",
                      text="  offline · encrypted · by QuickOpen").pack(side="left")
            self._theme_btn = ttk.Button(
                top, style="Toggle.TButton", command=self.toggle_theme,
                text="☀ Light mode" if self.theme == "dark" else "🌙 Dark mode")
            self._theme_btn.pack(side="right")

            self.container = ttk.Frame(self, style="TFrame", padding=(16, 12))
            self.container.pack(fill="both", expand=True)

            bar = ttk.Frame(self, style="Sidebar.TFrame", padding=(12, 6))
            bar.pack(fill="x", side="bottom")
            self.status_lbl = ttk.Label(bar, text="Locked", style="Status.TLabel",
                                        width=16, anchor="w")
            self.status_lbl.pack(side="left")
            self.result_lbl = ttk.Label(bar, text="", style="Status.TLabel",
                                        anchor="w", wraplength=560, justify="left")
            self.result_lbl.pack(side="left", fill="x", expand=True, padx=8)

        def _clear_container(self):
            for child in self.container.winfo_children():
                child.destroy()
            self._rows = []

        # ---- result bar helpers
        def _set_status(self, text, kind="idle"):
            p = self._pal()
            color = {"working": p["primary"], "ok": p["ok"], "err": p["err"]}.get(
                kind, p["muted"])
            self.status_lbl.configure(text=text, foreground=color)

        def _clear_result(self):
            self.result_lbl.configure(text="")

        def _show_error(self, message):
            self.result_lbl.configure(text="✕ " + message,
                                      foreground=self._pal()["err"])

        def _show_ok(self, message):
            self.result_lbl.configure(text="✓ " + message,
                                      foreground=self._pal()["ok"])
            self._set_status("done", kind="ok")

        # ---- background operation runner
        def _bg(self, work, on_ok, button=None, busy="Working…"):
            """Run ``work()`` off the UI thread; call ``on_ok(result)`` back on it.

            Errors surface inline (AuthKeeperError message, or a generic note),
            never as a traceback.  Refuses to start a second op while busy.
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
            self._clear_result()

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
                    self._set_status("error", kind="err")
                    self._show_error(err)
                    return
                self._set_status("unlocked", kind="ok")
                try:
                    on_ok(res)
                except Exception as ex:
                    self._show_error(f"Post-processing error: {ex}")

            threading.Thread(target=run, daemon=True).start()

        # =====================================================================
        # UNLOCK SCREEN
        # =====================================================================
        def _show_unlock(self):
            self._stop_tick()
            self._clear_container()
            self._set_status("Locked")

            wrap = ttk.Frame(self.container, style="TFrame")
            wrap.pack(expand=True)

            ttk.Label(wrap, text="Unlock your vault",
                      style="Header.TLabel").pack(anchor="w")
            ttk.Label(wrap, style="Sub.TLabel", wraplength=440, justify="left",
                      text="Everything is stored locally and encrypted with your "
                           "master passphrase (scrypt + AES-256-GCM). Nothing is "
                           "uploaded anywhere.").pack(anchor="w", pady=(2, 14))

            form = ttk.Frame(wrap, style="TFrame")
            form.pack(fill="x")

            ttk.Label(form, text="Vault file", width=12, anchor="w").grid(
                row=0, column=0, sticky="w", pady=4)
            self._path_var = tk.StringVar(value=self._default_vault_path())
            ent = ttk.Entry(form, textvariable=self._path_var, width=40)
            ent.grid(row=0, column=1, sticky="ew", pady=4)
            ttk.Button(form, text="Browse…", command=self._browse_vault).grid(
                row=0, column=2, padx=(6, 0))

            ttk.Label(form, text="Passphrase", width=12, anchor="w").grid(
                row=1, column=0, sticky="w", pady=4)
            self._pw_var = tk.StringVar()
            pw = ttk.Entry(form, textvariable=self._pw_var, show="•", width=40)
            pw.grid(row=1, column=1, sticky="ew", pady=4)
            pw.bind("<Return>", lambda e: self._do_unlock())
            form.columnconfigure(1, weight=1)

            btns = ttk.Frame(wrap, style="TFrame")
            btns.pack(fill="x", pady=(14, 0))
            self._unlock_btn = ttk.Button(btns, text="Unlock", style="Accent.TButton",
                                          command=self._do_unlock)
            self._unlock_btn.pack(side="left")
            ttk.Button(btns, text="Create new vault…",
                       command=self._do_create).pack(side="left", padx=8)

            recent = guiconfig.get_recent()
            if recent:
                rf = ttk.Frame(wrap, style="TFrame")
                rf.pack(fill="x", pady=(16, 0))
                ttk.Label(rf, text="Recent vaults", style="Sub.TLabel").pack(
                    anchor="w")
                for path in recent[:5]:
                    exists = os.path.exists(path)
                    txt = path if exists else path + "  (missing)"
                    b = ttk.Button(rf, text=txt,
                                   command=(lambda pp=path: self._path_var.set(pp)))
                    if not exists:
                        b.state(["disabled"])
                    b.pack(anchor="w", pady=1)

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
                filetypes=VAULT_TYPES,
                initialfile="vault.akv")
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
            self._show_vault()
            n = len(vault.accounts(vault_dict))
            self._show_ok(f"Unlocked — {n} account(s).")

        # =====================================================================
        # VAULT SCREEN
        # =====================================================================
        def _show_vault(self):
            self._clear_container()
            self._set_status("unlocked", kind="ok")

            # toolbar
            tools = ttk.Frame(self.container, style="TFrame")
            tools.pack(fill="x")
            ttk.Button(tools, text="＋ Add account", style="Accent.TButton",
                       command=self._add_dialog).pack(side="left")
            ttk.Button(tools, text="Backup…",
                       command=self._backup).pack(side="left", padx=(8, 0))
            ttk.Button(tools, text="Restore…",
                       command=self._restore).pack(side="left", padx=(6, 0))
            ttk.Button(tools, text="🔒 Lock", command=self.lock).pack(side="right")

            # search
            sf = ttk.Frame(self.container, style="TFrame")
            sf.pack(fill="x", pady=(10, 6))
            ttk.Label(sf, text="Search", style="Sub.TLabel").pack(side="left")
            self._search_var = tk.StringVar(value=self._filter)
            se = ttk.Entry(sf, textvariable=self._search_var)
            se.pack(side="left", fill="x", expand=True, padx=(8, 0))
            self._search_var.trace_add("write", lambda *_: self._on_search())

            # scrollable account list
            body = ttk.Frame(self.container, style="TFrame")
            body.pack(fill="both", expand=True)
            self._canvas = tk.Canvas(body, highlightthickness=0, bd=0)
            sb = ttk.Scrollbar(body, orient="vertical",
                               command=self._canvas.yview)
            self._canvas.configure(yscrollcommand=sb.set)
            sb.pack(side="right", fill="y")
            self._canvas.pack(side="left", fill="both", expand=True)
            self.track(self._canvas, "canvas")
            self._list = ttk.Frame(self._canvas, style="TFrame")
            self._list_win = self._canvas.create_window(
                (0, 0), window=self._list, anchor="nw")
            self._list.bind(
                "<Configure>",
                lambda e: self._canvas.configure(
                    scrollregion=self._canvas.bbox("all")))
            self._canvas.bind(
                "<Configure>",
                lambda e: self._canvas.itemconfigure(self._list_win, width=e.width))

            self._render_accounts()
            self._start_tick()

        def _on_search(self):
            self._filter = self._search_var.get().strip()
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
                msg = ("No accounts yet — click “＋ Add account”."
                       if not self._filter else "No accounts match your search.")
                ttk.Label(self._list, text=msg, style="Muted.TLabel").pack(
                    anchor="w", pady=20, padx=4)
                return
            for acc in items:
                self._build_row(acc)
            self._refresh_codes()

        def _build_row(self, acc):
            p = self._pal()
            card = ttk.Frame(self._list, style="Card.TFrame", padding=(12, 10))
            card.pack(fill="x", pady=4, padx=2)

            left = ttk.Frame(card, style="Card.TFrame")
            left.pack(side="left", fill="x", expand=True)
            ttk.Label(left, text=vault.display_name(acc), style="Card.TLabel",
                      font=(FONT, 11, "bold")).pack(anchor="w")
            kind = acc.get("type", "totp").upper()
            ttk.Label(left, style="CardMuted.TLabel",
                      text=f"{kind} · {acc.get('digits', 6)} digits · "
                           f"{acc.get('algorithm', 'SHA1')}").pack(anchor="w")

            code_var = tk.StringVar(value="------")
            ttk.Label(left, textvariable=code_var, style="Code.TLabel").pack(
                anchor="w", pady=(4, 0))

            is_totp = str(acc.get("type", "totp")).lower() == "totp"
            prog = None
            remain_var = tk.StringVar(value="")
            if is_totp:
                prog = ttk.Progressbar(
                    left, style="Countdown.Horizontal.TProgressbar",
                    orient="horizontal", mode="determinate",
                    maximum=int(acc.get("period", 30)), length=200)
                prog.pack(anchor="w", pady=(6, 0))
                ttk.Label(left, textvariable=remain_var,
                          style="CardMuted.TLabel").pack(anchor="w")

            right = ttk.Frame(card, style="Card.TFrame")
            right.pack(side="right")
            ttk.Button(right, text="Copy", style="Card.TButton",
                       command=lambda a=acc: self._copy_code(a)).pack(fill="x")
            if not is_totp:
                ttk.Button(right, text="Next", style="Card.TButton",
                           command=lambda a=acc: self._hotp_next(a)).pack(
                    fill="x", pady=(4, 0))
            ttk.Button(right, text="Share QR…", style="Card.TButton",
                       command=lambda a=acc: self._share_qr(a)).pack(
                fill="x", pady=(4, 0))
            ttk.Button(right, text="Delete", style="Card.TButton",
                       command=lambda a=acc: self._delete(a)).pack(
                fill="x", pady=(4, 0))

            self._rows.append({
                "acc": acc, "code_var": code_var, "prog": prog,
                "remain_var": remain_var, "totp": is_totp,
            })

        # ---- live refresh
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
                        row["prog"].configure(value=remaining)
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

        def _backup(self):
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
                     lambda n: (self._save(lambda: self._render_accounts(),
                                           ok=f"Restored {n} account(s)."),),
                     busy="Restoring…")

        # ---- lock / close
        def lock(self):
            """Drop the passphrase and decrypted vault from memory."""
            self._stop_tick()
            self._passphrase = None
            self._vault = None
            self._vault_path = None
            self._rows = []
            self._show_unlock()
            self._show_ok("Locked. Your vault is encrypted on disk.")

        def _about(self):
            win = tk.Toplevel(self)
            win.title("About AuthKeeper")
            win.configure(bg=self._pal()["bg"])
            win.resizable(False, False)
            frm = ttk.Frame(win, style="TFrame", padding=18)
            frm.pack(fill="both", expand=True)
            ttk.Label(frm, text="AuthKeeper", style="Header.TLabel").pack(anchor="w")
            ttk.Label(frm, text=f"Version {APP_VERSION}",
                      style="Sub.TLabel").pack(anchor="w", pady=(0, 8))
            ttk.Label(frm, style="TLabel", justify="left", wraplength=380,
                      text="A fast, fully-offline 2FA / TOTP authenticator with a "
                           "passphrase-encrypted local vault (scrypt + "
                           "AES-256-GCM).\n\n100% AI-built, open source, published "
                           "on QuickOpen. Your secrets never leave the "
                           "device.").pack(anchor="w")
            ttk.Label(frm, style="Sub.TLabel", justify="left", wraplength=380,
                      text="Licensed under Apache-2.0. Built on permissive "
                           "libraries: pyotp, cryptography, segno, Pillow.").pack(
                anchor="w", pady=(8, 4))
            link = ttk.Label(frm, text="Project page: quickopen.ai",
                             style="Sub.TLabel", cursor="hand2")
            link.pack(anchor="w", pady=(4, 10))
            link.bind("<Button-1>", lambda e: open_with_default_app(PROJECT_URL))
            ttk.Button(frm, text="Close", command=win.destroy).pack(anchor="e")
            win.transient(self)
            win.grab_set()

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
            self.top = top = tk.Toplevel(app)
            top.title("Create vault" if create else "Passphrase")
            top.configure(bg=app._pal()["bg"])
            top.resizable(False, False)
            frm = ttk.Frame(top, style="TFrame", padding=16)
            frm.pack(fill="both", expand=True)
            ttk.Label(frm, text=prompt, style="TLabel").pack(anchor="w")
            self._pw = tk.StringVar()
            e1 = ttk.Entry(frm, textvariable=self._pw, show="•", width=34)
            e1.pack(fill="x", pady=(4, 6))
            self._pw2 = tk.StringVar()
            if create:
                ttk.Label(frm, text="Confirm passphrase:", style="TLabel").pack(
                    anchor="w")
                ttk.Entry(frm, textvariable=self._pw2, show="•", width=34).pack(
                    fill="x", pady=(4, 6))
                ttk.Label(frm, style="Sub.TLabel", wraplength=300, justify="left",
                          text="There is no recovery — if you forget this "
                               "passphrase the vault cannot be opened.").pack(
                    anchor="w", pady=(0, 6))
            self._create = create
            self._err = ttk.Label(frm, text="", style="Sub.TLabel")
            self._err.configure(foreground=app._pal()["err"])
            self._err.pack(anchor="w")
            btns = ttk.Frame(frm, style="TFrame")
            btns.pack(fill="x", pady=(8, 0))
            ttk.Button(btns, text="OK", style="Accent.TButton",
                       command=self._ok).pack(side="right")
            ttk.Button(btns, text="Cancel",
                       command=self._cancel).pack(side="right", padx=6)
            e1.bind("<Return>", lambda e: self._ok())
            top.bind("<Escape>", lambda e: self._cancel())
            top.transient(app)
            top.grab_set()
            app.after(60, e1.focus_set)

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
            self.top = top = tk.Toplevel(app)
            top.title("Add account")
            top.configure(bg=app._pal()["bg"])
            top.geometry("460x430")
            frm = ttk.Frame(top, style="TFrame", padding=16)
            frm.pack(fill="both", expand=True)

            ttk.Label(frm, text="Paste an otpauth:// URI",
                      style="TLabel").pack(anchor="w")
            self._uri = tk.StringVar()
            ttk.Entry(frm, textvariable=self._uri).pack(fill="x", pady=(4, 2))
            ttk.Button(frm, text="Open a QR image…",
                       command=self._open_qr).pack(anchor="w", pady=(2, 8))

            ttk.Separator(frm).pack(fill="x", pady=4)
            ttk.Label(frm, text="…or enter the details manually",
                      style="Sub.TLabel").pack(anchor="w", pady=(4, 4))

            grid = ttk.Frame(frm, style="TFrame")
            grid.pack(fill="x")
            self._issuer = tk.StringVar()
            self._label = tk.StringVar()
            self._secret = tk.StringVar()
            self._digits = tk.StringVar(value="6")
            self._period = tk.StringVar(value="30")
            self._algorithm = tk.StringVar(value="SHA1")
            self._type = tk.StringVar(value="totp")

            def field(r, text, var, **kw):
                ttk.Label(grid, text=text, width=10, anchor="w").grid(
                    row=r, column=0, sticky="w", pady=3)
                ent = ttk.Entry(grid, textvariable=var, **kw)
                ent.grid(row=r, column=1, sticky="ew", pady=3)

            grid.columnconfigure(1, weight=1)
            field(0, "Issuer", self._issuer)
            field(1, "Label", self._label)
            field(2, "Secret", self._secret)
            ttk.Label(grid, text="Digits", width=10, anchor="w").grid(
                row=3, column=0, sticky="w", pady=3)
            ttk.Combobox(grid, textvariable=self._digits, width=6, state="readonly",
                         values=["6", "7", "8"]).grid(row=3, column=1, sticky="w")
            ttk.Label(grid, text="Period", width=10, anchor="w").grid(
                row=4, column=0, sticky="w", pady=3)
            ttk.Entry(grid, textvariable=self._period, width=8).grid(
                row=4, column=1, sticky="w")
            ttk.Label(grid, text="Algorithm", width=10, anchor="w").grid(
                row=5, column=0, sticky="w", pady=3)
            ttk.Combobox(grid, textvariable=self._algorithm, width=8,
                         state="readonly",
                         values=["SHA1", "SHA256", "SHA512"]).grid(
                row=5, column=1, sticky="w")
            ttk.Label(grid, text="Type", width=10, anchor="w").grid(
                row=6, column=0, sticky="w", pady=3)
            ttk.Combobox(grid, textvariable=self._type, width=8, state="readonly",
                         values=["totp", "hotp"]).grid(row=6, column=1, sticky="w")

            self._err = ttk.Label(frm, text="", style="Sub.TLabel")
            self._err.configure(foreground=app._pal()["err"])
            self._err.pack(anchor="w", pady=(8, 0))
            btns = ttk.Frame(frm, style="TFrame")
            btns.pack(fill="x", pady=(6, 0))
            ttk.Button(btns, text="Add", style="Accent.TButton",
                       command=self._ok).pack(side="right")
            ttk.Button(btns, text="Cancel",
                       command=self.top.destroy).pack(side="right", padx=6)
            top.transient(app)
            top.grab_set()

        def _open_qr(self):
            p = filedialog.askopenfilename(title="Open a QR image",
                                           filetypes=IMAGE_TYPES)
            if not p:
                return
            try:
                uri = self.qr.decode_image(p)
                self._uri.set(uri)
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
    With no display (e.g. a server), it prints a friendly note and returns 0
    instead of raising.
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
