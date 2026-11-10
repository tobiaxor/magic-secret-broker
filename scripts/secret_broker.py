"""Secret broker CLI: KeePass vault, names visible to the agent, values only after user approval."""

import argparse
import base64
import contextlib
import hashlib
import hmac
import ctypes
import json
import os
import re
import secrets
import shutil
import string
import stat
import subprocess
import sys
import tempfile
import time
import types
from ctypes import wintypes
from datetime import datetime
from pathlib import Path

HOME = Path.home()
# A redirected state dir would let a caller supply its own approvals and settings; only a test vault may use one.
STATE_DIR = Path(os.environ["SECRET_BROKER_STATE"] if "SECRET_BROKER_KDBX" in os.environ and "SECRET_BROKER_STATE" in os.environ
                 else HOME / ".claude" / "secret-broker")
CONFIG_FILE = STATE_DIR / "config.json"


def _load_config() -> dict:
    try:
        data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _setting(env: str, key: str, default):
    """Environment beats config.json; a vault set by environment (tests) never inherits config.json's backup task."""
    if env in os.environ:
        return os.environ[env]
    if key == "backup_task" and "SECRET_BROKER_KDBX" in os.environ:
        return ""
    return CONFIG.get(key, default)


def _ui_language() -> str:
    try:
        return "pl" if ctypes.windll.kernel32.GetUserDefaultUILanguage() & 0x3FF == 0x15 else "en"
    except (AttributeError, OSError):
        return "en"


CONFIG = _load_config()
KDBX_PATH = Path(os.path.expanduser(_setting("SECRET_BROKER_KDBX", "vault", str(HOME / "Documents" / "secret-broker.kdbx"))))
KEYFILE = _setting("SECRET_BROKER_KEYFILE", "keyfile", None) or None
# Windows scheduled task run after each vault write (e.g. an off-site backup); empty disables it.
BACKUP_TASK = _setting("SECRET_BROKER_BACKUP_TASK", "backup_task", "")
LANG = (_setting("SECRET_BROKER_LANG", "lang", "") or _ui_language()).lower()[:2]


def tr(text: str, **kw) -> str:
    if LANG == "pl":
        from i18n_pl import PL
        text = PL.get(text, text)
    return text.format(**kw) if kw else text

APPROVALS_FILE = STATE_DIR / "approvals.json"
DAY_APPROVALS_FILE = STATE_DIR / "approvals_day.json"
DAY_APPROVAL_S = 24 * 3600
AUDIT_FILE = STATE_DIR / "audit.jsonl"
NO_FILE_STATE = STATE_DIR / "no_file.json"
SETTINGS_FILE = STATE_DIR / "settings.json"
MODES = {"prompt": tr("Ask in a window"), "notify": tr("Notify only")}
TRAY_MUTEX = r"Local\secret-broker-tray"
NO_FILE_TAG = "no-file"
ALWAYS_LABEL = tr("Always in this project: the agent gets this secret without asking")
KEYRING_SERVICE = "secret-broker"
DIALOG_TIMEOUT_S = 180

STANDARD_FIELDS = {"password": "password", "username": "username", "url": "url", "notes": "notes"}

EXIT_DENIED = 1
EXIT_NOT_FOUND = 2
EXIT_LOCKED = 3
EXIT_FORBIDDEN = 4


THEMES = {
    "approve": {"accent": "#2563eb", "hover": "#1d4ed8", "tint": "#eff6ff", "soft": "#bfdbfe", "icon": ""},
    "unlock": {"accent": "#334155", "hover": "#1e293b", "tint": "#f1f5f9", "soft": "#cbd5e1", "icon": ""},
    "forget": {"accent": "#ea580c", "hover": "#c2410c", "tint": "#fff7ed", "soft": "#fed7aa", "icon": ""},
    "store": {"accent": "#059669", "hover": "#047857", "tint": "#ecfdf5", "soft": "#a7f3d0", "icon": ""},
    "ask": {"accent": "#7c3aed", "hover": "#6d28d9", "tint": "#f5f3ff", "soft": "#ddd6fe", "icon": ""},
    "delete": {"accent": "#b91c1c", "hover": "#991b1b", "tint": "#fef2f2", "soft": "#fecaca", "icon": ""},
}
BG = "#ffffff"
FOOTER_BG = "#f8fafc"
FG = "#0f172a"
MUTED = "#64748b"
BORDER = "#cbd5e1"
DANGER = "#b91c1c"
FONT = "Segoe UI"
MONO = "Consolas"


class _Dialog:
    def __init__(self, theme: str, window_title: str, heading: str, subheading: str, project: str | None):
        import tkinter as tk

        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(2)
        except (AttributeError, OSError):
            pass
        self.tk = tk
        self.t = THEMES[theme]
        self.root = root = tk.Tk()
        root.withdraw()
        # Tk scales fonts with DPI but not pixel paddings.
        self.scale = max(1.0, float(root.tk.call("tk", "scaling")) / (96 / 72))
        root.title(window_title)
        root.configure(bg=BG)
        root.resizable(False, False)
        root.attributes("-topmost", True)
        root.after(DIALOG_TIMEOUT_S * 1000, root.destroy)

        a = self.t["accent"]
        head = tk.Frame(root, bg=a, padx=self.px(20), pady=self.px(16))
        head.pack(fill="x")
        tk.Label(head, text=self.t["icon"], font=("Segoe MDL2 Assets", 22), bg=a, fg="white").pack(side="left", padx=(0, self.px(16)))
        txt = tk.Frame(head, bg=a)
        txt.pack(side="left", fill="x")
        tk.Label(txt, text=heading, font=(FONT, 14, "bold"), bg=a, fg="white").pack(anchor="w")
        if subheading:
            tk.Label(txt, text=subheading, font=(FONT, 9), bg=a, fg=self.t["soft"]).pack(anchor="w")

        self.body = tk.Frame(root, bg=BG, padx=self.px(22), pady=self.px(18))
        self.body.pack(fill="both", expand=True)
        if project:
            self.section(tr("PROJECT"))
            tk.Label(self.body, text=Path(project).name or project, font=(FONT, 15, "bold"), bg=BG, fg=FG).pack(anchor="w")
            tk.Label(self.body, text=project, font=(FONT, 8), bg=BG, fg=MUTED).pack(anchor="w", pady=(0, self.px(14)))

        tk.Frame(root, bg=BORDER, height=1).pack(fill="x")
        self.footer = tk.Frame(root, bg=FOOTER_BG, padx=self.px(22), pady=self.px(14))
        self.footer.pack(fill="x")

    def px(self, n: int) -> int:
        return round(n * self.scale)

    def section(self, label: str) -> None:
        self.tk.Label(self.body, text=label, font=(FONT, 8, "bold"), bg=BG, fg=MUTED).pack(anchor="w", pady=(0, self.px(2)))

    def note(self, text: str, fg: str = FG) -> None:
        box = self.tk.Frame(self.body, bg=self.t["tint"], padx=self.px(12), pady=self.px(9))
        box.pack(fill="x", pady=(0, self.px(4)))
        self.tk.Label(box, text=text, font=(FONT, 10), bg=self.t["tint"], fg=fg, justify="left",
                      wraplength=self.px(440)).pack(anchor="w")

    def button(self, text: str, command, primary: bool = False, side: str = "right"):
        a = self.t["accent"]
        bg, fg, hover = (a, "white", self.t["hover"]) if primary else (BG, FG, self.t["tint"])
        b = self.tk.Button(
            self.footer, text=text, command=command, font=(FONT, 10, "bold" if primary else "normal"),
            bg=bg, fg=fg, activebackground=hover, activeforeground=fg,
            disabledforeground=self.t["soft"] if primary else MUTED,
            relief="flat", bd=0, cursor="hand2", padx=self.px(16), pady=self.px(7),
            highlightthickness=1, highlightbackground=a if primary else BORDER, highlightcolor=FG,
        )
        b.bind("<Enter>", lambda _e: b["state"] != "disabled" and b.configure(bg=hover))
        b.bind("<Leave>", lambda _e: b.configure(bg=bg))
        b.pack(side=side, padx=(self.px(10), 0) if side == "right" else (0, self.px(10)))
        return b

    def comment_box(self, on_submit, label: str = ""):
        """Enter inside the box refuses with the comment, never approves."""
        label = label or tr("COMMENT FOR THE AGENT IF YOU REFUSE (optional)")
        tk = self.tk
        tk.Frame(self.body, bg=BG, height=self.px(10)).pack()
        self.section(label)
        var = tk.StringVar()
        e = tk.Entry(self.body, textvariable=var, width=40, font=(FONT, 10), relief="flat", bg=FOOTER_BG, fg=FG, insertbackground=FG,
                     highlightthickness=1, highlightbackground=BORDER, highlightcolor=self.t["accent"])
        e.pack(fill="x", ipady=self.px(4))
        e.bind("<Return>", lambda _e: (on_submit(), "break")[1])
        # A Tk variable cannot be read once the window is destroyed, so mirror the text as it is typed.
        text = {"v": ""}
        var.trace_add("write", lambda *_: text.update(v=var.get()))
        return types.SimpleNamespace(get=lambda: text["v"])

    def check(self, text: str, default: bool, locked: bool = False, pady=None):
        tk = self.tk
        var = tk.BooleanVar(value=default)
        state = {"v": default}
        var.trace_add("write", lambda *_: state.update(v=var.get()))
        tk.Checkbutton(self.body, text=text, variable=var, font=(FONT, 9), bg=BG, fg=FG, activebackground=BG, selectcolor=BG, bd=0,
                       highlightthickness=0, state="disabled" if locked else "normal",
                       ).pack(anchor="w", pady=pady if pady is not None else (self.px(6), 0))
        return lambda: state["v"]

    def arm_after_delay(self, *buttons) -> None:
        """The window steals focus, so a stray keypress from whatever the user was typing must not confirm."""
        for b in buttons:
            b.configure(state="disabled")
        self.root.after(800, lambda: [b.configure(state="normal") for b in buttons])

    def run(self, focus) -> None:
        root = self.root
        root.update_idletasks()
        w, h = root.winfo_reqwidth(), root.winfo_reqheight()
        root.geometry(f"+{(root.winfo_screenwidth() - w) // 2}+{(root.winfo_screenheight() - h) // 3}")
        root.deiconify()
        root.lift()
        root.focus_force()
        focus.focus_set()
        root.mainloop()


def dialog_approve(secret: str, field: str, project: str, reason: str, no_file: bool = False) -> tuple[str, str]:
    result = {"choice": "deny"}
    d = _Dialog("approve", tr("Secret broker — secret request"), tr("The agent asks for a secret"), "secret-broker get", project)
    tk = d.tk

    d.section(tr("SECRET"))
    row = tk.Frame(d.body, bg=BG)
    row.pack(anchor="w", pady=(0, d.px(14)))
    tk.Label(row, text=secret, font=(MONO, 13, "bold"), bg=BG, fg=FG).pack(side="left")
    tk.Label(row, text=" " + tr("field: {field}", field=field) + " ", font=(FONT, 9), bg=d.t["tint"], fg=d.t["accent"]).pack(side="left", padx=(d.px(10), 0))
    d.section(tr("REASON"))
    d.note(reason or tr("(the agent gave no reason)"), fg=FG if reason else MUTED)
    if no_file:
        warn = THEMES["forget"]
        tk.Label(d.body, text="  " + tr("{tag}: the agent may not write this value to files (except a git-ignored file in a temporary worktree)", tag=NO_FILE_TAG) + "  ",
                 font=(FONT, 9), bg=warn["tint"], fg=warn["hover"], wraplength=d.px(440), justify="left").pack(anchor="w", pady=(d.px(4), 0))

    def pick(choice: str):
        result["choice"] = choice
        d.root.destroy()

    comment = d.comment_box(lambda: pick("deny"))
    deny = d.button(tr("Deny"), lambda: pick("deny"), side="left")
    once = d.button(tr("Once"), lambda: pick("once"), primary=True)
    day = d.button(tr("For 24 hours"), lambda: pick("day"))
    always = d.button(tr("Always in this project"), lambda: pick("always"))
    d.root.bind("<Escape>", lambda _e: pick("deny"))
    d.root.protocol("WM_DELETE_WINDOW", lambda: pick("deny"))
    d.arm_after_delay(once, day, always)
    d.run(deny)
    return result["choice"], comment.get().strip() if result["choice"] == "deny" else ""


def _masked(value: str) -> str:
    lines = value.count("\n") + 1
    size = tr("{n} lines", n=lines) if lines > 1 else tr("{n} characters", n=len(value))
    return f"{'•' * min(len(value), 16)}  ({size})"


def dialog_store(secret: str, changes: list[dict], project: str, reason: str, new_entry: bool, no_file_locked: bool = False,
                 no_file_default: bool = False, offer_always: bool = True) -> tuple[bool, str, dict]:
    """changes: [{"field", "value", "state": "new"|"overwrite", "sensitive": bool}]; returns (ok, comment, {"no_file", "always"})."""
    result = {"ok": False}
    d = _Dialog("store", tr("Secret broker — save a secret"), tr("The agent wants to save a secret"), "secret-broker set", project)
    tk = d.tk
    warn = THEMES["forget"]

    d.section(tr("ENTRY"))
    row = tk.Frame(d.body, bg=BG)
    row.pack(anchor="w", pady=(0, d.px(14)))
    tk.Label(row, text=secret, font=(MONO, 13, "bold"), bg=BG, fg=FG).pack(side="left")
    tk.Label(row, text=" " + (tr("new entry") if new_entry else tr("existing entry")) + " ", font=(FONT, 9, "bold"),
             bg=d.t["tint"], fg=d.t["accent"]).pack(side="left", padx=(d.px(10), 0))

    d.section(tr("FIELDS"))
    grid = tk.Frame(d.body, bg=FOOTER_BG, padx=d.px(10), pady=d.px(6))
    grid.pack(fill="x", pady=(0, d.px(14)))
    secret_labels = []
    for i, ch in enumerate(changes):
        tk.Label(grid, text=ch["field"], font=(FONT, 9, "bold"), bg=FOOTER_BG, fg=MUTED).grid(row=i, column=0, sticky="nw", pady=d.px(3))
        lbl = tk.Label(grid, text=_masked(ch["value"]) if ch["sensitive"] else ch["value"], font=(MONO, 10), bg=FOOTER_BG,
                       fg=FG, justify="left", anchor="w", wraplength=d.px(300))
        lbl.grid(row=i, column=1, sticky="w", padx=d.px(12), pady=d.px(3))
        if ch["sensitive"]:
            secret_labels.append((lbl, ch["value"]))
        if ch["state"] == "overwrite":
            tk.Label(grid, text=" " + tr("overwrites") + " ", font=(FONT, 8, "bold"), bg=warn["tint"], fg=warn["hover"]).grid(row=i, column=2, sticky="ne", pady=d.px(3))
    grid.columnconfigure(1, weight=1)

    if secret_labels:
        def toggle():
            show = toggle_btn["text"] == tr("Show values")
            for lbl, value in secret_labels:
                lbl.configure(text=value if show else _masked(value))
            toggle_btn.configure(text=tr("Hide values") if show else tr("Show values"))

        toggle_btn = tk.Button(d.body, text=tr("Show values"), command=toggle, font=(FONT, 9), bg=BG, fg=d.t["accent"],
                               activebackground=BG, activeforeground=d.t["hover"], relief="flat", bd=0, cursor="hand2")
        toggle_btn.pack(anchor="e", pady=(0, d.px(8)))

    d.section(tr("REASON"))
    d.note(reason or tr("(the agent gave no reason)"), fg=FG if reason else MUTED)
    no_file = d.check(tr("{tag}: the agent may not write this value to files", tag=NO_FILE_TAG), no_file_locked or no_file_default,
                      locked=no_file_locked, pady=(d.px(10), 0))
    always = d.check(ALWAYS_LABEL, new_entry) if offer_always else (lambda: False)

    def pick(ok: bool):
        result["ok"] = ok
        d.root.destroy()

    overwrite = any(ch["state"] == "overwrite" for ch in changes)
    comment = d.comment_box(lambda: pick(False))
    deny = d.button(tr("Deny"), lambda: pick(False), side="left")
    save = d.button(tr("Overwrite") if overwrite else tr("Save"), lambda: pick(True), primary=True)
    d.root.bind("<Escape>", lambda _e: pick(False))
    d.root.protocol("WM_DELETE_WINDOW", lambda: pick(False))
    d.arm_after_delay(save)
    d.run(deny)
    if not result["ok"]:
        return False, comment.get().strip(), {}
    return True, "", {"no_file": no_file(), "always": always()}


def dialog_ask(secret: str, fields: list[str], project: str, reason: str, username: str, url: str, attrs: list[tuple[str, str]],
               existing: bool, overwrite: list[str], no_file_locked: bool, no_file_default: bool, to_agent: bool,
               offer_always: bool = True) -> tuple[dict | None, str]:
    """The user types the value; the agent only named the entry."""
    result = {}
    d = _Dialog("ask", tr("Secret broker — new secret"), tr("The agent asks you to enter a secret"), "secret-broker ask", project)
    tk = d.tk
    warn = THEMES["forget"]

    d.section(tr("ENTRY"))
    row = tk.Frame(d.body, bg=BG)
    row.pack(anchor="w", pady=(0, d.px(14)))
    tk.Label(row, text=secret, font=(MONO, 13, "bold"), bg=BG, fg=FG).pack(side="left")
    tk.Label(row, text=" " + (tr("existing entry") if existing else tr("new entry")) + " ", font=(FONT, 9, "bold"),
             bg=d.t["tint"], fg=d.t["accent"]).pack(side="left", padx=(d.px(10), 0))
    d.section(tr("REASON"))
    d.note(reason or tr("(the agent gave no reason)"), fg=FG if reason else MUTED)
    tk.Frame(d.body, bg=BG, height=d.px(10)).pack()

    def entry(label, value="", show=""):
        d.section(label)
        var = tk.StringVar(value=value)
        e = tk.Entry(d.body, textvariable=var, show=show, width=40, font=(MONO if show else FONT, 12), relief="flat", bg=FOOTER_BG,
                     fg=FG, insertbackground=FG, highlightthickness=1, highlightbackground=BORDER, highlightcolor=d.t["accent"])
        e.pack(fill="x", ipady=d.px(5), pady=(0, d.px(4)))
        return var, e

    values = [(f, *entry(tr("VALUE  ·  field {f}", f=f) if len(fields) == 1 else tr("FIELD  ·  {f}", f=f), show="•")) for f in fields]
    value_entries = [e for _f, _v, e in values]
    tools = tk.Frame(d.body, bg=BG)
    tools.pack(fill="x", pady=(0, d.px(10)))
    shown = tk.BooleanVar(value=False)

    def show_values():
        for e in value_entries:
            e.configure(show="" if shown.get() else "•")

    tk.Checkbutton(tools, text=tr("Show"), variable=shown, font=(FONT, 9), bg=BG, fg=FG, activebackground=BG, selectcolor=BG, bd=0,
                   highlightthickness=0, command=show_values).pack(side="left")

    if len(fields) == 1:
        def generate():
            values[0][1].set(generate_password(32))
            shown.set(True)
            show_values()

        tk.Button(tools, text=tr("Generate password"), command=generate, font=(FONT, 9), bg=BG, fg=d.t["accent"], activebackground=BG,
                  activeforeground=d.t["hover"], relief="flat", bd=0, cursor="hand2").pack(side="right")
    if overwrite:
        tk.Label(tools, text=" " + tr("overwrites current {fields}", fields=', '.join(overwrite)) + " ", font=(FONT, 8, "bold"), bg=warn["tint"], fg=warn["hover"],
                 ).pack(side="right", padx=d.px(8))

    user_var, _ = entry(tr("USERNAME (optional)"), username)
    tk.Frame(d.body, bg=BG, height=d.px(6)).pack()
    url_var, _ = entry(tr("URL (optional)"), url)
    if attrs:
        tk.Label(d.body, text=tr("Attributes from the agent: ") + ", ".join(f"{k}={v}" for k, v in attrs), font=(FONT, 9), bg=BG, fg=MUTED,
                 wraplength=d.px(440), justify="left").pack(anchor="w", pady=(d.px(6), 0))

    no_file = d.check(tr("{tag}: the agent may not write this value to files", tag=NO_FILE_TAG), no_file_locked or no_file_default,
                      locked=no_file_locked, pady=(d.px(10), 0))
    always = d.check(ALWAYS_LABEL, not existing) if offer_always else (lambda: False)
    if to_agent:
        tk.Label(d.body, text="  " + tr("After saving, the agent receives this value (--print).") + "  ", font=(FONT, 9), bg=warn["tint"], fg=warn["hover"],
                 ).pack(anchor="w", pady=(d.px(8), 0))
    comment = d.comment_box(d.root.destroy, tr("COMMENT FOR THE AGENT IF YOU CANCEL (optional)"))
    error = tk.Label(d.body, text="", font=(FONT, 9, "bold"), bg=BG, fg=DANGER)
    error.pack(anchor="w")

    def ok():
        if any(not v.get() for _f, v, _e in values):
            error.configure(text=tr("Fill in all values or click Cancel.") if len(fields) > 1 else tr("Enter a value or click Cancel."))
            return
        result.update(values={f: v.get() for f, v, _e in values}, username=user_var.get().strip(), url=url_var.get().strip(), no_file=no_file(), always=always())
        d.root.destroy()

    cancel = d.button(tr("Cancel"), d.root.destroy, side="left")
    save = d.button(tr("Overwrite") if overwrite else tr("Save"), ok, primary=True)
    d.root.bind("<Return>", lambda _e: save["state"] != "disabled" and ok())
    d.arm_after_delay(save)
    d.root.bind("<Escape>", lambda _e: d.root.destroy())
    d.run(value_entries[0])
    return (result, "") if result else (None, comment.get().strip())


def dialog_new_vault(vault: str) -> dict:
    result = {"password": None, "remember": False}
    d = _Dialog("store", tr("Secret broker — new vault"), tr("Create a new vault"), vault, None)
    tk = d.tk

    def field(label):
        d.section(label)
        var = tk.StringVar()
        e = tk.Entry(d.body, textvariable=var, show="•", width=36, font=(FONT, 12), relief="flat", bg=FOOTER_BG, fg=FG,
                     insertbackground=FG, highlightthickness=1, highlightbackground=BORDER, highlightcolor=d.t["accent"])
        e.pack(fill="x", ipady=d.px(5), pady=(0, d.px(10)))
        return var, e

    pw1, first = field(tr("NEW MASTER PASSWORD"))
    pw2, _ = field(tr("REPEAT PASSWORD"))
    error = tk.Label(d.body, text="", font=(FONT, 9, "bold"), bg=BG, fg=DANGER)
    error.pack(anchor="w")
    remember = tk.BooleanVar(value=True)
    tk.Checkbutton(d.body, text=tr("Remember in Windows Credential Manager"), variable=remember, font=(FONT, 9),
                   bg=BG, fg=FG, activebackground=BG, selectcolor=BG, bd=0, highlightthickness=0).pack(anchor="w")
    tk.Label(d.body, text=tr("The password cannot be recovered. Keep a copy off this computer."), font=(FONT, 8), bg=BG,
             fg=MUTED).pack(anchor="w", pady=(d.px(8), 0))

    def ok():
        if len(pw1.get()) < 8:
            error.configure(text=tr("The password must have at least 8 characters."))
        elif pw1.get() != pw2.get():
            error.configure(text=tr("The passwords do not match."))
        else:
            result["password"] = pw1.get()
            result["remember"] = remember.get()
            d.root.destroy()

    d.button(tr("Create vault"), ok, primary=True)
    d.button(tr("Cancel"), d.root.destroy)
    d.root.bind("<Return>", lambda _e: ok())
    d.root.bind("<Escape>", lambda _e: d.root.destroy())
    d.run(first)
    return result


def dialog_password(vault: str, error: str, project: str | None = None) -> dict:
    result = {"password": None, "remember": False}
    d = _Dialog("unlock", tr("Secret broker — unlock the vault"), tr("Unlock the vault"), vault, project)
    tk = d.tk

    d.section(tr("MASTER PASSWORD"))
    pw = tk.StringVar()
    remember = tk.BooleanVar(value=True)
    entry = tk.Entry(d.body, textvariable=pw, show="•", width=36, font=(FONT, 12), relief="flat", bg=FOOTER_BG, fg=FG,
                     insertbackground=FG, highlightthickness=1, highlightbackground=BORDER, highlightcolor=d.t["accent"])
    entry.pack(fill="x", ipady=d.px(5), pady=(0, d.px(8)))
    if error:
        tk.Label(d.body, text=error, font=(FONT, 9, "bold"), bg=BG, fg=DANGER).pack(anchor="w", pady=(0, d.px(6)))
    tk.Checkbutton(d.body, text=tr("Remember in Windows Credential Manager"), variable=remember, font=(FONT, 9),
                   bg=BG, fg=FG, activebackground=BG, selectcolor=BG, bd=0, highlightthickness=0).pack(anchor="w")

    def ok():
        result["password"] = pw.get()
        result["remember"] = remember.get()
        d.root.destroy()

    unlock = d.button(tr("Unlock"), ok, primary=True)
    d.button(tr("Cancel"), d.root.destroy)
    d.root.bind("<Return>", lambda _e: unlock["state"] != "disabled" and ok())
    d.arm_after_delay(unlock)
    d.root.bind("<Escape>", lambda _e: d.root.destroy())
    d.run(entry)
    return result


def dialog_mode(scope: str, project: str | None, write: bool = False) -> bool:
    result = {"ok": False}
    if write:
        d = _Dialog("forget", tr("Secret broker — notify-only mode"), tr("Save without asking?"), "secret-broker mode notify --write", project)
        d.section(tr("WHAT HAPPENS"))
        d.note(tr("In {scope}, the agent will create and overwrite vault entries without a window; you only get a notification. "
                  "Overwritten values stay in the entry's KeePass history.", scope=scope))
    else:
        d = _Dialog("forget", tr("Secret broker — notify-only mode"), tr("Turn on notify-only mode?"), "secret-broker mode notify", project)
        d.section(tr("WHAT HAPPENS"))
        d.note(tr("In {scope}, secrets without a standing approval will be released to the agent without a window; "
                  "you only get a notification.", scope=scope))
    d.tk.Label(d.body, text=tr("This was requested from the command line, possibly by an agent."), font=(FONT, 9), bg=BG,
               fg=MUTED).pack(anchor="w", pady=(d.px(4), 0))

    def pick(ok: bool):
        result["ok"] = ok
        d.root.destroy()

    cancel = d.button(tr("Cancel"), lambda: pick(False), side="left")
    turn_on = d.button(tr("Turn on"), lambda: pick(True), primary=True)
    d.root.bind("<Escape>", lambda _e: pick(False))
    d.root.protocol("WM_DELETE_WINDOW", lambda: pick(False))
    d.arm_after_delay(turn_on)
    d.run(cancel)
    return result["ok"]


def dialog_forget(vault: str, project: str, reason: str) -> tuple[bool, str]:
    result = {"ok": False}
    d = _Dialog("forget", tr("Secret broker — forget the password"), tr("Forget the vault password?"), "secret-broker forget", project)

    d.section(tr("WHAT HAPPENS"))
    d.note(tr("The remembered master password and key will be removed from Windows Credential Manager. The broker will ask for the password the next time the vault is used."))
    d.tk.Label(d.body, text=vault, font=(FONT, 8), bg=BG, fg=MUTED).pack(anchor="w", pady=(0, d.px(10)))
    if reason:
        d.section(tr("REASON"))
        d.note(reason)

    def pick(ok: bool):
        result["ok"] = ok
        d.root.destroy()

    comment = d.comment_box(lambda: pick(False), tr("COMMENT FOR THE AGENT IF YOU CANCEL (optional)"))
    cancel = d.button(tr("Cancel"), lambda: pick(False), side="left")
    forget = d.button(tr("Forget password"), lambda: pick(True), primary=True)
    d.root.bind("<Escape>", lambda _e: pick(False))
    d.root.protocol("WM_DELETE_WINDOW", lambda: pick(False))
    d.arm_after_delay(forget)
    d.run(cancel)
    return result["ok"], "" if result["ok"] else comment.get().strip()


def dialog_delete(secret: str, fields: list[str], project: str, reason: str) -> tuple[bool, str]:
    result = {"ok": False}
    d = _Dialog("delete", tr("Secret broker — delete a secret"), tr("The agent wants to delete a secret"), "secret-broker delete", project)

    d.section(tr("ENTRY"))
    d.tk.Label(d.body, text=secret, font=(FONT, 11, "bold"), bg=BG, fg=FG).pack(anchor="w")
    d.tk.Label(d.body, text=", ".join(fields), font=(FONT, 8), bg=BG, fg=MUTED).pack(anchor="w", pady=(0, d.px(10)))
    d.section(tr("WHAT HAPPENS"))
    d.note(tr("The entry moves to the vault's Recycle Bin (restorable in KeePassXC) and its approvals are revoked in every project."))
    d.section(tr("REASON"))
    d.note(reason or tr("(the agent gave no reason)"))

    def pick(ok: bool):
        result["ok"] = ok
        d.root.destroy()

    comment = d.comment_box(lambda: pick(False), tr("COMMENT FOR THE AGENT IF YOU CANCEL (optional)"))
    cancel = d.button(tr("Cancel"), lambda: pick(False), side="left")
    delete = d.button(tr("Delete"), lambda: pick(True), primary=True)
    d.root.bind("<Escape>", lambda _e: pick(False))
    d.root.protocol("WM_DELETE_WINDOW", lambda: pick(False))
    d.arm_after_delay(delete)
    d.run(cancel)
    return result["ok"], "" if result["ok"] else comment.get().strip()


class Locked(Exception):
    pass


# Direct Credential Manager calls: the `keyring` package spends ~300 ms on backend discovery per process.
_CRED_TYPE_GENERIC = 1
_CRED_PERSIST_LOCAL_MACHINE = 2


class _CREDENTIAL(ctypes.Structure):
    _fields_ = [
        ("Flags", wintypes.DWORD),
        ("Type", wintypes.DWORD),
        ("TargetName", wintypes.LPWSTR),
        ("Comment", wintypes.LPWSTR),
        ("LastWritten", wintypes.FILETIME),
        ("CredentialBlobSize", wintypes.DWORD),
        ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)),
        ("Persist", wintypes.DWORD),
        ("AttributeCount", wintypes.DWORD),
        ("Attributes", ctypes.c_void_p),
        ("TargetAlias", wintypes.LPWSTR),
        ("UserName", wintypes.LPWSTR),
    ]


_advapi = ctypes.WinDLL("advapi32", use_last_error=True)
_advapi.CredReadW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(ctypes.POINTER(_CREDENTIAL))]
_advapi.CredWriteW.argtypes = [ctypes.POINTER(_CREDENTIAL), wintypes.DWORD]
_advapi.CredDeleteW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD]
_advapi.CredFree.argtypes = [ctypes.c_void_p]


def _target(user: str) -> str:
    return f"{KEYRING_SERVICE}:{user}"


def _kr_get(user: str) -> str | None:
    p = ctypes.POINTER(_CREDENTIAL)()
    if not _advapi.CredReadW(_target(user), _CRED_TYPE_GENERIC, 0, ctypes.byref(p)):
        return None
    try:
        c = p.contents
        return ctypes.string_at(c.CredentialBlob, c.CredentialBlobSize).decode("utf-16-le")
    finally:
        _advapi.CredFree(p)


def _kr_set(user: str, value: str) -> None:
    blob = value.encode("utf-16-le")
    buf = (ctypes.c_ubyte * len(blob)).from_buffer_copy(blob)
    cred = _CREDENTIAL(
        Type=_CRED_TYPE_GENERIC, TargetName=_target(user), CredentialBlobSize=len(blob),
        CredentialBlob=ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte)),
        Persist=_CRED_PERSIST_LOCAL_MACHINE, UserName=KEYRING_SERVICE,
    )
    if not _advapi.CredWriteW(ctypes.byref(cred), 0):
        raise ctypes.WinError(ctypes.get_last_error())


def _kr_del(user: str) -> None:
    _advapi.CredDeleteW(_target(user), _CRED_TYPE_GENERIC, 0)


def open_vault(project: str | None = None, for_write: bool = False, interactive: bool = True):
    """Cached transformed key first (skips Argon2); it goes stale whenever KeePassXC re-saves with a new salt.

    for_write needs the real password: pykeepass saving a vault opened only by transformed_key writes an unopenable file.
    """
    from pykeepass import PyKeePass
    from pykeepass.exceptions import CredentialsError

    if not KDBX_PATH.exists():
        raise Locked(tr("Vault file not found: {path}. Create it with: secret-broker init", path=KDBX_PATH))

    pw_user = str(KDBX_PATH)
    tk_user = f"{KDBX_PATH}#transformed_key"

    def remember_tkey(kp):
        _kr_set(tk_user, base64.b64encode(kp.transformed_key).decode())

    tkey = None if for_write else _kr_get(tk_user)
    if tkey:
        try:
            return PyKeePass(str(KDBX_PATH), transformed_key=base64.b64decode(tkey))
        except CredentialsError:
            _kr_del(tk_user)

    stored = _kr_get(pw_user)
    if stored is not None:
        try:
            kp = PyKeePass(str(KDBX_PATH), password=stored, keyfile=KEYFILE)
            remember_tkey(kp)
            return kp
        except CredentialsError:
            _kr_del(pw_user)

    if not interactive:
        raise Locked(tr("The vault is locked; run any secret-broker command to unlock it."))
    error = ""
    for _ in range(3):
        res = dialog_password(str(KDBX_PATH), error, project)
        pw = res.get("password")
        if pw is None:
            raise Locked(tr("The user did not unlock the vault."))
        try:
            kp = PyKeePass(str(KDBX_PATH), password=pw, keyfile=KEYFILE)
        except CredentialsError:
            error = tr("Wrong password, try again.")
            continue
        if res.get("remember"):
            _kr_set(pw_user, pw)
            remember_tkey(kp)
        return kp
    raise Locked(tr("Could not unlock the vault."))


def _swap(tmp: Path, target: Path) -> None:
    """KeePassXC's file watcher or AV briefly holding the vault makes rename-over fail with WinError 5."""
    for _ in range(10):
        try:
            os.replace(tmp, target)
            return
        except PermissionError:
            time.sleep(0.3)
    raise Locked(tr("Could not replace the vault file (locked by another program?). The new version is kept in {tmp}", tmp=tmp))


def save_vault(kp):
    """Write to a temp file, prove it opens, keep a .bak, then swap; refresh the cached key (new salt)."""
    from pykeepass import PyKeePass

    fd, name = tempfile.mkstemp(dir=KDBX_PATH.parent, prefix=KDBX_PATH.name, suffix=".tmp")
    os.close(fd)
    tmp = Path(name)
    kp.save(str(tmp))
    fresh = PyKeePass(str(tmp), password=kp.password, keyfile=kp.keyfile)
    if KDBX_PATH.exists():
        shutil.copy2(KDBX_PATH, KDBX_PATH.with_name(KDBX_PATH.name + ".bak"))
    _swap(tmp, KDBX_PATH)
    if BACKUP_TASK:
        try:
            subprocess.Popen(["schtasks", "/run", "/tn", BACKUP_TASK], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except OSError:
            pass
    tk_user = f"{KDBX_PATH}#transformed_key"
    if _kr_get(str(KDBX_PATH)) is not None:
        _kr_set(tk_user, base64.b64encode(fresh.transformed_key).decode())
    else:
        _kr_del(tk_user)
    return fresh


def ensure_group(kp, parts: list[str]):
    group = kp.root_group
    for part in parts:
        group = next((g for g in group.subgroups if g.name == part), None) or kp.add_group(group, part)
    return group


def set_field(entry, field: str, value: str, sensitive: bool) -> None:
    if field.lower() in STANDARD_FIELDS:
        setattr(entry, STANDARD_FIELDS[field.lower()], value)
    else:
        entry.set_custom_property(field, value, protect=sensitive)


def entry_name(entry) -> str:
    path = [p for p in (entry.path or []) if p]
    return "/".join(path) if path else (entry.title or "")


def _in_recycle_bin(entry, recycle) -> bool:
    g = entry.group
    while g is not None:
        if g == recycle:
            return True
        g = g.parentgroup
    return False


def vault_entries(kp) -> dict:
    recycle = kp.recyclebin_group
    return {entry_name(e): e for e in kp.entries if recycle is None or not _in_recycle_bin(e, recycle)}


def entry_fields(entry) -> list[str]:
    fields = [k for k, attr in STANDARD_FIELDS.items() if getattr(entry, attr)]
    fields += sorted(entry.custom_properties.keys())
    return fields


def entry_value(entry, field: str) -> str | None:
    if field.lower() in STANDARD_FIELDS:
        return getattr(entry, STANDARD_FIELDS[field.lower()])
    return entry.custom_properties.get(field)


def is_no_file(entry) -> bool:
    return NO_FILE_TAG in (entry.tags or [])


def _hmac_key() -> bytes:
    key = _kr_get("#no-file-hmac")
    if key is None:
        key = secrets.token_hex(32)
        _kr_set("#no-file-hmac", key)
    return key.encode()


def _digest(key: bytes, value: str) -> str:
    return hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()


def load_no_file() -> dict:
    try:
        data = json.loads(NO_FILE_STATE.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        data = {}
    return {"names": data.get("names", []), "values": data.get("values", {})}


def save_no_file(data: dict) -> None:
    _write_json(NO_FILE_STATE, data)


def remember_no_file(names: list[str] | None = None, value: tuple[str, str] | None = None) -> None:
    """Values are stored as HMACs (key in Credential Manager) so the hook can spot them without holding them."""
    with state_lock():
        data = load_no_file()
        if names is not None:
            data["names"] = sorted(names)
        if value is not None:
            name, secret = value
            data["values"][_digest(_hmac_key(), secret)] = {"name": name, "len": len(secret)}
            data["names"] = sorted(set(data["names"]) | {name})
        save_no_file(data)


def _git(cwd: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(cwd), *args], stdin=subprocess.DEVNULL, capture_output=True, text=True,
                          timeout=5, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))


def temp_dir() -> Path:
    """%TEMP% is set by the caller, so it cannot decide what counts as disposable."""
    buf = ctypes.create_unicode_buffer(260)
    if ctypes.windll.shell32.SHGetFolderPathW(None, 0x001C, None, 0, buf) == 0:  # CSIDL_LOCAL_APPDATA
        return Path(buf.value) / "Temp"
    return HOME / "AppData" / "Local" / "Temp"


def disposable_path(path: str) -> bool:
    """Temp dir, or a git-ignored file inside a linked worktree (it disappears with the worktree)."""
    target = Path(path).resolve()
    if target.is_relative_to(temp_dir().resolve()):
        return True
    d = target.parent
    while not d.exists() and d != d.parent:
        d = d.parent
    try:
        return in_linked_worktree(d) and _git(d, "check-ignore", "-q", str(target)).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def in_linked_worktree(d: Path) -> bool:
    try:
        dirs = _git(d, "rev-parse", "--path-format=absolute", "--git-dir", "--git-common-dir")
        git_dir, common = (Path(x).resolve() for x in dirs.stdout.splitlines())
        return dirs.returncode == 0 and git_dir != common
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return False


def _stdout_file() -> str | None:
    try:
        fd = sys.stdout.fileno()
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
    except (OSError, ValueError, AttributeError):
        return None
    import msvcrt

    buf = ctypes.create_unicode_buffer(1024)
    n = ctypes.windll.kernel32.GetFinalPathNameByHandleW(wintypes.HANDLE(msvcrt.get_osfhandle(fd)), buf, 1024, 0)
    path = buf.value if n else ""
    return path[4:] if path.startswith("\\\\?\\") else (path or "?")


def project_root(path: str) -> str:
    """Worktrees of one repo share approvals, so resolve to the main checkout."""
    try:
        common = subprocess.run(
            ["git", "-C", path, "rev-parse", "--path-format=absolute", "--git-common-dir"],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=5,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if common.returncode == 0 and common.stdout.strip():
            git_dir = Path(common.stdout.strip())
            if git_dir.name == ".git":
                return str(git_dir.parent.resolve())
    except (OSError, subprocess.TimeoutExpired):
        pass
    return str(Path(path).resolve())


_held: dict[str, int] = {}


@contextlib.contextmanager
def file_lock(name: str, timeout: float):
    """Several agents can run the broker at once; one writer at a time per lock. Reentrant within a process."""
    if _held.get(name):
        _held[name] += 1
        try:
            yield
        finally:
            _held[name] -= 1
        return
    import msvcrt

    STATE_DIR.mkdir(parents=True, exist_ok=True)
    f = open(STATE_DIR / f".{name}.lock", "a+b")
    deadline = time.time() + timeout
    while True:
        try:
            f.seek(0)
            msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
            break
        except OSError:
            if time.time() > deadline:
                f.close()
                raise Locked(tr("Another secret-broker process is busy; try again."))
            time.sleep(0.1)
    _held[name] = 1
    try:
        yield
    finally:
        _held[name] = 0
        f.seek(0)
        msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
        f.close()


def state_lock():
    return file_lock("state", 15)


def _write_json(path: Path, data) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=path.name, suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(json.dumps(data, indent=2, ensure_ascii=False))
    os.replace(tmp, path)


def load_approvals() -> dict:
    try:
        return json.loads(APPROVALS_FILE.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_approvals(data: dict, path: Path = APPROVALS_FILE) -> None:
    _write_json(path, data)


def load_day_approvals() -> dict:
    """{project: {name: expiry epoch seconds}}, expired grants dropped."""
    try:
        data = json.loads(DAY_APPROVALS_FILE.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}
    now = time.time()
    live = {p: {n: t for n, t in grants.items() if now < t <= now + DAY_APPROVAL_S + 60} for p, grants in data.items()}
    return {p: g for p, g in live.items() if g}


def grant_day(project: str, name: str) -> None:
    with state_lock():
        data = load_day_approvals()
        data.setdefault(project, {})[name] = time.time() + DAY_APPROVAL_S
        save_approvals(data, DAY_APPROVALS_FILE)


def grant_always(project: str, name: str) -> None:
    with state_lock():
        approvals = load_approvals()
        approvals[project] = sorted(set(approvals.get(project, [])) | {name})
        save_approvals(approvals)


def revoke(project: str, name: str) -> None:
    with state_lock():
        data = load_approvals()
        names = [n for n in data.get(project, []) if n != name]
        if names:
            data[project] = names
        else:
            data.pop(project, None)
        save_approvals(data)
        day = load_day_approvals()
        day.get(project, {}).pop(name, None)
        save_approvals({p: g for p, g in day.items() if g}, DAY_APPROVALS_FILE)


def has_always(project: str, name: str) -> bool:
    return name in load_approvals().get(project, [])


def approval(project: str, name: str) -> str | None:
    """Label of the active grant shown by list, or None."""
    if name in load_approvals().get(project, []):
        return tr("always")
    expiry = load_day_approvals().get(project, {}).get(name)
    return tr("24 hours, until {when}", when=f"{datetime.fromtimestamp(expiry):%d.%m %H:%M}") if expiry else None


def load_settings() -> dict:
    """Read mode (get) and write mode (set): a global default plus per-project overrides; popup filter for the tray."""
    try:
        data = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        data = {}
    out = {}
    for key in ("", "write_"):
        mode = data.get(f"{key}default_mode")
        out[f"{key}default_mode"] = mode if mode in MODES else "prompt"
        out[f"{key}projects"] = {k: v for k, v in (data.get(f"{key}projects") or {}).items() if v in MODES}
    out["popup"] = "selected" if data.get("popup") == "selected" else "all"
    out["popup_secrets"] = {k: v for k, v in (data.get("popup_secrets") or {}).items() if isinstance(v, bool)}
    hours = data.get("cache_hours")
    out["cache_hours"] = hours if isinstance(hours, (int, float)) and not isinstance(hours, bool) and 0 <= hours <= 24 else 0
    return out


def set_cache_hours(hours: float) -> None:
    with state_lock():
        data = load_settings()
        data["cache_hours"] = hours
        save_settings(data)


def save_settings(data: dict) -> None:
    save_approvals(data, SETTINGS_FILE)


def set_mode(mode: str | None, project: str | None, write: bool = False) -> dict:
    """project None sets the global default; mode None drops the project override."""
    key = "write_" if write else ""
    with state_lock():
        data = load_settings()
        if project is None:
            data[f"{key}default_mode"] = mode or "prompt"
        elif mode is None:
            data[f"{key}projects"].pop(project, None)
        else:
            data[f"{key}projects"][project] = mode
        save_settings(data)
    return data


def project_mode(project: str, write: bool = False) -> str:
    key = "write_" if write else ""
    data = load_settings()
    return data[f"{key}projects"].get(project, data[f"{key}default_mode"])


def popup_wanted(settings: dict, name: str) -> bool:
    own = settings["popup_secrets"].get(name)
    return own if own is not None else settings["popup"] == "all"


def set_popup(name: str | None, on: bool | None, default: str | None = None) -> None:
    """Tray only: there is deliberately no CLI for this, so an agent cannot silence its own notifications."""
    with state_lock():
        data = load_settings()
        if default:
            data["popup"] = default
            data["popup_secrets"] = {k: v for k, v in data["popup_secrets"].items() if v != (default == "all")}
        if name is not None:
            if on is None or on == (data["popup"] == "all"):
                data["popup_secrets"].pop(name, None)
            else:
                data["popup_secrets"][name] = on
        save_settings(data)


def tray_running() -> bool:
    try:
        h = ctypes.windll.kernel32.OpenMutexW(0x00100000, False, TRAY_MUTEX)
    except (AttributeError, OSError):
        return False
    if h:
        ctypes.windll.kernel32.CloseHandle(h)
    return bool(h)


def start_tray() -> None:
    """The tray icon shows the notification; every std handle goes to DEVNULL so $(secret-broker get) does not wait for it."""
    if tray_running():
        return
    exe = Path(sys.executable)
    exe = exe.with_name("pythonw.exe") if exe.with_name("pythonw.exe").exists() else exe
    flags = getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | getattr(subprocess, "CREATE_NO_WINDOW", 0)
    # The agent's environment (tokens, PYTHONPATH) must not leak into a long-lived process.
    keep = ("SYSTEMROOT", "WINDIR", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "HOMEDRIVE", "HOMEPATH", "USERNAME", "TEMP", "TMP",
            "SECRET_BROKER_KDBX", "SECRET_BROKER_STATE", "SECRET_BROKER_KEYFILE", "SECRET_BROKER_BACKUP_TASK", "SECRET_BROKER_LANG")
    env = {k: os.environ[k] for k in keep if k in os.environ}
    try:
        subprocess.Popen([str(exe), "-E", "-s", str(Path(__file__).resolve()), "tray"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, close_fds=True, creationflags=flags, cwd=str(HOME), env=env)
    except OSError:
        pass


def ensure_tray(wait_s: float = 3.0) -> bool:
    start_tray()
    deadline = time.time() + wait_s
    while not tray_running():
        if time.time() > deadline:
            return False
        time.sleep(0.1)
    return True


def audit(**event) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    event["ts"] = datetime.now().isoformat(timespec="seconds")
    with AUDIT_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")


def fail(msg: str, code: int) -> int:
    print(msg, file=sys.stderr)
    return code


def refuse(msg: str, comment: str) -> int:
    return fail(msg + " " + tr("User comment: {comment}", comment=comment) if comment else msg, EXIT_DENIED)


def cmd_list(args) -> int:
    project = project_root(os.getcwd())
    try:
        entries = vault_entries(open_vault(project))
    except Locked as e:
        return fail(str(e), EXIT_LOCKED)
    rows = []
    for n, e in sorted(entries.items()):
        grant = approval(project, n)
        rows.append({"name": n, "fields": entry_fields(e), "approved_for_project": grant is not None, "approval": grant,
                     "no_file": is_no_file(e)})
    remember_no_file(names=[r["name"] for r in rows if r["no_file"]])
    if args.json:
        print(json.dumps({"project": project, "secrets": rows}, ensure_ascii=False, indent=1))
    else:
        for r in rows:
            mark = (f"  [{r['approval']}]" if r["approval"] else "") + (f"  [{NO_FILE_TAG}]" if r["no_file"] else "")
            print(f"{r['name']}  ({', '.join(r['fields'])}){mark}")
    return 0


def cmd_get(args) -> int:
    project = project_root(os.getcwd())
    import vault_cache
    hit, entry = vault_cache.cached_entry(args.name)
    if not hit:
        try:
            entry = vault_entries(open_vault(project)).get(args.name)
        except Locked as e:
            return fail(str(e), EXIT_LOCKED)
    if entry is None:
        return fail(tr("No secret '{name}'. Use: secret-broker list", name=args.name), EXIT_NOT_FOUND)
    value = entry_value(entry, args.field)
    if value is None:
        return fail(tr("Secret '{name}' has no field '{field}'. Available: {fields}", name=args.name, field=args.field, fields=', '.join(entry_fields(entry))), EXIT_NOT_FOUND)

    no_file = is_no_file(entry)
    if no_file:
        target = _stdout_file()
        if target and not disposable_path(target):
            audit(project=project, secret=args.name, field=args.field, decision="blocked-file", target=target)
            return fail(tr("'{name}' is tagged {tag}: it may not be redirected to a file ({target}). Keep it in a variable or pass it straight to a process.", name=args.name, tag=NO_FILE_TAG, target=target), EXIT_FORBIDDEN)

    if approval(project, args.name):
        audit(project=project, secret=args.name, field=args.field, decision="remembered")
    elif project_mode(project) == "notify" and ensure_tray():
        audit(project=project, secret=args.name, field=args.field, decision="notified", reason=args.reason or "")
    else:
        choice, comment = dialog_approve(args.name, args.field, project, args.reason or "", no_file)
        audit(project=project, secret=args.name, field=args.field, decision=choice, reason=args.reason or "", comment=comment)
        if choice == "deny":
            return refuse(tr("The user denied access to the secret."), comment)
        if choice == "always":
            grant_always(project, args.name)
        elif choice == "day":
            grant_day(project, args.name)
    if no_file:
        remember_no_file(value=(args.name, value))
        print(tr("NOTE: '{name}' is tagged {tag}. Keep it only in a variable/process; do not write it to .env, configs, scripts or other files (exception: a git-ignored file in a temporary worktree).", name=args.name, tag=NO_FILE_TAG), file=sys.stderr)
    sys.stdout.write(value)
    if sys.stdout.isatty():
        sys.stdout.write("\n")
    return 0


def generate_password(length: int) -> str:
    alphabet = string.ascii_letters + string.digits + "-_.!@#%^*+="
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if any(c.islower() for c in pw) and any(c.isupper() for c in pw) and any(c.isdigit() for c in pw):
            return pw


def cmd_set(args) -> int:
    parts = [p for p in args.name.split("/") if p]
    if not parts:
        return fail(tr("Give an entry name, e.g. Hosting/Database."), EXIT_NOT_FOUND)
    if args.field.lower() == "title":
        return fail(tr("Field 'title' is the entry name; change it in KeePassXC."), EXIT_NOT_FOUND)

    changes = []
    if args.generate:
        changes.append({"field": args.field, "value": generate_password(args.generate), "sensitive": True})
    elif args.stdin:
        value = sys.stdin.buffer.read().decode("utf-8")
        if "\n" not in value.rstrip("\r\n"):
            value = value.rstrip("\r\n")
        if not value:
            return fail(tr("Empty value on stdin."), EXIT_NOT_FOUND)
        changes.append({"field": args.field, "value": value, "sensitive": True})
    if args.username is not None:
        changes.append({"field": "username", "value": args.username, "sensitive": False})
    if args.url is not None:
        changes.append({"field": "url", "value": args.url, "sensitive": False})
    for kv in args.attr or []:
        key, sep, val = kv.partition("=")
        if not sep or not key:
            return fail(tr("--attr needs KEY=VALUE, got '{kv}'.", kv=kv), EXIT_NOT_FOUND)
        if key.lower() in {"password", "title", args.field.lower()}:
            return fail(tr("--attr {key} would store a secret in plain text; use --stdin or --generate.", key=key), EXIT_NOT_FOUND)
        changes.append({"field": key, "value": val, "sensitive": False})
    if not changes and not args.no_file:
        return fail(tr("Nothing to save: use --stdin, --generate, --username, --url, --attr or --no-file."), EXIT_NOT_FOUND)
    if args.generate and args.no_file:
        target = _stdout_file()
        if target and not disposable_path(target):
            return fail(tr("set --generate --no-file may not write to a file ({target}). Keep the value in a variable.", target=target), EXIT_FORBIDDEN)

    name = "/".join(parts)
    project = project_root(os.getcwd())
    try:
        with file_lock("vault", DIALOG_TIMEOUT_S + 30):
            return _set_locked(args, parts, name, project, changes)
    except Locked as e:
        return fail(str(e), EXIT_LOCKED)


def _set_locked(args, parts, name, project, changes) -> int:
    kp = open_vault(project, for_write=True)
    entry = vault_entries(kp).get(name)
    locked = entry is not None and is_no_file(entry)
    for ch in changes:
        old = entry_value(entry, ch["field"]) if entry is not None else None
        ch["state"] = "same" if old == ch["value"] else ("overwrite" if old else "new")
    changes = [ch for ch in changes if ch["state"] != "same"]
    if not changes and (locked or not args.no_file):
        print(tr("No change: the entry already has these values."), file=sys.stderr)
        return 0

    fields = [f"{c['field']}:{c['state']}" for c in changes]
    if project_mode(project, write=True) == "notify" and ensure_tray():
        ok, comment, opts = True, "", {"no_file": bool(args.no_file), "always": False}
        audit(project=project, action="set", secret=name, fields=fields, decision="notified", reason=args.reason, **opts)
    else:
        ok, comment, opts = dialog_store(name, changes, project, args.reason, entry is None, locked, args.no_file,
                                         not has_always(project, name))
        audit(project=project, action="set", secret=name, fields=fields,
              decision="ok" if ok else "deny", reason=args.reason, comment=comment, **opts)
    if not ok:
        return refuse(tr("The user refused the save."), comment)
    tag = opts["no_file"] and not locked
    if not changes and not tag:
        print(tr("No change: no-file was not ticked."), file=sys.stderr)
        return 0
    if entry is None:
        entry = kp.add_entry(ensure_group(kp, parts[:-1]), parts[-1], "", "")
    else:
        entry.save_history()
    for ch in changes:
        set_field(entry, ch["field"], ch["value"], ch["sensitive"])
    if tag:
        entry.tags = (entry.tags or []) + [NO_FILE_TAG]
    entry.touch(modify=True)
    save_vault(kp)
    if opts["always"]:
        grant_always(project, name)
    if opts["no_file"]:
        secret = next((c["value"] for c in changes if c["sensitive"]), None) or entry_value(entry, args.field)
        remember_no_file(names=sorted(set(load_no_file()["names"]) | {name}), value=(name, secret) if secret else None)
    extras = ([NO_FILE_TAG] if opts["no_file"] else []) + ([tr("always in this project")] if opts["always"] else [])
    print(tr("Saved {name}: {fields}", name=name, fields=', '.join(c['field'] for c in changes) or 'tags')
          + (f" [{', '.join(extras)}]" if extras else "") + ".", file=sys.stderr)
    if args.generate:
        sys.stdout.write(changes[0]["value"])
        if sys.stdout.isatty():
            sys.stdout.write("\n")
    return 0


def cmd_ask(args) -> int:
    parts = [p for p in args.name.split("/") if p]
    if not parts:
        return fail(tr("Give an entry name, e.g. Hosting/Database."), EXIT_NOT_FOUND)
    fields = list(dict.fromkeys(args.field or ["password"]))
    for f in fields:
        if f.lower() in ("title", "username", "url"):
            return fail(tr("--field {f} cannot hold the secret value; username and URL are separate fields in the window.", f=f), EXIT_NOT_FOUND)
    if args.print and len(fields) > 1:
        return fail(tr("ask --print works with a single --field only."), EXIT_NOT_FOUND)
    attrs = []
    for kv in args.attr or []:
        key, sep, val = kv.partition("=")
        if not sep or not key:
            return fail(tr("--attr needs KEY=VALUE, got '{kv}'.", kv=kv), EXIT_NOT_FOUND)
        if key.lower() in {"password", "title"} | {f.lower() for f in fields}:
            return fail(tr("--attr {key} would store a secret in plain text; use --stdin or --generate.", key=key), EXIT_NOT_FOUND)
        attrs.append((key, val))
    if args.print:
        target = _stdout_file()
        if target and not disposable_path(target):
            return fail(tr("ask --print may not write to a file ({target}). Keep the value in a variable.", target=target), EXIT_FORBIDDEN)

    name = "/".join(parts)
    project = project_root(os.getcwd())
    try:
        with file_lock("vault", DIALOG_TIMEOUT_S + 30):
            return _ask_locked(args, parts, name, project, fields, attrs)
    except Locked as e:
        return fail(str(e), EXIT_LOCKED)


def _ask_locked(args, parts, name, project, fields, attrs) -> int:
    kp = open_vault(project, for_write=True)
    entry = vault_entries(kp).get(name)
    locked = entry is not None and is_no_file(entry)
    res, comment = dialog_ask(name, fields, project, args.reason, args.username if args.username is not None else (entry and entry.username) or "",
                     args.url if args.url is not None else (entry and entry.url) or "", attrs, entry is not None,
                     [f for f in fields if entry is not None and entry_value(entry, f)], locked, args.no_file, args.print,
                     not has_always(project, name))
    audit(project=project, action="ask", secret=name, field=",".join(fields), decision="ok" if res else "cancel", reason=args.reason,
          print=args.print, comment=comment, **({"no_file": res["no_file"], "always": res["always"]} if res else {}))
    if not res:
        return refuse(tr("The user cancelled entering the secret."), comment)

    if entry is None:
        entry = kp.add_entry(ensure_group(kp, parts[:-1]), parts[-1], "", "")
    else:
        entry.save_history()
    for f, val in res["values"].items():
        set_field(entry, f, val, True)
    for field, val in (("username", res["username"]), ("url", res["url"])):
        if val or entry_value(entry, field):
            set_field(entry, field, val, False)
    for key, val in attrs:
        set_field(entry, key, val, False)
    if res["no_file"] and not locked:
        entry.tags = (entry.tags or []) + [NO_FILE_TAG]
    entry.touch(modify=True)
    save_vault(kp)
    if res["always"]:
        grant_always(project, name)
    get_hint = " ".join(f'secret-broker get "{name}"' + (f" --field {f}" if f != "password" else "") for f in fields[:1])
    flags = ", ".join(fields + ([NO_FILE_TAG] if res["no_file"] else []) + ([tr("always in this project")] if res["always"] else []))
    print((tr("Saved {name} ({flags}). The value is not shown; fetch it with: {hint}", name=name, flags=flags, hint=get_hint)
           if len(fields) == 1 else tr("Saved {name} ({flags}). Values are not shown; fetch each field separately, e.g.: {hint}", name=name, flags=flags, hint=get_hint)),
          file=sys.stderr)
    if res["no_file"]:
        remember_no_file(names=sorted(set(load_no_file()["names"]) | {name}), value=(name, res["values"][fields[0]]) if args.print else None)
    if args.print:
        sys.stdout.write(res["values"][fields[0]])
        if sys.stdout.isatty():
            sys.stdout.write("\n")
    return 0


def cmd_init(_args) -> int:
    from pykeepass import create_database

    if KDBX_PATH.exists():
        print(tr("The vault already exists: {path}", path=KDBX_PATH))
        return 0
    res = dialog_new_vault(str(KDBX_PATH))
    if res["password"] is None:
        return fail(tr("Vault creation cancelled."), EXIT_DENIED)
    KDBX_PATH.parent.mkdir(parents=True, exist_ok=True)
    kp = create_database(str(KDBX_PATH), password=res["password"], keyfile=KEYFILE)
    if res["remember"]:
        _kr_set(str(KDBX_PATH), res["password"])
        _kr_set(f"{KDBX_PATH}#transformed_key", base64.b64encode(kp.transformed_key).decode())
    audit(action="init", vault=str(KDBX_PATH))
    print(tr("Created vault: {path}", path=KDBX_PATH))
    return 0


def cmd_approvals(args) -> int:
    data = load_approvals()
    day = load_day_approvals()
    if args.revoke:
        project = project_root(args.project or os.getcwd())
        revoke(project, args.revoke)
        audit(project=project, secret=args.revoke, action="revoke", decision="revoked")
        data, day = load_approvals(), load_day_approvals()
    day_view = {p: {n: datetime.fromtimestamp(t).isoformat(timespec="minutes") for n, t in g.items()} for p, g in day.items()}
    print(json.dumps({"always": data, "day": day_view}, indent=2, ensure_ascii=False))
    return 0


def cmd_mode(args) -> int:
    if args.mode:
        project = None if args.globally else project_root(args.project or os.getcwd())
        new = None if args.mode == "default" else args.mode
        before = load_settings()
        key = "write_" if args.write else ""
        if project is None:
            loosens = new == "notify" and before[f"{key}default_mode"] != "notify"
        else:
            after = new or before[f"{key}default_mode"]
            loosens = after == "notify" and project_mode(project, args.write) != "notify"
        if loosens and not dialog_mode(tr("all projects") if project is None else project, project, args.write):
            audit(project=project or "*", action="mode", mode=args.mode, write=args.write, decision="deny")
            return fail(tr("Notify-only mode was not turned on."), EXIT_DENIED)
        set_mode(new, project, args.write)
        audit(project=project or "*", action="mode", mode=args.mode, write=args.write, decision="ok")
        if loosens:
            ensure_tray()
    data = load_settings()
    here = project_root(args.project or os.getcwd())
    print(json.dumps({**data, "current_project": here, "current_mode": project_mode(here),
                      "current_write_mode": project_mode(here, True)}, indent=2, ensure_ascii=False))
    return 0


def cmd_cache(args) -> int:
    """Turning the cache on or lengthening it is a tray click only: an agent must not widen it by itself."""
    import vault_cache
    if args.action in ("off", "clear"):
        if args.action == "off":
            set_cache_hours(0)
        vault_cache.request({"op": "clear"})
        audit(project="*", action="cache", mode=args.action, decision="ok")
    status = vault_cache.request({"op": "status"}) or {"ok": False, "hours": load_settings()["cache_hours"], "loaded": False,
                                                      "tray": "not running"}
    print(json.dumps(status, indent=2, ensure_ascii=False))
    return 0


def cmd_tray(_args) -> int:
    import tray
    return tray.main()


def cmd_forget(args) -> int:
    users = (str(KDBX_PATH), f"{KDBX_PATH}#transformed_key")
    if all(_kr_get(u) is None for u in users):
        print(tr("Nothing is remembered."))
        return 0
    project = project_root(os.getcwd())
    ok, comment = dialog_forget(str(KDBX_PATH), project, args.reason)
    audit(project=project, action="forget", decision="ok" if ok else "deny", reason=args.reason, comment=comment)
    if not ok:
        return refuse(tr("The user cancelled removing the password."), comment)
    for u in users:
        _kr_del(u)
    print(tr("Removed the remembered password and key from Credential Manager."))
    return 0


def cmd_delete(args) -> int:
    """Always asks in a window: neither notify mode nor a standing approval covers destroying an entry."""
    name = "/".join(p for p in args.name.split("/") if p)
    project = project_root(os.getcwd())
    try:
        with file_lock("vault", DIALOG_TIMEOUT_S + 30):
            kp = open_vault(project, for_write=True)
            entry = vault_entries(kp).get(name)
            if entry is None:
                return fail(tr("No secret '{name}'. Use: secret-broker list", name=name), EXIT_NOT_FOUND)
            ok, comment = dialog_delete(name, entry_fields(entry), project, args.reason)
            audit(project=project, action="delete", secret=name, decision="ok" if ok else "deny", reason=args.reason, comment=comment)
            if not ok:
                return refuse(tr("The user refused the deletion."), comment)
            kp.trash_entry(entry)
            save_vault(kp)
    except Locked as e:
        return fail(str(e), EXIT_LOCKED)
    for p in {*load_approvals(), *load_day_approvals()}:
        revoke(p, name)
    with state_lock():
        data = load_no_file()
        if name in data["names"]:
            data["names"] = [n for n in data["names"] if n != name]
            data["values"] = {k: v for k, v in data["values"].items() if v.get("name") != name}
            save_no_file(data)
    print(tr("Moved {name} to the Recycle Bin.", name=name), file=sys.stderr)
    return 0


WRITE_TO_FILE = re.compile(
    r"(?<![2>])>>?(?!\s*(?:&|/dev/null\b|\$null\b|nul\b))|\btee\b|Out-File|Set-Content|Add-Content|-OutFile\b|\bsed\s+-i"
    r"|\[IO\.File\]::Write|New-Item\b.*-Value|\bsetx\b|SetEnvironmentVariable", re.I)


def _contains_value(text: str, data: dict) -> str | None:
    if not data["values"] or not text:
        return None
    key = _hmac_key()
    variants = {text, text.replace("\r\n", "\n")}
    for length in {v["len"] for v in data["values"].values()}:
        for t in variants:
            for i in range(len(t) - length + 1):
                hit = data["values"].get(_digest(key, t[i:i + length]))
                if hit:
                    return hit["name"]
    return None


def cmd_guard_hook(_args) -> int:
    """Claude Code PreToolUse hook: exit 2 blocks the tool call and shows stderr to the agent."""
    try:
        event = json.loads(sys.stdin.buffer.read().decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return 0
    data = load_no_file()
    if not data["names"]:
        return 0
    tool, inp = event.get("tool_name", ""), event.get("tool_input") or {}
    cwd = event.get("cwd") or os.getcwd()
    rule = tr("Secrets tagged {tag} are not written to files (.env, configs, scripts); keep them in a variable or pass them straight to a process. Exception: a git-ignored file in a temporary worktree.", tag=NO_FILE_TAG)

    if tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        path = inp.get("file_path") or inp.get("notebook_path") or ""
        if path and disposable_path(path if os.path.isabs(path) else os.path.join(cwd, path)):
            return 0
        text = "\n".join([inp.get("content") or "", inp.get("new_string") or "", inp.get("new_source") or ""]
                         + [e.get("new_string") or "" for e in inp.get("edits") or []])
        name = _contains_value(text, data)
        if name:
            print(tr("Blocked: the write to {path} contains the value of '{name}'. {rule}", path=path, name=name, rule=rule), file=sys.stderr)
            return 2
        return 0

    if tool in ("Bash", "PowerShell") or tool.endswith("execute_command"):
        cmd = inp.get("command") or ""
        if not WRITE_TO_FILE.search(cmd):
            return 0
        name = _contains_value(cmd, data) or next((n for n in data["names"] if "secret-broker" in cmd and n in cmd), None)
        if name:
            print(tr("Blocked: the command writes to a file and touches '{name}'. {rule} Split fetching the secret and writing files into separate commands.", name=name, rule=rule), file=sys.stderr)
            return 2
    return 0


def _drop_own_console() -> None:
    """A caller without a console (a GUI agent, a scheduled task) makes Windows open an empty black one for python.exe.
    With Windows Terminal as the default terminal, hiding that window does nothing; detaching closes it."""
    k = ctypes.windll.kernel32
    if not k.GetConsoleWindow():
        return
    pids = (wintypes.DWORD * 8)()
    n = k.GetConsoleProcessList(pids, 8)
    # uv's venv python.exe is a launcher, so a console made just for us may also hold our parent.
    if not (0 < n <= 2 and set(pids[:n]) <= {os.getpid(), os.getppid()}):
        return
    on_console = [name for name in ("stdout", "stderr") if getattr(sys, name) is not None and getattr(sys, name).isatty()]
    k.FreeConsole()
    for name in on_console:
        setattr(sys, name, open(os.devnull, "w", encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    _drop_own_console()
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")

    parser = argparse.ArgumentParser(prog="secret-broker", description=tr("Vault: {path}", path=KDBX_PATH))
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_list = sub.add_parser("list", help=tr("secret and field names (no values)"))
    p_list.add_argument("--json", action="store_true")
    p_get = sub.add_parser("get", help=tr("a secret's value (after approval in a window)"))
    p_get.add_argument("name")
    p_get.add_argument("--field", default="password")
    p_get.add_argument("--reason", default="")
    p_set = sub.add_parser("set", help=tr("save/update an entry (after approval in a window)"))
    p_set.add_argument("name", help=tr("Group/Title; missing groups are created"))
    p_set.add_argument("--field", default="password", help=tr("field for the --stdin/--generate value (default password)"))
    src = p_set.add_mutually_exclusive_group()
    src.add_argument("--stdin", action="store_true", help=tr("value from stdin (may span lines)"))
    src.add_argument("--generate", type=int, nargs="?", const=32, metavar=tr("LEN"), help=tr("generate a password and print it to stdout"))
    p_set.add_argument("--username", help=tr("username (plain text)"))
    p_set.add_argument("--url")
    p_set.add_argument("--attr", action="append", metavar=tr("KEY=VALUE"), help=tr("plain attribute, e.g. host=db.example.com"))
    p_set.add_argument("--no-file", action="store_true", help=tr("pre-tick {tag} in the window (the user can untick it)", tag=NO_FILE_TAG))
    p_set.add_argument("--reason", default="")
    p_ask = sub.add_parser("ask", help=tr("a window where the user types a new secret (the agent never sees it)"))
    p_ask.add_argument("name", help=tr("Group/Title; missing groups are created"))
    p_ask.add_argument("--field", action="append", help=tr("field for the typed value (default password); repeat to fill several fields in one window"))
    p_ask.add_argument("--username", help=tr("suggested username (the user can change it)"))
    p_ask.add_argument("--url", help=tr("suggested URL"))
    p_ask.add_argument("--attr", action="append", metavar=tr("KEY=VALUE"), help=tr("plain attribute, e.g. host=db.example.com"))
    p_ask.add_argument("--no-file", action="store_true", help=tr("pre-tick {tag} in the window (the user can untick it)", tag=NO_FILE_TAG))
    p_ask.add_argument("--print", action="store_true", help=tr("print the value to stdout after saving (the window says so)"))
    p_ask.add_argument("--reason", default="")
    sub.add_parser("init", help=tr("create a new vault (you type the password in a window)"))
    p_appr = sub.add_parser("approvals", help=tr("show/revoke 'always in project' and '24 hours' approvals"))
    p_appr.add_argument("--revoke", metavar="NAZWA")
    p_appr.add_argument("--project", metavar=tr("PATH"))
    p_forget = sub.add_parser("forget", help=tr("remove the remembered password from Credential Manager (confirmed in a window)"))
    p_forget.add_argument("--reason", default="")
    p_delete = sub.add_parser("delete", help=tr("move an entry to the vault's Recycle Bin (always confirmed in a window)"))
    p_delete.add_argument("name", help=tr("Group/Title"))
    p_delete.add_argument("--reason", default="")
    p_mode = sub.add_parser("mode", help=tr("mode for secrets without a standing approval: prompt (window) / notify (notification only)"))
    p_mode.add_argument("mode", nargs="?", choices=[*MODES, "default"], help=tr("default removes the project's override"))
    where = p_mode.add_mutually_exclusive_group()
    where.add_argument("--global", dest="globally", action="store_true", help=tr("set the default mode for all projects"))
    where.add_argument("--project", metavar=tr("PATH"))
    p_mode.add_argument("--write", action="store_true", help=tr("the mode for saving (set) instead of reading (get)"))
    p_cache = sub.add_parser("cache", help=tr("in-memory vault cache in the tray: status, off, clear (turn it on in the tray menu)"))
    p_cache.add_argument("action", nargs="?", choices=["status", "off", "clear"], default="status")
    sub.add_parser("tray", help=tr("tray icon: mode, history, approvals"))
    sub.add_parser("guard-hook", help=tr("Claude Code PreToolUse hook: blocks writing no-file secrets to files"))
    args = parser.parse_args(argv)

    return {"list": cmd_list, "get": cmd_get, "set": cmd_set, "ask": cmd_ask, "init": cmd_init, "approvals": cmd_approvals, "forget": cmd_forget, "delete": cmd_delete,
            "mode": cmd_mode, "cache": cmd_cache, "tray": cmd_tray, "guard-hook": cmd_guard_hook}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
