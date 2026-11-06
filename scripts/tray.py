"""Tray icon for secret-broker: notifications for secrets used without a window, mode settings, history, approvals."""

import ctypes
import json
import queue
import threading
import time
from ctypes import wintypes
from datetime import datetime
from pathlib import Path

import pystray
from PIL import Image, ImageDraw

import secret_broker as sb
import vault_cache
from secret_broker import tr

POLL_S = 1.0
# The tray is often started by the very `get` that must be announced, so look back a little at startup.
STARTUP_LOOKBACK_S = 30
HISTORY_LIMIT = 500
POPUP_SHOW_MS = 7000
POPUP_MAX = 3
NOTIFY_ACCENT = "#d97706"

DECISIONS = {
    "notified": tr("without asking (notified)"),
    "remembered": tr("standing approval"),
    "once": tr("once"),
    "day": tr("24 hours"),
    "always": tr("always in project"),
    "deny": tr("denied"),
    "blocked-file": tr("blocked (no-file → file)"),
    "ok": "OK",
}
ACTIONS = {"set": tr("save"), "ask": tr("typed in"), "revoke": tr("revoke"), "mode": tr("mode"), "popup": tr("notification")}


def icon_image(mode: str) -> Image.Image:
    accent = NOTIFY_ACCENT if mode == "notify" else sb.THEMES["approve"]["accent"]
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle((2, 2, 62, 62), radius=14, fill=accent)
    d.ellipse((10, 18, 34, 42), outline="white", width=6)
    d.rectangle((32, 27, 54, 33), fill="white")
    d.rectangle((44, 33, 49, 42), fill="white")
    d.rectangle((52, 33, 56, 39), fill="white")
    if mode == "notify":
        d.ellipse((42, 2, 62, 22), fill="#dc2626", outline="white", width=2)
    return img


def read_audit() -> list[dict]:
    try:
        lines = sb.AUDIT_FILE.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return []
    out = []
    for line in lines[-HISTORY_LIMIT * 4:]:
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return out


def _ts(e: dict) -> float:
    try:
        return datetime.fromisoformat(e.get("ts", "")).timestamp()
    except ValueError:
        return 0.0


def _fields(e: dict) -> str:
    if e.get("fields"):
        return ", ".join(f.split(":")[0] for f in e["fields"])
    return e.get("field", "")


class AuditTail:
    def __init__(self):
        self.pos = 0
        try:
            size = sb.AUDIT_FILE.stat().st_size
        except FileNotFoundError:
            size = 0
        cutoff = time.time() - STARTUP_LOOKBACK_S
        self.pending = [e for e in read_audit() if e.get("decision") == "notified" and _ts(e) >= cutoff]
        self.pos = size

    def new_events(self) -> list[dict]:
        events, self.pending = self.pending, []
        try:
            with sb.AUDIT_FILE.open("rb") as f:
                f.seek(0, 2)
                end = f.tell()
                if end < self.pos:  # rotated or truncated: do not replay the history
                    self.pos = end
                f.seek(self.pos)
                chunk = f.read()
        except FileNotFoundError:
            return events
        # Keep a half-written last line for the next poll.
        cut = chunk.rfind(b"\n") + 1
        self.pos += cut
        for line in chunk[:cut].decode("utf-8", "replace").splitlines():
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        return events


def known_projects() -> list[str]:
    s = sb.load_settings()
    names = set(s["projects"]) | set(s["write_projects"]) | set(sb.load_approvals()) | set(sb.load_day_approvals())
    names |= {e["project"] for e in read_audit() if e.get("project") and e.get("project") != "*"}
    return sorted(names, key=str.lower)


def notification_text(e: dict) -> tuple[str, str]:
    if e.get("action") == "set":
        title = tr("The agent saved: {name}", name=e.get("secret", "?"))
    else:
        title = tr("The agent fetched: {name}", name=e.get("secret", "?"))
    sub = [Path(e.get("project", "")).name, _fields(e) or "password"]
    if e.get("reason"):
        sub.append(e["reason"])
    text = "  ·  ".join(x for x in sub if x)
    return title, text if len(text) <= 90 else text[:89] + "…"


def _work_area() -> tuple[int, int, int, int]:
    r = wintypes.RECT()
    ctypes.windll.user32.SystemParametersInfoW(0x30, 0, ctypes.byref(r), 0)  # SPI_GETWORKAREA
    return r.left, r.top, r.right, r.bottom


class Popups:
    """Small silent cards in the bottom-right corner; they never take focus and fade out on their own."""

    def __init__(self, root, on_click):
        import tkinter as tk
        self.tk, self.root, self.on_click = tk, root, on_click
        self.cards: list = []

    def show(self, e: dict) -> None:
        tk = self.tk
        title, sub = notification_text(e)
        w = tk.Toplevel(self.root)
        w.withdraw()
        w.overrideredirect(True)
        w.attributes("-topmost", True)
        w.attributes("-alpha", 0.0)
        w.configure(bg="#cbd5e1")
        card = tk.Frame(w, bg=sb.BG)
        card.pack(fill="both", expand=True, padx=1, pady=1)
        tk.Frame(card, bg=NOTIFY_ACCENT, width=4).pack(side="left", fill="y")
        body = tk.Frame(card, bg=sb.BG, padx=10, pady=7)
        body.pack(side="left", fill="both", expand=True)
        top = tk.Frame(body, bg=sb.BG)
        top.pack(fill="x")
        glyph = "" if e.get("action") == "set" else ""
        tk.Label(top, text=glyph, font=("Segoe MDL2 Assets", 9), bg=sb.BG, fg=NOTIFY_ACCENT).pack(side="left", padx=(0, 6))
        tk.Label(top, text=title, font=(sb.FONT, 9, "bold"), bg=sb.BG, fg="#0f172a", anchor="w").pack(side="left")
        close = tk.Label(top, text="", font=("Segoe MDL2 Assets", 7), bg=sb.BG, fg=sb.MUTED, cursor="hand2")
        close.pack(side="right", padx=(12, 0))
        tk.Label(body, text=sub, font=(sb.FONT, 8), bg=sb.BG, fg=sb.MUTED, anchor="w").pack(fill="x", pady=(2, 0))

        item = {"win": w, "after": None, "event": e}

        def widgets(x):
            yield x
            for c in x.winfo_children():
                yield from widgets(c)

        for x in widgets(w):
            if x is not close:
                x.bind("<Button-1>", lambda _e: (self.close(item), self.on_click(e)))
            x.configure(cursor="hand2")
        close.bind("<Button-1>", lambda _e: self.close(item))
        w.bind("<Enter>", lambda _e: self._cancel(item))
        w.bind("<Leave>", lambda _e: self._schedule(item, 3000))

        w.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(w.winfo_id()) or w.winfo_id()
        ex = ctypes.windll.user32.GetWindowLongW(hwnd, -20)  # GWL_EXSTYLE
        ctypes.windll.user32.SetWindowLongW(hwnd, -20, ex | 0x08000000 | 0x80)  # WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW

        self.cards.append(item)
        while len(self.cards) > POPUP_MAX:
            self.close(self.cards[0])
        self._layout()
        ctypes.windll.user32.ShowWindow(hwnd, 4)  # SW_SHOWNOACTIVATE
        w.deiconify()
        self._layout()  # Tk drops the geometry of an override-redirect window on its first map
        self._fade(item, 0.0, 0.96, 0.12)
        self._schedule(item, POPUP_SHOW_MS)

    def _layout(self) -> None:
        _l, _t, right, bottom = _work_area()
        gap = max(8, int(self.root.winfo_fpixels("3m")))
        y = bottom - gap
        width = max([int(self.root.winfo_fpixels("75m"))] + [i["win"].winfo_reqwidth() for i in self.cards])
        for item in reversed(self.cards):
            w = item["win"]
            height = w.winfo_reqheight()
            y -= height
            w.geometry(f"{width}x{height}+{right - width - gap}+{y}")
            y -= gap // 2

    def _fade(self, item, a: float, target: float, step: float, done=None) -> None:
        w = item["win"]
        if not w.winfo_exists():
            return
        a = min(target, a + step) if step > 0 else max(target, a + step)
        w.attributes("-alpha", a)
        if a != target:
            w.after(25, lambda: self._fade(item, a, target, step, done))
        elif done:
            done()

    def _cancel(self, item) -> None:
        if item["after"]:
            item["win"].after_cancel(item["after"])
            item["after"] = None
        if item["win"].winfo_exists():
            item["win"].attributes("-alpha", 0.96)

    def _schedule(self, item, ms: int) -> None:
        self._cancel(item)
        item["after"] = item["win"].after(ms, lambda: self._fade(item, 0.96, 0.0, -0.08, lambda: self.close(item)))

    def close(self, item) -> None:
        if item in self.cards:
            self.cards.remove(item)
        try:
            item["win"].destroy()
        except self.tk.TclError:
            pass
        self._layout()


class Window:
    """Settings / history / approvals window; lives on the Tk thread and is reopened on demand."""

    def __init__(self, root, on_mode_change):
        import tkinter as tk
        from tkinter import ttk

        self.tk, self.ttk, self.root, self.on_mode_change = tk, ttk, root, on_mode_change
        self.win = None

    def show(self, tab: int = 0) -> None:
        if self.win is not None and self.win.winfo_exists():
            self.nb.select(tab)
            self.refresh()
            self.win.deiconify()
            self.win.lift()
            self.win.focus_force()
            return
        self.build()
        self.nb.select(tab)
        self.refresh()

    def show_event(self, e: dict) -> None:
        self.show(1)
        for iid in self.hist_tree.get_children():
            h = self.hist_events.get(iid, {})
            if h.get("ts") == e.get("ts") and h.get("secret") == e.get("secret"):
                self.hist_tree.selection_set(iid)
                self.hist_tree.see(iid)
                break

    def build(self) -> None:
        tk, ttk = self.tk, self.ttk
        t = sb.THEMES["approve"]
        self.win = w = tk.Toplevel(self.root)
        w.title("Secret broker")
        w.configure(bg=sb.BG)
        w.geometry("1180x660")
        w.minsize(780, 480)

        style = ttk.Style(w)
        style.theme_use("vista" if "vista" in style.theme_names() else style.theme_use())
        style.configure("Treeview", font=(sb.FONT, 9), rowheight=24)
        style.configure("Treeview.Heading", font=(sb.FONT, 9, "bold"))
        style.configure("TNotebook.Tab", font=(sb.FONT, 10), padding=(14, 6))

        head = tk.Frame(w, bg=t["accent"], padx=20, pady=14)
        head.pack(fill="x")
        tk.Label(head, text="", font=("Segoe MDL2 Assets", 20), bg=t["accent"], fg="white").pack(side="left", padx=(0, 14))
        txt = tk.Frame(head, bg=t["accent"])
        txt.pack(side="left")
        tk.Label(txt, text="Secret broker", font=(sb.FONT, 14, "bold"), bg=t["accent"], fg="white").pack(anchor="w")
        tk.Label(txt, text=str(sb.KDBX_PATH), font=(sb.FONT, 9), bg=t["accent"], fg=t["soft"]).pack(anchor="w")

        self.nb = nb = ttk.Notebook(w)
        nb.pack(fill="both", expand=True, padx=12, pady=12)
        nb.add(self._settings_tab(nb), text=tr("Mode"))
        nb.add(self._history_tab(nb), text=tr("History"))
        nb.add(self._approvals_tab(nb), text=tr("Standing approvals"))
        nb.add(self._popups_tab(nb), text=tr("Notifications"))
        nb.bind("<<NotebookTabChanged>>", lambda _e: self.refresh())

    def _tree(self, parent, cols: dict[str, int], select: str = "browse"):
        ttk = self.ttk
        frame = self.tk.Frame(parent, bg=sb.BG)
        tree = ttk.Treeview(frame, columns=list(cols), show="headings", selectmode=select)
        for c, width in cols.items():
            tree.heading(c, text=c)
            tree.column(c, width=width, stretch=width > 150)
        sbar = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=sbar.set)
        tree.pack(side="left", fill="both", expand=True)
        sbar.pack(side="right", fill="y")
        return frame, tree

    def _label(self, parent, text, **kw):
        return self.tk.Label(parent, text=text, font=(sb.FONT, 8, "bold"), bg=sb.BG, fg=sb.MUTED, **kw)

    def _note(self, parent, text):
        return self.tk.Label(parent, text=text, font=(sb.FONT, 9), bg=sb.BG, fg=sb.MUTED, wraplength=1000, justify="left")

    def _settings_tab(self, nb):
        tk, ttk = self.tk, self.ttk
        f = tk.Frame(nb, bg=sb.BG, padx=16, pady=14)
        self._label(f, tr("DEFAULT MODE (ALL PROJECTS)")).pack(anchor="w")
        grid = tk.Frame(f, bg=sb.BG)
        grid.pack(anchor="w", pady=(4, 2))
        self.default_var = tk.StringVar(value=sb.load_settings()["default_mode"])
        self.write_default_var = tk.StringVar(value=sb.load_settings()["write_default_mode"])
        for r, (label, var, write) in enumerate(((tr("Reading (get):"), self.default_var, False),
                                                 (tr("Saving (set):"), self.write_default_var, True))):
            tk.Label(grid, text=label, font=(sb.FONT, 10), bg=sb.BG).grid(row=r, column=0, sticky="w", padx=(0, 16), pady=1)
            for c, (mode, mlabel) in enumerate(sb.MODES.items(), start=1):
                tk.Radiobutton(grid, text=mlabel, value=mode, variable=var, font=(sb.FONT, 10), bg=sb.BG, activebackground=sb.BG,
                               command=lambda v=var, wr=write: self._set(v.get(), None, wr)).grid(row=r, column=c, sticky="w", padx=(0, 18))
        self._note(f, tr("“Notify only”: the agent reads (or saves) at once; a small notification appears in the corner of the screen and the request is logged in the history. Secrets with a standing approval (“always” / “24 hours”) are read without asking or notifying. Overwritten values stay in the entry's KeePass history.")).pack(anchor="w", pady=(4, 14))

        self._label(f, tr("PROJECTS (OVERRIDE THE DEFAULT MODE)")).pack(anchor="w")
        frame, self.proj_tree = self._tree(f, {tr("Project"): 170, tr("Path"): 400, tr("Reading"): 210, tr("Saving"): 210})
        frame.pack(fill="both", expand=True, pady=(4, 8))
        for write, label in ((False, tr("Reading:")), (True, tr("Saving:"))):
            btns = tk.Frame(f, bg=sb.BG)
            btns.pack(fill="x", pady=(0, 4))
            tk.Label(btns, text=label, font=(sb.FONT, 9), bg=sb.BG, width=12, anchor="w").pack(side="left")
            ttk.Button(btns, text=tr("Use default"), command=lambda wr=write: self._set_selected(None, wr)).pack(side="left")
            ttk.Button(btns, text=sb.MODES["prompt"], command=lambda wr=write: self._set_selected("prompt", wr)).pack(side="left", padx=6)
            ttk.Button(btns, text=sb.MODES["notify"], command=lambda wr=write: self._set_selected("notify", wr)).pack(side="left")
            if not write:
                ttk.Button(btns, text=tr("Add folder…"), command=self._add_project).pack(side="right")
        return f

    def _history_tab(self, nb):
        tk, ttk = self.tk, self.ttk
        f = tk.Frame(nb, bg=sb.BG, padx=16, pady=14)
        bar = tk.Frame(f, bg=sb.BG)
        bar.pack(fill="x", pady=(0, 6))
        self.only_notified = tk.BooleanVar(value=False)
        ttk.Checkbutton(bar, text=tr("Only without asking"), variable=self.only_notified, command=self.refresh).pack(side="left")
        ttk.Button(bar, text=tr("Refresh"), command=self.refresh).pack(side="right")
        self.mute_btn = ttk.Button(bar, text=tr("Do not notify about this secret"), command=self._toggle_selected_popup)
        self.mute_btn.pack(side="right", padx=6)
        frame, self.hist_tree = self._tree(f, {tr("Time"): 130, tr("Project"): 130, tr("Action"): 80, tr("Secret"): 210, tr("Field"): 80,
                                               tr("Decision"): 170, tr("Notification"): 115, tr("Reason"): 310})
        frame.pack(fill="both", expand=True)
        self.hist_tree.tag_configure("notified", background="#fffbeb")
        self.hist_tree.tag_configure("deny", foreground=sb.DANGER)
        self.hist_tree.bind("<<TreeviewSelect>>", lambda _e: self._update_mute_btn())
        self.hist_tree.bind("<Button-3>", self._history_menu)
        self.hist_events: dict[str, dict] = {}
        return f

    def _approvals_tab(self, nb):
        tk, ttk = self.tk, self.ttk
        f = tk.Frame(nb, bg=sb.BG, padx=16, pady=14)
        frame, self.appr_tree = self._tree(f, {tr("Project"): 180, tr("Secret"): 300, tr("Approval"): 200, tr("Path"): 300})
        frame.pack(fill="both", expand=True, pady=(0, 8))
        ttk.Button(f, text=tr("Revoke selected"), command=self._revoke).pack(anchor="e")
        return f

    def _popups_tab(self, nb):
        tk, ttk = self.tk, self.ttk
        f = tk.Frame(nb, bg=sb.BG, padx=16, pady=14)
        self._label(f, tr("SHOW A NOTIFICATION FOR")).pack(anchor="w")
        self.popup_var = tk.StringVar(value=sb.load_settings()["popup"])
        row = tk.Frame(f, bg=sb.BG)
        row.pack(anchor="w", pady=(4, 2))
        for value, label in (("all", tr("every secret, except the ones turned off below")),
                             ("selected", tr("only the secrets turned on below"))):
            tk.Radiobutton(row, text=label, value=value, variable=self.popup_var, font=(sb.FONT, 10), bg=sb.BG, activebackground=sb.BG,
                           command=lambda: (sb.set_popup(None, None, self.popup_var.get()), self.refresh())).pack(anchor="w")
        self._note(f, tr("Applies to secrets used without asking. Every use is still logged in the history. To turn a secret on or off, select it in the History tab (or right-click it there).")).pack(anchor="w", pady=(4, 14))
        self._label(f, tr("SECRETS SET BY HAND")).pack(anchor="w")
        frame, self.popup_tree = self._tree(f, {tr("Secret"): 400, tr("Notification"): 200}, select="extended")
        frame.pack(fill="both", expand=True, pady=(4, 8))
        ttk.Button(f, text=tr("Back to the default"), command=self._reset_popups).pack(anchor="e")
        return f

    def refresh(self) -> None:
        if self.win is None or not self.win.winfo_exists():
            return
        s = sb.load_settings()
        self.default_var.set(s["default_mode"])
        self.write_default_var.set(s["write_default_mode"])
        self.popup_var.set(s["popup"])

        def mode_label(own, default):
            return sb.MODES[own] if own else tr("default ({mode})", mode=sb.MODES[default].lower())

        sel = self.proj_tree.selection()
        self.proj_tree.delete(*self.proj_tree.get_children())
        for p in known_projects():
            self.proj_tree.insert("", "end", iid=p, values=(Path(p).name or p, p, mode_label(s["projects"].get(p), s["default_mode"]),
                                                            mode_label(s["write_projects"].get(p), s["write_default_mode"])))
        if sel and self.proj_tree.exists(sel[0]):
            self.proj_tree.selection_set(sel[0])

        sel = self.hist_tree.selection()
        self.hist_tree.delete(*self.hist_tree.get_children())
        self.hist_events = {}
        events = [e for e in read_audit() if e.get("secret")]
        if self.only_notified.get():
            events = [e for e in events if e.get("decision") == "notified"]
        for i, e in enumerate(reversed(events[-HISTORY_LIMIT:])):
            d = e.get("decision", "")
            iid = f"h{i}"
            self.hist_events[iid] = e
            popup = (tr("on") if sb.popup_wanted(s, e["secret"]) else tr("off")) if d == "notified" else ""
            self.hist_tree.insert("", "end", iid=iid, tags=(d,), values=(
                e.get("ts", "").replace("T", " "), Path(e.get("project", "")).name, ACTIONS.get(e.get("action"), tr("read")),
                e["secret"], _fields(e), DECISIONS.get(d, d), popup,
                " — ".join(x for x in (e.get("reason", ""), e.get("comment", "")) if x)))
        if sel and self.hist_tree.exists(sel[0]):
            self.hist_tree.selection_set(sel[0])
        self._update_mute_btn()

        self.appr_tree.delete(*self.appr_tree.get_children())
        for p, names in sorted(sb.load_approvals().items()):
            for n in names:
                self.appr_tree.insert("", "end", iid=json.dumps([p, n]), values=(Path(p).name, n, tr("always"), p))
        for p, grants in sorted(sb.load_day_approvals().items()):
            for n, t in grants.items():
                iid = json.dumps([p, n])
                if not self.appr_tree.exists(iid):
                    self.appr_tree.insert("", "end", iid=iid, values=(
                        Path(p).name, n, tr("24 hours, until {when}", when=f"{datetime.fromtimestamp(t):%d.%m %H:%M}"), p))

        self.popup_tree.delete(*self.popup_tree.get_children())
        for n, on in sorted(s["popup_secrets"].items(), key=lambda kv: kv[0].lower()):
            self.popup_tree.insert("", "end", iid=n, values=(n, tr("show") if on else tr("do not show")))

    def _selected_secret(self) -> str | None:
        sel = self.hist_tree.selection()
        return self.hist_events[sel[0]]["secret"] if sel and sel[0] in self.hist_events else None

    def _update_mute_btn(self) -> None:
        name = self._selected_secret()
        if name is None:
            self.mute_btn.configure(text=tr("Do not notify about this secret"), state="disabled")
        elif sb.popup_wanted(sb.load_settings(), name):
            self.mute_btn.configure(text=tr("Do not notify about this secret"), state="normal")
        else:
            self.mute_btn.configure(text=tr("Notify about this secret"), state="normal")

    def _toggle_selected_popup(self) -> None:
        name = self._selected_secret()
        if name is None:
            return
        on = not sb.popup_wanted(sb.load_settings(), name)
        sb.set_popup(name, on)
        sb.audit(project="*", secret=name, action="popup", popup=on, decision="ok-tray")
        self.refresh()

    def _history_menu(self, ev) -> None:
        iid = self.hist_tree.identify_row(ev.y)
        if not iid:
            return
        self.hist_tree.selection_set(iid)
        name = self._selected_secret()
        on = sb.popup_wanted(sb.load_settings(), name)
        m = self.tk.Menu(self.win, tearoff=0)
        m.add_command(label=tr("Do not notify about {name}", name=name) if on else tr("Notify about {name}", name=name),
                      command=self._toggle_selected_popup)
        m.tk_popup(ev.x_root, ev.y_root)

    def _reset_popups(self) -> None:
        for n in self.popup_tree.selection():
            sb.set_popup(n, None)
        self.refresh()

    def _set(self, mode, project, write=False) -> None:
        sb.set_mode(mode, project, write)
        sb.audit(project=project or "*", action="mode", mode=mode or "default", write=write, decision="ok-tray")
        self.on_mode_change()
        self.refresh()

    def _set_selected(self, mode, write) -> None:
        sel = self.proj_tree.selection()
        if sel:
            self._set(mode, sel[0], write)

    def _add_project(self) -> None:
        from tkinter import filedialog
        d = filedialog.askdirectory(parent=self.win, title=tr("Project folder"))
        if d:
            self._set("prompt", sb.project_root(d))

    def _revoke(self) -> None:
        sel = self.appr_tree.selection()
        if not sel:
            return
        project, name = json.loads(sel[0])
        sb.revoke(project, name)
        sb.audit(project=project, secret=name, action="revoke", decision="revoked-in-tray")
        self.refresh()


def main() -> int:
    import tkinter as tk

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    mutex = k32.CreateMutexW(None, False, sb.TRAY_MUTEX)
    if ctypes.get_last_error() == 183:  # ERROR_ALREADY_EXISTS
        return 0
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
    except (AttributeError, OSError):
        pass

    root = tk.Tk()
    root.withdraw()
    calls: queue.Queue = queue.Queue()
    icon: pystray.Icon

    def mode_title() -> str:
        s = sb.load_settings()
        return (f"Secret broker — {tr('reading')}: {sb.MODES[s['default_mode']].lower()}, "
                f"{tr('saving')}: {sb.MODES[s['write_default_mode']].lower()}")

    def icon_mode() -> str:
        s = sb.load_settings()
        return "notify" if "notify" in (s["default_mode"], s["write_default_mode"]) else "prompt"

    def refresh_icon() -> None:
        icon.icon = icon_image(icon_mode())
        icon.title = mode_title()
        icon.update_menu()

    window = Window(root, refresh_icon)
    popups = Popups(root, window.show_event)

    def set_default(mode, write=False):
        return lambda _i, _it: (sb.set_mode(mode, None, write),
                                sb.audit(project="*", action="mode", mode=mode, write=write, decision="ok-tray"),
                                refresh_icon(), calls.put(window.refresh))

    def is_default(mode, write=False):
        return lambda _it: sb.load_settings()["write_default_mode" if write else "default_mode"] == mode

    def set_cache(hours):
        def go(_i, _it):
            sb.set_cache_hours(hours)
            if not hours:
                vault_cache.request({"op": "clear"})
            sb.audit(project="*", action="cache", mode=f"{hours}h", decision="ok-tray")
            refresh_icon()
        return go

    def is_cache(hours):
        return lambda _it: sb.load_settings()["cache_hours"] == hours

    def cache_label(hours):
        return tr("Off") if not hours else tr("{hours} h", hours=hours)

    def quit_all(_i, _it):
        icon.stop()
        calls.put(root.destroy)

    menu = pystray.Menu(
        pystray.MenuItem(tr("Settings…"), lambda _i, _it: calls.put(lambda: window.show(0)), default=True),
        pystray.MenuItem(tr("History…"), lambda _i, _it: calls.put(lambda: window.show(1))),
        pystray.MenuItem(tr("Standing approvals…"), lambda _i, _it: calls.put(lambda: window.show(2))),
        pystray.MenuItem(tr("Notifications…"), lambda _i, _it: calls.put(lambda: window.show(3))),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem(tr("Reading: ask in a window"), set_default("prompt"), checked=is_default("prompt"), radio=True),
        pystray.MenuItem(tr("Reading: notify only"), set_default("notify"), checked=is_default("notify"), radio=True),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem(tr("Saving: ask in a window"), set_default("prompt", True), checked=is_default("prompt", True), radio=True),
        pystray.MenuItem(tr("Saving: notify only"), set_default("notify", True), checked=is_default("notify", True), radio=True),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem(tr("Vault cache in memory"), pystray.Menu(*[
            pystray.MenuItem(cache_label(h), set_cache(h), checked=is_cache(h), radio=True) for h in vault_cache.HOUR_CHOICES])),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem(tr("Quit"), quit_all),
    )
    icon = pystray.Icon("secret-broker", icon_image(icon_mode()), mode_title(), menu)
    icon.run_detached()

    tail = AuditTail()

    def pump():
        try:
            while not calls.empty():
                calls.get_nowait()()
            root.after(100, pump)
        except tk.TclError:
            pass

    def poll_loop():
        while True:
            time.sleep(POLL_S)
            try:
                events = tail.new_events()
                if not events:
                    continue
                s = sb.load_settings()
                for e in events:
                    if e.get("decision") == "notified" and sb.popup_wanted(s, e.get("secret", "")):
                        calls.put(lambda e=e: popups.show(e))
                calls.put(window.refresh)
            except Exception:  # noqa: BLE001 - a bad audit line must not kill the tray
                pass

    threading.Thread(target=poll_loop, daemon=True).start()
    threading.Thread(target=vault_cache.serve, daemon=True).start()
    root.after(100, pump)
    root.mainloop()
    k32.CloseHandle(mutex)
    return 0
