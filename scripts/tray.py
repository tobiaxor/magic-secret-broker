"""Tray icon for secret-broker: notifications for secrets released without a window, mode settings, history, approvals."""

import ctypes
import json
import queue
import threading
import time
from datetime import datetime
from pathlib import Path

import pystray
from PIL import Image, ImageDraw

import secret_broker as sb
from secret_broker import tr

POLL_S = 1.0
# The tray is often started by the very `get` that must be announced, so look back a little at startup.
STARTUP_LOOKBACK_S = 30
HISTORY_LIMIT = 500

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


def icon_image(mode: str) -> Image.Image:
    accent = "#d97706" if mode == "notify" else sb.THEMES["approve"]["accent"]
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
    names = set(s["projects"]) | set(sb.load_approvals()) | set(sb.load_day_approvals())
    names |= {e["project"] for e in read_audit() if e.get("project")}
    return sorted(names, key=str.lower)


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

    def build(self) -> None:
        tk, ttk = self.tk, self.ttk
        t = sb.THEMES["approve"]
        self.win = w = tk.Toplevel(self.root)
        w.title("Secret broker")
        w.configure(bg=sb.BG)
        w.geometry("1120x620")
        w.minsize(760, 460)

        style = ttk.Style(w)
        style.theme_use("vista" if "vista" in style.theme_names() else style.theme_use())
        style.configure("Treeview", font=(sb.FONT, 9), rowheight=24)
        style.configure("Treeview.Heading", font=(sb.FONT, 9, "bold"))
        style.configure("TNotebook.Tab", font=(sb.FONT, 10), padding=(14, 6))

        head = tk.Frame(w, bg=t["accent"], padx=20, pady=14)
        head.pack(fill="x")
        tk.Label(head, text="", font=("Segoe MDL2 Assets", 20), bg=t["accent"], fg="white").pack(side="left", padx=(0, 14))
        txt = tk.Frame(head, bg=t["accent"])
        txt.pack(side="left")
        tk.Label(txt, text="Secret broker", font=(sb.FONT, 14, "bold"), bg=t["accent"], fg="white").pack(anchor="w")
        tk.Label(txt, text=str(sb.KDBX_PATH), font=(sb.FONT, 9), bg=t["accent"], fg=t["soft"]).pack(anchor="w")

        self.nb = nb = ttk.Notebook(w)
        nb.pack(fill="both", expand=True, padx=12, pady=12)
        nb.add(self._settings_tab(nb), text=tr("Mode"))
        nb.add(self._history_tab(nb), text=tr("History"))
        nb.add(self._approvals_tab(nb), text=tr("Standing approvals"))
        nb.bind("<<NotebookTabChanged>>", lambda _e: self.refresh())

    def _tree(self, parent, cols: dict[str, int]):
        ttk = self.ttk
        frame = self.tk.Frame(parent, bg=sb.BG)
        tree = ttk.Treeview(frame, columns=list(cols), show="headings", selectmode="browse")
        for c, width in cols.items():
            tree.heading(c, text=c)
            tree.column(c, width=width, stretch=width > 150)
        sbar = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=sbar.set)
        tree.pack(side="left", fill="both", expand=True)
        sbar.pack(side="right", fill="y")
        return frame, tree

    def _settings_tab(self, nb):
        tk, ttk = self.tk, self.ttk
        f = tk.Frame(nb, bg=sb.BG, padx=16, pady=14)
        tk.Label(f, text=tr("SECRETS WITHOUT A STANDING APPROVAL — DEFAULT MODE (ALL PROJECTS)"), font=(sb.FONT, 8, "bold"), bg=sb.BG,
                 fg=sb.MUTED).pack(anchor="w")
        self.default_var = tk.StringVar(value=sb.load_settings()["default_mode"])
        row = tk.Frame(f, bg=sb.BG)
        row.pack(anchor="w", pady=(4, 2))
        for mode, label in sb.MODES.items():
            tk.Radiobutton(row, text=label, value=mode, variable=self.default_var, font=(sb.FONT, 10), bg=sb.BG,
                           activebackground=sb.BG, command=lambda: self._set(self.default_var.get(), None)).pack(side="left", padx=(0, 18))
        tk.Label(f, text=tr("“Notify only”: the agent gets the value at once; a notification appears in the corner of the screen and the request is logged in the history. Secrets with a standing approval (“always” / “24 hours”) never ask and never notify."),
                 font=(sb.FONT, 9), bg=sb.BG, fg=sb.MUTED, wraplength=860, justify="left").pack(anchor="w", pady=(0, 14))

        tk.Label(f, text=tr("PROJECTS (OVERRIDE THE DEFAULT MODE)"), font=(sb.FONT, 8, "bold"), bg=sb.BG, fg=sb.MUTED).pack(anchor="w")
        frame, self.proj_tree = self._tree(f, {tr("Project"): 180, tr("Path"): 420, tr("Mode"): 230})
        frame.pack(fill="both", expand=True, pady=(4, 8))
        btns = tk.Frame(f, bg=sb.BG)
        btns.pack(fill="x")
        ttk.Button(btns, text=tr("Use default"), command=lambda: self._set_selected(None)).pack(side="left")
        ttk.Button(btns, text=sb.MODES["prompt"], command=lambda: self._set_selected("prompt")).pack(side="left", padx=6)
        ttk.Button(btns, text=sb.MODES["notify"], command=lambda: self._set_selected("notify")).pack(side="left")
        ttk.Button(btns, text=tr("Add folder…"), command=self._add_project).pack(side="right")
        return f

    def _history_tab(self, nb):
        tk, ttk = self.tk, self.ttk
        f = tk.Frame(nb, bg=sb.BG, padx=16, pady=14)
        bar = tk.Frame(f, bg=sb.BG)
        bar.pack(fill="x", pady=(0, 6))
        self.only_notified = tk.BooleanVar(value=False)
        ttk.Checkbutton(bar, text=tr("Only fetched without asking"), variable=self.only_notified, command=self.refresh).pack(side="left")
        ttk.Button(bar, text=tr("Refresh"), command=self.refresh).pack(side="right")
        frame, self.hist_tree = self._tree(f, {tr("Time"): 130, tr("Project"): 150, tr("Secret"): 220, tr("Field"): 70, tr("Decision"): 180, tr("Reason"): 360})
        frame.pack(fill="both", expand=True)
        self.hist_tree.tag_configure("notified", background="#fffbeb")
        self.hist_tree.tag_configure("deny", foreground=sb.DANGER)
        return f

    def _approvals_tab(self, nb):
        tk, ttk = self.tk, self.ttk
        f = tk.Frame(nb, bg=sb.BG, padx=16, pady=14)
        frame, self.appr_tree = self._tree(f, {tr("Project"): 180, tr("Secret"): 300, tr("Approval"): 200, tr("Path"): 300})
        frame.pack(fill="both", expand=True, pady=(0, 8))
        ttk.Button(f, text=tr("Revoke selected"), command=self._revoke).pack(anchor="e")
        return f

    def refresh(self) -> None:
        if self.win is None or not self.win.winfo_exists():
            return
        s = sb.load_settings()
        self.default_var.set(s["default_mode"])
        self.proj_tree.delete(*self.proj_tree.get_children())
        for p in known_projects():
            own = s["projects"].get(p)
            label = sb.MODES[own] if own else tr("default ({mode})", mode=sb.MODES[s['default_mode']].lower())
            self.proj_tree.insert("", "end", iid=p, values=(Path(p).name or p, p, label))

        self.hist_tree.delete(*self.hist_tree.get_children())
        events = [e for e in read_audit() if e.get("secret")]
        if self.only_notified.get():
            events = [e for e in events if e.get("decision") == "notified"]
        for e in reversed(events[-HISTORY_LIMIT:]):
            d = e.get("decision", "")
            when = e.get("ts", "").replace("T", " ")
            self.hist_tree.insert("", "end", tags=(d,), values=(
                when, Path(e.get("project", "")).name, e["secret"], e.get("field", ""), DECISIONS.get(d, d),
                " — ".join(x for x in (e.get("reason", ""), e.get("comment", "")) if x)))

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

    def _set(self, mode, project) -> None:
        sb.set_mode(mode, project)
        sb.audit(project=project or "*", action="mode", mode=mode or "default", decision="ok-tray")
        self.on_mode_change()
        self.refresh()

    def _set_selected(self, mode) -> None:
        sel = self.proj_tree.selection()
        if sel:
            self._set(mode, sel[0])

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


def notification_text(e: dict) -> tuple[str, str]:
    title = tr("The agent fetched a secret: {name}", name=e.get('secret', '?'))
    lines = [tr("Project: {project}  ·  field: {field}", project=Path(e.get('project', '')).name, field=e.get('field', 'password'))]
    if e.get("reason"):
        lines.append(e["reason"])
    return title, "\n".join(lines)[:250]


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
        return f"Secret broker — {sb.MODES[sb.load_settings()['default_mode']].lower()}"

    def refresh_icon() -> None:
        icon.icon = icon_image(sb.load_settings()["default_mode"])
        icon.title = mode_title()
        icon.update_menu()

    window = Window(root, refresh_icon)

    def set_default(mode):
        return lambda _i, _it: (sb.set_mode(mode, None), sb.audit(project="*", action="mode", mode=mode, decision="ok-tray"),
                                refresh_icon(), calls.put(window.refresh))

    def is_default(mode):
        return lambda _it: sb.load_settings()["default_mode"] == mode

    def quit_all(_i, _it):
        icon.stop()
        calls.put(root.destroy)

    menu = pystray.Menu(
        pystray.MenuItem(tr("Settings…"), lambda _i, _it: calls.put(lambda: window.show(0)), default=True),
        pystray.MenuItem(tr("History…"), lambda _i, _it: calls.put(lambda: window.show(1))),
        pystray.MenuItem(tr("Standing approvals…"), lambda _i, _it: calls.put(lambda: window.show(2))),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem(tr("Default: ask in a window"), set_default("prompt"), checked=is_default("prompt"), radio=True),
        pystray.MenuItem(tr("Default: notify only"), set_default("notify"), checked=is_default("notify"), radio=True),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem(tr("Quit"), quit_all),
    )
    icon = pystray.Icon("secret-broker", icon_image(sb.load_settings()["default_mode"]), mode_title(), menu)
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
                for e in tail.new_events():
                    if e.get("decision") == "notified":
                        title, body = notification_text(e)
                        icon.notify(body, title)
                        calls.put(window.refresh)
            except Exception:  # noqa: BLE001 - a bad audit line must not kill the tray
                pass

    threading.Thread(target=poll_loop, daemon=True).start()
    root.after(100, pump)
    root.mainloop()
    k32.CloseHandle(mutex)
    return 0
