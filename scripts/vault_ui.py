"""Secrets window: browse, search, edit, unlock and lock the vault without a separate KeePass app. Lives on the tray's Tk thread."""

import base64
import ctypes
import time
from ctypes import wintypes
from datetime import datetime

import hello
import secret_broker as sb
import vault_cache
from secret_broker import tr

IDLE_LOCK_S = 10 * 60
CLIPBOARD_CLEAR_S = 30
TICK_MS = 3000
RESERVED = {"title", "username", "password", "url", "notes", "tags", "iconid", "times", "history", "otp"}
WDA_EXCLUDEFROMCAPTURE = 0x11

_u32 = ctypes.WinDLL("user32", use_last_error=True)
_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
for _fn, _args, _res in (
    (_u32.OpenClipboard, [wintypes.HWND], wintypes.BOOL),
    (_u32.CloseClipboard, [], wintypes.BOOL),
    (_u32.EmptyClipboard, [], wintypes.BOOL),
    (_u32.SetClipboardData, [wintypes.UINT, wintypes.HANDLE], wintypes.HANDLE),
    (_u32.RegisterClipboardFormatW, [wintypes.LPCWSTR], wintypes.UINT),
    (_u32.GetClipboardSequenceNumber, [], wintypes.DWORD),
    (_k32.GlobalAlloc, [wintypes.UINT, ctypes.c_size_t], ctypes.c_void_p),
    (_k32.GlobalLock, [ctypes.c_void_p], ctypes.c_void_p),
    (_k32.GlobalUnlock, [ctypes.c_void_p], wintypes.BOOL),
    (_k32.GlobalFree, [ctypes.c_void_p], ctypes.c_void_p),
    (_u32.GetParent, [wintypes.HWND], wintypes.HWND),
    (_u32.SetWindowDisplayAffinity, [wintypes.HWND, wintypes.DWORD], wintypes.BOOL),
):
    _fn.argtypes, _fn.restype = _args, _res


def hide_from_capture(top) -> None:
    """Screenshots, recordings and screen sharing show the window as a black box."""
    top.update_idletasks()
    _u32.SetWindowDisplayAffinity(_u32.GetParent(top.winfo_id()), WDA_EXCLUDEFROMCAPTURE)


def _put(fmt: int, data: bytes) -> bool:
    h = _k32.GlobalAlloc(0x0002, len(data))  # GMEM_MOVEABLE
    ptr = _k32.GlobalLock(h) if h else None
    if not ptr:
        if h:
            _k32.GlobalFree(h)
        return False
    ctypes.memmove(ptr, data, len(data))
    _k32.GlobalUnlock(h)
    if not _u32.SetClipboardData(fmt, h):
        _k32.GlobalFree(h)
        return False
    return True


def _open_clipboard() -> bool:
    for _ in range(20):
        if _u32.OpenClipboard(None):
            return True
        time.sleep(0.05)
    return False


def copy_secret(text: str) -> int | None:
    """Marked so Win+V history and the cloud clipboard skip it; returns the sequence number to clear it by later."""
    if not _open_clipboard():
        return None
    try:
        _u32.EmptyClipboard()
        # The markers go first: without them the value must not reach the clipboard at all.
        ok = all(_put(_u32.RegisterClipboardFormatW(fmt), data) for fmt, data in (
            ("ExcludeClipboardContentFromMonitorProcessing", b"\0"),
            ("CanIncludeInClipboardHistory", b"\0\0\0\0"),
            ("CanUploadToCloudClipboard", b"\0\0\0\0")))
        ok = ok and _put(13, (text + "\0").encode("utf-16-le"))  # CF_UNICODETEXT
        if not ok:
            _u32.EmptyClipboard()
    finally:
        _u32.CloseClipboard()
    return _u32.GetClipboardSequenceNumber() if ok else None


def clear_clipboard(seq: int | None) -> None:
    """Only if the clipboard still holds what we put there."""
    if seq is not None and _u32.GetClipboardSequenceNumber() == seq and _open_clipboard():
        try:
            _u32.EmptyClipboard()
        finally:
            _u32.CloseClipboard()


def _signature():
    try:
        st = sb.KDBX_PATH.stat()
        return st.st_mtime_ns, st.st_size
    except FileNotFoundError:
        return None


def _tk_user() -> str:
    return f"{sb.KDBX_PATH}#transformed_key"


class Busy(Exception):
    pass


class NoChange(Exception):
    pass


class Session:
    """The open vault and its password, held only while the window is unlocked."""

    def __init__(self):
        self.kp = None
        self.password = None
        self.sig = None

    @property
    def unlocked(self) -> bool:
        return self.kp is not None

    @staticmethod
    def _open(password: str):
        from pykeepass import PyKeePass
        return PyKeePass(str(sb.KDBX_PATH), password=password, keyfile=sb.KEYFILE)

    def _load(self, password: str) -> None:
        # The signature is taken before the read and must still hold after it: opening takes about a second, and a
        # signature newer than the contents would let the next write overwrite an agent's save.
        for _ in range(5):
            sig = _signature()
            kp = self._open(password)
            if _signature() == sig:
                break
        else:
            raise Busy(tr("The vault keeps changing on disk; try again."))
        self.kp, self.password, self.sig = kp, password, sig

    @staticmethod
    def remembered() -> bool:
        return sb._kr_get(str(sb.KDBX_PATH)) is not None

    @staticmethod
    def remember(kp, password: str) -> None:
        sb._kr_set(str(sb.KDBX_PATH), password)
        sb._kr_set(_tk_user(), base64.b64encode(kp.transformed_key).decode())

    def unlock(self, password: str, remember: bool) -> None:
        self._load(password)
        if remember:
            self.remember(self.kp, password)

    def unlock_remembered(self) -> bool:
        from pykeepass.exceptions import CredentialsError

        pw = sb._kr_get(str(sb.KDBX_PATH))
        if pw is None or not sb.KDBX_PATH.exists():
            return False
        try:
            self._load(pw)
        except CredentialsError:
            sb._kr_del(str(sb.KDBX_PATH))
            return False
        return True

    def create(self, password: str, remember: bool) -> None:
        from pykeepass import create_database

        sb.KDBX_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = sb.KDBX_PATH.with_name(sb.KDBX_PATH.name + ".new")
        with sb.file_lock("vault", 3):
            create_database(str(tmp), password=password, keyfile=sb.KEYFILE)
            try:
                # On Windows a rename refuses to replace: a vault that appeared meanwhile is never overwritten.
                tmp.rename(sb.KDBX_PATH)
            except FileExistsError:
                tmp.unlink()
                raise ValueError(tr("The vault already exists: {path}", path=sb.KDBX_PATH))
        self._load(password)
        if remember:
            self.remember(self.kp, password)

    def lock(self) -> None:
        self.kp = self.password = self.sig = None

    def reload_if_changed(self) -> bool:
        if self.kp is None or _signature() == self.sig:
            return False
        self._load(self.password)
        return True

    def modify(self, fn, after=None):
        """One write: under the CLI's vault lock, on the file as it is now, so an agent's save in between is never lost.

        `after(result)` runs under the same lock once the file is written: state keyed by entry name moves with the entry.
        """
        if self.password is None:
            raise Busy(tr("The vault is locked"))
        try:
            lock = sb.file_lock("vault", 3)
            lock.__enter__()
        except sb.Locked:
            raise Busy(tr("The vault is busy: a window from an agent is open. Close it and try again."))
        try:
            if _signature() != self.sig:
                self._load(self.password)
            try:
                result = fn(self.kp)
                fresh = sb.save_vault(self.kp)
            except NoChange:
                return None
            except Exception:
                self._load(self.password)
                raise
            self.kp, self.sig = fresh, _signature()
            if after is not None:
                after(result)
            return result
        finally:
            lock.__exit__(None, None, None)


def _find(kp, uid: str):
    import uuid as uuidlib
    return kp.find_entries(uuid=uuidlib.UUID(hex=uid), first=True)


def _group_path(group) -> str:
    return "/".join(p for p in (group.path or []) if p)


def _spec(entry) -> dict:
    return {
        "name": sb.entry_name(entry),
        "username": entry.username or "",
        "password": entry.password or "",
        "url": entry.url or "",
        "notes": entry.notes or "",
        "custom": [(k, v or "", entry.is_custom_property_protected(k)) for k, v in entry.custom_properties.items()],
        "no_file": sb.is_no_file(entry),
    }


def _same(a: dict, b: dict) -> bool:
    return {**a, "custom": sorted(a["custom"])} == {**b, "custom": sorted(b["custom"])}


def _sensitive_values(spec: dict) -> list[str]:
    return [v for v in [spec["password"]] + [v for _k, v, prot in spec["custom"] if prot] if v]


def _fmt_time(t) -> str:
    try:
        return t.astimezone().strftime("%Y-%m-%d %H:%M") if t else ""
    except (AttributeError, ValueError, OSError):
        return ""


def _masked(value: str) -> str:
    return "•" * min(len(value), 16) if value else ""


class SecretsWindow:
    def __init__(self, root):
        import tkinter as tk
        from tkinter import ttk

        self.tk, self.ttk, self.root = tk, ttk, root
        self.win = None
        self.session = Session()
        self.clip_seq = None
        self.clip_after = None
        self.hello_op = None
        self.last_activity = time.time()
        self.dialogs = 0
        self.modals: list = []
        self.revealed: set[str] = set()
        self.selected: str | None = None
        self.items: dict[str, tuple[str, object]] = {}
        self.scale = max(1.0, float(root.tk.call("tk", "scaling")) / (96 / 72))

    def px(self, n: int) -> int:
        return round(n * self.scale)

    # ---------- window ----------

    def show(self, by_user: bool = True) -> None:
        """`by_user` is False for `secret-broker open`: any process can send that, so it never unlocks or takes the keyboard."""
        if self.win is not None and self.win.winfo_exists():
            self.win.deiconify()
            self.win.lift()
            if by_user:
                self.win.focus_force()
            self._reload_if_changed()
            return
        self.build()
        self.render()
        if by_user and not self.session.unlocked and sb.KDBX_PATH.exists() and Session.remembered():
            self.use_remembered()
        self.win.after(TICK_MS, self._tick)

    def use_remembered(self) -> None:
        """Where Windows Hello is set up, the remembered password opens the window only after Hello confirms the person."""
        if self.hello_op is not None or self.session.unlocked:
            return
        if not hello.available():
            return self._unlock_remembered(False)
        self.hello_op = hello.request(_u32.GetParent(self.win.winfo_id()), tr("Unlock the Secrets window"))
        self.status(tr("Waiting for Windows Hello…"))
        self._hello_poll()

    def _hello_poll(self) -> None:
        op = self.hello_op
        if op is None:
            return
        if self.win is None or not self.win.winfo_exists() or self.session.unlocked:
            op.cancel()
            self.hello_op = None
            return
        result = op.poll()
        if result is None:
            self.win.after(150, self._hello_poll)
            return
        self.hello_op = None
        if result == hello.VERIFIED:
            self._unlock_remembered(True)
        else:
            self.status(tr("Windows Hello did not confirm it is you. Enter the master password."))

    def _unlock_remembered(self, confirmed: bool) -> None:
        try:
            opened = self.session.unlock_remembered()
        except Exception as e:  # noqa: BLE001 - a broken vault file must still show the window with the error
            return self.status(str(e))
        if not opened:
            return self.status(tr("The remembered password no longer opens the vault."))
        sb.audit(action="unlock", vault=str(sb.KDBX_PATH), decision="ok-tray", remembered=True, hello=confirmed)
        self.render()

    def build(self) -> None:
        tk, ttk = self.tk, self.ttk
        t = sb.THEMES["unlock"]
        self.win = w = tk.Toplevel(self.root)
        w.title(tr("Secrets — secret broker"))
        w.configure(bg=sb.BG)
        w.geometry(f"{self.px(1100)}x{self.px(680)}")
        w.minsize(self.px(760), self.px(460))
        w.protocol("WM_DELETE_WINDOW", self.close)
        hide_from_capture(w)

        style = ttk.Style(w)
        style.configure("Secrets.Treeview", font=(sb.FONT, 10), rowheight=self.px(26))
        style.configure("Secrets.Treeview.Heading", font=(sb.FONT, 9, "bold"))

        head = tk.Frame(w, bg=t["accent"], padx=self.px(20), pady=self.px(12))
        head.pack(fill="x")
        tk.Label(head, text=t["icon"], font=("Segoe MDL2 Assets", 20), bg=t["accent"], fg="white").pack(side="left", padx=(0, self.px(14)))
        txt = tk.Frame(head, bg=t["accent"])
        txt.pack(side="left")
        tk.Label(txt, text=tr("Secrets"), font=(sb.FONT, 14, "bold"), bg=t["accent"], fg="white").pack(anchor="w")
        tk.Label(txt, text=str(sb.KDBX_PATH), font=(sb.FONT, 9), bg=t["accent"], fg=t["soft"]).pack(anchor="w")
        self.lock_btn = tk.Button(head, text=tr("Lock"), command=self.lock, font=(sb.FONT, 10, "bold"),
                                  bg=t["hover"], fg="white", activebackground=t["accent"], activeforeground="white",
                                  relief="flat", bd=0, cursor="hand2", padx=self.px(14), pady=self.px(6))

        self.body = tk.Frame(w, bg=sb.BG)
        self.body.pack(fill="both", expand=True)
        self.status_var = tk.StringVar()
        bar = tk.Frame(w, bg=sb.FOOTER_BG, padx=self.px(14), pady=self.px(5))
        bar.pack(fill="x", side="bottom")
        tk.Label(bar, textvariable=self.status_var, font=(sb.FONT, 9), bg=sb.FOOTER_BG, fg=sb.MUTED, anchor="w").pack(fill="x")

        for seq in ("<Any-KeyPress>", "<Motion>", "<Button>"):
            w.bind(seq, self._touch, add="+")
        w.bind("<Control-f>", lambda _e: self._focus_search())
        w.bind("<Control-n>", lambda _e: self.session.unlocked and self.new_entry())
        w.bind("<Control-l>", lambda _e: self.lock())
        w.bind("<Control-b>", lambda _e: self._copy_selected("username"))
        w.bind("<Control-c>", self._ctrl_c)
        w.bind("<Control-e>", lambda _e: self.edit_selected())

    def close(self) -> None:
        if self.hello_op is not None:
            self.hello_op.cancel()
            self.hello_op = None
        self.lock(render=False)
        self.win.destroy()
        self.win = None

    def status(self, text: str) -> None:
        if self.win is not None and self.win.winfo_exists():
            self.status_var.set(text)

    def _touch(self, _e=None) -> None:
        self.last_activity = time.time()

    def _tick(self) -> None:
        if self.win is None or not self.win.winfo_exists():
            return
        if self.session.unlocked:
            if time.time() - self.last_activity > IDLE_LOCK_S:
                self.lock()
                self.status(tr("Locked after {m} minutes without activity.", m=IDLE_LOCK_S // 60))
            elif not self.dialogs:
                self._reload_if_changed()
        self.win.after(TICK_MS, self._tick)

    def _reload_if_changed(self) -> None:
        if self.dialogs:
            return
        try:
            if self.session.reload_if_changed():
                self.populate()
                self.status(tr("The vault changed on disk; reloaded."))
        except Exception as e:  # noqa: BLE001 - e.g. the password was changed elsewhere
            self.lock()
            self.status(str(e))

    def lock(self, render: bool = True) -> None:
        for m in list(self.modals):
            m.close()
        self.session.lock()
        self.revealed.clear()
        self.selected = None
        self.items = {}
        clear_clipboard(self.clip_seq)
        self.clip_seq = None
        if render and self.win is not None and self.win.winfo_exists():
            self.render()

    def render(self) -> None:
        for c in self.body.winfo_children():
            c.destroy()
        if self.session.unlocked:
            self.lock_btn.pack(side="right")
            self._main_view()
            self.populate()
        else:
            self.lock_btn.pack_forget()
            self._locked_view()

    # ---------- locked ----------

    def _field(self, parent, label: str, show: str = "•", width: int = 34):
        tk = self.tk
        tk.Label(parent, text=label, font=(sb.FONT, 8, "bold"), bg=sb.BG, fg=sb.MUTED).pack(anchor="w", pady=(0, self.px(2)))
        var = tk.StringVar()
        e = tk.Entry(parent, textvariable=var, show=show, width=width, font=(sb.FONT, 12), relief="flat", bg=sb.FOOTER_BG, fg=sb.FG,
                     insertbackground=sb.FG, highlightthickness=1, highlightbackground=sb.BORDER, highlightcolor=sb.THEMES["unlock"]["accent"])
        e.pack(fill="x", ipady=self.px(5), pady=(0, self.px(10)))
        return var, e

    def _primary(self, parent, text: str, command):
        t = sb.THEMES["unlock"]
        return self.tk.Button(parent, text=text, command=command, font=(sb.FONT, 10, "bold"), bg=t["accent"], fg="white",
                              activebackground=t["hover"], activeforeground="white", relief="flat", bd=0, cursor="hand2",
                              padx=self.px(18), pady=self.px(7))

    def _link(self, parent, text: str, command, fg=None):
        t = sb.THEMES["unlock"]
        return self.tk.Button(parent, text=text, command=command, font=(sb.FONT, 9), bg=sb.BG, fg=fg or t["accent"],
                              activebackground=sb.BG, activeforeground=t["hover"], relief="flat", bd=0, cursor="hand2")

    def _locked_view(self) -> None:
        tk = self.tk
        box = tk.Frame(self.body, bg=sb.BG, padx=self.px(40), pady=self.px(36))
        box.place(relx=0.5, rely=0.42, anchor="center")
        remember = tk.BooleanVar(value=True)
        error = tk.StringVar()

        if not sb.KDBX_PATH.exists():
            tk.Label(box, text=tr("There is no vault yet"), font=(sb.FONT, 16, "bold"), bg=sb.BG, fg=sb.FG).pack(anchor="w")
            tk.Label(box, text=tr("Choose a master password for the new vault."), font=(sb.FONT, 10), bg=sb.BG,
                     fg=sb.MUTED).pack(anchor="w", pady=(self.px(2), self.px(16)))
            pw1, first = self._field(box, tr("NEW MASTER PASSWORD"))
            pw2, _ = self._field(box, tr("REPEAT PASSWORD"))

            def create():
                if len(pw1.get()) < 8:
                    return error.set(tr("The password must have at least 8 characters."))
                if pw1.get() != pw2.get():
                    return error.set(tr("The passwords do not match."))
                try:
                    self.session.create(pw1.get(), remember.get())
                except (ValueError, sb.Locked) as e:
                    error.set(str(e))
                    return self.win.after(1500, self.render)
                sb.audit(action="init", vault=str(sb.KDBX_PATH), decision="ok-tray")
                self.render()

            action, label = create, tr("Create vault")
            tk.Label(box, text=tr("The password cannot be recovered. Keep a copy off this computer."), font=(sb.FONT, 8), bg=sb.BG,
                     fg=sb.MUTED).pack(anchor="w")
        else:
            tk.Label(box, text=tr("The vault is locked"), font=(sb.FONT, 16, "bold"), bg=sb.BG, fg=sb.FG).pack(anchor="w")
            tk.Label(box, text=tr("Enter the master password to see and edit your secrets."), font=(sb.FONT, 10), bg=sb.BG,
                     fg=sb.MUTED).pack(anchor="w", pady=(self.px(2), self.px(16)))
            pw, first = self._field(box, tr("MASTER PASSWORD"))

            def unlock():
                from pykeepass.exceptions import CredentialsError
                self.win.configure(cursor="watch")
                self.win.update_idletasks()
                try:
                    self.session.unlock(pw.get(), remember.get())
                except CredentialsError:
                    pw.set("")
                    return error.set(tr("Wrong password, try again."))
                except Exception as e:  # noqa: BLE001 - a damaged file is reported, not raised into Tk
                    return error.set(str(e))
                finally:
                    self.win.configure(cursor="")
                sb.audit(action="unlock", vault=str(sb.KDBX_PATH), decision="ok-tray", remember=remember.get())
                self.render()

            action, label = unlock, tr("Unlock")

        tk.Checkbutton(box, text=tr("Remember in Windows Credential Manager"), variable=remember, font=(sb.FONT, 9), bg=sb.BG, fg=sb.FG,
                       activebackground=sb.BG, selectcolor=sb.BG, bd=0, highlightthickness=0).pack(anchor="w", pady=(0, self.px(6)))
        tk.Label(box, textvariable=error, font=(sb.FONT, 9, "bold"), bg=sb.BG, fg=sb.DANGER).pack(anchor="w")
        row = tk.Frame(box, bg=sb.BG)
        row.pack(fill="x", pady=(self.px(10), 0))
        self._primary(row, label, action).pack(side="left")
        if sb.KDBX_PATH.exists() and Session.remembered():
            self._link(row, tr("Use the remembered password"), self.use_remembered).pack(side="left", padx=(self.px(14), 0))
            self._link(box, tr("Forget the remembered password"), self.forget_remembered, fg=sb.THEMES["forget"]["hover"]
                       ).pack(anchor="w", pady=(self.px(14), 0))
        first.bind("<Return>", lambda _e: action())
        first.focus_set()

    def forget_remembered(self) -> None:
        from tkinter import messagebox
        if not messagebox.askyesno(tr("Forget the vault password?"), tr(
                "The remembered master password and key will be removed from Windows Credential Manager. The broker will ask for the password the next time the vault is used."),
                parent=self.win):
            return
        sb._kr_del(str(sb.KDBX_PATH))
        sb._kr_del(_tk_user())
        vault_cache.request({"op": "clear"})
        sb.audit(action="forget", decision="ok-tray")
        self.lock()
        self.status(tr("Removed the remembered password and key from Credential Manager."))

    # ---------- unlocked ----------

    def _main_view(self) -> None:
        tk, ttk = self.tk, self.ttk
        bar = tk.Frame(self.body, bg=sb.BG, padx=self.px(14), pady=self.px(10))
        bar.pack(fill="x")
        tk.Label(bar, text="", font=("Segoe MDL2 Assets", 11), bg=sb.BG, fg=sb.MUTED).pack(side="left", padx=(0, self.px(6)))
        self.search_var = tk.StringVar()
        self.search = tk.Entry(bar, textvariable=self.search_var, width=34, font=(sb.FONT, 11), relief="flat", bg=sb.FOOTER_BG, fg=sb.FG,
                               insertbackground=sb.FG, highlightthickness=1, highlightbackground=sb.BORDER,
                               highlightcolor=sb.THEMES["unlock"]["accent"])
        self.search.pack(side="left", ipady=self.px(4))
        self.search_var.trace_add("write", lambda *_: self.populate())
        self.search.bind("<Escape>", lambda _e: self.search_var.set(""))
        self.search.bind("<Down>", lambda _e: self._focus_tree())
        self.trash_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(bar, text=tr("Recycle Bin"), variable=self.trash_var, command=self._mode_changed).pack(side="left", padx=self.px(14))
        self.actions = tk.Frame(bar, bg=sb.BG)
        self.actions.pack(side="right")

        pane = ttk.PanedWindow(self.body, orient="horizontal")
        pane.pack(fill="both", expand=True, padx=self.px(14), pady=(0, self.px(10)))
        left = tk.Frame(pane, bg=sb.BG)
        self.tree = ttk.Treeview(left, columns=("user", "url", "mtime"), style="Secrets.Treeview", selectmode="browse")
        self.tree.heading("#0", text=tr("Name"))
        self.tree.heading("user", text=tr("Username"))
        self.tree.heading("url", text="URL")
        self.tree.heading("mtime", text=tr("Modified"))
        self.tree.column("#0", width=self.px(270))
        self.tree.column("user", width=self.px(150))
        self.tree.column("url", width=self.px(150))
        self.tree.column("mtime", width=self.px(120), stretch=False)
        self.tree.tag_configure("group", font=(sb.FONT, 10, "bold"))
        self.tree.tag_configure("nofile", foreground=sb.THEMES["forget"]["hover"])
        sbar = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sbar.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sbar.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", lambda _e: self._selection_changed())
        self.tree.bind("<Double-1>", self._double_click)
        self.tree.bind("<Return>", lambda _e: self.edit_selected())
        self.tree.bind("<Delete>", lambda _e: self.delete_selected())
        self.tree.bind("<Button-3>", self._context_menu)
        pane.add(left, weight=3)

        self.detail = tk.Frame(pane, bg=sb.BG, padx=self.px(18), pady=self.px(4))
        pane.add(self.detail, weight=2)
        self._actions()
        self.search.focus_set()

    def _mode_changed(self) -> None:
        self.selected = None
        self._actions()
        self.populate()

    def _actions(self) -> None:
        ttk = self.ttk
        for c in self.actions.winfo_children():
            c.destroy()
        if self.trash_var.get():
            ttk.Button(self.actions, text=tr("Empty the Recycle Bin"), command=self.empty_trash).pack(side="right")
            ttk.Button(self.actions, text=tr("Delete permanently"), command=self.purge_selected).pack(side="right", padx=self.px(6))
            ttk.Button(self.actions, text=tr("Restore"), command=self.restore_selected).pack(side="right")
        else:
            ttk.Button(self.actions, text=tr("Delete"), command=self.delete_selected).pack(side="right")
            ttk.Button(self.actions, text=tr("Edit"), command=self.edit_selected).pack(side="right", padx=self.px(6))
            ttk.Button(self.actions, text=tr("New entry"), command=self.new_entry).pack(side="right")

    def _focus_search(self) -> None:
        if self.session.unlocked:
            self.search.focus_set()
            self.search.select_range(0, "end")

    def _focus_tree(self) -> None:
        kids = self.tree.get_children()
        if kids:
            self.tree.focus_set()
            if not self.tree.selection():
                self.tree.selection_set(kids[0])
            self.tree.focus(self.tree.selection()[0])

    def _matches(self, e, q: str) -> bool:
        hay = [sb.entry_name(e), e.username or "", e.url or "", e.notes or "", *e.tags]
        hay += [f"{k} {'' if e.is_custom_property_protected(k) else v or ''}" for k, v in e.custom_properties.items()]
        return all(any(word in h.lower() for h in hay) for word in q.split())

    def populate(self) -> None:
        kp = self.session.kp
        tree = getattr(self, "tree", None)
        if kp is None or tree is None or not tree.winfo_exists():
            return
        tree.delete(*tree.get_children())
        self.items = {}
        recycle = kp.recyclebin_group
        q = self.search_var.get().strip().lower()
        trash = self.trash_var.get()

        def add_entry(parent, e, label):
            iid = e.uuid.hex
            self.items[iid] = ("entry", e)
            tags = ("nofile",) if sb.is_no_file(e) else ()
            tree.insert(parent, "end", iid=iid, text="  " + label, tags=tags,
                        values=(e.username or "", e.url or "", _fmt_time(e.mtime)))

        if trash or q:
            pool = [e for e in kp.entries if sb.in_trash(kp, e) == trash and (not q or self._matches(e, q))]
            for e in sorted(pool, key=lambda e: sb.entry_name(e).lower()):
                add_entry("", e, (e.title or "") if trash else sb.entry_name(e))
            count = len(pool)
        else:
            count = 0

            def walk(group, parent):
                nonlocal count
                for g in sorted(group.subgroups, key=lambda g: (g.name or "").lower()):
                    if recycle is not None and g == recycle:
                        continue
                    iid = "g" + g.uuid.hex
                    self.items[iid] = ("group", g)
                    tree.insert(parent, "end", iid=iid, text="  " + (g.name or ""), open=True, tags=("group",))
                    walk(g, iid)
                for e in sorted(group.entries, key=lambda e: (e.title or "").lower()):
                    add_entry(parent, e, e.title or "")
                    count += 1

            walk(kp.root_group, "")

        if self.selected and tree.exists(self.selected):
            tree.selection_set(self.selected)
            tree.see(self.selected)
        else:
            self.selected = None
        self._render_detail()
        where = tr("in the Recycle Bin") if trash else ""
        self.status(tr("{n} entries {where}", n=count, where=where).strip() if not q else tr("{n} found", n=count))

    def _selection_changed(self) -> None:
        sel = self.tree.selection()
        new = sel[0] if sel else None
        if new != self.selected:
            self.revealed.clear()
        self.selected = new
        self._render_detail()

    def _selected_entry(self):
        kind, obj = self.items.get(self.selected or "", (None, None))
        return obj if kind == "entry" else None

    def _selected_group(self):
        kind, obj = self.items.get(self.selected or "", (None, None))
        if kind == "group":
            return obj
        return obj.group if kind == "entry" else None

    def _double_click(self, ev) -> None:
        iid = self.tree.identify_row(ev.y)
        if iid and self.items.get(iid, ("",))[0] == "entry":
            self.restore_selected() if self.trash_var.get() else self.edit_selected()
            return "break"

    # ---------- detail ----------

    def _render_detail(self) -> None:
        tk = self.tk
        d = self.detail
        for c in d.winfo_children():
            c.destroy()
        e = self._selected_entry()
        if e is None:
            g = self.items.get(self.selected or "", (None, None))[1]
            msg = tr("Group {name}", name=_group_path(g)) if g is not None else tr("Select an entry.")
            tk.Label(d, text=msg, font=(sb.FONT, 10), bg=sb.BG, fg=sb.MUTED).pack(anchor="w", pady=self.px(10))
            if g is None:
                tk.Label(d, text=tr("Ctrl+F search · Ctrl+N new · Enter edit · Ctrl+C copy password · Ctrl+B copy username · Ctrl+L lock"),
                         font=(sb.FONT, 8), bg=sb.BG, fg=sb.MUTED, wraplength=self.px(360), justify="left").pack(anchor="w")
            return

        title = tk.Frame(d, bg=sb.BG)
        title.pack(fill="x", pady=(self.px(6), 0))
        tk.Label(title, text=e.title or "", font=(sb.FONT, 15, "bold"), bg=sb.BG, fg=sb.FG).pack(side="left")
        if sb.is_no_file(e):
            warn = sb.THEMES["forget"]
            tk.Label(title, text=f" {sb.NO_FILE_TAG} ", font=(sb.FONT, 8, "bold"), bg=warn["tint"], fg=warn["hover"]).pack(side="left", padx=self.px(10))
        tk.Label(d, text=_group_path(e.group) or "/", font=(sb.FONT, 9), bg=sb.BG, fg=sb.MUTED).pack(anchor="w", pady=(0, self.px(12)))

        grid = tk.Frame(d, bg=sb.FOOTER_BG, padx=self.px(10), pady=self.px(6))
        grid.pack(fill="x")
        grid.columnconfigure(1, weight=1)
        rows = [("username", tr("Username"), e.username, False), ("password", tr("Password"), e.password, True),
                ("url", "URL", e.url, False)]
        rows += [(k, k, v, e.is_custom_property_protected(k)) for k, v in e.custom_properties.items()]
        r = 0
        for key, label, value, sensitive in rows:
            if not value:
                continue
            shown = not sensitive or key in self.revealed
            tk.Label(grid, text=label, font=(sb.FONT, 9, "bold"), bg=sb.FOOTER_BG, fg=sb.MUTED).grid(row=r, column=0, sticky="nw", pady=self.px(4))
            tk.Label(grid, text=value if shown else _masked(value), font=(sb.MONO, 10), bg=sb.FOOTER_BG, fg=sb.FG, anchor="w",
                     justify="left", wraplength=self.px(260)).grid(row=r, column=1, sticky="w", padx=self.px(10), pady=self.px(4))
            tools = tk.Frame(grid, bg=sb.FOOTER_BG)
            tools.grid(row=r, column=2, sticky="ne", pady=self.px(2))
            if sensitive:
                self._icon(tools, "" if shown else "", tr("Hide") if shown else tr("Show"),
                           lambda k=key: (self.revealed.symmetric_difference_update({k}), self._render_detail()))
            self._icon(tools, "", tr("Copy"), lambda k=key: self._copy(e, k))
            r += 1
        if not r:
            tk.Label(grid, text=tr("(no fields)"), font=(sb.FONT, 9), bg=sb.FOOTER_BG, fg=sb.MUTED).grid(row=0, column=0)

        if e.notes:
            tk.Label(d, text=tr("NOTES"), font=(sb.FONT, 8, "bold"), bg=sb.BG, fg=sb.MUTED).pack(anchor="w", pady=(self.px(12), self.px(2)))
            notes = tk.Text(d, height=min(8, e.notes.count("\n") + 1), font=(sb.FONT, 10), relief="flat", bg=sb.FOOTER_BG, fg=sb.FG,
                            wrap="word", padx=self.px(8), pady=self.px(6))
            notes.insert("1.0", e.notes)
            notes.configure(state="disabled")
            self.guard_copy(notes)
            notes.pack(fill="x")

        grants = []
        for p, names in sb.load_approvals().items():
            if sb.entry_name(e) in names:
                grants.append(f"{p}  —  {tr('always')}")
        for p, g in sb.load_day_approvals().items():
            if sb.entry_name(e) in g:
                grants.append(f"{p}  —  " + tr("24 hours, until {when}", when=f"{datetime.fromtimestamp(g[sb.entry_name(e)]):%d.%m %H:%M}"))
        if not self.trash_var.get():
            tk.Label(d, text=tr("STANDING APPROVALS"), font=(sb.FONT, 8, "bold"), bg=sb.BG, fg=sb.MUTED).pack(anchor="w", pady=(self.px(12), self.px(2)))
            tk.Label(d, text="\n".join(grants) or tr("none: the agent asks every time"), font=(sb.FONT, 9), bg=sb.BG, fg=sb.FG,
                     justify="left", wraplength=self.px(380)).pack(anchor="w")

        meta = tk.Frame(d, bg=sb.BG)
        meta.pack(fill="x", pady=(self.px(14), 0))
        tk.Label(meta, text=tr("Created {c} · modified {m}", c=_fmt_time(e.ctime), m=_fmt_time(e.mtime)), font=(sb.FONT, 8),
                 bg=sb.BG, fg=sb.MUTED).pack(side="left")
        if e.history:
            self._link(meta, tr("History ({n})…", n=len(e.history)), lambda: self.show_history(e.uuid.hex)).pack(side="right")

    def _icon(self, parent, glyph: str, tip: str, command):
        b = self.tk.Button(parent, text=glyph, command=command, font=("Segoe MDL2 Assets", 10), bg=sb.FOOTER_BG, fg=sb.MUTED,
                           activebackground=sb.BORDER, relief="flat", bd=0, cursor="hand2", padx=self.px(6), pady=self.px(2))
        b.bind("<Enter>", lambda _e: self.status(tip))
        b.pack(side="left")
        return b

    # ---------- clipboard ----------

    def _ctrl_c(self, ev):
        if isinstance(ev.widget, (self.tk.Entry, self.tk.Text)):
            return None
        self._copy_selected("password")
        return "break"

    def _copy_selected(self, key: str) -> None:
        e = self._selected_entry()
        if e is not None:
            self._copy(e, key)

    def _copy(self, e, key: str, name: str | None = None) -> None:
        name = name or sb.entry_name(e)
        value = sb.entry_value(e, key)
        if not value:
            return self.status(tr("This entry has no {field}.", field=key))
        if not self._to_clipboard(value):
            return
        sensitive = key == "password" or (key in e.custom_properties and e.is_custom_property_protected(key))
        if sensitive:
            sb.audit(project="*", action="copy", secret=name, field=key, decision="ok-tray")
        self.status(tr("Copied {field} of {name}; the clipboard clears in {s} s.", field=key, name=name, s=CLIPBOARD_CLEAR_S))

    def _to_clipboard(self, value: str) -> bool:
        seq = copy_secret(value)
        if seq is None:
            # The earlier copy keeps its timer, so it is still cleared.
            self.status(tr("The clipboard is busy; try again."))
            return False
        if self.clip_after:
            self.win.after_cancel(self.clip_after)
        self.clip_seq = seq
        self.clip_after = self.win.after(CLIPBOARD_CLEAR_S * 1000, self._clear_clipboard)
        return True

    def guard_copy(self, widget) -> None:
        """Tk's own copy would skip the history exclusion and the timed clear."""
        def copy(ev, cut=False):
            try:
                text = ev.widget.selection_get()
            except self.tk.TclError:
                return "break"
            if self._to_clipboard(text) and cut:
                ev.widget.delete("sel.first", "sel.last")
            return "break"

        widget.bind("<<Copy>>", copy)
        widget.bind("<<Cut>>", lambda ev: copy(ev, cut=True))

    def _clear_clipboard(self) -> None:
        clear_clipboard(self.clip_seq)
        self.clip_seq = self.clip_after = None
        self.status(tr("Clipboard cleared."))

    # ---------- writes ----------

    def _write(self, fn, done: str | None = None, after=None):
        """Returns fn's result, or None after showing why the write failed."""
        from tkinter import messagebox
        try:
            result = self.session.modify(fn, after)
        except (Busy, ValueError, sb.Locked) as e:
            messagebox.showwarning(tr("Secrets"), str(e), parent=self.win)
            return None
        except Exception as e:  # noqa: BLE001 - keep the window alive and say what happened
            messagebox.showerror(tr("Secrets"), f"{type(e).__name__}: {e}", parent=self.win)
            return None
        if done:
            self.status(done)
        return result

    def new_entry(self) -> None:
        if self.trash_var.get():
            self.trash_var.set(False)
            self._mode_changed()
        g = self._selected_group()
        prefix = _group_path(g) + "/" if g is not None and _group_path(g) else ""
        EntryDialog(self, None, {"name": prefix, "username": "", "password": "", "url": "", "notes": "", "custom": [], "no_file": False})

    def edit_selected(self) -> None:
        e = self._selected_entry()
        if e is None or self.trash_var.get():
            return
        EntryDialog(self, e.uuid.hex, _spec(e))

    def save_entry(self, uid: str | None, spec: dict, base: dict | None = None) -> str | None:
        """Called by the dialog; returns an error to show there, or None when saved. `base` is the entry as the dialog loaded it."""
        parts = [p.strip() for p in spec["name"].split("/") if p.strip()]
        if not parts:
            return tr("Give the entry a name, e.g. Hosting/Database.")
        name = "/".join(parts)
        # A name the dialog did not touch stays as it is, even where the vault spells it differently (spaces, a slash in a title).
        if base is not None and spec["name"] == base["name"]:
            name = base["name"]
        for k, _v, _p in spec["custom"]:
            if k.lower() in RESERVED or not sb.valid_field_name(k):
                return tr("The field name {key} has characters that are not allowed.", key=repr(k))

        def apply(kp):
            recycle = kp.recyclebin_group
            if recycle is not None and len(parts) > 1 and parts[0] == recycle.name and recycle.parentgroup == kp.root_group:
                raise ValueError(tr("“{group}” is the Recycle Bin; choose another group.", group=recycle.name))
            names = sb.vault_entries(kp)
            entry = _find(kp, uid) if uid else None
            if uid and entry is None:
                raise ValueError(tr("The entry no longer exists (deleted elsewhere?)."))
            if entry is not None and sb.in_trash(kp, entry):
                raise ValueError(tr("The entry no longer exists (deleted elsewhere?)."))
            old = _spec(entry) if entry is not None else None
            if old is not None and base is not None and not _same(old, base):
                raise ValueError(tr("The entry was changed elsewhere while this window was open. Close it and open the entry again."))
            if old is not None and _same(old, {**spec, "name": name}):
                raise NoChange
            if name in names and (entry is None or names[name].uuid != entry.uuid):
                raise ValueError(tr("Another entry is already called {name}.", name=name))
            if entry is None:
                entry = kp.add_entry(sb.ensure_group(kp, parts[:-1]), parts[-1], "", "", force_creation=True)
            else:
                entry.save_history()
                if name != old["name"]:
                    target = sb.ensure_group(kp, parts[:-1])
                    if target != entry.group:
                        kp.move_entry(entry, target)
                    entry.title = parts[-1]
            entry.username, entry.password, entry.url, entry.notes = spec["username"], spec["password"], spec["url"], spec["notes"]
            keep = {k for k, _v, _p in spec["custom"]}
            for k in list(entry.custom_properties):
                if k not in keep:
                    entry.delete_custom_property(k)
            for k, v, prot in spec["custom"]:
                entry.set_custom_property(k, v, protect=prot)
            entry.tags = [t for t in entry.tags if t and t != sb.NO_FILE_TAG] + ([sb.NO_FILE_TAG] if spec["no_file"] else [])
            entry.touch(modify=True)
            changed = [f for f in ("username", "password", "url", "notes") if old is None or old[f] != spec[f]]
            changed += sorted({k for k, _v, _p in set(spec["custom"]) ^ set(old["custom"] if old else [])})
            return {"old": old["name"] if old else None, "fields": changed, "no_file_was": bool(old and old["no_file"])}

        def state(res):
            if res["old"] is None:
                sb.drop_secret_state(name)
            elif res["old"] != name:
                sb.rename_secret_state(res["old"], name)
            if spec["no_file"]:
                with sb.state_lock():
                    sb.remember_no_file(names=sorted(set(sb.load_no_file()["names"]) | {name}))
                for v in _sensitive_values(spec):
                    sb.remember_no_file(value=(name, v))
            elif res["no_file_was"]:
                sb.forget_no_file(name)

        try:
            res = self.session.modify(apply, state)
        except (Busy, ValueError, sb.Locked) as e:
            return str(e)
        except Exception as e:  # noqa: BLE001
            return f"{type(e).__name__}: {e}"
        if res is None:
            self.status(tr("No change."))
            return None
        sb.audit(project="*", action="edit" if res["old"] else "create", secret=name, fields=res["fields"], decision="ok-tray",
                 **({"renamed_from": res["old"]} if res["old"] and res["old"] != name else {}))
        found = sb.vault_entries(self.session.kp).get(name)
        if found is not None:
            self.selected = found.uuid.hex
        self.populate()
        self.status(tr("Saved {name}.", name=name))
        return None

    def delete_selected(self) -> None:
        from tkinter import messagebox
        if self.trash_var.get():
            return self.purge_selected()
        e = self._selected_entry()
        if e is None:
            return self._delete_group()
        name, uid = sb.entry_name(e), e.uuid.hex
        if not messagebox.askyesno(tr("Delete"), tr("Move {name} to the Recycle Bin? Its approvals are revoked in every project.", name=name),
                                   parent=self.win):
            return
        if self._write(lambda kp: sb.trash_entry(kp, _find(kp, uid)) or True, tr("Moved {name} to the Recycle Bin.", name=name),
                       after=lambda _r: sb.drop_secret_state(name)):
            sb.audit(project="*", action="trash", secret=name, decision="ok-tray")
            self.populate()

    def restore_selected(self) -> None:
        e = self._selected_entry()
        if e is None:
            return
        uid = e.uuid.hex

        def apply(kp):
            entry = _find(kp, uid)
            group = sb.restore_group(kp, entry)
            name = "/".join([*[p for p in (group.path or []) if p], entry.title or ""])
            if name in sb.vault_entries(kp):
                raise ValueError(tr("Another entry is already called {name}. Rename or delete it first.", name=name))
            kp.move_entry(entry, group)
            prev = entry._element.find("PreviousParentGroup")
            if prev is not None:
                entry._element.remove(prev)
            entry.touch(modify=True)
            return name

        name = self._write(apply, after=sb.drop_secret_state)
        if name:
            sb.audit(project="*", action="restore", secret=name, decision="ok-tray")
            self.populate()
            self.status(tr("Restored {name}.", name=name))

    def purge_selected(self) -> None:
        from tkinter import messagebox
        e = self._selected_entry()
        if e is None or not self.trash_var.get():
            return
        uid, title = e.uuid.hex, e.title or ""
        if not messagebox.askyesno(tr("Delete permanently"), tr("Delete {name} permanently? This cannot be undone.", name=title),
                                   icon="warning", parent=self.win):
            return
        if self._write(lambda kp: kp.delete_entry(_find(kp, uid)) or True, tr("Deleted {name} permanently.", name=title)):
            sb.audit(project="*", action="purge", secret=title, decision="ok-tray")
            self.populate()

    def empty_trash(self) -> None:
        from tkinter import messagebox
        kp = self.session.kp
        n = sum(1 for e in kp.entries if sb.in_trash(kp, e))
        if not n:
            return self.status(tr("The Recycle Bin is empty."))
        if not messagebox.askyesno(tr("Empty the Recycle Bin"), tr("Delete all {n} entries in the Recycle Bin permanently? This cannot be undone.", n=n),
                                   icon="warning", parent=self.win):
            return
        if self._write(lambda kp: kp.empty_group(kp.recyclebin_group) or True, tr("The Recycle Bin is empty.")):
            sb.audit(project="*", action="purge", secret="*", count=n, decision="ok-tray")
            self.populate()

    def _delete_group(self) -> None:
        from tkinter import messagebox
        kind, g = self.items.get(self.selected or "", (None, None))
        if kind != "group":
            return
        if g.entries or g.subgroups:
            return self.status(tr("Only an empty group can be deleted; move or delete its entries first."))
        uid, path = g.uuid, _group_path(g)
        if messagebox.askyesno(tr("Delete"), tr("Delete the empty group {name}?", name=path), parent=self.win):
            def apply(kp):
                group = kp.find_groups(uuid=uid, first=True)
                if group is None:
                    raise NoChange
                if group.entries or group.subgroups:
                    raise ValueError(tr("Only an empty group can be deleted; move or delete its entries first."))
                kp.delete_group(group)
                return True

            if self._write(apply, tr("Deleted the group {name}.", name=path)):
                self.selected = None
                self.populate()

    def rename_group(self) -> None:
        from tkinter import simpledialog
        kind, g = self.items.get(self.selected or "", (None, None))
        if kind != "group":
            return
        uid = g.uuid
        self.dialogs += 1
        try:
            new = simpledialog.askstring(tr("Rename group"), tr("New name for {name}:", name=_group_path(g)), initialvalue=g.name or "",
                                         parent=self.win)
        finally:
            self.dialogs -= 1
        new = (new or "").strip().replace("/", "-")
        if not new or new == g.name:
            return

        def apply(kp):
            group = kp.find_groups(uuid=uid, first=True)
            if any(s.name == new for s in group.parentgroup.subgroups if s != group):
                raise ValueError(tr("A group called {name} already exists here.", name=new))
            before = {e.uuid: sb.entry_name(e) for e in kp.entries if self._under(e, group)}
            group.name = new
            return {before[e.uuid]: sb.entry_name(e) for e in kp.entries if e.uuid in before}

        def state(renames):
            for old, nn in renames.items():
                sb.rename_secret_state(old, nn)

        renames = self._write(apply, tr("Renamed the group to {name}.", name=new), after=state)
        if renames is not None:
            for old, nn in renames.items():
                sb.audit(project="*", action="edit", secret=nn, renamed_from=old, fields=[], decision="ok-tray")
            self.populate()

    @staticmethod
    def _under(e, group) -> bool:
        g = e.group
        while g is not None:
            if g == group:
                return True
            g = g.parentgroup
        return False

    def _context_menu(self, ev) -> None:
        iid = self.tree.identify_row(ev.y)
        if not iid:
            return
        self.tree.selection_set(iid)
        self._selection_changed()
        m = self.tk.Menu(self.win, tearoff=0)
        kind = self.items.get(iid, ("",))[0]
        if self.trash_var.get():
            m.add_command(label=tr("Restore"), command=self.restore_selected)
            m.add_command(label=tr("Delete permanently"), command=self.purge_selected)
        elif kind == "entry":
            e = self._selected_entry()
            m.add_command(label=tr("Copy username"), accelerator="Ctrl+B", command=lambda: self._copy(e, "username"))
            m.add_command(label=tr("Copy password"), accelerator="Ctrl+C", command=lambda: self._copy(e, "password"))
            m.add_separator()
            m.add_command(label=tr("Edit"), accelerator="Enter", command=self.edit_selected)
            if e.history:
                m.add_command(label=tr("History ({n})…", n=len(e.history)), command=lambda: self.show_history(e.uuid.hex))
            m.add_command(label=tr("Delete"), accelerator="Del", command=self.delete_selected)
        else:
            m.add_command(label=tr("New entry here"), command=self.new_entry)
            m.add_command(label=tr("Rename group…"), command=self.rename_group)
            m.add_command(label=tr("Delete group"), command=self._delete_group)
        m.tk_popup(ev.x_root, ev.y_root)

    # ---------- history ----------

    def show_history(self, uid: str) -> None:
        if _find(self.session.kp, uid) is None:
            return self.populate()
        HistoryDialog(self, uid)

    def restore_version(self, uid: str, index: int, mtime) -> str | None:
        def apply(kp):
            entry = _find(kp, uid)
            if entry is None:
                raise ValueError(tr("The entry no longer exists (deleted elsewhere?)."))
            hist = entry.history
            if index >= len(hist) or hist[index].mtime != mtime:
                raise ValueError(tr("The vault changed meanwhile; open the history again."))
            h = hist[index]
            values = {f: getattr(h, f) or "" for f in ("username", "password", "url", "notes")}
            custom = [(k, v or "", h.is_custom_property_protected(k)) for k, v in h.custom_properties.items()]
            entry.save_history()
            for f, v in values.items():
                setattr(entry, f, v)
            for k in list(entry.custom_properties):
                entry.delete_custom_property(k)
            for k, v, prot in custom:
                entry.set_custom_property(k, v, protect=prot)
            entry.touch(modify=True)
            return sb.entry_name(entry), _sensitive_values({"password": values["password"], "custom": custom}), sb.is_no_file(entry)

        try:
            name, sensitive, no_file = self.session.modify(apply)
        except (Busy, ValueError, sb.Locked) as e:
            return str(e)
        if no_file:
            for v in sensitive:
                sb.remember_no_file(value=(name, v))
        sb.audit(project="*", action="edit", secret=name, fields=["history"], decision="ok-tray")
        self.populate()
        self.status(tr("Restored an earlier version of {name}.", name=name))
        return None


class _Modal:
    def __init__(self, owner: SecretsWindow, title: str):
        tk = owner.tk
        self.owner, self.tk = owner, tk
        self.top = top = tk.Toplevel(owner.win)
        top.title(title)
        top.configure(bg=sb.BG)
        top.transient(owner.win)
        top.protocol("WM_DELETE_WINDOW", self.close)
        top.bind("<Escape>", lambda _e: self.close())
        for seq in ("<Any-KeyPress>", "<Motion>"):
            top.bind(seq, owner._touch, add="+")
        owner.dialogs += 1
        owner.modals.append(self)
        hide_from_capture(top)
        self.body = tk.Frame(top, bg=sb.BG, padx=owner.px(20), pady=owner.px(16))
        self.body.pack(fill="both", expand=True)
        tk.Frame(top, bg=sb.BORDER, height=1).pack(fill="x")
        self.footer = tk.Frame(top, bg=sb.FOOTER_BG, padx=owner.px(20), pady=owner.px(12))
        self.footer.pack(fill="x")

    def label(self, parent, text):
        return self.tk.Label(parent, text=text, font=(sb.FONT, 8, "bold"), bg=sb.BG, fg=sb.MUTED)

    def entry(self, parent, value="", show="", mono=False, width=44):
        var = self.tk.StringVar(value=value)
        e = self.tk.Entry(parent, textvariable=var, show=show, width=width, font=(sb.MONO if mono else sb.FONT, 11), relief="flat",
                          bg=sb.FOOTER_BG, fg=sb.FG, insertbackground=sb.FG, highlightthickness=1, highlightbackground=sb.BORDER,
                          highlightcolor=sb.THEMES["unlock"]["accent"])
        self.owner.guard_copy(e)
        return var, e

    def place(self):
        top = self.top
        top.update_idletasks()
        w, h = top.winfo_reqwidth(), top.winfo_reqheight()
        ow = self.owner.win
        top.geometry(f"+{ow.winfo_rootx() + max(0, (ow.winfo_width() - w) // 2)}+{ow.winfo_rooty() + max(0, (ow.winfo_height() - h) // 3)}")
        top.grab_set()
        top.focus_force()

    def close(self):
        if self in self.owner.modals:
            self.owner.modals.remove(self)
            self.owner.dialogs -= 1
            if self.top.winfo_exists():
                self.top.grab_release()
                self.top.destroy()


class EntryDialog(_Modal):
    def __init__(self, owner: SecretsWindow, uid: str | None, spec: dict):
        super().__init__(owner, tr("Edit entry") if uid else tr("New entry"))
        tk, ttk, px = self.tk, owner.ttk, owner.px
        self.uid = uid
        self.base = spec if uid else None
        b = self.body
        b.columnconfigure(1, weight=1)

        def row(r, label, widget, **grid):
            self.label(b, label).grid(row=r, column=0, sticky="nw", padx=(0, px(14)), pady=px(7))
            widget.grid(row=r, column=1, sticky="ew", pady=px(4), ipady=px(3), **grid)

        self.name, name_e = self.entry(b, spec["name"])
        row(0, tr("NAME (Group/Title)"), name_e)
        self.username, e = self.entry(b, spec["username"])
        row(1, tr("USERNAME"), e)

        pwrow = tk.Frame(b, bg=sb.BG)
        self.password, self.pw_entry = self.entry(pwrow, spec["password"], show="•", mono=True, width=36)
        self.pw_entry.pack(side="left", fill="x", expand=True, ipady=px(3))
        self.pw_shown = False
        self.eye = tk.Button(pwrow, text="", font=("Segoe MDL2 Assets", 10), command=self._toggle_pw, bg=sb.BG, fg=sb.MUTED, relief="flat",
                             bd=0, cursor="hand2", padx=px(8))
        self.eye.pack(side="left")
        owner._link(pwrow, tr("Generate"), self._generate).pack(side="left")
        self.label(b, tr("PASSWORD")).grid(row=2, column=0, sticky="nw", padx=(0, px(14)), pady=px(7))
        pwrow.grid(row=2, column=1, sticky="ew", pady=px(4))

        self.url, e = self.entry(b, spec["url"])
        row(3, "URL", e)
        self.label(b, tr("NOTES")).grid(row=4, column=0, sticky="nw", padx=(0, px(14)), pady=px(7))
        self.notes = tk.Text(b, height=4, width=44, font=(sb.FONT, 10), relief="flat", bg=sb.FOOTER_BG, fg=sb.FG, wrap="word",
                             highlightthickness=1, highlightbackground=sb.BORDER, highlightcolor=sb.THEMES["unlock"]["accent"],
                             padx=px(6), pady=px(4))
        self.notes.insert("1.0", spec["notes"])
        owner.guard_copy(self.notes)
        self.notes.grid(row=4, column=1, sticky="ew", pady=px(4))

        self.label(b, tr("OTHER FIELDS")).grid(row=5, column=0, sticky="nw", padx=(0, px(14)), pady=px(9))
        self.custom_box = tk.Frame(b, bg=sb.BG)
        self.custom_box.grid(row=5, column=1, sticky="ew", pady=px(4))
        self.custom_box.columnconfigure(1, weight=1)
        self.custom_rows: list[dict] = []
        for k, v, prot in spec["custom"]:
            self._add_custom(k, v, prot)
        self.add_btn = owner._link(b, tr("+ Add field"), lambda: self._add_custom("", "", True))
        self.add_btn.grid(row=6, column=1, sticky="w")

        self.no_file = tk.BooleanVar(value=spec["no_file"])
        tk.Checkbutton(b, text=tr("{tag}: the agent may not write this value to files", tag=sb.NO_FILE_TAG), variable=self.no_file,
                       font=(sb.FONT, 9), bg=sb.BG, fg=sb.FG, activebackground=sb.BG, selectcolor=sb.BG, bd=0,
                       highlightthickness=0).grid(row=7, column=1, sticky="w", pady=(px(10), 0))
        self.error = tk.Label(b, text="", font=(sb.FONT, 9, "bold"), bg=sb.BG, fg=sb.DANGER, wraplength=px(440), justify="left")
        self.error.grid(row=8, column=1, sticky="w", pady=(px(6), 0))

        ttk.Button(self.footer, text=tr("Cancel"), command=self.close).pack(side="right")
        owner._primary(self.footer, tr("Save"), self.save).pack(side="right", padx=px(10))
        self.top.bind("<Control-s>", lambda _e: self.save())
        self.place()
        (self.pw_entry if uid else name_e).focus_set()
        if not uid:
            name_e.icursor("end")

    def _toggle_pw(self):
        self.pw_shown = not self.pw_shown
        self.pw_entry.configure(show="" if self.pw_shown else "•")
        for r in self.custom_rows:
            if r["prot"].get():
                r["entry"].configure(show="" if self.pw_shown else "•")
        self.eye.configure(text="" if self.pw_shown else "")

    def _generate(self):
        self.password.set(sb.generate_password(32))
        if not self.pw_shown:
            self._toggle_pw()

    def _add_custom(self, key: str, value: str, protected: bool):
        tk, px = self.tk, self.owner.px
        r = len(self.custom_rows)
        kv, ke = self.entry(self.custom_box, key, width=14)
        vv, ve = self.entry(self.custom_box, value, show="•" if protected and not self.pw_shown else "", mono=True, width=24)
        prot = tk.BooleanVar(value=protected)
        item = {"key": kv, "value": vv, "prot": prot, "entry": ve, "widgets": []}

        def on_prot():
            ve.configure(show="•" if prot.get() and not self.pw_shown else "")

        cb = tk.Checkbutton(self.custom_box, text=tr("secret"), variable=prot, command=on_prot, font=(sb.FONT, 9), bg=sb.BG,
                            activebackground=sb.BG, selectcolor=sb.BG, bd=0, highlightthickness=0)
        rm = tk.Button(self.custom_box, text="", font=("Segoe MDL2 Assets", 8), bg=sb.BG, fg=sb.MUTED, relief="flat", bd=0, cursor="hand2",
                       command=lambda: self._remove_custom(item))
        ke.grid(row=r, column=0, sticky="ew", padx=(0, px(6)), pady=px(2), ipady=px(2))
        ve.grid(row=r, column=1, sticky="ew", pady=px(2), ipady=px(2))
        cb.grid(row=r, column=2, padx=px(6))
        rm.grid(row=r, column=3)
        item["widgets"] = [ke, ve, cb, rm]
        self.custom_rows.append(item)
        if not key:
            ke.focus_set()

    def _remove_custom(self, item):
        for w in item["widgets"]:
            w.destroy()
        self.custom_rows.remove(item)

    def save(self):
        custom, seen = [], set()
        for r in self.custom_rows:
            k, v = r["key"].get().strip(), r["value"].get()
            if not k and not v:
                continue
            if not k:
                return self.error.configure(text=tr("Every extra field needs a name."))
            if k.lower() in RESERVED:
                return self.error.configure(text=tr("“{key}” is a built-in field; use the field above.", key=k))
            if k in seen:
                return self.error.configure(text=tr("The field {key} appears twice.", key=k))
            seen.add(k)
            custom.append((k, v, r["prot"].get()))
        spec = {"name": self.name.get(), "username": self.username.get(), "password": self.password.get(), "url": self.url.get().strip(),
                "notes": self.notes.get("1.0", "end-1c"), "custom": custom, "no_file": self.no_file.get()}
        error = self.owner.save_entry(self.uid, spec, self.base)
        if error:
            self.error.configure(text=error)
        else:
            self.close()


class HistoryDialog(_Modal):
    def __init__(self, owner: SecretsWindow, uid: str):
        super().__init__(owner, tr("History"))
        ttk, px = owner.ttk, owner.px
        self.uid = uid
        e = _find(owner.session.kp, uid)
        self.name = sb.entry_name(e)
        self.versions = list(e.history)
        self.shown = False
        self.label(self.body, tr("EARLIER VERSIONS OF {name}", name=sb.entry_name(e))).pack(anchor="w", pady=(0, px(6)))
        self.tree = ttk.Treeview(self.body, columns=("mtime", "user", "pw", "url", "other"), show="headings", height=10,
                                 style="Secrets.Treeview", selectmode="browse")
        for c, label, w in (("mtime", tr("Saved"), 130), ("user", tr("Username"), 140), ("pw", tr("Password"), 200),
                            ("url", "URL", 160), ("other", tr("Other fields"), 160)):
            self.tree.heading(c, text=label)
            self.tree.column(c, width=px(w))
        self.tree.pack(fill="both", expand=True)
        self._fill()

        ttk.Button(self.footer, text=tr("Close"), command=self.close).pack(side="right")
        ttk.Button(self.footer, text=tr("Restore this version"), command=self._restore).pack(side="right", padx=px(10))
        ttk.Button(self.footer, text=tr("Copy password"), command=self._copy).pack(side="left")
        self.toggle = ttk.Button(self.footer, text=tr("Show passwords"), command=self._toggle)
        self.toggle.pack(side="left", padx=px(10))
        self.place()

    def _fill(self):
        self.tree.delete(*self.tree.get_children())
        for i, h in reversed(list(enumerate(self.versions))):
            pw = h.password or ""
            self.tree.insert("", "end", iid=str(i), values=(_fmt_time(h.mtime), h.username or "", pw if self.shown else _masked(pw),
                                                             h.url or "", ", ".join(h.custom_properties)))

    def _toggle(self):
        self.shown = not self.shown
        self.toggle.configure(text=tr("Hide passwords") if self.shown else tr("Show passwords"))
        sel = self.tree.selection()
        self._fill()
        if sel:
            self.tree.selection_set(sel)

    def _index(self):
        sel = self.tree.selection()
        return int(sel[0]) if sel else None

    def _copy(self):
        i = self._index()
        if i is not None:
            self.owner._copy(self.versions[i], "password", self.name)

    def _restore(self):
        from tkinter import messagebox
        i = self._index()
        if i is None:
            return
        error = self.owner.restore_version(self.uid, i, self.versions[i].mtime)
        if error:
            messagebox.showwarning(tr("History"), error, parent=self.top)
        else:
            self.close()
