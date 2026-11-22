"""End-to-end test of the Secrets window logic on a throwaway vault and state folder.

Run: <venv python> -E -s tests/test_vault_ui.py  (Windows; opens a Tk window briefly, touches the clipboard)
"""
import os, subprocess, sys, tempfile
from pathlib import Path

work = Path(tempfile.mkdtemp(prefix="sbui-"))
os.environ["SECRET_BROKER_KDBX"] = str(work / "test.kdbx")
os.environ["SECRET_BROKER_STATE"] = str(work / "state")
os.environ["SECRET_BROKER_LANG"] = os.environ.get("SECRET_BROKER_LANG", "en")
SCRIPTS = str(Path(__file__).resolve().parents[1] / "scripts")
sys.path.insert(0, SCRIPTS)

import tkinter as tk
from tkinter import messagebox
from pykeepass import PyKeePass

import secret_broker as sb
import vault_ui as ui

PW = "test-pw-123"
results = []


def check(name, cond):
    results.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name)


def disk():
    return PyKeePass(str(sb.KDBX_PATH), password=PW)


def by_name(kp, name):
    return sb.vault_entries(kp).get(name)


messagebox.askyesno = lambda *a, **k: True
warnings = []
messagebox.showwarning = lambda title, msg, **k: warnings.append(msg)
messagebox.showerror = lambda title, msg, **k: warnings.append(msg)

root = tk.Tk()
root.withdraw()
w = ui.SecretsWindow(root)
try:
    w.show()
    check("no vault: create view", not w.session.unlocked)
    w.session.create(PW, remember=False)
    w.render()
    check("created and unlocked", w.session.unlocked and sb.KDBX_PATH.exists())
    check("nothing remembered", not ui.Session.remembered())

    spec = {"name": "Hosting/DB", "username": "admin", "password": "s3cret-1", "url": "https://db", "notes": "line1\nline2",
            "custom": [("token", "tok-123", True), ("host", "db.example", False)], "no_file": True}
    check("save new entry", w.save_entry(None, spec) is None)
    e = by_name(disk(), "Hosting/DB")
    check("on disk with fields", e and e.password == "s3cret-1" and e.custom_properties == {"token": "tok-123", "host": "db.example"})
    check("protected flag kept", e.is_custom_property_protected("token") and not e.is_custom_property_protected("host"))
    check("no-file tag", sb.is_no_file(e))
    nf = sb.load_no_file()
    check("no-file state has name + 2 fingerprints", nf["names"] == ["Hosting/DB"] and len(nf["values"]) == 2)
    check("duplicate name refused", "already" in (w.save_entry(None, {**spec, "no_file": False}) or ""))

    sb.grant_always("C:/proj", "Hosting/DB")
    sb.grant_day("C:/proj2", "Hosting/DB")
    uid = e.uuid.hex
    check("rename + new password", w.save_entry(uid, {**spec, "name": "Prod/DB2", "password": "s3cret-2"}) is None)
    kp = disk()
    e = by_name(kp, "Prod/DB2")
    check("renamed and moved", e and by_name(kp, "Hosting/DB") is None and e.password == "s3cret-2")
    check("history kept", len(e.history) == 1 and e.history[0].password == "s3cret-1")
    check("always approval moved", sb.load_approvals().get("C:/proj") == ["Prod/DB2"])
    check("day approval moved", "Prod/DB2" in sb.load_day_approvals().get("C:/proj2", {}))
    check("no-file names moved", sb.load_no_file()["names"] == ["Prod/DB2"])
    check("unchanged save is a no-op", w.save_entry(uid, {**spec, "name": "Prod/DB2", "password": "s3cret-2"}) is None
          and len(by_name(disk(), "Prod/DB2").history) == 1)

    # An agent saves through the CLI path while the window holds an older copy.
    other = disk()
    other.add_entry(other.root_group, "FromAgent", "u", "agent-pw")
    sb.save_vault(other)
    check("edit after external save", w.save_entry(uid, {**spec, "name": "Prod/DB2", "password": "s3cret-3"}) is None)
    kp = disk()
    check("external entry not lost", by_name(kp, "FromAgent") is not None and by_name(kp, "Prod/DB2").password == "s3cret-3")

    check("restore version", w.restore_version(uid, 0, by_name(disk(), "Prod/DB2").history[0].mtime) is None)
    check("restored value", by_name(disk(), "Prod/DB2").password == "s3cret-1")

    w.populate()
    w.tree.selection_set(uid)
    w._selection_changed()
    check("detail renders", any(isinstance(c, tk.Label) and c.cget("text") == "DB2" for c in w.detail.winfo_children()[0].winfo_children()))
    w._copy(w._selected_entry(), "password")
    seq = w.clip_seq
    check("clipboard holds password", root.clipboard_get() == "s3cret-1")
    w._clear_clipboard()
    try:
        cleared = root.clipboard_get() != "s3cret-1"
    except tk.TclError:
        cleared = True
    check("clipboard cleared", seq is not None and cleared)
    check("copy audited", any('"action": "copy"' in ln for ln in sb.AUDIT_FILE.read_text(encoding="utf-8").splitlines()))

    w.delete_selected()
    kp = disk()
    trashed = [x for x in kp.entries if sb.in_trash(kp, x)]
    check("moved to bin", len(trashed) == 1 and trashed[0].title == "DB2")
    check("approvals dropped", "C:/proj" not in sb.load_approvals() and "Prod/DB2" not in sb.load_no_file()["names"])
    check("previous group recorded", trashed[0]._element.find("PreviousParentGroup") is not None)
    w.trash_var.set(True)
    w._mode_changed()
    w.tree.selection_set(uid)
    w._selection_changed()
    w.restore_selected()
    check("restored to its group", by_name(disk(), "Prod/DB2") is not None)

    env = {**os.environ}
    sb._kr_set(str(sb.KDBX_PATH), PW)
    try:
        r = subprocess.run([sys.executable, "-E", "-s", os.path.join(SCRIPTS, "secret_broker.py"), "list"], capture_output=True, text=True,
                           env=env, encoding="utf-8")
        check("CLI list sees the edits", "Prod/DB2" in r.stdout and "FromAgent" in r.stdout)
    finally:
        sb._kr_del(str(sb.KDBX_PATH))
        sb._kr_del(f"{sb.KDBX_PATH}#transformed_key")

    w.trash_var.set(False)
    w._mode_changed()
    w.tree.selection_set(uid)
    w._selection_changed()
    w.delete_selected()
    w.trash_var.set(True)
    w._mode_changed()
    w.empty_trash()
    kp = disk()
    check("bin emptied", not [x for x in kp.entries if sb.in_trash(kp, x)] and by_name(kp, "Prod/DB2") is None)

    holder = subprocess.Popen([sys.executable, "-E", "-s", "-c",
                               "import sys,time; sys.path.insert(0, sys.argv[1]); import secret_broker as sb\n"
                               "with sb.file_lock('vault', 5):\n    print('held', flush=True); time.sleep(6)", SCRIPTS],
                              stdout=subprocess.PIPE, text=True, env=env)
    holder.stdout.readline()
    err = w.save_entry(None, {**spec, "name": "Busy/X", "no_file": False})
    check("busy vault reported", err and "busy" in err.lower())
    holder.wait()

    w.lock()
    check("lock drops the session", not w.session.unlocked and w.session.password is None)
    w.session.unlock(PW, remember=False)
    w.render()
    check("unlock again", w.session.unlocked)
    check("no unexpected warnings", not warnings or warnings == [])
finally:
    try:
        w.lock(render=False)
        root.destroy()
    except tk.TclError:
        pass

print(f"\n{sum(ok for _n, ok in results)}/{len(results)} passed; work dir {work}")
sys.exit(0 if all(ok for _n, ok in results) else 1)
