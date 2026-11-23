"""The Hello-protected vault on a throwaway vault, with the Windows Hello key and the dialogs faked.

Run: <venv python> -E -s tests/test_keeper.py  (Windows; writes test entries to Credential Manager and removes them)
"""
import contextlib, hashlib, hmac, io, os, sys, tempfile, threading
from pathlib import Path

work = Path(tempfile.mkdtemp(prefix="sbkeep-"))
os.environ["SECRET_BROKER_KDBX"] = str(work / "test.kdbx")
os.environ["SECRET_BROKER_STATE"] = str(work / "state")
os.environ["SECRET_BROKER_LANG"] = "en"
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from pykeepass import create_database

import keeper
import secret_broker as sb
import vault_cache

PW = "keeper-pw-1"
results = []
prompts = []
hello_ok = True


def check(name, cond):
    results.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name)


def fake_sign(name, data, pump, create=False):
    prompts.append(create)
    return hmac.new(b"device-key", data, hashlib.sha256).digest() if hello_ok else None


keeper.hello.sign = fake_sign
keeper.hello.keys_supported = lambda: True
keeper.hello.delete_key = lambda name: None
keeper.hello.raise_prompt = lambda: None
USERS = (str(sb.KDBX_PATH), f"{sb.KDBX_PATH}#transformed_key", sb.hello_user())


def run(k, argv, stdin=b"", stdout_file=None):
    sb.VAULT_PROVIDER = k.vault
    keeper.KEEPER = k
    import base64
    return keeper.run_command({"argv": argv, "cwd": str(work), "tty": False, "stdout_file": stdout_file,
                               "stdin": base64.b64encode(stdin).decode()})


try:
    kp = create_database(str(sb.KDBX_PATH), password=PW)
    kp.add_entry(kp.root_group, "Api", "user", "value-1")
    kp.save()

    k = keeper.Keeper()
    check("nothing remembered: refuses to turn on", k.enable() and not sb.protected())
    sb._kr_set(USERS[0], PW)
    sb._kr_set(USERS[1], "stale")
    check("turned on", k.enable() is None and sb.protected())
    check("asked for a second signature before deleting", prompts == [True, False])
    check("plain password and key removed", sb._kr_get(USERS[0]) is None and sb._kr_get(USERS[1]) is None)
    check("stored blob does not hold the password", PW not in sb._kr_get(USERS[2]))

    prompts.clear()
    k = keeper.Keeper()
    sb.dialog_approve = lambda *a, **kw: ("once", "")
    r = run(k, ["get", "Api", "--reason", "test"])
    check("get through the tray", r["code"] == 0 and r["out"] == "value-1")
    r = run(k, ["list"])
    check("list through the tray", r["code"] == 0 and "Api" in r["out"])
    check("one Hello prompt for the whole session", prompts == [False])

    sb.dialog_approve = lambda *a, **kw: ("deny", "use the other one")
    r = run(k, ["get", "Api"])
    check("refusal and comment reach the client", r["code"] == sb.EXIT_DENIED and "use the other one" in r["err"] and not r["out"])

    sb.dialog_store = lambda *a, **kw: (True, "", {"no_file": True, "always": False})
    r = run(k, ["set", "Group/New", "--stdin"], stdin=b"value-2\n")
    check("set through the tray", r["code"] == 0)
    sb.dialog_approve = lambda *a, **kw: ("once", "")
    r = run(k, ["get", "Group/New"])
    check("the shared copy follows the save", r["out"] == "value-2")
    r = run(k, ["get", "Group/New"], stdout_file=str(Path.home() / "nofile-out.txt"))
    check("no-file redirect refused from the client's stdout", r["code"] == sb.EXIT_FORBIDDEN and not r["out"])
    r = run(k, ["get"])
    check("bad arguments give an exit code, not a crash", r["code"] == 2 and sb.REMOTE is None)

    check("cache pipe gives no entry while protected", vault_cache.Cache().lookup("Api") == {"ok": False, "reason": "off"})

    hello_ok = False
    r = run(keeper.Keeper(), ["get", "Api"])
    check("Hello cancelled: locked", r["code"] == sb.EXIT_LOCKED and not r["out"])
    hello_ok = True

    k = keeper.Keeper()
    stop = threading.Event()
    threading.Thread(target=vault_cache.serve, kwargs={"stop": stop, "on_run": lambda req: run(k, req["argv"])}, daemon=True).start()
    sb.VAULT_PROVIDER = None
    sb.ensure_tray = lambda *a: True
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = sb.main(["get", "Api", "--reason", "pipe"])
    check("CLI forwards to the pipe", code == 0 and out.getvalue() == "value-1")

    k = keeper.Keeper()
    check("turned off", k.disable() is None and not sb.protected() and sb._kr_get(USERS[0]) == PW)
finally:
    for u in USERS:
        sb._kr_del(u)

print(f"\n{sum(ok for _n, ok in results)}/{len(results)} passed; work dir {work}")
sys.exit(0 if all(ok for _n, ok in results) else 1)
