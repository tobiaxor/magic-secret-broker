"""End-to-end test of the tray vault cache on a throwaway vault and state folder.

Run: <venv python> -E -s tests/test_vault_cache.py  (Windows; creates and removes test Credential Manager entries)
"""
import os, sys, subprocess, tempfile, threading, time
from pathlib import Path

work = Path(tempfile.mkdtemp(prefix="sbcache-"))
os.environ["SECRET_BROKER_KDBX"] = str(work / "test.kdbx")
os.environ["SECRET_BROKER_STATE"] = str(work / "state")
os.environ["SECRET_BROKER_LANG"] = "en"
SCRIPTS = str(Path(__file__).resolve().parents[1] / "scripts")
sys.path.insert(0, SCRIPTS)

from pykeepass import create_database
PW = "test-pw-123"
kp = create_database(os.environ["SECRET_BROKER_KDBX"], password=PW)
g = kp.add_group(kp.root_group, "G")
e = kp.add_entry(g, "A", "user-a", "secret-a")
e.set_custom_property("host", "h.example")
kp.add_entry(g, "B", "user-b", "secret-b", tags=["no-file"])
kp.save()

import secret_broker as sb
import vault_cache as vc
sb._kr_set(str(sb.KDBX_PATH), PW)
results = []
def check(name, cond):
    results.append((name, bool(cond))); print(("PASS " if cond else "FAIL ") + name)

try:
    threading.Thread(target=vc.serve, daemon=True).start()
    time.sleep(0.3)
    check("pipe name is per vault", "secret-broker-cache-" in vc.PIPE_NAME)
    check("off by default: no hit", vc.cached_entry("G/A") == (False, None))
    s = vc.request({"op": "status"}); check("status answers while off", s and s["hours"] == 0 and not s["loaded"])

    sb.set_cache_hours(4)
    hit, ent = vc.cached_entry("G/A")
    check("on: hit with values", hit and ent.password == "secret-a" and ent.username == "user-a" and ent.custom_properties["host"] == "h.example")
    check("entry helpers work on cached entry", sb.entry_value(ent, "host") == "h.example" and "host" in sb.entry_fields(ent) and not sb.is_no_file(ent))
    hit, entb = vc.cached_entry("G/B"); check("tags survive (no-file)", hit and sb.is_no_file(entb))
    check("missing name: hit, None", vc.cached_entry("G/nope") == (True, None))
    t = time.perf_counter(); [vc.cached_entry("G/A") for _ in range(20)]; per = (time.perf_counter() - t) / 20
    check(f"round trip fast ({per*1000:.1f} ms)", per < 0.05)

    time.sleep(0.05)
    kp2 = sb.open_vault(for_write=True); kp2.add_entry(kp2.find_groups(name="G", first=True), "C", "u", "secret-c"); kp2.save()
    hit, entc = vc.cached_entry("G/C"); check("vault change reloads", hit and entc and entc.password == "secret-c")

    # CLI end to end, notify mode in the test state so no window opens
    sb.set_mode("notify", None)
    env = dict(os.environ)
    def cli_get(name):
        t = time.perf_counter()
        r = subprocess.run([sys.executable, "-E", "-s", os.path.join(SCRIPTS, "secret_broker.py"), "get", name, "--reason", "test"],
                           capture_output=True, text=True, env=env, cwd=str(work))
        return r, time.perf_counter() - t
    r, dt_on = cli_get("G/A"); check(f"CLI get via cache ({dt_on*1000:.0f} ms)", r.returncode == 0 and r.stdout.strip() == "secret-a")
    r, _ = cli_get("G/nope"); check("CLI get missing -> exit 2", r.returncode == 2)
    sb.set_cache_hours(0); vc.request({"op": "clear"})
    r, dt_off = cli_get("G/A"); check(f"CLI get with cache off ({dt_off*1000:.0f} ms)", r.returncode == 0 and r.stdout.strip() == "secret-a")
    s = vc.request({"op": "status"}); check("off clears memory", not s["loaded"])

    sb.set_cache_hours(1); vc.cached_entry("G/A")
    c = None
    # expiry: age the snapshot through the status/lookup path
    import vault_cache
    for obj in [o for o in __import__("gc").get_objects() if isinstance(o, vault_cache.Cache)]:
        obj.loaded_at -= 2 * 3600; obj.expire(); c = obj
    check("TTL expiry drops entries", c is not None and c.entries is None)

    # Get-Acl opens the pipe, so it can land between two server instances; retry that race.
    ids = []
    for _ in range(5):
        r = subprocess.run(["pwsh", "-NoProfile", "-Command", f"(Get-Acl '{vc.PIPE_NAME}').Access | % {{ $_.IdentityReference.Value }}"],
                           capture_output=True, text=True)
        ids = [l.strip() for l in r.stdout.splitlines() if l.strip()]
        if ids:
            break
        time.sleep(0.3)
    check(f"pipe ACL only this user ({ids})", len(ids) == 1 and ids[0].lower().endswith(os.environ["USERNAME"].lower()))

    r = subprocess.run([sys.executable, "-E", "-s", os.path.join(SCRIPTS, "secret_broker.py"), "cache", "off"], capture_output=True, text=True, env=env)
    check("CLI cache off", r.returncode == 0 and sb.load_settings()["cache_hours"] == 0)
finally:
    sb._kr_del(str(sb.KDBX_PATH)); sb._kr_del(f"{sb.KDBX_PATH}#transformed_key")
    print(f"{sum(ok for _, ok in results)}/{len(results)} passed")
sys.exit(0 if all(ok for _, ok in results) else 1)
