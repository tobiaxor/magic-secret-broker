"""The hardened process refuses memory access from another process of the same user, but can still be ended.

Run: <venv python> -E -s tests/test_harden.py  (Windows)
"""
import ctypes, os, subprocess, sys
from ctypes import wintypes
from pathlib import Path

SCRIPTS = str(Path(__file__).resolve().parents[1] / "scripts")
k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.OpenProcess.argtypes, k32.OpenProcess.restype = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD], wintypes.HANDLE
k32.CloseHandle.argtypes = [wintypes.HANDLE]
k32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
RIGHTS = {"VM_READ": 0x0010, "VM_WRITE": 0x0020, "VM_OPERATION": 0x0008, "CREATE_THREAD": 0x0002, "DUP_HANDLE": 0x0040,
          "WRITE_DAC": 0x00040000, "WRITE_OWNER": 0x00080000, "QUERY_LIMITED": 0x1000, "TERMINATE": 0x0001}
results = []


def check(name, cond):
    results.append(bool(cond))
    print(("PASS " if cond else "FAIL ") + name)


def can_open(pid, right):
    h = k32.OpenProcess(right, False, pid)
    if h:
        k32.CloseHandle(h)
    return bool(h)


def child(harden):
    code = ("import os,sys,time; sys.path.insert(0, sys.argv[1]); import vault_cache\n"
            + ("print(os.getpid(), vault_cache.harden_process(), flush=True)\n" if harden else "print(os.getpid(), True, flush=True)\n") + "time.sleep(30)")
    p = subprocess.Popen([sys.executable, "-E", "-s", "-c", code, SCRIPTS], stdout=subprocess.PIPE, text=True)
    # A venv's python.exe is a launcher: the interpreter is its child, so the pid comes from the process itself.
    pid, said = p.stdout.readline().split()
    return p, int(pid), said


plain, pid, _ = child(False)
check("control: an unhardened process can be read", can_open(pid, RIGHTS["VM_READ"]))
k32.TerminateProcess(k32.OpenProcess(RIGHTS["TERMINATE"], False, pid), 1)
plain.kill()

p, pid, said = child(True)
check("harden_process reports success", said == "True")
for name in ("VM_READ", "VM_WRITE", "VM_OPERATION", "CREATE_THREAD", "DUP_HANDLE", "WRITE_DAC", "WRITE_OWNER"):
    check(f"{name} denied", not can_open(pid, RIGHTS[name]))
check("still visible to Task Manager", can_open(pid, RIGHTS["QUERY_LIMITED"]))
h = k32.OpenProcess(RIGHTS["TERMINATE"], False, pid)
check("can still be ended", bool(h) and k32.TerminateProcess(h, 1))
p.kill()

# Started through the venv launcher, the process must end up with no living parent that holds a handle to it.
import tempfile, time
out = Path(tempfile.mkdtemp(prefix="sbhard-")) / "pid"
code = ("import os,sys,time; sys.path.insert(0, sys.argv[1]); import vault_cache" + chr(10)
        + "if vault_cache.leave_launcher(['-c', sys.argv[3], *sys.argv[1:]]): sys.exit(0)" + chr(10)
        + "import pykeepass; vault_cache.harden_process()" + chr(10)
        + "open(sys.argv[2], 'w').write(f'{os.getpid()} {os.getppid()} {sys.prefix}')" + chr(10) + "time.sleep(30)")
subprocess.run([sys.executable, "-E", "-s", "-c", code, SCRIPTS, str(out), code], timeout=20)
for _ in range(50):
    if out.exists() and out.read_text():
        break
    time.sleep(0.1)
pid, ppid, prefix = out.read_text().split(" ", 2)
time.sleep(0.5)
k32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
hp, exit_code = k32.OpenProcess(RIGHTS["QUERY_LIMITED"], False, int(ppid)), wintypes.DWORD(259)
if hp:
    k32.GetExitCodeProcess(hp, ctypes.byref(exit_code))
check("relaunched without a living parent", not hp or exit_code.value != 259)
check("relaunched process still uses the venv", os.path.normcase(prefix) == os.path.normcase(sys.prefix))
check("relaunched process is hardened", not can_open(int(pid), RIGHTS["VM_READ"]))
k32.TerminateProcess(k32.OpenProcess(RIGHTS["TERMINATE"], False, int(pid)), 1)

print(f"\n{sum(results)}/{len(results)} passed")
sys.exit(0 if all(results) else 1)
