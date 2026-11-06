"""In-memory vault cache, served by the tray over a named pipe that only the current Windows user can open."""

import ctypes
import hashlib
import json
import os
import threading
import time
import types
from ctypes import wintypes

import secret_broker as sb

PIPE_NAME = r"\\.\pipe\secret-broker-cache-" + hashlib.sha256(
    f"{os.environ.get('USERNAME', '')}|{str(sb.KDBX_PATH).lower()}".encode()).hexdigest()[:16]
HOUR_CHOICES = (0, 1, 4, 8)
MAX_MSG = 1 << 20
CLIENT_TIMEOUT_MS = 1500

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_adv = ctypes.WinDLL("advapi32", use_last_error=True)
_H, _D, _P, _B = wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, wintypes.BOOL
for _fn, _args, _res in (
    (_k32.GetCurrentProcess, [], _H),
    (_k32.CloseHandle, [_H], _B),
    (_k32.LocalFree, [_P], _P),
    (_k32.CreateNamedPipeW, [wintypes.LPCWSTR, _D, _D, _D, _D, _D, _D, _P], _H),
    (_k32.ConnectNamedPipe, [_H, _P], _B),
    (_k32.DisconnectNamedPipe, [_H], _B),
    (_k32.ReadFile, [_H, _P, _D, ctypes.POINTER(_D), _P], _B),
    (_k32.WriteFile, [_H, _P, _D, ctypes.POINTER(_D), _P], _B),
    (_k32.FlushFileBuffers, [_H], _B),
    (_k32.WaitNamedPipeW, [wintypes.LPCWSTR, _D], _B),
    (_adv.OpenProcessToken, [_H, _D, ctypes.POINTER(_H)], _B),
    (_adv.GetTokenInformation, [_H, ctypes.c_int, _P, _D, ctypes.POINTER(_D)], _B),
    (_adv.ConvertSidToStringSidW, [_P, ctypes.POINTER(wintypes.LPWSTR)], _B),
    (_adv.ConvertStringSecurityDescriptorToSecurityDescriptorW, [wintypes.LPCWSTR, _D, ctypes.POINTER(_P), _P], _B),
):
    _fn.argtypes, _fn.restype = _args, _res

PIPE_ACCESS_DUPLEX = 0x3
FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000
PIPE_TYPE_MESSAGE = 0x4
PIPE_READMODE_MESSAGE = 0x2
PIPE_REJECT_REMOTE_CLIENTS = 0x8
ERROR_PIPE_CONNECTED = 535
INVALID_HANDLE = ctypes.c_void_p(-1).value


class _SA(ctypes.Structure):
    _fields_ = [("nLength", wintypes.DWORD), ("lpSecurityDescriptor", ctypes.c_void_p), ("bInheritHandle", wintypes.BOOL)]


def _user_sid() -> str:
    token = wintypes.HANDLE()
    if not _adv.OpenProcessToken(_k32.GetCurrentProcess(), 0x0008, ctypes.byref(token)):  # TOKEN_QUERY
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        size = wintypes.DWORD()
        _adv.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))  # TokenUser
        buf = ctypes.create_string_buffer(size.value)
        if not _adv.GetTokenInformation(token, 1, buf, size, ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        psid = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0]
        out = wintypes.LPWSTR()
        if not _adv.ConvertSidToStringSidW(psid, ctypes.byref(out)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return out.value
        finally:
            _k32.LocalFree(ctypes.cast(out, ctypes.c_void_p))
    finally:
        _k32.CloseHandle(token)


def _user_only_sa() -> _SA:
    # The default pipe DACL grants read to Everyone; this one is protected and names only this user.
    sd = ctypes.c_void_p()
    if not _adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(f"D:P(A;;GA;;;{_user_sid()})", 1, ctypes.byref(sd), None):
        raise ctypes.WinError(ctypes.get_last_error())
    return _SA(ctypes.sizeof(_SA), sd, False)


def cache_hours() -> float:
    return sb.load_settings().get("cache_hours", 0)


def _vault_signature():
    st = sb.KDBX_PATH.stat()
    return st.st_mtime_ns, st.st_size


def _snapshot(kp) -> dict:
    out = {}
    for name, e in sb.vault_entries(kp).items():
        out[name] = {
            **{attr: getattr(e, attr) for attr in sb.STANDARD_FIELDS.values()},
            "custom_properties": dict(e.custom_properties),
            "tags": list(e.tags or []),
        }
    return out


class Cache:
    def __init__(self):
        self.lock = threading.Lock()
        self.entries: dict | None = None
        self.loaded_at = 0.0
        self.signature = None

    def clear(self) -> None:
        with self.lock:
            self.entries = None
            self.signature = None

    def expire(self) -> None:
        hours = cache_hours()
        with self.lock:
            if self.entries is not None and (not hours or time.time() - self.loaded_at > hours * 3600):
                self.entries = None
                self.signature = None

    def lookup(self, name: str) -> dict:
        hours = cache_hours()
        if not hours:
            self.clear()
            return {"ok": False, "reason": "off"}
        with self.lock:
            sig = _vault_signature()
            stale = self.entries is None or sig != self.signature or time.time() - self.loaded_at > hours * 3600
            if stale:
                try:
                    kp = sb.open_vault(interactive=False)
                except sb.Locked as e:
                    self.entries = None
                    return {"ok": False, "reason": "locked", "detail": str(e)}
                self.entries = _snapshot(kp)
                self.loaded_at = time.time()
                self.signature = sig
            entry = self.entries.get(name)
            return {"ok": True, "found": entry is not None, "entry": entry, "loaded_at": self.loaded_at}

    def status(self) -> dict:
        with self.lock:
            return {"ok": True, "hours": cache_hours(), "loaded": self.entries is not None,
                    "loaded_at": self.loaded_at if self.entries is not None else None,
                    "entries": len(self.entries) if self.entries is not None else 0}


def _handle(cache: Cache, raw: bytes) -> dict:
    try:
        req = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {"ok": False, "reason": "bad request"}
    op = req.get("op")
    if op == "entry" and isinstance(req.get("name"), str):
        return cache.lookup(req["name"])
    if op == "status":
        return cache.status()
    if op == "clear":
        cache.clear()
        return {"ok": True}
    return {"ok": False, "reason": "bad request"}


def serve(stop: threading.Event | None = None) -> None:
    """Blocking server loop; the tray runs it in a daemon thread."""
    cache = Cache()
    sa = _user_only_sa()

    def expiry_loop():
        while not (stop and stop.is_set()):
            time.sleep(30)
            cache.expire()

    threading.Thread(target=expiry_loop, daemon=True).start()
    first = True
    while not (stop and stop.is_set()):
        flags = PIPE_ACCESS_DUPLEX | (FILE_FLAG_FIRST_PIPE_INSTANCE if first else 0)
        h = _k32.CreateNamedPipeW(PIPE_NAME, flags, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_REJECT_REMOTE_CLIENTS,
                                  255, MAX_MSG, MAX_MSG, 0, ctypes.byref(sa))
        if h == INVALID_HANDLE:
            # Another process already owns the name (a second tray, or a squatter): serve nothing.
            return
        first = False
        try:
            if not _k32.ConnectNamedPipe(h, None) and ctypes.get_last_error() != ERROR_PIPE_CONNECTED:
                continue
            buf = ctypes.create_string_buffer(MAX_MSG)
            got = wintypes.DWORD()
            if not _k32.ReadFile(h, ctypes.cast(buf, ctypes.c_void_p), MAX_MSG, ctypes.byref(got), None):
                continue
            try:
                resp = _handle(cache, buf.raw[:got.value])
            except Exception as e:  # noqa: BLE001 - one bad request must not stop the server
                resp = {"ok": False, "reason": "error", "detail": type(e).__name__}
            data = json.dumps(resp, ensure_ascii=False).encode("utf-8")
            written = wintypes.DWORD()
            _k32.WriteFile(h, ctypes.cast(ctypes.c_char_p(data), ctypes.c_void_p), len(data), ctypes.byref(written), None)
            _k32.FlushFileBuffers(h)
        finally:
            _k32.DisconnectNamedPipe(h)
            _k32.CloseHandle(h)


def request(payload: dict) -> dict | None:
    """One round trip; None when no cache server answers (the caller then opens the vault itself)."""
    if not _k32.WaitNamedPipeW(PIPE_NAME, CLIENT_TIMEOUT_MS):
        return None
    try:
        with open(PIPE_NAME, "r+b", buffering=0) as f:
            f.write(json.dumps(payload).encode("utf-8"))
            chunks = []
            while True:
                try:
                    chunk = f.read(MAX_MSG)
                except OSError:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
        return json.loads(b"".join(chunks).decode("utf-8"))
    except (OSError, ValueError):
        return None


def cached_entry(name: str):
    """(hit, entry): hit=False means ask the vault directly; entry is None when the cache knows the name is absent."""
    resp = request({"op": "entry", "name": name})
    if not resp or not resp.get("ok"):
        return False, None
    e = resp.get("entry")
    return True, (types.SimpleNamespace(**e) if e is not None else None)
