"""Windows Hello consent prompt (fingerprint, face or PIN) through WinRT, without extra packages."""

import ctypes
import time
from ctypes import wintypes

VERIFIED = 0
_STARTED = 0
_CLASS = "Windows.Security.Credentials.UI.UserConsentVerifier"
_IID_STATICS = "AF4F3F91-564C-4DDC-B8B5-973447627C65"
_IID_INTEROP = "39E050C3-4E74-441A-8DC0-B81104DF949C"
_IID_RESULT_OP = "FD596FFD-2318-558F-9DBE-D21DF43764A5"  # IAsyncOperation<UserConsentVerificationResult>
_IID_ASYNC_INFO = "00000036-0000-0000-C000-000000000046"


class _GUID(ctypes.Structure):
    _fields_ = [("a", wintypes.DWORD), ("b", wintypes.WORD), ("c", wintypes.WORD), ("d", ctypes.c_ubyte * 8)]

    def __init__(self, text: str):
        super().__init__()
        h = text.replace("-", "")
        self.a, self.b, self.c = int(h[:8], 16), int(h[8:12], 16), int(h[12:16], 16)
        self.d = (ctypes.c_ubyte * 8)(*bytes.fromhex(h[16:]))


def _call(ptr, index: int, *args, argtypes=()):
    vtbl = ctypes.cast(ctypes.cast(ptr, ctypes.POINTER(ctypes.c_void_p))[0], ctypes.POINTER(ctypes.c_void_p))
    fn = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p, *argtypes)(vtbl[index])
    return fn(ptr, *args)


def _release(ptr) -> None:
    if ptr:
        _call(ptr, 2)


class _HString:
    def __init__(self, text: str):
        self.h = ctypes.c_void_p()
        _combase().WindowsCreateString(text, len(text), ctypes.byref(self.h))

    def __enter__(self):
        return self.h

    def __exit__(self, *_):
        _combase().WindowsDeleteString(self.h)


_dll = None


def _combase():
    global _dll
    if _dll is None:
        _dll = ctypes.WinDLL("combase")
        _dll.WindowsCreateString.argtypes = [wintypes.LPCWSTR, wintypes.UINT, ctypes.POINTER(ctypes.c_void_p)]
        _dll.WindowsDeleteString.argtypes = [ctypes.c_void_p]
        _dll.RoGetActivationFactory.argtypes = [ctypes.c_void_p, ctypes.POINTER(_GUID), ctypes.POINTER(ctypes.c_void_p)]
        _dll.RoGetActivationFactory.restype = ctypes.c_long
        _dll.RoInitialize.argtypes = [ctypes.c_int]
        _dll.RoInitialize.restype = ctypes.c_long
        _dll.RoInitialize(0)  # fails harmlessly when Tk already initialised COM on this thread
    return _dll


def _factory(iid: str):
    out = ctypes.c_void_p()
    with _HString(_CLASS) as name:
        hr = _combase().RoGetActivationFactory(name, ctypes.byref(_GUID(iid)), ctypes.byref(out))
    return out if hr >= 0 and out else None


class Operation:
    """A running prompt or query; `poll()` gives None while it runs, then the WinRT result code (-1 on failure)."""

    def __init__(self, op):
        self.op = op
        self.info = ctypes.c_void_p()
        if op and _call(op, 0, ctypes.byref(_GUID(_IID_ASYNC_INFO)), ctypes.byref(self.info),
                        argtypes=(ctypes.POINTER(_GUID), ctypes.POINTER(ctypes.c_void_p))) < 0:
            self.info = ctypes.c_void_p()
        self.result = None if self.info else -1

    def poll(self):
        if self.result is not None:
            return self.result
        status = ctypes.c_int()
        if _call(self.info, 7, ctypes.byref(status), argtypes=(ctypes.POINTER(ctypes.c_int),)) < 0:
            return self._finish(-1)
        if status.value == _STARTED:
            return None
        value = ctypes.c_int(-1)
        if status.value != 1 or _call(self.op, 8, ctypes.byref(value), argtypes=(ctypes.POINTER(ctypes.c_int),)) < 0:
            return self._finish(-1)
        return self._finish(value.value)

    def cancel(self) -> None:
        if self.result is None:
            _call(self.info, 9)
            self._finish(-1)

    def _finish(self, value: int) -> int:
        self.result = value
        _release(self.info)
        _release(self.op)
        self.info = self.op = None
        return value


def available(timeout: float = 3.0) -> bool:
    """True when this user has Hello set up (a PIN is enough)."""
    try:
        statics = _factory(_IID_STATICS)
        if not statics:
            return False
        out = ctypes.c_void_p()
        hr = _call(statics, 6, ctypes.byref(out), argtypes=(ctypes.POINTER(ctypes.c_void_p),))
        _release(statics)
        if hr < 0 or not out:
            return False
        op = Operation(out)
        end = time.time() + timeout
        while op.poll() is None and time.time() < end:
            time.sleep(0.02)
        op.cancel()
        return op.result == 0
    except OSError:
        return False


def request(hwnd: int, message: str) -> Operation:
    """Shows the system prompt over `hwnd`; poll the result."""
    try:
        interop = _factory(_IID_INTEROP)
        if not interop:
            return Operation(None)
        out = ctypes.c_void_p()
        with _HString(message) as text:
            hr = _call(interop, 6, hwnd, text, ctypes.byref(_GUID(_IID_RESULT_OP)), ctypes.byref(out),
                       argtypes=(wintypes.HWND, ctypes.c_void_p, ctypes.POINTER(_GUID), ctypes.POINTER(ctypes.c_void_p)))
        _release(interop)
        return Operation(out if hr >= 0 else None)
    except OSError:
        return Operation(None)
