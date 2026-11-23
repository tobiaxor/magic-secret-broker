"""Windows Hello consent prompt (fingerprint, face or PIN) through WinRT, without extra packages."""

import ctypes
import time
from ctypes import wintypes

VERIFIED = 0
_STARTED = 0
KEY_OK = 0
_CLASS = "Windows.Security.Credentials.UI.UserConsentVerifier"
_KEY_CLASS = "Windows.Security.Credentials.KeyCredentialManager"
_BUFFER_CLASS = "Windows.Security.Cryptography.CryptographicBuffer"
_IID_KEY_STATICS = "6AAC468B-0EF1-4CE0-8290-4106DA6A63B5"
_IID_BUFFER_STATICS = "320B7E22-3CB0-4CDF-8663-1D28910065EB"
_PP = ctypes.POINTER(ctypes.c_void_p)
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


def _factory(iid: str, cls: str = _CLASS):
    out = ctypes.c_void_p()
    with _HString(cls) as name:
        hr = _combase().RoGetActivationFactory(name, ctypes.byref(_GUID(iid)), ctypes.byref(out))
    return out if hr >= 0 and out else None


class Operation:
    """A running prompt or query; `poll()` gives None while it runs, then the WinRT result (-1 on failure)."""

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
        # An enum, a bool or an interface pointer, depending on the operation.
        value = ctypes.c_void_p(0)
        if status.value != 1 or _call(self.op, 8, ctypes.byref(value), argtypes=(_PP,)) < 0:
            return self._finish(-1)
        return self._finish(value.value or 0)

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


def _await(op: Operation, pump) -> int:
    while op.poll() is None:
        pump()
        time.sleep(0.03)
    return op.result


def raise_prompt() -> None:
    """A key prompt has no owner window and can open behind everything else."""
    u32 = ctypes.windll.user32
    u32.FindWindowW.restype = wintypes.HWND
    hwnd = u32.FindWindowW("Credential Dialog Xaml Host", None)
    if hwnd:
        u32.SetForegroundWindow(wintypes.HWND(hwnd))


def keys_supported() -> bool:
    try:
        statics = _factory(_IID_KEY_STATICS, _KEY_CLASS)
        if not statics:
            return False
        out = ctypes.c_void_p()
        hr = _call(statics, 6, ctypes.byref(out), argtypes=(_PP,))
        _release(statics)
        return hr >= 0 and _await(Operation(out), lambda: None) == 1
    except OSError:
        return False


def _status(result) -> int:
    status = ctypes.c_int(-1)
    _call(result, 7, ctypes.byref(status), argtypes=(ctypes.POINTER(ctypes.c_int),))
    return status.value


def _key(name: str, create: bool, pump):
    statics = _factory(_IID_KEY_STATICS, _KEY_CLASS)
    if not statics:
        return None
    out = ctypes.c_void_p()
    with _HString(name) as h:
        if create:  # option 0 replaces an existing key
            hr = _call(statics, 8, h, 0, ctypes.byref(out), argtypes=(ctypes.c_void_p, ctypes.c_int, _PP))
        else:
            hr = _call(statics, 9, h, ctypes.byref(out), argtypes=(ctypes.c_void_p, _PP))
    _release(statics)
    result = _await(Operation(out), pump) if hr >= 0 and out else -1
    if result in (-1, 0):
        return None
    cred = ctypes.c_void_p()
    if _status(result) == KEY_OK:
        _call(result, 6, ctypes.byref(cred), argtypes=(_PP,))
    _release(result)
    return cred if cred else None


def sign(name: str, data: bytes, pump, create: bool = False) -> bytes | None:
    """Signs `data` with this user's Hello key `name`; every call asks for the fingerprint, face or PIN.
    `pump()` runs while the prompt is open. None when the user cancels or the key is missing."""
    try:
        cred = _key(name, create, pump)
        buffers = _factory(_IID_BUFFER_STATICS, _BUFFER_CLASS) if cred else None
        if not buffers:
            _release(cred)
            return None
        raw = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
        buf, out = ctypes.c_void_p(), ctypes.c_void_p()
        _call(buffers, 9, len(data), raw, ctypes.byref(buf), argtypes=(wintypes.UINT, ctypes.c_void_p, _PP))
        hr = _call(cred, 9, buf, ctypes.byref(out), argtypes=(ctypes.c_void_p, _PP)) if buf else -1
        _release(buf)
        _release(cred)
        result = _await(Operation(out), pump) if hr >= 0 and out else -1
        signature = None
        if result not in (-1, 0):
            sig_buf = ctypes.c_void_p()
            if _status(result) == KEY_OK:
                _call(result, 6, ctypes.byref(sig_buf), argtypes=(_PP,))
            _release(result)
            if sig_buf:
                size, ptr = wintypes.UINT(), ctypes.c_void_p()
                _call(buffers, 10, sig_buf, ctypes.byref(size), ctypes.byref(ptr), argtypes=(ctypes.c_void_p, ctypes.POINTER(wintypes.UINT), _PP))
                if ptr:
                    signature = ctypes.string_at(ptr.value, size.value)
                    ctypes.windll.ole32.CoTaskMemFree(ptr)
                _release(sig_buf)
        _release(buffers)
        return signature or None
    except OSError:
        return None


def delete_key(name: str) -> None:
    try:
        statics = _factory(_IID_KEY_STATICS, _KEY_CLASS)
        if not statics:
            return
        out = ctypes.c_void_p()
        with _HString(name) as h:
            hr = _call(statics, 10, h, ctypes.byref(out), argtypes=(ctypes.c_void_p, _PP))
        _release(statics)
        if hr >= 0 and out:
            _await(Operation(out), lambda: None)
    except OSError:
        pass
