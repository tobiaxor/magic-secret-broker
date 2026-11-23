"""Tray side of a Hello-protected vault: the master password is stored encrypted with a Windows Hello key, the tray decrypts
it once and then opens the vault, asks for approval and saves on behalf of the CLI until the tray exits."""

import base64
import contextlib
import hashlib
import io
import json
import os

import hello
import secret_broker as sb
from secret_broker import tr

KEY_NAME = "secret-broker-" + hashlib.sha256(str(sb.KDBX_PATH).lower().encode()).hexdigest()[:16]


def _signature():
    st = sb.KDBX_PATH.stat()
    return st.st_mtime_ns, st.st_size


def _seal(key: bytes, challenge: bytes, password: str) -> str:
    from Cryptodome.Cipher import AES

    cipher = AES.new(key, AES.MODE_GCM)
    data, tag = cipher.encrypt_and_digest(password.encode("utf-8"))
    return json.dumps({"v": 1, **{k: base64.b64encode(v).decode() for k, v in
                                  (("challenge", challenge), ("nonce", cipher.nonce), ("data", data), ("tag", tag))}})


def _open(key: bytes, blob: dict) -> str | None:
    from Cryptodome.Cipher import AES

    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=base64.b64decode(blob["nonce"]))
        return cipher.decrypt_and_verify(base64.b64decode(blob["data"]), base64.b64decode(blob["tag"])).decode("utf-8")
    except (KeyError, ValueError):
        return None


class Keeper:
    def __init__(self):
        self.pump = lambda: None
        self.key = None
        self.challenge = None
        self.password = None
        self.kp = None
        self.sig = None

    @property
    def unlocked(self) -> bool:
        return self.password is not None

    def lock(self) -> None:
        self.key = self.challenge = self.password = self.kp = self.sig = None

    def _sign(self, challenge: bytes, create: bool = False) -> bytes | None:
        def pump():
            hello.raise_prompt()
            self.pump()

        signature = hello.sign(KEY_NAME, challenge, pump, create)
        return hashlib.sha256(signature).digest() if signature else None

    def unlock(self) -> bool:
        """One Hello prompt; afterwards the password stays in this process."""
        if self.unlocked:
            return True
        try:
            blob = json.loads(sb._kr_get(sb.hello_user()) or "")
            challenge = base64.b64decode(blob["challenge"])
        except (ValueError, KeyError):
            return False
        key = self._sign(challenge)
        password = _open(key, blob) if key else None
        if password is None:
            return False
        self.key, self.challenge, self.password = key, challenge, password
        return True

    def adopt(self, password: str, remember: bool) -> None:
        """The user typed the master password: as good as Hello for this session."""
        self.password, self.kp = password, None
        if remember and self.key:
            sb._kr_set(sb.hello_user(), _seal(self.key, self.challenge, password))

    def enable(self) -> str | None:
        """Moves the remembered password under a new Hello key. Returns an error text, or None when done."""
        password = sb._kr_get(str(sb.KDBX_PATH))
        if password is None:
            return tr("Unlock the vault in the Secrets window with \"Remember\" ticked first.")
        if not hello.keys_supported():
            return tr("Windows Hello is not set up on this computer.")
        challenge = os.urandom(32)
        key = self._sign(challenge, create=True)
        # The stored password is deleted only once a second prompt gave the same key again.
        if not key or self._sign(challenge) != key:
            hello.delete_key(KEY_NAME)
            return tr("Windows Hello did not confirm it is you; nothing was changed.")
        blob = _seal(key, challenge, password)
        if _open(key, json.loads(blob)) != password:
            return tr("Windows Hello did not confirm it is you; nothing was changed.")
        sb._kr_set(sb.hello_user(), blob)
        sb._kr_del(str(sb.KDBX_PATH))
        sb._kr_del(f"{sb.KDBX_PATH}#transformed_key")
        self.key, self.challenge, self.password, self.kp = key, challenge, password, None
        sb.audit(action="hello", decision="ok-tray", mode="on")
        return None

    def disable(self) -> str | None:
        if not self.unlock():
            return tr("Windows Hello did not confirm it is you; nothing was changed.")
        sb._kr_set(str(sb.KDBX_PATH), self.password)
        sb._kr_del(sb.hello_user())
        hello.delete_key(KEY_NAME)
        self.lock()
        sb.audit(action="hello", decision="ok-tray", mode="off")
        return None

    def forget(self) -> None:
        sb._kr_del(sb.hello_user())
        hello.delete_key(KEY_NAME)
        self.lock()

    def vault(self, for_write: bool = False):
        """sb.VAULT_PROVIDER: a write gets its own freshly read copy, so a refused or failed save never dirties the shared one."""
        from pykeepass import PyKeePass
        from pykeepass.exceptions import CredentialsError

        if not self.unlock():
            raise sb.Locked(tr("Windows Hello did not confirm it is you; the vault stays locked."))
        sig = _signature()
        if for_write or self.kp is None or sig != self.sig:
            try:
                kp = PyKeePass(str(sb.KDBX_PATH), password=self.password, keyfile=sb.KEYFILE)
            except CredentialsError:
                self.lock()
                raise sb.Locked(tr("The remembered password no longer opens the vault."))
            if for_write:
                self.kp = None
                return kp
            self.kp, self.sig = kp, sig
        return self.kp


KEEPER = Keeper()


def run_command(req: dict) -> dict:
    """One CLI command on behalf of a pipe client; must run on the Tk thread, one at a time."""
    out, err = io.StringIO(), io.StringIO()
    code = sb.EXIT_LOCKED
    try:
        argv = [str(a) for a in req["argv"]]
        sb.REMOTE = {"cwd": str(req["cwd"]), "tty": bool(req.get("tty")), "stdout_file": req.get("stdout_file") or None,
                     "stdin": base64.b64decode(req.get("stdin") or "")}
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            args = sb.build_parser().parse_args(argv)
            if args.cmd in sb.FORWARDED:
                code = sb.run(args)
                if not sb.protected():
                    KEEPER.lock()
    except SystemExit as e:
        code = e.code if isinstance(e.code, int) else sb.EXIT_NOT_FOUND
    except Exception as e:  # noqa: BLE001 - the client gets an exit code, the tray keeps running
        err.write(f"{type(e).__name__}: {e}\n")
    finally:
        sb.REMOTE = None
    return {"ok": True, "code": code, "out": out.getvalue(), "err": err.getvalue()}
