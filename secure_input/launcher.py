"""Parent-side API (docs/protocol.md 6, 9).

    handle = start_request(spec, static_dir=None, serve=None, python=sys.executable)
    handle.url, handle.request_id
    outcome = handle.wait(timeout=None, heartbeat=None)   # Outcome(status, meta, code)
    handle.cancel()
    sweep_stale(hermes_root) -> int

One child server process per request. The launcher keeps an active-request record at
``<requester profile home>/secure-input/active/<request_id>.json`` (0600) and, however the child
ends, runs ``serve ... off`` for the token once more and deletes the record.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional, Sequence

from .audit import AuditLog
from .config import (CANCEL_MARGIN_S, KIND_STORES, MAX_ACTIVE_REQUESTS, OPEN_TTL_S, READY_TIMEOUT_S, STORE_TIMEOUT_S,
                     SUBMIT_TTL_S)
from .profiles import ProfileError, all_profile_homes, resolve_profile_home
from .serve import ServeError, ServeManager
from .spec import RequestSpec
from .storage import hermes_agent_dir

log = logging.getLogger(__name__)

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_STATIC_DIR = Path(__file__).resolve().parent / "static"
STALE_AFTER_S = OPEN_TTL_S + SUBMIT_TTL_S + 120
HEARTBEAT_INTERVAL_S = 5.0
STDERR_KEEP = 64 * 1024


class TooManyActive(RuntimeError):
    pass


class StartError(RuntimeError):
    pass


@dataclass
class Outcome:
    status: str  # saved | delivered | expired | cancelled | failed
    meta: dict = field(default_factory=dict)
    code: Optional[str] = field(default=None, repr=False)  # otp_code only

    def __repr__(self) -> str:
        return f"Outcome(status={self.status!r}, meta={self.meta!r}, code={'<set>' if self.code else None})"


def cancel_grace_s(kind: str) -> float:
    """How long the parent waits after closing the child's stdin before SIGTERM (plan appendix A.1): the sum of
    ``STORE_TIMEOUT_S`` over the stores the kind can use, plus ``CANCEL_MARGIN_S`` (api_key 35, login 35, secret 25,
    otp_code 5 seconds), so a save in progress can finish and be reported."""
    return float(sum(STORE_TIMEOUT_S[s] for s in KIND_STORES[kind]) + CANCEL_MARGIN_S)


def new_token() -> str:
    return secrets.token_urlsafe(32)


def _pid_alive(pid) -> bool:
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return False
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _write_private_json(path: Path, data: dict) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, json.dumps(data).encode("utf-8"))
    finally:
        os.close(fd)
    os.replace(tmp, path)


def _active_dirs(hermes_root) -> list[Path]:
    try:
        return [h / "secure-input" / "active" for h in all_profile_homes(hermes_root)]
    except ProfileError:
        return []


def _iter_active(hermes_root):
    for d in _active_dirs(hermes_root):
        if not d.is_dir():
            continue
        for p in sorted(d.glob("*.json")):
            try:
                data = json.loads(p.read_text())
                if not isinstance(data, dict):
                    raise ValueError
            except (OSError, ValueError):
                data = None
            yield p, data


def sweep_stale(hermes_root, serve: Optional[ServeManager] = None) -> int:
    """Remove Serve paths and records of requests whose server process is gone (or far too old)."""
    serve = serve or ServeManager()
    removed = 0
    now = time.time()
    for path, data in _iter_active(hermes_root):
        if data is not None:
            alive = _pid_alive(data.get("pid"))
            too_old = now - float(data.get("created_at") or 0) > STALE_AFTER_S
            if alive and not too_old:
                continue
            token = data.get("token")
            if isinstance(token, str):
                try:
                    serve.remove(token)
                except ServeError:
                    pass
        try:
            path.unlink()
        except FileNotFoundError:
            continue
        removed += 1
    return removed


def count_active(hermes_root) -> int:
    return sum(1 for _p, d in _iter_active(hermes_root) if d is not None and _pid_alive(d.get("pid")))


class RequestHandle:
    def __init__(self, spec: RequestSpec, proc: subprocess.Popen, token: str, request_id: str, public_host: str,
                 active_file: Path, serve: ServeManager):
        self.spec = spec
        self._proc = proc
        self._token = token
        self.request_id = request_id
        self.url = f"https://{public_host}/{token}/"
        self.port: Optional[int] = None
        self.pid = proc.pid
        self._active_file = active_file
        self._serve = serve
        self._audit = AuditLog(spec, token, request_id)
        self.events: list[dict] = []  # parsed stdout events, ``code`` removed
        self._stderr = bytearray()
        self._ready = threading.Event()
        self._finished = threading.Event()
        self._finalize_lock = threading.Lock()
        self._outcome: Optional[Outcome] = None
        self._done_seen = False
        self.returncode: Optional[int] = None
        threading.Thread(target=self._read_stderr, daemon=True).start()
        threading.Thread(target=self._read_stdout, daemon=True).start()

    def __repr__(self) -> str:
        return f"RequestHandle(request_id={self.request_id}, pid={self.pid})"

    @property
    def local_url(self) -> str:
        """Loopback address of this request's page (tests, diagnostics)."""
        return f"http://127.0.0.1:{self.port}/{self._token}/"

    @property
    def stderr_text(self) -> str:
        return self._stderr.decode("utf-8", "replace")

    # -- child I/O ----------------------------------------------------------------------
    def _read_stderr(self) -> None:
        for chunk in iter(lambda: self._proc.stderr.read1(4096) if self._proc.stderr else b"", b""):
            self._stderr += chunk
            if len(self._stderr) > STDERR_KEEP:
                del self._stderr[: len(self._stderr) - STDERR_KEEP]

    def _read_stdout(self) -> None:
        assert self._proc.stdout is not None
        for raw in self._proc.stdout:
            try:
                ev = json.loads(raw)
            except ValueError:
                continue
            finally:
                raw = b""
            if not isinstance(ev, dict):
                continue
            code = ev.pop("code", None)
            self.events.append(ev)
            if ev.get("event") == "ready":
                self.port = int(ev["port"])
                self._update_active(port=self.port)
                self._ready.set()
            elif ev.get("event") == "done":
                self._done_seen = True
                status = str(ev.get("status") or "failed")
                self._outcome = Outcome(status=status, meta=dict(ev.get("meta") or {}),
                                        code=code if status == "delivered" else None)
            code = None
        self.returncode = self._proc.wait()
        self._finalize()

    def _update_active(self, **fields) -> None:
        try:
            data = json.loads(self._active_file.read_text())
            data.update(fields)
            _write_private_json(self._active_file, data)
        except (OSError, ValueError):
            pass

    def _finalize(self) -> None:
        with self._finalize_lock:
            if self._finished.is_set():
                return
            removed = False
            try:
                removed = self._serve.remove(self._token)
            except ServeError:
                pass
            try:
                self._active_file.unlink()
            except FileNotFoundError:
                pass
            if self._outcome is None:
                self._outcome = Outcome(status="failed", meta={
                    "request_id": self.request_id, "kind": self.spec.kind, "label": self.spec.label,
                    "target_profile": self.spec.target_profile, "reason": "child_exited",
                    "returncode": self.returncode})
                self._audit.write("failed", detail={"reason": "child_exited", "returncode": self.returncode})
            self._audit.write("cleanup", detail={"by": "launcher", "serve_removed": removed})
            log.info("secure-input request %s ended: %s", self.request_id, self._outcome.status)
            self._ready.set()
            self._finished.set()
            for s in (self._proc.stdin,):
                try:
                    if s:
                        s.close()
                except OSError:
                    pass

    # -- public API ------------------------------------------------------------------------
    @property
    def done(self) -> bool:
        return self._finished.is_set()

    def wait(self, timeout: Optional[float] = None, heartbeat: Optional[Callable[[], None]] = None) -> Outcome:
        """Block until the request ends. Raises ``TimeoutError`` if ``timeout`` passes first
        (the request keeps running; call again or ``cancel()``)."""
        deadline = None if timeout is None else time.monotonic() + timeout
        while not self._finished.is_set():
            slice_s = HEARTBEAT_INTERVAL_S
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("secure-input request still open")
                slice_s = min(slice_s, remaining)
            if self._finished.wait(slice_s):
                break
            if heartbeat is not None:
                heartbeat()
        assert self._outcome is not None
        return self._outcome

    def cancel(self, grace: Optional[float] = None) -> Outcome:
        """Ask the child to stop (stdin EOF); escalate to SIGTERM/SIGKILL if it does not. ``grace`` ``None`` = the
        kind's wait after a cancel (:func:`cancel_grace_s`): a save in progress ends first and is reported."""
        if grace is None:
            grace = cancel_grace_s(self.spec.kind)
        if not self._finished.is_set():
            try:
                if self._proc.stdin:
                    self._proc.stdin.close()
            except OSError:
                pass
            if not self._finished.wait(grace):
                self._proc.terminate()
                if not self._finished.wait(3.0):
                    self._proc.kill()
                    self._finished.wait(5.0)
        if not self._finished.is_set():  # pragma: no cover - reader thread stuck
            self.returncode = self._proc.poll()
            self._finalize()
        assert self._outcome is not None
        return self._outcome


def start_request(spec: RequestSpec, *, static_dir=None, serve: Optional[ServeManager] = None,
                  python: str = sys.executable, _test_ttls: Optional[dict] = None,
                  allowed_logins: Optional[Sequence[str]] = None,
                  allow_no_identity_header: bool = False) -> RequestHandle:
    """``allowed_logins``: Tailscale accounts that may use the link (``Tailscale-User-Login``). ``None`` means
    only this Mac's Tailscale owner (``serve.owner_login()``; failure is :class:`StartError`). The plugin
    always passes the list it computed. ``allow_no_identity_header`` is for tests that talk to 127.0.0.1."""
    if not isinstance(spec, RequestSpec):
        raise TypeError("spec must be a RequestSpec")
    if allowed_logins is not None and (isinstance(allowed_logins, str)
                                       or not all(isinstance(x, str) for x in allowed_logins)):
        raise TypeError("allowed_logins must be a list of strings")
    static = Path(static_dir) if static_dir is not None else DEFAULT_STATIC_DIR
    if not (static / "index.html").is_file():
        raise StartError("static_dir has no index.html (build the UI first)")
    serve = serve or ServeManager()
    root = spec.hermes_root
    requester_home = resolve_profile_home(spec.requester["profile"], root)
    resolve_profile_home(spec.target_profile, root)

    sweep_stale(root, serve=serve)
    if count_active(root) >= MAX_ACTIVE_REQUESTS:
        raise TooManyActive(f"at most {MAX_ACTIVE_REQUESTS} secure-input requests may be open at once")

    try:
        host = serve.dns_name()
        logins = [serve.owner_login()] if allowed_logins is None else list(allowed_logins)
    except ServeError as exc:
        raise StartError(str(exc)) from None

    token = new_token()
    request_id = uuid.uuid4().hex
    active_file = requester_home / "secure-input" / "active" / f"{request_id}.json"

    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    # The server rebuilds the RequestSpec, whose env-name check imports hermes_cli.config: put Hermes'
    # source folder on its path (with -P the plugin folder alone does not reach it).
    agent_dir = hermes_agent_dir()
    env["PYTHONPATH"] = os.pathsep.join([str(PLUGIN_ROOT)] + ([str(agent_dir)] if agent_dir else [])
                                        + ([env["PYTHONPATH"]] if env.get("PYTHONPATH") else []))
    env["PYTHONUNBUFFERED"] = "1"
    proc = subprocess.Popen([python, "-P", "-m", "secure_input.server"], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, cwd=str(PLUGIN_ROOT))
    try:
        _write_private_json(active_file, {"request_id": request_id, "token": token, "pid": proc.pid, "port": None,
                                          "created_at": time.time()})
    except OSError as exc:
        proc.kill()
        proc.wait()
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            if stream:
                stream.close()
        raise StartError(f"could not write active record ({type(exc).__name__})") from None
    cfg = {"spec": spec.to_dict(), "token": token, "request_id": request_id, "static_dir": str(static.resolve()),
           "public_host": host, "tailscale_bin": serve.bin, "parent_pid": os.getpid(),
           "active_file": str(active_file), "python": python,
           "allowed_logins": logins, "allow_no_identity_header": allow_no_identity_header is True}
    if _test_ttls:
        cfg["ttls"] = dict(_test_ttls)
    handle = RequestHandle(spec, proc, token, request_id, host, active_file, serve)
    try:
        assert proc.stdin is not None
        proc.stdin.write((json.dumps(cfg) + "\n").encode("utf-8"))
        proc.stdin.flush()
    except (OSError, ValueError):
        pass
    cfg = {}
    if not handle._ready.wait(READY_TIMEOUT_S) or handle.port is None:
        outcome = handle.cancel(grace=1.0)
        reason = outcome.meta.get("reason") or outcome.status
        raise StartError(f"secure-input server did not start ({reason})")
    return handle
