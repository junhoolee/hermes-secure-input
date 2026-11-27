"""The storage process (plan 5.1-5.2, appendix A.9).

The server process calls :func:`run_storage`, which starts ``python -m secure_input.storage`` in a new process
group with ``HERMES_HOME=<target profile home>`` and passes the request on stdin only (never argv or
environment). The grandchild answers with JSON lines on stdout, none of them with a value, a value's length or a
login id:

- one ``{"event": "preflight", "store", "available", "reason", "exists"}`` line per store (``preflight``:
  writes nothing),
- for ``phase: "save"`` when every store is usable: one ``{"event": "store", <store result row>}`` line per
  store, written in ``STORE_NAMES`` order and flushed at once,
- a last ``{"event": "done", "ok", "error"?}`` line. Exit code 0 (done), 2 (``masked_value`` or
  ``store_unavailable``: nothing written), 3 (``internal_error``).

The store modules live in :mod:`secure_input.stores` (A.10). The keychain module gets exactly the five keys
``service``, ``account``, ``listed``, ``request_id``, ``value`` (``value`` only for ``phase: "save"``).
"""

from __future__ import annotations

import contextlib
import importlib.util
import json
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Optional

from . import stores as store_modules
from .config import KIND_STORES, PREFLIGHT_AT_CREATE_TIMEOUT_S, STORE_NAMES, STORE_TIMEOUT_S
from .stores.base import make_row

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
SAVE_KINDS = ("api_key", "login", "secret")
KILL_GRACE_S = 1.0  # appendix A.9: SIGTERM to the group, SIGKILL one second later


def _emit(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def _masked_value_check():
    """Hermes' ``refuse_redacted_env_value`` (raises ``ValueError`` for a masked-looking credential value),
    or ``None`` when it cannot be imported."""
    with contextlib.redirect_stdout(sys.stderr):
        try:
            from hermes_cli.config import refuse_redacted_env_value
        except Exception:  # health: allow BLE001
            try:
                from hermes_cli.config_credential_values import refuse_redacted_env_value
            except Exception:  # health: allow BLE001
                return None
    return refuse_redacted_env_value


def hermes_agent_dir() -> Optional[Path]:
    """Folder containing Hermes' ``agent/vault_store.py`` (needed on the grandchild's path)."""
    env = os.environ.get("SECURE_INPUT_HERMES_AGENT_DIR", "").strip()
    if env:
        return Path(env)
    try:
        spec = importlib.util.find_spec("agent")
    except (ImportError, ValueError):
        spec = None
    for loc in (spec.submodule_search_locations or []) if spec else []:
        cand = Path(loc).parent
        if (cand / "agent" / "vault_store.py").exists():
            return cand
    return None


# --- grandchild side ------------------------------------------------------------------------------------------

def store_request(store: str, req: dict) -> dict:
    """The dict one store module sees (A.10): only that store's fields, the value only for ``phase: "save"``."""
    save = req.get("phase") == "save"
    if store == "env":
        out = {"env_var": req.get("env_var")}
        if save:
            out["value"] = req.get("value")
        return out
    if store == "hermes_vault":
        out = {"label": req.get("label"), "origin": req.get("origin")}
        if save:
            out.update({k: req.get(k, "") for k in ("identifier_type", "identifier", "password", "otp_secret")})
        return out
    kc = req.get("keychain") if isinstance(req.get("keychain"), dict) else {}
    out = {"service": kc.get("service"), "account": kc.get("account"), "listed": kc.get("listed") is True,
           "request_id": req.get("request_id")}
    if save:
        out["value"] = req.get("value")
    return out


def store_ident(store: str, req: dict) -> dict:
    """The naming fields of a store's result row, known before the store answers (A.8)."""
    if store == "env":
        return {"env_var": req.get("env_var")}
    if store == "hermes_vault":
        return {"origin": req.get("origin")}
    kc = req.get("keychain") if isinstance(req.get("keychain"), dict) else {}
    return {"service": kc.get("service"), "account": kc.get("account"), "listed": kc.get("listed") is True}


def _preflight_line(mod, request: dict) -> dict:
    try:
        res = mod.preflight(request)
    except Exception:  # health: allow BLE001 - the reason word only (A.4 internal_error)
        res = None
    if not isinstance(res, dict):
        return {"available": False, "reason": "internal_error", "exists": None}
    available = res.get("available") is True
    reason = None if available else (res.get("reason") if isinstance(res.get("reason"), str) else "internal_error")
    exists = res.get("exists") if res.get("exists") in (True, False) else None
    return {"available": available, "reason": reason, "exists": exists}


def _run(req: dict) -> int:
    phase, kind, chosen = req.get("phase"), req.get("kind"), req.get("stores")
    if (phase not in ("preflight", "save") or not isinstance(chosen, list) or not chosen
            or any(s not in STORE_NAMES for s in chosen) or len(set(chosen)) != len(chosen)):
        raise ValueError("malformed storage request")
    order = [s for s in STORE_NAMES if s in chosen]
    if kind not in SAVE_KINDS or any(s not in KIND_STORES[kind] for s in order):
        for s in order:
            _emit({"event": "preflight", "store": s, "available": False, "reason": "unsupported_kind", "exists": None})
        _emit({"event": "done", "ok": False, "error": "store_unavailable"})
        return 2
    if phase == "save" and kind == "api_key" and req.get("masked_check") is not True:
        refuse = _masked_value_check()
        if refuse is not None:
            try:
                with contextlib.redirect_stdout(sys.stderr):
                    refuse(req.get("env_var"), req.get("value"))
            except ValueError:
                _emit({"event": "done", "ok": False, "error": "masked_value"})
                return 2
            except Exception:  # health: allow BLE001 - pre-check only; Hermes' writer checks again
                pass
    start_ppid = os.getppid()
    modules: dict = {}
    usable = True
    for s in order:
        try:
            modules[s] = store_modules.load(s)
        except Exception:  # health: allow BLE001 - e.g. the keychain module is not installed
            line = {"available": False, "reason": "internal_error", "exists": None}
        else:
            line = _preflight_line(modules[s], store_request(s, req))
        _emit({"event": "preflight", "store": s, **line})
        usable = usable and line["available"]
    if phase == "preflight":
        _emit({"event": "done", "ok": True})
        return 0
    if not usable:
        _emit({"event": "done", "ok": False, "error": "store_unavailable"})
        return 2
    for s in order:
        if os.getppid() != start_ppid:  # the server is gone: write nothing more (A.9)
            break
        try:
            res = modules[s].save(store_request(s, req))
        except Exception:  # health: allow BLE001 - W-7: unknown whether the write started
            res = None
        if not isinstance(res, dict):
            res = {"saved": None, "error": "internal_error"}
        row = make_row(s, res, **store_ident(s, req))
        row.pop("profile", None)  # the server knows the profile
        _emit({"event": "store", **row})
    _emit({"event": "done", "ok": True})
    return 0


def main() -> int:
    req = None
    try:
        req = json.loads(sys.stdin.read())
        if not isinstance(req, dict):
            raise ValueError("not an object")
        return _run(req)
    except Exception:  # health: allow BLE001 - never a traceback with a value in it
        _emit({"event": "done", "ok": False, "error": "internal_error"})
        return 3
    finally:
        req = None


# --- caller side (server process) -----------------------------------------------------------------------------

def save_timeout(chosen) -> float:
    """The storage process' time limit for a save: the sum of the chosen stores' ``STORE_TIMEOUT_S`` (A.9)."""
    return float(sum(STORE_TIMEOUT_S[s] for s in chosen))


def _child_env(home: Path) -> dict:
    env = dict(os.environ)
    env["HERMES_HOME"] = str(home)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    paths = [str(PLUGIN_ROOT)]
    agent_dir = hermes_agent_dir()
    if agent_dir:
        paths.append(str(agent_dir))
    if env.get("PYTHONPATH"):
        paths.append(env["PYTHONPATH"])
    env["PYTHONPATH"] = os.pathsep.join(paths)
    return env


def _end_group(proc: subprocess.Popen) -> None:
    """SIGTERM to the storage process' group, SIGKILL to what is left one second later (A.9, W-6)."""
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(proc.pid, signal.SIGTERM)
    with contextlib.suppress(subprocess.TimeoutExpired):
        proc.wait(timeout=KILL_GRACE_S)
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(proc.pid, signal.SIGKILL)
    proc.wait()


def _take_line(result: dict, raw: bytes, chosen) -> None:
    try:
        ev = json.loads(raw)
    except ValueError:
        return
    if not isinstance(ev, dict):
        return
    kind = ev.get("event")
    if kind == "preflight" and ev.get("store") in chosen:
        result["preflight"][ev["store"]] = {"available": ev.get("available") is True, "reason": ev.get("reason"),
                                            "exists": ev.get("exists")}
    elif kind == "store" and ev.get("store") in chosen:
        result["stores"][ev["store"]] = {k: v for k, v in ev.items() if k not in ("event", "store")}
    elif kind == "done":
        result["done"] = ev


def run_storage(python: str, home: Path, request: dict, timeout: Optional[float] = None) -> dict:
    """Run one storage process and collect what it said: ``{"preflight": {store: line}, "stores": {store: row},
    "done": <done line> | None, "timed_out": bool, "returncode": int}``. Never raises for the process' own
    failures. ``timeout`` defaults to A.9's limit for the request's phase; when it passes, the whole process
    group is ended and the lines received so far are kept."""
    chosen = list(request.get("stores") or [])
    if timeout is None:
        timeout = PREFLIGHT_AT_CREATE_TIMEOUT_S if request.get("phase") == "preflight" else save_timeout(chosen)
    result: dict = {"preflight": {}, "stores": {}, "done": None, "timed_out": False, "returncode": None}
    # -P and cwd=PLUGIN_ROOT: never put the profile home (scripts, skills) on sys.path of a process that
    # receives secrets. .env and vault paths come from HERMES_HOME, not cwd. A new session = a new process group,
    # so a time-out ends the storage process and the `security` calls it started together (A.9, A.11).
    proc = subprocess.Popen([python, "-P", "-m", "secure_input.storage"], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=_child_env(home),
                            cwd=str(PLUGIN_ROOT), start_new_session=True)

    def read() -> None:
        assert proc.stdout is not None
        for raw in proc.stdout:
            _take_line(result, raw, chosen)

    reader = threading.Thread(target=read, daemon=True)
    reader.start()
    deadline = time.monotonic() + timeout
    try:
        assert proc.stdin is not None
        proc.stdin.write(json.dumps(request).encode("utf-8"))
        proc.stdin.close()
    except (OSError, ValueError):
        pass
    try:
        proc.wait(timeout=max(0.0, deadline - time.monotonic()))
    except subprocess.TimeoutExpired:
        result["timed_out"] = True
        _end_group(proc)
    reader.join(timeout=KILL_GRACE_S)
    if reader.is_alive():  # something of the group still holds stdout: end it
        _end_group(proc)
        reader.join(timeout=KILL_GRACE_S)
    with contextlib.suppress(OSError):
        if proc.stdout:
            proc.stdout.close()
    result["returncode"] = proc.returncode
    return result


def result_rows(chosen, raw: dict, ident: Optional[dict] = None) -> dict:
    """Complete store result rows for the chosen stores (A.9 item 7): a store without a ``store`` line is
    ``saved: null`` with ``store_timeout`` (the process was ended at its time limit) or ``no_result``."""
    ident = ident or {}
    rows = {}
    for s in STORE_NAMES:
        if s not in chosen:
            continue
        got = raw["stores"].get(s)
        if got is None:
            got = {"saved": None, "error": "store_timeout" if raw["timed_out"] else "no_result"}
        rows[s] = make_row(s, got, **ident.get(s, {}))
    return rows


def save_outcome(chosen, raw: dict, ident: Optional[dict] = None) -> dict:
    """Which row of the A.2 table "storage process ended" a save is:

    ``{"category", "rows", "partial", "unavailable", "wrote", "detail"}`` with ``category`` one of
    ``masked`` (the storage process found a masked value), ``unavailable`` (a pre-write check failed; nothing
    written), ``saved`` (one store or more saved; ``partial`` when not all), ``none_saved`` (every store answered
    ``saved: false``) and ``unknown`` (no store saved and one or more unknown; ``detail`` is ``store_timeout`` or
    ``no_result``). ``wrote`` is true once every pre-write check passed (A.13)."""
    order = [s for s in STORE_NAMES if s in chosen]
    done = raw.get("done") or {}
    pre = raw.get("preflight") or {}
    base = {"rows": [], "partial": False, "unavailable": [], "wrote": False, "detail": None}
    if done.get("ok") is False and done.get("error") == "masked_value" and not raw["stores"]:
        return dict(base, category="masked")
    unavailable = [{"store": s, "reason": pre[s]["reason"]} for s in order if s in pre and not pre[s]["available"]]
    if unavailable and not raw["stores"]:
        return dict(base, category="unavailable", unavailable=unavailable)
    wrote = bool(raw["stores"]) or all(s in pre and pre[s]["available"] for s in order)
    rows = list(result_rows(order, raw, ident).values())
    saved = [r for r in rows if r["saved"] is True]
    if saved:
        return dict(base, category="saved", rows=rows, partial=len(saved) != len(rows), wrote=wrote)
    if all(r["saved"] is False for r in rows):
        return dict(base, category="none_saved", rows=rows, wrote=wrote)
    return dict(base, category="unknown", rows=rows, wrote=wrote,
                detail="store_timeout" if raw["timed_out"] else "no_result")


if __name__ == "__main__":
    sys.exit(main())
