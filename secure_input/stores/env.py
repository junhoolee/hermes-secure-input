"""Store ``env``: the profile's ``.env`` through Hermes' own writer (plan 5.2, appendix A.4, A.10).

``request``: ``{"env_var", "value"?}``. The profile folder is ``HERMES_HOME`` of the storage process. The
masked-value check is not part of this module (plan 5.2): the server, or the storage process before any store,
does it for every ``api_key`` submit.
"""

from __future__ import annotations

import contextlib
import os
import stat
import sys
import tempfile
from pathlib import Path
from typing import Optional

from ..validation import check_env_var_name, is_clean_single_line
from .base import StoreError, preflight_result, profile_home


def _hermes():
    """``(hermes_cli.config, invalidate_env_file_cache, load_env_file)``; ``env_write_failed`` without them."""
    with contextlib.redirect_stdout(sys.stderr):
        try:
            from agent.secret_scope import invalidate_env_file_cache, load_env_file
            from hermes_cli import config as core
        except Exception:  # health: allow BLE001 - no Hermes writer, no write
            raise StoreError("env_write_failed") from None
    return core, invalidate_env_file_cache, load_env_file


def _check(home: Path, name: str, value: Optional[str], with_value: bool):
    """The checks shared by :func:`preflight` and :func:`write_env`, in the A.4 order. Returns Hermes' modules
    and the ``.env`` path."""
    try:
        check_env_var_name(name)
    except ValueError:
        raise StoreError("invalid_env_var") from None
    if with_value and (not isinstance(value, str) or not is_clean_single_line(value) or not value.isascii()):
        raise StoreError("invalid_value")
    core, invalidate, load = _hermes()
    path = Path(home) / ".env"
    with contextlib.redirect_stdout(sys.stderr):
        try:
            same = core.get_env_path().resolve() == path.resolve()
        except Exception:  # health: allow BLE001
            same = False
        if not same:
            raise StoreError("bad_home")
        try:
            core.require_env_writable(name, "set")
        except ValueError:
            raise StoreError("env_not_writable") from None
    return core, invalidate, load, path


def _defined(core, path: Path, name: str) -> bool:
    """Whether ``name`` has a line in ``.env``. Lines stay in memory; nothing of them is returned."""
    if not path.exists():
        return False
    with contextlib.redirect_stdout(sys.stderr):
        return any(core._env_line_defines_key(ln, name) for ln in core._read_env_lines(path))


def preflight(request: dict) -> dict:
    home = profile_home()
    if home is None:
        return preflight_result(False, "bad_home")
    name = request.get("env_var")
    try:
        core, _inv, _load, path = _check(home, name, request.get("value"), "value" in request)
        exists = _defined(core, path, name)
    except StoreError as exc:
        return preflight_result(False, exc.reason)
    return preflight_result(True, exists=exists)


def save(request: dict) -> dict:
    name = request.get("env_var")
    home = profile_home()
    if home is None:
        return {"saved": False, "replaced": None, "error": "bad_home", "env_var": name}
    try:
        core, _inv, _load, path = _check(home, name, request.get("value"), True)
        existed = _defined(core, path, name)
        write_env(home, name, request.get("value"))
    except StoreError as exc:
        return {"saved": False, "replaced": None, "error": exc.reason, "env_var": name}
    except Exception:  # health: allow BLE001 - never a traceback with the value in it
        return {"saved": None, "replaced": None, "error": "internal_error", "env_var": name}
    return {"saved": True, "replaced": existed, "error": None, "env_var": name}


def write_env(home: Path, name: str, value: str) -> dict:
    """Write ``name=value`` to ``<home>/.env`` through Hermes' own writer (security review S-3).

    Order: name and value checks; ``home`` must be the folder Hermes computes from ``HERMES_HOME``;
    ``require_env_writable``; then under Hermes' ``.env.lock``: capture the file, remove duplicate lines of the
    same variable, ``save_env_value``, read back with Hermes' own reader, mode 0600. On any failure the file is
    restored byte-for-byte inside the same lock (security review 2, T-1). Anything Hermes prints goes to stderr
    so the grandchild's stdout stays JSON lines.
    """
    core, invalidate, load, path = _check(home, name, value, True)
    with contextlib.redirect_stdout(sys.stderr):
        try:
            with core._env_write_lock(path):  # reentrant: the calls below take it again
                _write_env_locked(core, path, name, value, invalidate, load)
        except StoreError:
            raise
        except Exception:  # health: allow BLE001 - reason code only, never the value
            raise StoreError("env_write_failed") from None
    return {"type": "env", "env_var": name}


def _write_env_locked(core, path: Path, name: str, value: str, invalidate, load) -> None:
    """Called with Hermes' ``.env`` lock held (security review 2, T-1).

    The file's bytes and mode are captured first. Removing duplicate lines, ``save_env_value`` and the
    read-back all run under the same lock. If any step fails (an exception, or a read-back that differs,
    e.g. ``save_env_value`` refusing by returning), the file is put back exactly as it was (or removed
    when it did not exist) before ``StoreError`` is raised. Nothing of the value or the old content is
    written to an exception, a log or stdout/stderr.
    """
    original = _capture(path)
    env_before = os.environ.get(name)
    reason = None
    try:
        if original is not None:
            defined = [ln for ln in core._read_env_lines(path) if core._env_line_defines_key(ln, name)]
            if len(defined) > 1:
                core.remove_env_value(name)
        core.save_env_value(name, value)
    except Exception:  # health: allow BLE001 - reason code only, never the value
        reason = "env_write_failed"
    if reason is None:
        try:
            invalidate(path)
            if load(path).get(name) != value:
                reason = "verify_failed"
        except Exception:  # health: allow BLE001
            reason = "verify_failed"
    if reason is None:
        try:
            if stat.S_IMODE(path.stat().st_mode) != 0o600:
                os.chmod(path, 0o600)
            return
        except OSError:
            reason = "env_write_failed"
    try:
        _restore(path, original)
    except Exception:  # health: allow BLE001 - still only the reason code
        pass
    original = None
    if env_before is None:
        os.environ.pop(name, None)
    else:
        os.environ[name] = env_before
    with contextlib.suppress(Exception):
        invalidate(path)
    with contextlib.suppress(Exception):
        core.invalidate_env_cache()
    raise StoreError(reason)


def _capture(path: Path) -> Optional[tuple[bytes, int]]:
    """``(bytes, mode)`` of ``path``, or ``None`` when it does not exist."""
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        return None
    return data, stat.S_IMODE(path.stat().st_mode)


def _restore(path: Path, original: Optional[tuple[bytes, int]]) -> None:
    """Put ``path`` back to ``original`` (see :func:`_capture`). Writes only when the bytes differ:
    a temp file in the same folder (0600 until it gets the original mode), then ``os.replace``."""
    if original is None:
        with contextlib.suppress(FileNotFoundError):
            path.unlink()
        return
    data, mode = original
    try:
        same = path.read_bytes() == data
    except FileNotFoundError:
        same = False
    if same:
        if stat.S_IMODE(path.stat().st_mode) != mode:
            os.chmod(path, mode)
        return
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".env_restore_", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
