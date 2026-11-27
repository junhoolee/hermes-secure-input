"""Mac keychain store (plan appendix A.1, A.4, A.8, A.10, A.11).

Two functions, the shape every store module shares (A.10):

- ``preflight(request, *, security_path=SECURITY_PATH)`` -> ``{"available", "reason", "exists"}``.
  Writes nothing and reads no value. With ``value`` in the request (the check right after a
  submit) it also checks the value rules of plan section 3.1.
- ``save(request, *, security_path=SECURITY_PATH)`` -> the store result row of A.8 without
  ``store``. Never raises; a failure is one word of A.4 in ``error``.

``request`` is read for ``service``, ``account``, ``listed``, ``request_id`` and ``value`` only.

Every keychain operation goes through ``/usr/bin/security``. A value only ever reaches it on the
standard input of ``security -i``, as the hex of its UTF-8 bytes (``-X``); never in an argument or
an environment variable. ``security`` output is dropped, except the ``-w`` read back and the
access-list dump, which are compared or filtered in memory and then dropped. Each call has a
``CALL_TIMEOUT_S`` limit; over it the process gets SIGKILL. ``security`` stays in the caller's
process group so the server can end the storage process group together with it (A.9, A.11).

This module imports nothing from the plugin; standard library only.
"""

from __future__ import annotations

import os
import re
import subprocess

SECURITY_PATH = "/usr/bin/security"
SERVICE_PREFIX = "hermes-secure-input."
FIXED_ACCOUNT = "hermes-secure-input"
TMP_PREFIX = "hermes-secure-input.tmp."
TEST_PREFIX = "hermes-secure-input-test-"
CALL_TIMEOUT_S = 5.0
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$")
MAX_LINE_BYTES = 2400
MAX_VALUE_CHARS = 1024

_EXISTS_RC = 0
_MISSING_RC = 44

# Default keychain path seen by the last successful preflight, per ``security_path``.
# ``save()`` does not repeat check 2 (A.11), but step (나) needs this path. The storage process
# runs preflight and save in the same process (A.9), so the path is known by then.
_DEFAULT_KEYCHAIN: dict[str, str] = {}


class _Stop(Exception):
    """Ends ``save()`` early with one A.4 word and a ``saved`` value."""

    def __init__(self, error: str, saved: bool | None, exists: bool | None = None):
        super().__init__(error)
        self.error = error
        self.saved = saved
        self.exists = exists


# ---- one security call -------------------------------------------------------------------------

def _run(security_path: str, argv: list[str], *, stdin: bytes | None = None,
         capture: bool = False) -> dict:
    """Run ``security`` once. Returns ``{"rc", "out", "timeout"}``; ``out`` is stdout bytes only
    when ``capture`` is true. stderr is always dropped."""
    proc = subprocess.Popen(
        [security_path, *argv],
        stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
    )
    try:
        out, _ = proc.communicate(stdin, timeout=CALL_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        proc.kill()                      # SIGKILL to this process only
        proc.communicate()
        return {"rc": None, "out": b"", "timeout": True}
    return {"rc": proc.returncode, "out": out or b"", "timeout": False}


def _add_line(service: str, account: str, value: str) -> bytes:
    hexed = value.encode("utf-8").hex()
    return f'add-generic-password -a "{account}" -s "{service}" -U -X {hexed}\n'.encode("utf-8")


def _tmp_service(request_id: str) -> str:
    return TMP_PREFIX + str(request_id)[:12]


def _value_ok(value) -> bool:
    if not isinstance(value, str) or not 1 <= len(value) <= MAX_VALUE_CHARS:
        return False
    if any(not 0x20 <= ord(ch) <= 0x7E for ch in value):
        return False
    return value[0] != " " and value[-1] != " "


def _name_ok(name) -> bool:
    return isinstance(name, str) and NAME_RE.fullmatch(name) is not None


# ---- checks 5 and 6 (also steps (가) and (나) of save) -----------------------------------------

def _exists(security_path: str, service: str, account: str) -> bool:
    r = _run(security_path, ["find-generic-password", "-s", service, "-a", account])
    if r["timeout"]:
        raise _Stop("keychain_timeout", False)
    if r["rc"] == _EXISTS_RC:
        return True
    if r["rc"] == _MISSING_RC:
        return False
    raise _Stop("keychain_unavailable", False)


def _blocks(text: str) -> list[list[str]]:
    """Split ``dump-keychain`` output into item blocks, one per ``keychain: `` line."""
    blocks: list[list[str]] = []
    for line in text.splitlines():
        if line.startswith("keychain: "):
            blocks.append([line])
        elif blocks:
            blocks[-1].append(line)
    return blocks


def _decrypt_entries(block: list[str]) -> list[dict]:
    """Access entries of one block: ``{"decrypt": bool, "any_app": bool, "apps": [...]}``."""
    entries: list[dict] = []
    cur: dict | None = None
    in_apps = False
    for raw in block:
        line = raw.strip()
        if re.fullmatch(r"entry \d+:", line):
            cur = {"decrypt": False, "any_app": False, "apps": []}
            entries.append(cur)
            in_apps = False
            continue
        if cur is None:
            continue
        m = re.fullmatch(r"authorizations \(\d+\): (.*)", line)
        if m:
            cur["decrypt"] = "decrypt" in m.group(1).split()
            in_apps = False
            continue
        if line == "applications: <null>":
            cur["any_app"] = True
            in_apps = False
            continue
        if re.fullmatch(r"applications \(\d+\):", line):
            in_apps = True
            continue
        if in_apps:
            m = re.fullmatch(r"\d+: (.+?) \([^()]*\)", line)
            if m:
                cur["apps"].append(m.group(1))
                continue
            in_apps = False
    return [e for e in entries if e["decrypt"]]


def _acl_allows_security(text: str, service: str, account: str) -> bool:
    svce_line = f'"svce"<blob>="{service}"'
    acct_line = f'"acct"<blob>="{account}"'
    matches = []
    for block in _blocks(text):
        stripped = {ln.strip() for ln in block}
        if 'class: "genp"' in stripped and svce_line in stripped and acct_line in stripped:
            matches.append(block)
    if len(matches) != 1:
        return False
    dec = _decrypt_entries(matches[0])
    if not dec or any(e["any_app"] for e in dec):
        return False
    return any(SECURITY_PATH in e["apps"] for e in dec)


def _check_acl(security_path: str, keychain_path: str, service: str, account: str) -> None:
    r = _run(security_path, ["dump-keychain", "-a", keychain_path], capture=True)
    if r["timeout"]:
        raise _Stop("keychain_timeout", False)
    ok = r["rc"] == 0 and _acl_allows_security(r["out"].decode("utf-8", "replace"), service, account)
    r["out"] = b""
    if not ok:
        raise _Stop("keychain_acl_denied", False)


# ---- preflight ---------------------------------------------------------------------------------

def preflight(request: dict, *, security_path: str = SECURITY_PATH) -> dict:
    """Checks 1 to 6 of A.11. Writes nothing, reads no value."""
    try:
        return _preflight(request, security_path)
    except _Stop as stop:
        return {"available": False, "reason": stop.error, "exists": stop.exists}
    except Exception:  # noqa: BLE001 - never raise to the storage process
        return {"available": False, "reason": "internal_error", "exists": None}


def _preflight(request: dict, security_path: str) -> dict:
    # 1. the executable exists
    if not (os.path.isfile(security_path) and os.access(security_path, os.X_OK)):
        raise _Stop("keychain_unavailable", None)
    # 2. the default keychain can be looked up
    r = _run(security_path, ["default-keychain"], capture=True)
    if r["timeout"]:
        raise _Stop("keychain_timeout", None)
    if r["rc"] != 0:
        raise _Stop("keychain_unavailable", None)
    keychain_path = r["out"].decode("utf-8", "replace").strip().strip('"')
    if not keychain_path:
        raise _Stop("keychain_unavailable", None)
    _DEFAULT_KEYCHAIN[security_path] = keychain_path
    # 3. names
    service, account = request.get("service"), request.get("account")
    if not (_name_ok(service) and _name_ok(account)):
        raise _Stop("keychain_name_invalid", None)
    # 4. value rules and line length, only after a submit
    if "value" in request:
        value = request.get("value")
        if not _value_ok(value):
            raise _Stop("keychain_value_unsupported", None)
        lines = (_add_line(service, account, value),
                 _add_line(_tmp_service(request.get("request_id", "")), FIXED_ACCOUNT, value))
        if any(len(line) > MAX_LINE_BYTES for line in lines):
            raise _Stop("keychain_line_too_long", None)
    # 5. does the item exist (no value read)
    exists = _exists(security_path, service, account)
    # 6. access list of an existing item
    if exists:
        try:
            _check_acl(security_path, keychain_path, service, account)
        except _Stop as stop:
            stop.exists = True
            raise
    return {"available": True, "reason": None, "exists": exists}


# ---- save --------------------------------------------------------------------------------------

def save(request: dict, *, security_path: str = SECURITY_PATH) -> dict:
    """Steps (가) to (바) of A.11. Never raises."""
    row = {"saved": None, "replaced": None, "error": None,
           "service": request.get("service") if isinstance(request, dict) else None,
           "account": request.get("account") if isinstance(request, dict) else None,
           "listed": bool(request.get("listed")) if isinstance(request, dict) else False,
           "new_item": False, "tmp_left": False, "main_touched": False, "main_created": False}
    state = {"tmp_made": False, "tmp_service": None}
    try:
        _save(request, security_path, row, state)
    except _Stop as stop:
        row["saved"], row["error"] = stop.saved, stop.error
    except Exception:  # noqa: BLE001
        row["saved"], row["error"] = None, "internal_error"
    finally:
        if state["tmp_made"]:
            row["tmp_left"] = _delete_tmp(security_path, state["tmp_service"])
    if row["saved"] is not True:
        row["replaced"] = None
    return row


def _delete_tmp(security_path: str, tmp_service: str) -> bool:
    """(바) Returns ``tmp_left``."""
    try:
        r = _run(security_path, ["delete-generic-password", "-s", tmp_service, "-a", FIXED_ACCOUNT])
    except Exception:  # noqa: BLE001
        return True
    return r["timeout"] or r["rc"] not in (_EXISTS_RC, _MISSING_RC)


def _write(security_path: str, line: bytes) -> dict:
    if len(line) > MAX_LINE_BYTES:
        raise _Stop("keychain_line_too_long", False)
    return _run(security_path, ["-i"], stdin=line)


def _read_equals(security_path: str, service: str, account: str, value: str) -> dict:
    r = _run(security_path, ["find-generic-password", "-s", service, "-a", account, "-w"], capture=True)
    got = r["out"]
    r["out"] = b""
    if got.endswith(b"\n"):
        got = got[:-1]
    equal = (not r["timeout"]) and r["rc"] == 0 and got == value.encode("utf-8")
    got = b""
    return {"timeout": r["timeout"], "equal": equal}


def _save(request: dict, security_path: str, row: dict, state: dict) -> None:
    service, account, value = request["service"], request["account"], request["value"]
    listed = bool(request.get("listed"))
    main_line = _add_line(service, account, value)
    # (가) does the item exist
    exists = _exists(security_path, service, account)
    row["new_item"] = (not listed) and not exists
    if exists:
        # (나) access list
        keychain_path = _DEFAULT_KEYCHAIN.get(security_path)
        if not keychain_path:
            raise _Stop("keychain_unavailable", False)
        _check_acl(security_path, keychain_path, service, account)
        # (다) temp item first, same value, read back
        tmp_service = _tmp_service(request.get("request_id", ""))
        tmp_line = _add_line(tmp_service, FIXED_ACCOUNT, value)
        if len(tmp_line) > MAX_LINE_BYTES or len(main_line) > MAX_LINE_BYTES:
            raise _Stop("keychain_line_too_long", False)
        state["tmp_service"] = tmp_service
        state["tmp_made"] = True
        w = _write(security_path, tmp_line)
        if w["timeout"]:
            raise _Stop("keychain_timeout", False)
        if w["rc"] != 0:
            raise _Stop("keychain_write_failed", False)
        back = _read_equals(security_path, tmp_service, FIXED_ACCOUNT, value)
        if back["timeout"]:
            raise _Stop("keychain_timeout", False)
        if not back["equal"]:
            raise _Stop("keychain_verify_failed", False)
    # (라) main item
    if len(main_line) > MAX_LINE_BYTES:
        raise _Stop("keychain_line_too_long", False)
    row["main_touched"] = exists  # an earlier value may change only if the item was there (N-1)
    # RC-1: the write may make an item that holds the value sent; false again below when the write failed for sure
    row["main_created"] = not exists
    w = _write(security_path, main_line)
    if w["timeout"]:
        raise _Stop("keychain_timeout", None)
    # (마) read back the main item
    back = _read_equals(security_path, service, account, value)
    if back["timeout"]:
        raise _Stop("keychain_timeout", None)
    if not back["equal"]:
        if w["rc"] != 0:
            # the write failed for sure and the item does not hold the value: it was not made (review round 1)
            row["main_created"] = False
            raise _Stop("keychain_write_failed", False)
        raise _Stop("keychain_verify_failed", False)
    row["saved"], row["error"] = True, None
    row["replaced"] = exists
