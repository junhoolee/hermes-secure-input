"""A stand-in for ``secure_input.stores.keychain`` (plan appendix A.10, A.11), which card 1 builds.

The fake never touches the real keychain. It is configured by a JSON dict (in-process: :func:`make_module`;
in a storage grandchild: the ``FAKE_KEYCHAIN_CONFIG`` environment variable read by the wrapper from
:func:`storage_python`). Keys of the config:

- ``preflight``: dict returned by ``preflight()`` (default ``{"available": true, "reason": null, "exists": false}``)
- ``save``: dict returned by ``save()`` (default: saved, a new item)
- ``save_sleep``: seconds ``save()`` sleeps before answering
- ``save_child_pidfile``: ``save()`` first starts ``sleep 300`` (in the same process group, like ``security``) and
  writes its pid to this file
- ``save_exit``: ``save()`` ends the process with this exit code (no result line)
- ``save_raises``: ``save()`` raises
- ``log``: file that gets one JSON line per call: ``{"fn", "keys", "has_value"}`` (never the value)
- ``db``: file holding ``{"<service>|<account>": value}``; ``save()`` writes the value there (tests read it back)
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import time
import types
from pathlib import Path

DEFAULT_PREFLIGHT = {"available": True, "reason": None, "exists": False}


def _log(cfg: dict, fn: str, request: dict) -> None:
    if cfg.get("log"):
        with open(cfg["log"], "a") as f:
            f.write(json.dumps({"fn": fn, "keys": sorted(request), "has_value": "value" in request}) + "\n")


def make_module(cfg: dict) -> types.ModuleType:
    mod = types.ModuleType("secure_input.stores.keychain")
    mod.SECURITY_PATH = "/usr/bin/security"
    mod.calls = []

    def preflight(request, *, security_path=mod.SECURITY_PATH):
        mod.calls.append(("preflight", sorted(request)))
        _log(cfg, "preflight", request)
        return dict(cfg.get("preflight") or DEFAULT_PREFLIGHT)

    def save(request, *, security_path=mod.SECURITY_PATH):
        mod.calls.append(("save", sorted(request)))
        _log(cfg, "save", request)
        if cfg.get("save_child_pidfile"):
            child = subprocess.Popen(["/bin/sleep", "300"])
            Path(cfg["save_child_pidfile"]).write_text(str(child.pid))
        if cfg.get("save_sleep"):
            time.sleep(float(cfg["save_sleep"]))
        if cfg.get("save_exit") is not None:
            sys.stdout.flush()
            os._exit(int(cfg["save_exit"]))
        if cfg.get("save_raises"):
            raise RuntimeError("fake keychain failure")
        if cfg.get("db"):
            p = Path(cfg["db"])
            data = json.loads(p.read_text()) if p.exists() else {}
            data[f"{request['service']}|{request['account']}"] = request["value"]
            p.write_text(json.dumps(data))
            os.chmod(p, 0o600)
        out = {"saved": True, "replaced": False, "error": None, "service": request["service"],
               "account": request["account"], "listed": request["listed"], "new_item": not request["listed"],
               "tmp_left": False, "main_touched": True}
        out.update(cfg.get("save") or {})
        return out

    mod.preflight = preflight
    mod.save = save
    return mod


BOOT = r"""
import io, json, os, sys, time
data = sys.stdin.read()
req = json.loads(data)
cfg = json.loads(os.environ.get("FAKE_KEYCHAIN_CONFIG") or "{}")
sleep = cfg.get("wrapper_sleep_" + str(req.get("phase")))
if sleep:
    time.sleep(float(sleep))
gate = cfg.get("wrapper_gate_" + str(req.get("phase")))
if gate:  # wait until the test creates this file (at most 60 s), so a slow test run cannot outrun the save
    end = time.monotonic() + 60
    while not os.path.exists(gate) and time.monotonic() < end:
        time.sleep(0.02)
req = None
if cfg.get("install", True):
    sys.path.insert(0, os.environ["FAKE_KEYCHAIN_HELPERS"])
    import fake_keychain
    sys.modules["secure_input.stores.keychain"] = fake_keychain.make_module(cfg)
else:  # "install": false stands for a missing keychain module (the real one must not run here: it calls security)
    sys.modules["secure_input.stores.keychain"] = None
sys.stdin = io.StringIO(data)
data = None
from secure_input import storage
sys.exit(storage.main())
"""


FAKE_SECURITY = r"""
import json, sys
db_path = sys.argv[1]
args = sys.argv[2:]
try:
    db = json.load(open(db_path))
except (OSError, ValueError):
    db = {}
key = args[args.index("-s") + 1] + "|" + args[args.index("-a") + 1]
if args[0] == "find-generic-password":
    if key not in db:
        sys.exit(44)
    if "-w" in args:
        print(db[key])
    sys.exit(0)
if args[0] == "delete-generic-password":
    if key not in db:
        sys.exit(44)
    del db[key]
    json.dump(db, open(db_path, "w"))
    sys.exit(0)
sys.exit(1)
"""


def fake_security(folder: Path, db: Path) -> Path:
    """A ``security`` stand-in over the fake keychain's ``db`` file: ``find-generic-password -s -a [-w]`` and
    ``delete-generic-password -s -a`` (exit 44 when the item is missing), for read-back checks in tests."""
    folder.mkdir(parents=True, exist_ok=True)
    script = folder / "fake-security"
    script.write_text(f"#!/bin/sh\nexec '{sys.executable}' -c '{FAKE_SECURITY}' '{db}' \"$@\"\n")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return script


def storage_python(folder: Path) -> Path:
    """A ``python`` stand-in: the storage grandchild (``-m secure_input.storage``) runs with the fake keychain
    module installed and the sleeps of ``FAKE_KEYCHAIN_CONFIG``; anything else (the server) runs unchanged."""
    folder.mkdir(parents=True, exist_ok=True)
    wrapper = folder / "python-wrapper"
    wrapper.write_text("#!/bin/sh\n"
                       f"export FAKE_KEYCHAIN_HELPERS='{Path(__file__).resolve().parent}'\n"
                       "case \"$*\" in\n"
                       f"  *secure_input.storage*) exec '{sys.executable}' -P -c '{BOOT}' ;;\n"
                       "esac\n"
                       f"exec '{sys.executable}' \"$@\"\n")
    wrapper.chmod(wrapper.stat().st_mode | stat.S_IXUSR)
    return wrapper
