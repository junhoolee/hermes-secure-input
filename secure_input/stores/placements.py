"""Where copies of a credential were saved (plan 5.5). No values, no login ids.

File: ``<Hermes root>/secure-input/placements.json`` (0600, written under ``placements.lock``), one key per
credential: ``login|<origin>``, ``api_key|<env var>``, ``secret|<keychain_item>``. Each key maps a store name to a
list of places, newest last: ``env`` ``{"profile", "env_var", "saved_at"}``, ``hermes_vault``
``{"profile", "origin", "item_id", "saved_at"}``, ``keychain`` ``{"service", "account", "saved_at"}``. A place
saved again replaces its old entry (same profile; same service and account).

Uses: preselect the stores an ``api_key`` was saved to before (``by: "history"``), and tell the user where to
delete copies (README). There is no delete-everywhere feature (decision 4).
"""

from __future__ import annotations

import contextlib
import json
import os
from pathlib import Path
from typing import Optional

from ..config import STORE_NAMES

_PLACE_FIELDS = {"env": ("profile", "env_var"), "hermes_vault": ("profile", "origin", "item_id"),
                 "keychain": ("service", "account")}
_LOCATOR = {"env": ("profile",), "hermes_vault": ("profile",), "keychain": ("service", "account")}


def key_for(kind: str, *, env_var: Optional[str] = None, origin: Optional[str] = None,
            keychain_item: Optional[str] = None) -> str:
    name = {"api_key": env_var, "login": origin, "secret": keychain_item}[kind]
    return f"{kind}|{name}"


def _path(root) -> Path:
    return Path(root) / "secure-input" / "placements.json"


def load(root) -> dict:
    try:
        data = json.loads(_path(root).read_text())
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def previous_stores(root, key: str) -> tuple[str, ...]:
    entry = load(root).get(key)
    if not isinstance(entry, dict):
        return ()
    return tuple(s for s in STORE_NAMES if entry.get(s))


@contextlib.contextmanager
def _locked(folder: Path):
    import fcntl

    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(folder / "placements.lock", os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def record(root, key: str, rows, *, when: str) -> None:
    """Add the stores of ``rows`` (store result rows, A.8) that saved (``saved: true``) under ``key``."""
    saved = [r for r in rows if r.get("saved") is True and r.get("store") in _PLACE_FIELDS]
    if not saved:
        return
    path = _path(root)
    with _locked(path.parent):
        data = load(root)
        entry = data.get(key) if isinstance(data.get(key), dict) else {}
        for row in saved:
            store = row["store"]
            place = {k: row.get(k) for k in _PLACE_FIELDS[store]}
            place["saved_at"] = when
            same = tuple(place[k] for k in _LOCATOR[store])
            old = [p for p in entry.get(store) or [] if isinstance(p, dict)
                   and tuple(p.get(k) for k in _LOCATOR[store]) != same]
            entry[store] = old + [place]
        data[key] = entry
        tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, json.dumps(data, ensure_ascii=False, indent=1).encode("utf-8"))
        finally:
            os.close(fd)
        os.replace(tmp, path)
