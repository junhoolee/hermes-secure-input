"""Store ``hermes_vault``: a login item in the profile's Hermes vault (plan 5.2, 5.4, appendix A.4, A.10).

``request``: ``{"label", "origin", "identifier_type"?, "identifier"?, "password"?, "otp_secret"?}``. Always a new
item; only after it is saved, older logins (smaller ``(created_at, id)``) for the same origin and the same id are
removed (``replaced``, ``removed_count``, ``replace_error`` in the result; no values).
"""

from __future__ import annotations

import contextlib
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

from ..config import LOGIN_IDENTIFIER_TYPES
from .base import StoreError, preflight_result, profile_home


def preflight(request: dict) -> dict:
    """Profile folder, id type (when the submit gave one) and whether Hermes' ``VaultStore`` loads and an
    existing vault opens. A missing vault is fine (the first save creates it) and nothing is created here."""
    home = profile_home()
    if home is None:
        return preflight_result(False, "bad_home")
    if "identifier_type" in request and request["identifier_type"] not in LOGIN_IDENTIFIER_TYPES:
        return preflight_result(False, "invalid_identifier_type")
    try:
        with contextlib.redirect_stdout(sys.stderr):
            from agent.vault_store import VaultStore

            store = VaultStore()
            if (home / "vault" / "vault.json.enc").exists():
                store.list_items()
    except Exception:  # health: allow BLE001 - the reason word only
        return preflight_result(False, "vault_rejected")
    return preflight_result(True)


def save(request: dict) -> dict:
    base = {"saved": False, "replaced": None, "error": None, "origin": request.get("origin"), "item_id": None}
    if profile_home() is None:
        return dict(base, error="bad_home")
    try:
        with contextlib.redirect_stdout(sys.stderr):
            out = add_login(request)
    except StoreError as exc:
        return dict(base, error=exc.reason)
    except Exception:  # health: allow BLE001 - never a traceback with the password in it
        return dict(base, saved=None, error="internal_error")
    return {"saved": True, "replaced": out["replaced"], "error": None, "origin": out["origin"],
            "item_id": out["item_id"], "has_otp": out["has_otp"], "removed_count": out["removed_count"],
            "replace_error": out["replace_error"]}


def add_login(req: dict) -> dict:
    from agent.vault_store import VaultStore  # imported in the grandchild only

    if req.get("identifier_type") not in LOGIN_IDENTIFIER_TYPES:
        raise StoreError("invalid_identifier_type")
    secret = {"identifier_type": req["identifier_type"], "identifier": req.get("identifier", ""),
              "password": req.get("password", "")}
    if req.get("otp_secret"):
        secret["otp_secret"] = req["otp_secret"]
    store = VaultStore()
    with _login_save_lock():
        try:
            meta = store.add_item(kind="login", label=req["label"], secret=secret, origin=req["origin"])
        except Exception:
            raise StoreError("vault_rejected") from None
        removed, replace_error = _remove_older_logins(store, meta, secret["identifier"])
    return {"type": "vault", "origin": meta.origin, "item_id": meta.id, "has_otp": bool(meta.has_otp),
            "replaced": removed > 0, "removed_count": removed, "replace_error": replace_error}


@contextlib.contextmanager
def _login_save_lock():
    """Serialize this plugin's login saves in one profile (security review 2, T-2): add, list and remove
    run under ``<HERMES_HOME>/secure-input/login.lock`` (flock, 0600). Hermes stamps ``created_at`` before
    it takes its own vault lock, so without this an overlapping save can be added after the other one
    listed, and the two items then outlive each other. If the lock cannot be taken the save goes on
    unlocked; the ``(created_at, id)`` rule still never removes a newer item."""
    fd = None
    try:
        import fcntl

        home = Path(os.environ.get("HERMES_HOME", ""))
        if not home.is_absolute():
            raise ValueError("no profile home")
        folder = home / "secure-input"
        folder.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(folder / "login.lock", os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
    except Exception:  # health: allow BLE001 - no lock available: fall back to the ordering rule alone
        if fd is not None:
            os.close(fd)
        fd = None
    try:
        yield
    finally:
        if fd is not None:
            os.close(fd)  # closing the descriptor releases the flock


def _order_key(item) -> Optional[tuple[datetime, str]]:
    """``(created_at, id)`` of a vault item, or ``None`` when ``created_at`` is missing or not a
    timezone-aware ISO time (Hermes writes ``datetime.now(UTC).isoformat()``)."""
    raw = getattr(item, "created_at", None)
    if not isinstance(raw, str) or not raw:
        return None
    try:
        when = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if when.tzinfo is None or when.utcoffset() is None:
        return None
    return when, str(item.id)


def _remove_older_logins(store, new, identifier: str) -> tuple[int, bool]:
    """After the new item is saved, remove older logins for the same origin and the same id (compared
    case-sensitively after strip; the id type is not compared). Older items go whole, authenticator key
    included. A failure here leaves the new item in place: ``(removed so far, True)``.

    "Older" means a smaller ``(created_at, id)`` than the new item (security review 2, T-2): two saves
    that overlap never remove each other's newer item, so exactly the later one is left. The new item's
    ``created_at`` is read from the same listing. Items whose ``created_at`` cannot be compared are kept."""
    want = (identifier or "").strip()
    removed = 0
    try:
        items = store.list_items()
        mine = next((i for i in items if i.id == new.id), new)
        new_key = _order_key(mine)
        if new_key is None:
            return 0, False
        for item in items:
            if (item.kind == "login" and item.id != new.id and item.origin == new.origin
                    and (item.identifier or "").strip() == want):
                key = _order_key(item)
                if key is not None and key < new_key and store.remove_item(item.id):
                    removed += 1
    except Exception:  # health: allow BLE001 - the new item is saved; report, never raise
        return removed, True
    return removed, False
