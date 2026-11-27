"""What every store module shares (plan appendix A.8, A.10).

A store module (``env``, ``hermes_vault``, ``keychain``) has two functions:

- ``preflight(request) -> {"available": bool, "reason": str | None, "exists": bool | None}``; writes nothing,
- ``save(request) -> <store result row without "store">``; never raises, a failure is the ``error`` word.

``request`` is the dict the storage process (``secure_input.storage``) builds for that store only.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

# Per-store fields of the store result row (A.8), after store, saved, replaced, error.
ROW_FIELDS = {
    "env": ("env_var", "profile"),
    "hermes_vault": ("origin", "item_id", "profile", "has_otp", "removed_count", "replace_error"),
    "keychain": ("service", "account", "listed", "new_item", "tmp_left", "main_touched", "main_created"),
}
PARENT_ONLY_FIELDS = ("has_otp", "removed_count", "replace_error")  # A.8: not in the submit answer


class StoreError(Exception):
    """Carries an A.4 reason word only; never a value or its length."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def make_row(store: str, data: Optional[dict] = None, **ident) -> dict:
    """A complete store result row of ``store``: every A.8 field, unknown ones ``None``. ``replaced`` is kept
    only when ``saved`` is true (A.8)."""
    row = {"store": store, "saved": None, "replaced": None, "error": None}
    row.update({k: None for k in ROW_FIELDS[store]})
    for source in (ident, data or {}):
        row.update({k: v for k, v in source.items() if k in row and k != "store"})
    if row["saved"] not in (True, False, None):
        row["saved"] = None
    if row["saved"] is not True:
        row["replaced"] = None
    return row


def preflight_result(available: bool, reason: Optional[str] = None, exists: Optional[bool] = None) -> dict:
    return {"available": bool(available), "reason": None if available else reason, "exists": exists}


def profile_home() -> Optional[Path]:
    """The profile folder the storage process was started for (``HERMES_HOME``), or ``None`` when it is not an
    absolute existing folder (reason ``bad_home``)."""
    home = os.environ.get("HERMES_HOME", "")
    if not home or not Path(home).is_absolute() or not Path(home).is_dir():
        return None
    return Path(home)
