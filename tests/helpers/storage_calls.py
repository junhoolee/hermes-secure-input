"""Run one protocol-2 save through the real storage process for tests written against one-store requests.

``save_one(python, home, {"kind": "api_key", "env_var", "value"})`` or a ``login`` request
(``label``, ``origin``, ``identifier_type``, ``identifier``, ``password``, ``otp_secret``) returns the store result
row (A.8) when the store saved, and raises ``StoreError(<A.4 word>)`` otherwise. ``masked_check`` is false, as when
the server could not import Hermes' masked-value check, so the storage process runs it before any store.
"""

from __future__ import annotations

from secure_input.storage import run_storage
from secure_input.stores.base import StoreError


def save_one(python: str, home, req: dict) -> dict:
    kind = req["kind"]
    request = {"phase": "save", "kind": kind, "request_id": "0" * 32}
    if kind == "api_key":
        store = "env"
        request.update(stores=["env"], env_var=req.get("env_var"), value=req.get("value"), masked_check=False)
    else:
        store = "hermes_vault"
        request.update(stores=["hermes_vault"], **{k: req.get(k) for k in (
            "label", "origin", "identifier_type", "identifier", "password", "otp_secret")})
    raw = run_storage(python, home, request)
    done = raw["done"] or {}
    if done.get("error") == "store_unavailable":
        line = raw["preflight"].get(store) or {}
        raise StoreError(line.get("reason") or "store_unavailable")
    if done.get("error") in ("masked_value", "internal_error"):
        raise StoreError(done["error"])
    row = raw["stores"].get(store)
    if row is None:
        raise StoreError("store_timeout" if raw["timed_out"] else "no_result")
    if row.get("saved") is not True:
        raise StoreError(row.get("error") or "no_result")
    return row
