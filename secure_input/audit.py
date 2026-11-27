"""Append-only audit log (docs/protocol.md 10.4).

``<target profile home>/logs/secure-input.jsonl``, mode 0600, one JSON object per line.
Never written: credential values or their length, login identifiers, the path token, sid,
keys, ciphertext.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from .profiles import ProfileError, resolve_profile_home
from .spec import RequestSpec

EVENTS = ("created", "opened", "open_denied", "submitted", "saving", "saved", "delivered", "expired", "cancelled",
          "failed", "cleanup")
AUDIT_FIELDS = ("ts", "event", "request_id", "path_fp", "requester", "purpose", "kind", "label",
                "target_profile", "storage", "stores", "detail")


def path_fingerprint(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:8]


def storage_descriptor(spec: RequestSpec) -> dict:
    if spec.kind == "api_key":
        return {"type": "env", "env_var": spec.env_var}
    if spec.kind == "login":
        return {"type": "vault", "origin": spec.origin}
    if spec.kind == "secret":
        kc = spec.keychain or {}
        return {"type": "keychain", "service": kc.get("service"), "account": kc.get("account")}
    return {"type": "browser_page", "site": spec.site}


def stores_descriptor(spec: RequestSpec) -> list[dict]:
    """Plan 5.6: the stores the request preselected (with the agent's reason) and each store's naming field:
    the variable name, the site address, or the keychain service and account. Never a value."""
    out = []
    kc = spec.keychain or {}
    for row in spec.stores or []:
        d = {k: row[k] for k in ("store", "selected", "by", "reason", "needed")}
        if row["store"] == "env":
            d["env_var"] = spec.env_var
        elif row["store"] == "hermes_vault":
            d["origin"] = spec.origin
        else:
            d.update(service=kc.get("service"), account=kc.get("account"))
        out.append(d)
    return out


def append_jsonl(path: Path, record: dict) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, (json.dumps(record, ensure_ascii=False) + "\n").encode("utf-8"))
    finally:
        os.close(fd)


def _now() -> datetime:
    return datetime.now(timezone.utc).astimezone()


class AuditLog:
    def __init__(self, spec: RequestSpec, token: str, request_id: str,
                 now: Optional[Callable[[], datetime]] = None):
        self.spec = spec
        self.request_id = request_id
        self._fp = path_fingerprint(token)
        self._now = now or _now

    def _path(self, profile: str) -> Path:
        return resolve_profile_home(profile, self.spec.hermes_root) / "logs" / "secure-input.jsonl"

    def write(self, event: str, *, detail: Optional[dict] = None, profile: Optional[str] = None) -> bool:
        """Write one event. ``profile`` = the profile actually used when it differs from the
        requested one; the line then goes to both profiles' logs. Returns False on I/O failure."""
        assert event in EVENTS, event
        spec = self.spec
        used = profile or spec.target_profile
        det = dict(detail or {})
        if used != spec.target_profile:
            det["requested_profile"] = spec.target_profile
        record = {
            "ts": self._now().isoformat(),
            "event": event,
            "request_id": self.request_id,
            "path_fp": self._fp,
            "requester": dict(spec.requester),
            "purpose": spec.purpose,
            "kind": spec.kind,
            "label": spec.label,
            "target_profile": used,
            "storage": storage_descriptor(spec),
            "stores": stores_descriptor(spec),
            "detail": det,
        }
        ok = True
        targets = [spec.target_profile] + ([used] if used != spec.target_profile else [])
        for prof in targets:
            try:
                append_jsonl(self._path(prof), record)
            except (OSError, ProfileError):
                ok = False
        return ok
