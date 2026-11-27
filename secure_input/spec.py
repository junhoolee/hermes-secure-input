"""``RequestSpec``: what the parent asks the user to enter (docs/protocol.md 2)."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlsplit

from .config import (KEYCHAIN_ID_RE, KEYCHAIN_NAME_RE, KIND_DEFAULT_STORES, KIND_STORES, KINDS, MAX_KEYCHAIN_ITEMS,
                     STORE_NAMES)
from .profiles import PROFILE_NAME_RE
from .validation import ENV_VAR_RE, check_env_var_name, has_format_char, is_clean_single_line, is_reason_text
HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")
REQUESTER_KEYS = ("type", "profile", "platform", "session_key", "user_id")

# Plan 3.2 rule 5 and appendix A.1 (``SERVICE_PREFIX``, ``FIXED_ACCOUNT``; keychain.py keeps its own copy).
KEYCHAIN_SERVICE_PREFIX = "hermes-secure-input."
KEYCHAIN_FIXED_ACCOUNT = "hermes-secure-input"
STORE_ROW_KEYS = ("store", "selected", "fixed", "by", "reason", "needed")  # appendix A.5
KEYCHAIN_KEYS = ("id", "service", "account", "listed", "label", "used_by")  # appendix A.5
ALLOW_ITEM_KEYS = ("id", "service", "account", "label", "used_by")  # plan 3.2 rule 1
AGENT_STORE_KEYS = ("store", "reason", "needed")  # plan 2.2
BY_VALUES = ("agent", "history", "default", None)  # appendix A.6


class SpecError(ValueError):
    """Validation failure. Carries the field name and a reason, never the offending value."""

    def __init__(self, field: str, reason: str):
        super().__init__(f"{field}: {reason}")
        self.field = field
        self.reason = reason


class KeychainItemError(SpecError):
    """``keychain_item`` refused by plan 3.2. ``rule`` is the rule number there (3, 4, 7 or 8); ``listed_id`` is
    the allow-list id the agent should pass instead (rules 3 and 4)."""

    def __init__(self, rule: int, reason: str, listed_id: Optional[str] = None):
        super().__init__("keychain_item", reason)
        self.rule = rule
        self.listed_id = listed_id


# --- store rows (plan 2.3, appendix A.5, A.6) -----------------------------------------------------------------

def build_store_rows(kind: str, stores: Optional[list] = None, *, history=()) -> list[dict]:
    """The ``RequestSpec.stores`` rows of ``kind`` from the agent's ``stores`` argument (``None`` = omitted).

    Refused (``SpecError("stores", ...)``): a non-list, an empty list, an unknown store name, a store the kind
    cannot use, a store named twice, an item with other keys than ``store``, ``reason``, ``needed``, a ``reason``
    that is not one clean line of 1-120 characters, a non-boolean ``needed``. ``history`` lists the stores this
    credential was saved to before (``placements``); it preselects rows for ``api_key`` only."""
    if kind not in KIND_STORES:
        raise SpecError("kind", "must be api_key, login, secret or otp_code")
    allowed = KIND_STORES[kind]
    agent: dict[str, tuple] = {}
    if stores is not None:
        if not isinstance(stores, (list, tuple)):
            raise SpecError("stores", "must be a list")
        if not stores:
            raise SpecError("stores", "must not be empty")
        for item in stores:
            if not isinstance(item, dict) or "store" not in item or not set(item) <= set(AGENT_STORE_KEYS):
                raise SpecError("stores", "each item is {store, reason, needed}")
            name = item["store"]
            if not isinstance(name, str) or name not in STORE_NAMES:
                raise SpecError("stores", "unknown store")
            if name not in allowed:
                raise SpecError("stores", "this kind cannot use that store")
            if name in agent:
                raise SpecError("stores", "a store is named twice")
            reason, needed = item.get("reason"), item.get("needed", False)
            if reason is not None and not is_reason_text(reason):
                raise SpecError("stores", "reason must be one line of 1-120 characters")
            if not isinstance(needed, bool):
                raise SpecError("stores", "needed must be true or false")
            agent[name] = (reason, needed)
    hist = set(history or ()) if kind == "api_key" else set()
    rows = []
    for name in STORE_NAMES:
        if name not in allowed:
            continue
        if name in agent:
            by = "agent"
        elif name in hist:
            by = "history"
        elif stores is None and name in KIND_DEFAULT_STORES[kind]:
            by = "default"
        else:
            by = None
        reason, needed = agent.get(name, (None, False))
        rows.append({"store": name, "selected": by is not None, "fixed": len(allowed) == 1, "by": by,
                     "reason": reason, "needed": needed})
    return rows


def _check_store_rows(kind: str, rows) -> None:
    allowed = KIND_STORES[kind]
    if not isinstance(rows, list) or len(rows) != len(allowed):
        raise SpecError("stores", "must list every store of the kind")
    for name, row in zip(allowed, rows):
        if not isinstance(row, dict) or set(row) != set(STORE_ROW_KEYS) or row["store"] != name:
            raise SpecError("stores", "row shape")
        sel, fixed, by = row["selected"], row["fixed"], row["by"]
        if not isinstance(sel, bool) or fixed is not (len(allowed) == 1) or (fixed and not sel):
            raise SpecError("stores", "selected/fixed")
        if by not in BY_VALUES or (by is None) == sel or (by == "history" and kind != "api_key"):
            raise SpecError("stores", "by")
        if row["reason"] is not None and not is_reason_text(row["reason"]):
            raise SpecError("stores", "reason must be one line of 1-120 characters")
        if not isinstance(row["needed"], bool):
            raise SpecError("stores", "needed must be true or false")
    if allowed and not any(r["selected"] for r in rows):
        raise SpecError("stores", "at least one store must be selected")


# --- keychain names (plan 3.2) ----------------------------------------------------------------------------------

def parse_keychain_items(raw) -> tuple[list[dict], list[dict]]:
    """The plugin setting ``keychain_items`` (plan 3.2 rule 1) as ``(items, warnings)``. Items that break a rule,
    items whose ``service`` starts with ``hermes-secure-input.`` and later items repeating an ``id`` are left out;
    each one gives a warning ``{"index", "field"}`` (never the field's value). Only the first
    ``MAX_KEYCHAIN_ITEMS`` items that keep the rules are used; the rest are left out with one warning
    ``{"index": <first one left out>, "field": "limit"}`` (security review 3 N-4)."""
    if raw is None:
        return [], []
    if not isinstance(raw, list):
        return [], [{"index": None, "field": "keychain_items"}]
    items: list[dict] = []
    warnings: list[dict] = []
    seen: set[str] = set()
    for index, item in enumerate(raw):
        bad = None
        if not isinstance(item, dict) or set(item) != set(ALLOW_ITEM_KEYS):
            bad = "item"
        elif not isinstance(item["id"], str) or not KEYCHAIN_ID_RE.fullmatch(item["id"]):
            bad = "id"
        elif not isinstance(item["service"], str) or not KEYCHAIN_NAME_RE.fullmatch(item["service"]) \
                or item["service"].startswith(KEYCHAIN_SERVICE_PREFIX):
            bad = "service"
        elif not isinstance(item["account"], str) or not KEYCHAIN_NAME_RE.fullmatch(item["account"]):
            bad = "account"
        elif not is_reason_text(item["label"]):
            bad = "label"
        elif not is_reason_text(item["used_by"]):
            bad = "used_by"
        elif item["id"] in seen:
            bad = "id"
        if bad is not None:
            warnings.append({"index": index, "field": bad})
            continue
        if len(items) == MAX_KEYCHAIN_ITEMS:  # N-4: this and every later item is left out, one warning
            warnings.append({"index": index, "field": "limit"})
            break
        seen.add(item["id"])
        items.append({k: item[k] for k in ALLOW_ITEM_KEYS})
    return items, warnings


def _new_item(name: str) -> dict:
    return {"id": name, "service": KEYCHAIN_SERVICE_PREFIX + name, "account": KEYCHAIN_FIXED_ACCOUNT,
            "listed": False, "label": None, "used_by": None}


_NO_NAME = {"id": None, "service": None, "account": None, "listed": False, "label": None, "used_by": None}


def _clashing_item(name: str, allow) -> Optional[dict]:
    low = name.lower()
    return next((i for i in allow if low in (i["service"].lower(), i["account"].lower())), None)


def resolve_keychain(kind: str, keychain_item, *, env_var: Optional[str] = None, allow=(),
                     keychain_chosen: bool = False) -> Optional[dict]:
    """The ``RequestSpec.keychain`` value for ``kind`` (plan 3.2 rules 3-8). ``allow`` is the parsed allow list
    (:func:`parse_keychain_items`). ``keychain_chosen``: the agent put ``keychain`` in ``stores`` (rule 7).

    Returns ``None`` for kinds without the keychain store. Raises :class:`KeychainItemError` for rules 3, 4, 7
    and 8 and ``SpecError`` when ``login`` or ``otp_code`` gets a ``keychain_item``."""
    if "keychain" not in KIND_STORES.get(kind, ()):
        if keychain_item is not None:
            raise SpecError("keychain_item", "only for api_key and secret")
        return None
    allow = list(allow or ())
    if keychain_item is None and kind == "api_key":
        name = env_var.lower().replace("_", "-") if isinstance(env_var, str) else None
        usable = (name is not None and KEYCHAIN_ID_RE.fullmatch(name) is not None
                  and not any(i["id"] == name for i in allow) and _clashing_item(name, allow) is None)
        if usable:
            return _new_item(name)
        if keychain_chosen:
            raise KeychainItemError(7, "the default keychain name cannot be used; pass keychain_item")
        return dict(_NO_NAME)
    if not isinstance(keychain_item, str):
        raise KeychainItemError(8, "required: a name matching ^[a-z0-9][a-z0-9-]{0,39}$")
    listed = next((i for i in allow if i["id"] == keychain_item), None)
    if listed is not None:
        if kind != "secret":
            raise KeychainItemError(3, "an allow-list item is only for kind secret", listed_id=listed["id"])
        return dict(listed, listed=True)
    clash = _clashing_item(keychain_item, allow)
    if clash is not None:
        raise KeychainItemError(4, "this name belongs to an allow-list item", listed_id=clash["id"])
    if KEYCHAIN_ID_RE.fullmatch(keychain_item):
        return _new_item(keychain_item)
    raise KeychainItemError(8, "must match ^[a-z0-9][a-z0-9-]{0,39}$")


def _check_keychain(kind: str, kc) -> None:
    if not isinstance(kc, dict) or set(kc) != set(KEYCHAIN_KEYS) or not isinstance(kc["listed"], bool):
        raise SpecError("keychain", "shape")
    if kc["listed"]:
        ok = (kind == "secret" and isinstance(kc["id"], str) and KEYCHAIN_ID_RE.fullmatch(kc["id"])
              and isinstance(kc["service"], str) and KEYCHAIN_NAME_RE.fullmatch(kc["service"])
              and not kc["service"].startswith(KEYCHAIN_SERVICE_PREFIX)
              and isinstance(kc["account"], str) and KEYCHAIN_NAME_RE.fullmatch(kc["account"])
              and is_reason_text(kc["label"]) and is_reason_text(kc["used_by"]))
    elif kc["id"] is None:
        ok = kind == "api_key" and kc == _NO_NAME
    else:
        ok = (isinstance(kc["id"], str) and KEYCHAIN_ID_RE.fullmatch(kc["id"]) is not None
              and kc == _new_item(kc["id"]))
    if not ok:
        raise SpecError("keychain", "not a name plan 3.2 allows")


def _is_https_origin(value: Any) -> bool:
    if not isinstance(value, str) or not value.startswith("https://"):
        return False
    try:
        parts = urlsplit(value)
        _ = parts.port
    except ValueError:
        return False
    return (parts.scheme == "https" and bool(parts.hostname) and parts.path in ("",)
            and not parts.query and not parts.fragment and not parts.username and not parts.password)


def normalize_origin(value: str) -> str:
    """``https://<punycode host>[:port]`` for an https URL (path, query and fragment dropped; port 443
    dropped). The host goes through ``host.encode("idna")`` so a look-alike non-ASCII host is shown and
    stored as its ``xn--`` form. Raises ``SpecError("origin", ...)`` when that is not possible."""
    if not isinstance(value, str) or not value.startswith("https://"):
        raise SpecError("origin", "must be an https:// address")
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError:
        raise SpecError("origin", "must be an https:// address") from None
    host = parts.hostname
    if parts.scheme != "https" or not host or parts.username is not None or parts.password is not None:
        raise SpecError("origin", "must be an https:// address with a host")
    try:
        ascii_host = host.encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError):
        raise SpecError("origin", "host cannot be converted to ASCII (punycode)") from None
    if ":" in ascii_host:  # IPv6 literal
        ascii_host = f"[{ascii_host}]"
    return f"https://{ascii_host}" + (f":{port}" if port and port != 443 else "")


def normalize_hostname(value: str) -> str:
    """A bare host name in its ASCII (punycode) form, lower-cased. Raises ``SpecError("site", ...)``."""
    if not isinstance(value, str) or not value:
        raise SpecError("site", "must be a host name")
    try:
        return value.encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError):
        raise SpecError("site", "host cannot be converted to ASCII (punycode)") from None


@dataclass(frozen=True)
class RequestSpec:
    kind: str
    purpose: str
    label: str
    requester: dict = field(hash=False)
    target_profile: str
    profile_editable: bool
    hermes_root: str
    env_var: Optional[str] = None
    origin: Optional[str] = None
    site: Optional[str] = None
    # Appendix A.5. ``None`` at construction means "the kind's defaults": the rows of build_store_rows(kind) and,
    # for api_key, the default keychain name with an empty allow list (secret must pass ``keychain``).
    stores: Optional[list] = field(default=None, hash=False)
    keychain: Optional[dict] = field(default=None, hash=False)

    def __post_init__(self):
        if self.kind in KIND_STORES:
            if self.stores is None:
                object.__setattr__(self, "stores", build_store_rows(self.kind, None))
            if self.keychain is None and self.kind == "api_key":
                object.__setattr__(self, "keychain", resolve_keychain("api_key", None, env_var=self.env_var))
        self._validate()

    # -- construction -------------------------------------------------------
    @classmethod
    def from_dict(cls, data: dict) -> "RequestSpec":
        if not isinstance(data, dict):
            raise SpecError("spec", "must be an object")
        known = {"kind", "purpose", "label", "requester", "target_profile", "profile_editable",
                 "hermes_root", "env_var", "origin", "site", "stores", "keychain"}
        unknown = set(data) - known
        if unknown:
            raise SpecError(sorted(unknown)[0], "unknown field")
        for req in ("kind", "purpose", "label", "requester", "target_profile", "profile_editable", "hermes_root"):
            if req not in data:
                raise SpecError(req, "required")
        return cls(**{k: data.get(k) for k in known})

    def to_dict(self) -> dict:
        return asdict(self)

    # -- validation ---------------------------------------------------------
    def _validate(self) -> None:
        if self.kind not in KINDS:
            raise SpecError("kind", "must be api_key, login, secret or otp_code")
        for name, limit in (("purpose", 200), ("label", 80)):
            v = getattr(self, name)
            if not isinstance(v, str) or not v.strip() or len(v) > limit:
                raise SpecError(name, f"must be 1-{limit} characters")
            if not is_clean_single_line(v):
                raise SpecError(name, "must be one line without control characters")
            if has_format_char(v):  # review N-2: same rule as a store reason
                raise SpecError(name, "must not contain invisible format characters (Unicode Cf)")
        r = self.requester
        if not isinstance(r, dict) or set(r) != set(REQUESTER_KEYS):
            raise SpecError("requester", "must have exactly type, profile, platform, session_key, user_id")
        if r["type"] not in ("agent", "user"):
            raise SpecError("requester", "type must be agent or user")
        if not all(isinstance(r[k], str) for k in REQUESTER_KEYS):
            raise SpecError("requester", "all fields must be strings")
        if not PROFILE_NAME_RE.fullmatch(r["profile"]) and r["profile"] != "default":
            raise SpecError("requester", "invalid profile name")
        if not isinstance(self.target_profile, str) or not (
                self.target_profile == "default" or PROFILE_NAME_RE.fullmatch(self.target_profile)):
            raise SpecError("target_profile", "invalid profile name")
        if not isinstance(self.profile_editable, bool):
            raise SpecError("profile_editable", "must be a boolean")
        if not isinstance(self.hermes_root, str) or not Path(self.hermes_root).is_absolute():
            raise SpecError("hermes_root", "must be an absolute path")

        if self.kind == "api_key":
            if not isinstance(self.env_var, str) or not ENV_VAR_RE.fullmatch(self.env_var):
                raise SpecError("env_var", "must match ^[A-Z_][A-Z0-9_]*$")
            try:
                check_env_var_name(self.env_var)
            except ValueError:
                raise SpecError("env_var", "refused: this name cannot be written to .env") from None
        elif self.env_var is not None:
            raise SpecError("env_var", "only allowed for api_key")

        if self.kind == "login":
            if not _is_https_origin(self.origin):
                raise SpecError("origin", "must be an https:// origin without path")
            if not self.origin.isascii() or normalize_origin(self.origin) != self.origin:
                raise SpecError("origin", "must be the normalized ASCII (punycode) origin")
        elif self.origin is not None:
            raise SpecError("origin", "only allowed for login")

        if self.kind == "otp_code":
            if self.profile_editable:
                raise SpecError("profile_editable", "must be false for otp_code")
            if not isinstance(self.site, str) or not self.site.isascii() or not HOSTNAME_RE.fullmatch(self.site):
                raise SpecError("site", "must be a host name")
        elif self.site is not None:
            raise SpecError("site", "only allowed for otp_code")

        _check_store_rows(self.kind, self.stores)
        if "keychain" in KIND_STORES[self.kind]:
            _check_keychain(self.kind, self.keychain)
        elif self.keychain is not None:
            raise SpecError("keychain", "only allowed for api_key and secret")
