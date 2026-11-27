"""Per-request HTTP server (docs/protocol.md 3-6, 9; plan appendix A.2-A.9).

Run as ``python -m secure_input.server`` by :mod:`secure_input.launcher`. The first stdin line
is the JSON config; stdin then stays open and EOF means the parent is gone. stdout carries
exactly two JSON lines: ``ready`` and ``done``. Nothing secret is ever written to stderr.

A submit that passes every check moves the request to ``saving`` and hands the save to a *storage thread*
(:meth:`ServerContext.start_save`). That thread runs the storage process and applies its result to the request
state, the audit log and the parent's outcome; the submit coroutine only sends the answer it gets back. SIGTERM
is handled by :func:`main` itself (uvicorn's signal capture is turned off): while saving it is only the deferred
end reason; otherwise the request ends ``cancelled``/``terminated``. Either way the server writes ``done`` and
exits 0.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import contextlib
import json
import mimetypes
import os
import signal
import socket
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import unquote

from .audit import AuditLog
from .config import (KIND_STORES, LOGIN_IDENTIFIER_TYPES, MAX_BODY_BYTES, OPEN_TTL_S, PROTOCOL_VERSION,
                     SECURITY_HEADERS, STORE_NAMES, SUBMIT_TTL_S)
from .crypto import CryptoFormatError, DecryptError, ServerKey, b64u_decode, b64u_encode
from .lifecycle import HTTP_STATUS, Lifecycle, LifecycleError
from .profiles import ProfileError, list_profiles, resolve_profile_home
from .spec import RequestSpec
from .storage import _masked_value_check, run_storage, save_outcome
from .stores import placements
from .stores.base import PARENT_ONLY_FIELDS
from .notify import tmp_may_be_left
from .validation import is_clean_single_line, is_keychain_value

MESSAGES = {
    "already_opened": "이 링크는 이미 열렸습니다. 새 링크를 요청하세요.",
    "expired": "링크가 만료되었습니다. 새 링크를 요청하세요.",
    "bad_sid": "세션이 맞지 않습니다. 페이지를 새로 열어 주세요.",
    "decrypt_failed": "암호화된 값을 풀지 못했습니다. 다시 제출해 주세요.",
    "invalid_payload": "입력 형식이 올바르지 않습니다. 입력값을 확인해 주세요.",
    "storage_failed": "값을 저장하지 못했습니다. 다시 시도해 주세요.",
    "masked_value": "가려진 값처럼 보여 저장하지 않았습니다. 원래 키 전체를 붙여 넣어 주세요.",
    "replayed": "이미 받은 제출입니다. 다시 제출해 주세요.",
    "deadline_passed": "제출 시간이 지났습니다. 새 링크를 요청하세요.",
    "too_many_attempts": "실패가 너무 많아 이 요청을 끝냈습니다. 새 링크를 요청하세요.",
    "already_submitted": "이미 제출이 끝난 요청입니다.",
    "saving_in_progress": "저장 중입니다. 저장이 끝날 때까지 기다려 주세요.",
    "store_unavailable": "지금 쓸 수 없는 저장 위치가 있어 아무 데도 저장하지 않았습니다.",
    "not_found": "찾을 수 없습니다.",
    "gone": "이 링크는 더 이상 쓸 수 없습니다.",
    "bad_origin": "허용되지 않은 출처의 요청입니다.",
    "unsupported_media_type": "JSON 요청만 받습니다.",
    "payload_too_large": "요청이 너무 큽니다.",
    "method_not_allowed": "허용되지 않은 요청 방식입니다.",
    "internal_error": "서버 오류가 났습니다. 다시 시도해 주세요.",
    "identity_required": "Tailscale 계정을 확인할 수 없는 접속입니다. Tailscale에 로그인한 기기에서 링크를 여세요.",
    "identity_not_allowed": "이 Tailscale 계정으로는 이 링크를 쓸 수 없습니다. 요청한 사람의 계정으로 로그인한 기기에서 여세요.",
}
EXTRA_STATUS = {"not_found": 404, "gone": 410, "bad_origin": 403, "unsupported_media_type": 415,
                "payload_too_large": 413, "method_not_allowed": 405, "internal_error": 500,
                "identity_required": 403, "identity_not_allowed": 403}
IDENTITY_HEADER = "tailscale-user-login"
MAX_DENIAL_AUDIT_LINES = 5  # per request: later identity denials are answered but not logged

MAX_VALUE_CHARS = 8192


class PayloadError(ValueError):
    pass


def normalize_login(value) -> str:
    """Tailscale login names compare without surrounding spaces and case (``Alice@Example.com`` == ``alice@example.com``)."""
    return value.strip().lower() if isinstance(value, str) else ""


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _wall_now() -> datetime:
    return datetime.now(timezone.utc).astimezone()


def _error_body(code: str) -> tuple[int, dict]:
    return HTTP_STATUS.get(code) or EXTRA_STATUS[code], {"ok": False, "error_code": code, "message": MESSAGES[code]}


def _public_row(row: dict) -> dict:
    """A.8: the parent-only fields of the vault row stay out of the page's answer."""
    return {k: v for k, v in row.items() if k not in PARENT_ONLY_FIELDS}


def _audit_row(row: dict) -> dict:
    """Plan 5.6: per store ``saved``, ``replaced``, ``error`` (and the keychain's ``main_touched``, A.2/A.13,
    ``main_created``, RC-1: the main write may have made the item, and ``tmp_left``, R3-3: a temporary item that
    may still hold the new value)."""
    out = {k: row[k] for k in ("store", "saved", "replaced", "error")}
    if row["store"] == "keychain":
        out["main_touched"] = row.get("main_touched")
        out["main_created"] = row.get("main_created")
        out["tmp_left"] = row.get("tmp_left")
    return out


TerminalCallback = Callable[[str, dict, Optional[str]], None]
StoreFn = Callable[[Path, dict], dict]  # run_storage(python, home, request) with python bound
_NO_RESULT = {"preflight": {}, "stores": {}, "done": None, "timed_out": False}


class ServerContext:
    """Everything one request's server needs. Secrets live only in memory here."""

    def __init__(self, spec: RequestSpec, *, token: str, request_id: str, static_dir, public_host: str, port: int,
                 clock: Callable[[], float] = time.monotonic, wall: Callable[[], datetime] = _wall_now,
                 store: Optional[StoreFn] = None, on_terminal: Optional[TerminalCallback] = None,
                 python: str = sys.executable, profiles: Optional[list[str]] = None,
                 ttls: Optional[dict] = None, allowed_logins: Optional[list[str]] = None,
                 allow_no_identity_header: bool = False, masked_check: Optional[Callable] = None):
        self.spec = spec
        self.allow_no_identity_header = allow_no_identity_header is True
        self.allowed_logins = frozenset(n for n in (normalize_login(x) for x in (allowed_logins or ())) if n)
        self.denials_logged = 0
        self.token = token
        self.request_id = request_id
        self.static_dir = Path(static_dir).resolve()
        self.public_host = public_host
        self.port = port
        self.prefix = f"/{token}/"
        self.allowed_origins = {f"https://{public_host}", f"http://127.0.0.1:{port}"}
        ttls = ttls or {}
        # Test-only overrides may shorten the windows, never lengthen them past the contract.
        self.lc = Lifecycle(clock, open_ttl=min(float(ttls.get("open", OPEN_TTL_S)), OPEN_TTL_S),
                            submit_ttl=min(float(ttls.get("submit", SUBMIT_TTL_S)), SUBMIT_TTL_S))
        self.key = ServerKey()
        self.wall = wall
        self.profiles = profiles if profiles is not None else list_profiles(spec.hermes_root)
        self.store: StoreFn = store or (lambda home, req: run_storage(python, home, req))
        self.masked_check = masked_check or _masked_value_check  # returns Hermes' check or None
        self.on_terminal = on_terminal
        self.audit = AuditLog(spec, token, request_id, now=wall)
        self.submit_lock = asyncio.Lock()
        self._terminal_lock = threading.Lock()
        # Held from the end of a save to its report, and by tick/abort: the supervisor cannot report in between.
        self._end_lock = threading.RLock()
        self.terminal_reported = False
        # Create-time check (A.6): until it ran, a store counts as available with an unknown ``exists``.
        self.store_status = {s: {"available": True, "reason": None, "exists": None} for s in KIND_STORES[spec.kind]}
        self.save_thread: Optional[threading.Thread] = None
        self.written_rows: Optional[list] = None  # rows of the last save that reached the write phase (A.13)
        self.made_items: set = set()  # keychain services a failed save of this request made (RC-1)
        # RC2-1: what any save of this request left in its keychain item, for the end report (memory only).
        self.kc_left = {"main_touched": False, "main_created": False, "tmp_left": False}

    def __repr__(self) -> str:
        return f"ServerContext(request_id={self.request_id})"

    # -- terminal handling ----------------------------------------------------------
    def report_terminal(self, *, meta: Optional[dict] = None, code: Optional[str] = None,
                        profile: Optional[str] = None, detail: Optional[dict] = None) -> bool:
        """Audit the terminal state once and notify the owner. Returns True the first time."""
        with self._terminal_lock:
            if not self.lc.is_terminal or self.terminal_reported:
                return False
            self.terminal_reported = True
        state = self.lc.state
        det = dict(detail or {})
        if self.lc.detail and "reason" not in det:
            det["reason"] = self.lc.detail
        left = self.keychain_left()
        if left is not None:
            det["keychain_left"] = left
        self.audit.write(state, detail=det, profile=profile)
        full: dict = {"request_id": self.request_id, "kind": self.spec.kind, "label": self.spec.label,
                      "target_profile": profile or self.spec.target_profile}
        full.update(meta or {})
        if self.written_rows is not None:
            full.setdefault("stores", self.written_rows)
        if left is not None:
            full["keychain_left"] = dict(left)
        if state not in ("saved", "delivered"):
            full.setdefault("reason", self.lc.detail)
        if self.on_terminal:
            self.on_terminal(state, full, code)
        return True

    def report_end(self) -> bool:
        """The argument-less report of a page call that found the request ended: under ``_end_lock``, so a save
        that just ended is reported by its storage thread, with its stores, partial and profile."""
        with self._end_lock:
            return self.report_terminal()

    def tick(self) -> bool:
        with self._end_lock:
            self.lc.tick()
            return self.report_terminal()

    def abort(self, state: str, reason: str) -> bool:
        """End the request (parent gone, SIGTERM, internal error). While saving this only records the deferred
        reason and returns False."""
        with self._end_lock:
            self.lc.abort(state, reason)
            return self.report_terminal()

    # -- stores ------------------------------------------------------------------------
    def _store_fields(self, chosen) -> dict:
        """The naming fields of the chosen stores for the storage process (A.9). Never a value."""
        s = self.spec
        out: dict = {}
        if "env" in chosen:
            out["env_var"] = s.env_var
        if "hermes_vault" in chosen:
            out.update(label=s.label, origin=s.origin)
        if "keychain" in chosen:
            kc = s.keychain or {}
            out["keychain"] = (None if kc.get("id") is None
                               else {"service": kc["service"], "account": kc["account"], "listed": kc["listed"]})
        return out

    def run_create_preflight(self) -> None:
        """The create-time check (A.6): one storage process with ``phase: "preflight"`` over every store of the
        kind, in the requested profile, limited to ``PREFLIGHT_AT_CREATE_TIMEOUT_S``. A store without a check line
        is ``available: false``, ``store_timeout``. The 60 s open window starts when this returns."""
        chosen = list(KIND_STORES[self.spec.kind])
        if chosen:
            request = {"phase": "preflight", "kind": self.spec.kind, "stores": chosen, "request_id": self.request_id,
                       **self._store_fields(chosen)}
            missing = "store_timeout"
            try:
                raw = self.store(resolve_profile_home(self.spec.target_profile, self.spec.hermes_root), request)
            except ProfileError:
                raw, missing = _NO_RESULT, "bad_home"
            except Exception:  # health: allow BLE001 - the reason word only
                raw, missing = _NO_RESULT, "internal_error"
            for s in chosen:
                line = (raw.get("preflight") or {}).get(s)
                if line is None:
                    self.store_status[s] = {"available": False, "reason": missing, "exists": None}
                else:
                    ok = line.get("available") is True
                    self.store_status[s] = {"available": ok, "reason": None if ok else line.get("reason"),
                                            "exists": line.get("exists") if line.get("exists") in (True, False)
                                            else None}
        self.lc.restart_open_clock()

    def open_stores(self) -> list[dict]:
        """``target.stores`` of the open answer (A.6)."""
        kc = self.spec.keychain or {}
        out = []
        for row in self.spec.stores:
            name = row["store"]
            st = self.store_status[name]
            ident = {"env": self.spec.env_var, "hermes_vault": self.spec.origin, "keychain": kc.get("service")}[name]
            exists = st["exists"] if name == "env" or (name == "keychain" and kc.get("id") is not None) else None
            out.append(dict(row, scope="mac" if name == "keychain" else "profile", ident=ident,
                            available=st["available"], unavailable_reason=None if st["available"] else st["reason"],
                            exists=exists))
        return out

    def open_keychain(self) -> dict:
        """``target.keychain`` of the open answer (A.6)."""
        kc = self.spec.keychain
        exists = self.store_status["keychain"]["exists"]
        new_item = kc["id"] is not None and not kc["listed"] and exists is False
        return {"id": kc["id"], "service": kc["service"], "account": kc["account"], "listed": kc["listed"],
                "new_item": new_item, "label": kc["label"], "used_by": kc["used_by"]}

    def save_request(self, payload: dict, masked_checked: bool) -> dict:
        """The storage process' stdin for a submit (A.9). Holds the value: pass it on and drop it."""
        kind = self.spec.kind
        chosen = payload["stores"]
        req = {"phase": "save", "kind": kind, "stores": chosen, "request_id": self.request_id,
               **self._store_fields(chosen)}
        if kind == "api_key":
            req.update(env_var=self.spec.env_var, value=payload["value"], masked_check=masked_checked)
        elif kind == "secret":
            req["value"] = payload["value"]
        else:
            req.update({k: payload[k] for k in ("identifier_type", "identifier", "password", "otp_secret")})
        return req

    def _row_ident(self, profile: str) -> dict:
        kc = self.spec.keychain or {}
        return {"env": {"env_var": self.spec.env_var, "profile": profile},
                "hermes_vault": {"origin": self.spec.origin, "profile": profile},
                "keychain": {"service": kc.get("service"), "account": kc.get("account"),
                             "listed": kc.get("listed") is True}}

    def start_save(self, home: Path, request: dict, chosen: list, profile: str) -> concurrent.futures.Future:
        """Run the save in the storage thread. The future gets ``(http status, answer body)``."""
        fut: concurrent.futures.Future = concurrent.futures.Future()
        self.save_thread = threading.Thread(target=self._save_worker, args=(home, request, chosen, profile, fut),
                                            name="secure-input-save", daemon=True)
        self.save_thread.start()
        return fut

    def _save_worker(self, home: Path, request: dict, chosen: list, profile: str,
                     fut: concurrent.futures.Future) -> None:
        result = _error_body("internal_error")
        try:
            try:
                raw = self.store(home, request)
            except Exception:  # health: allow BLE001 - same as a storage process that said nothing
                raw = dict(_NO_RESULT)
            request.clear()
            with self._end_lock:
                result = self._apply_save(save_outcome(chosen, raw, self._row_ident(profile)), profile)
        except Exception:  # health: allow BLE001 - never leave the request in saving
            with self._end_lock:
                if self.lc.state == "saving":
                    self.lc.end_saving("failed", "no_result")
                    self.report_terminal(profile=profile)
        finally:
            fut.set_result(result)

    def _storage_of(self, rows: list, profile: str) -> tuple[dict, dict]:
        """The ``storage`` of the answer and of the parent's result (5.3, W-15): the first saved store in the
        order env, hermes_vault, keychain. The parent's copy keeps the vault's ``has_otp``, ``replaced``,
        ``replace_error``."""
        first = next(r for r in rows if r["saved"] is True)
        base = {"profile": profile, "origin": None, "env_var": None, "item_id": None}
        if first["store"] == "env":
            out = dict(base, type="env", env_var=first["env_var"])
            return out, dict(out)
        if first["store"] == "hermes_vault":
            out = dict(base, type="vault", origin=first["origin"], item_id=first["item_id"])
            return out, dict(out, has_otp=bool(first.get("has_otp")), replaced=first.get("replaced") is True,
                             replace_error=first.get("replace_error") is True)
        out = dict(base, type="keychain", service=first["service"], account=first["account"])
        return out, dict(out)

    def _record_placements(self, rows: list) -> None:
        s = self.spec
        key = placements.key_for(s.kind, env_var=s.env_var, origin=s.origin,
                                 keychain_item=(s.keychain or {}).get("id"))
        try:
            placements.record(s.hermes_root, key, rows, when=_iso(self.wall()))
        except OSError:
            pass

    def _mark_made_items(self, rows: list) -> None:
        """RC-1: a keychain item made by an earlier, failed save of this request (``main_created``) held no value
        before this request. A later save to it is reported as a new item: ``replaced`` false and, outside the
        allow list, ``new_item`` true. A later save to it that fails again is reported as the item made by this
        request: ``main_touched`` false (no earlier value could change) and ``main_created`` true, so the end
        result keeps saying the item was made. Kept in this process' memory only."""
        for r in rows:
            if r.get("store") != "keychain":
                continue
            made_before = r.get("service") in self.made_items
            if r.get("saved") is True and made_before:
                r["replaced"] = False
                if r.get("listed") is not True:
                    r["new_item"] = True
            elif r.get("saved") is not True and made_before:
                r["main_touched"], r["main_created"] = False, True
            elif r.get("main_created") is True:
                self.made_items.add(r.get("service"))

    def _note_keychain_left(self, rows: list) -> None:
        """RC2-1: keep, for the whole request, what this save's keychain line says it left. A line that did not
        save marks ``main_touched`` and ``main_created``; a line that saved clears both (the item now holds the
        value reported as saved). A temporary item that may be left (``notify.tmp_may_be_left``) stays marked."""
        for r in rows:
            if r.get("store") != "keychain":
                continue
            if r.get("saved") is True:
                self.kc_left["main_touched"] = self.kc_left["main_created"] = False
            else:
                for k in ("main_touched", "main_created"):
                    if r.get(k) is True:
                        self.kc_left[k] = True
            if tmp_may_be_left([r]):
                self.kc_left["tmp_left"] = True

    def keychain_left(self) -> Optional[dict]:
        """The end report's ``keychain_left`` (RC2-1): the request's keychain item by service and ``listed``, never
        its account, and the three facts. ``None`` when none of them holds."""
        if not any(self.kc_left.values()):
            return None
        kc = self.spec.keychain or {}
        return {"service": kc.get("service"), "listed": kc.get("listed") is True, **self.kc_left}

    def _apply_save(self, out: dict, profile: str) -> tuple[int, dict]:
        """A.2 "저장 프로세스가 끝났을 때의 갈림" for the storage thread: request state, log, parent result, answer."""
        cat, rows = out["category"], out["rows"]
        self._mark_made_items(rows)
        self._note_keychain_left(rows)
        public = [_public_row(r) for r in rows]
        deferred = self.lc.deferred
        if out["wrote"]:
            self.written_rows = rows
        if cat in ("saved", "unknown"):
            detail: dict = {"stores": [_audit_row(r) for r in rows], "partial": out["partial"]}
            if deferred is not None:
                detail["deferred"] = deferred[0]
            if cat == "saved":
                self.lc.end_saving("saved")
                answer, kept = self._storage_of(rows, profile)
                self._record_placements(rows)
                self.report_terminal(meta={"partial": out["partial"], "stores": rows, "storage": kept},
                                     profile=profile, detail=detail)
                return 200, {"ok": True, "result": {"status": "saved", "partial": out["partial"], "stores": public,
                                                    "storage": answer, "label": self.spec.label}}
            self.lc.end_saving("failed", out["detail"])
            self.report_terminal(meta={"partial": False, "stores": rows}, profile=profile, detail=detail)
            return 422, {"ok": False, "error_code": "storage_failed", "message": MESSAGES["storage_failed"],
                         "result_unknown": True, "stores": public}
        if self.lc.end_saving("retry") != "opened":  # outside the window: the deferred reason, or expired
            self.report_terminal(meta={"stores": rows} if out["wrote"] else None, profile=profile,
                                 detail={"stores": [_audit_row(r) for r in rows]} if out["wrote"] else None)
            return _error_body("deadline_passed")
        if cat == "unavailable":
            self.audit.write("failed", detail={"error_code": "store_unavailable", "stores": out["unavailable"],
                                               "attempt": self.lc.failures, "final": False}, profile=profile)
            return 422, {"ok": False, "error_code": "store_unavailable", "message": MESSAGES["store_unavailable"],
                         "stores": out["unavailable"]}
        if cat == "masked":
            return self.fail("masked_value", profile)
        return self.fail("storage_failed", profile, body_extra={"result_unknown": False, "stores": public},
                         audit_extra={"stores": [_audit_row(r) for r in rows]})

    def fail(self, code: str, profile: Optional[str], body_extra: Optional[dict] = None,
             audit_extra: Optional[dict] = None) -> tuple[int, dict]:
        """A failed submit that counts toward the five (A.3). Returns ``(status, body)``."""
        final = self.lc.record_failure(code)
        det = {"error_code": code, **(audit_extra or {}), "attempt": self.lc.failures, "final": False}
        if final == code:
            self.audit.write("failed", detail=det,
                             profile=profile if code in ("storage_failed", "masked_value") else None)
            status, body = _error_body(code)
            body.update(body_extra or {})
            return status, body
        det["final"] = True
        self.report_terminal(detail=det)
        return _error_body(final)

    # -- payload validation ------------------------------------------------------------
    def _check_stores(self, value) -> list[str]:
        """A.7: required, one or more, no repeats, a subset of the open answer's stores, every ``fixed`` one."""
        names = [r["store"] for r in self.spec.stores]
        fixed = {r["store"] for r in self.spec.stores if r["fixed"]}
        if (not isinstance(value, list) or not value or not all(isinstance(v, str) for v in value)
                or len(set(value)) != len(value) or not set(value) <= set(names) or not fixed <= set(value)):
            raise PayloadError("stores")
        return [s for s in STORE_NAMES if s in value]

    def validate_plain(self, raw: bytes) -> dict:
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise PayloadError("not json") from None
        if not isinstance(data, dict) or data.get("kind") != self.spec.kind:
            raise PayloadError("kind mismatch")
        kind = self.spec.kind

        def text(name: str, *, required: bool = True, limit: int = MAX_VALUE_CHARS, single_line: bool = True) -> str:
            v = data.get(name, "" if not required else None)
            if not isinstance(v, str) or (required and not v) or len(v) > limit or "\x00" in v:
                raise PayloadError(name)
            # One line as str.splitlines() sees it, no control/line/paragraph separators (S-2).
            # An optional field may stay empty.
            if single_line and v and not is_clean_single_line(v):
                raise PayloadError(name)
            return v

        if kind == "otp_code":
            if set(data) != {"kind", "code"}:
                raise PayloadError("fields")
            code = text("code", limit=64).strip()
            if not code or any(ord(c) < 32 or ord(c) == 127 for c in code):
                raise PayloadError("code")
            return {"kind": kind, "target_profile": self.spec.target_profile, "code": code}

        allowed = {"api_key": {"kind", "target_profile", "value", "stores"},
                   "secret": {"kind", "target_profile", "value", "stores"},
                   "login": {"kind", "target_profile", "identifier_type", "identifier", "password", "otp_secret",
                             "stores"}}[kind]
        required = allowed - ({"otp_secret"} if kind == "login" else set())
        if not required <= set(data) <= allowed:
            raise PayloadError("fields")
        profile = data.get("target_profile")
        if profile not in self.profiles:
            raise PayloadError("target_profile")
        if (not self.spec.profile_editable or kind == "secret") and profile != self.spec.target_profile:
            raise PayloadError("target_profile")  # A.7: the page sends the requested profile for secret
        stores = self._check_stores(data.get("stores"))
        if kind == "api_key":
            value = text("value")
            if not value.isascii():  # Hermes' save_env_value would silently drop non-ASCII characters
                raise PayloadError("value")
            return {"kind": kind, "target_profile": profile, "value": value, "stores": stores}
        if kind == "secret":
            if not is_keychain_value(data.get("value")):  # plan 3.1
                raise PayloadError("value")
            return {"kind": kind, "target_profile": profile, "value": data["value"], "stores": stores}
        if data.get("identifier_type") not in LOGIN_IDENTIFIER_TYPES:
            raise PayloadError("identifier_type")
        return {"kind": kind, "target_profile": profile, "identifier_type": data["identifier_type"],
                "identifier": text("identifier", limit=512).strip() or self._raise("identifier"),
                "password": text("password", limit=4096), "otp_secret": text("otp_secret", required=False, limit=1024),
                "stores": stores}

    @staticmethod
    def _raise(name: str):
        raise PayloadError(name)


# --- ASGI app --------------------------------------------------------------------------------

def _json_response(status: int, body: dict, background: Optional[Callable[[], Any]] = None):
    from starlette.background import BackgroundTask
    from starlette.responses import JSONResponse

    return JSONResponse(body, status_code=status, background=BackgroundTask(background) if background else None)


def _error(code: str, background=None):
    status, body = _error_body(code)
    return _json_response(status, body, background)


class SecurityHeaders:
    """Pure ASGI middleware: the 5.5 headers on every HTTP response, no Server header."""

    def __init__(self, app):
        self.app = app
        self._headers = [(k.lower().encode(), v.encode()) for k, v in SECURITY_HEADERS.items()]
        self._names = {k for k, _ in self._headers}

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        async def wrapped(message):
            if message["type"] == "http.response.start":
                hdrs = [(k, v) for k, v in message.get("headers", []) if k.lower() not in self._names
                        and k.lower() != b"server"]
                message = dict(message, headers=hdrs + self._headers)
            await send(message)

        return await self.app(scope, receive, wrapped)


def create_app(ctx: ServerContext, on_response_sent: Optional[Callable[[], None]] = None):
    """Build the ASGI app. ``on_response_sent`` runs after any response that ended the request."""
    from starlette.requests import Request
    from starlette.responses import FileResponse, PlainTextResponse

    def after_terminal():
        return on_response_sent if (ctx.lc.is_terminal and on_response_sent) else None

    async def read_json(request: Request):
        ctype = request.headers.get("content-type", "").split(";")[0].strip().lower()
        if ctype != "application/json":
            return None, _error("unsupported_media_type")
        origin = request.headers.get("origin")
        if origin is not None and origin not in ctx.allowed_origins:
            return None, _error("bad_origin")
        try:
            declared = int(request.headers.get("content-length", "0") or 0)
        except ValueError:
            declared = 0
        if declared > MAX_BODY_BYTES:
            return None, _error("payload_too_large")
        chunks, total = [], 0
        async for chunk in request.stream():
            total += len(chunk)
            if total > MAX_BODY_BYTES:
                return None, _error("payload_too_large")
            chunks.append(chunk)
        try:
            data = json.loads(b"".join(chunks).decode("utf-8") or "null")
        except (UnicodeDecodeError, ValueError):
            data = None
        if not isinstance(data, dict):
            return None, _error("invalid_payload")
        return data, None

    def serve_static(rel: str):
        if not ctx.lc.page_allowed():
            ctx.report_end()
            return PlainTextResponse(MESSAGES["gone"], status_code=410, background=_bg(after_terminal()))
        rel = rel or "index.html"
        parts = rel.split("/")
        if any(p in ("", ".", "..") or p.startswith(".") for p in parts):
            return _error("not_found")
        target = (ctx.static_dir / rel).resolve()
        try:
            target.relative_to(ctx.static_dir)
        except ValueError:
            return _error("not_found")
        if not target.is_file():
            return _error("not_found")
        media = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        if media.startswith("text/") or media in ("application/javascript",):
            media += "; charset=utf-8"
        return FileResponse(target, media_type=media)

    async def api_open():
        sid = os.urandom(32)
        try:
            opened = ctx.lc.open(sid)
        except LifecycleError as exc:
            ctx.report_end()
            return _error(exc.code, after_terminal())
        del opened
        opened_at = ctx.wall()
        ctx.audit.write("opened")
        s = ctx.spec
        target = {"profile": s.target_profile, "profiles": list(ctx.profiles),
                  "profile_editable": s.profile_editable, "env_var": s.env_var, "origin": s.origin,
                  "site": s.site, "stores": ctx.open_stores()}
        if "keychain" in KIND_STORES[s.kind]:
            target["keychain"] = ctx.open_keychain()
        return _json_response(200, {
            "v": PROTOCOL_VERSION, "request_id": ctx.request_id, "kind": s.kind,
            "purpose": s.purpose, "label": s.label,
            "requester": {"type": s.requester["type"], "profile": s.requester["profile"]},
            "target": target,
            "server_public_key": ctx.key.public_b64, "sid": b64u_encode(sid),
            "submit_deadline_s": int(ctx.lc.submit_ttl), "opened_at": _iso(opened_at)})

    def saving_refusal():
        """A.2: a second submit while saving is answered at once, never queued behind ``submit_lock``."""
        ctx.audit.write("failed", detail={"error_code": "saving_in_progress", "attempt": ctx.lc.failures,
                                          "final": False})
        return _error("saving_in_progress")

    async def api_submit(body: dict):
        if ctx.lc.state == "saving":
            return saving_refusal()
        async with ctx.submit_lock:
            if ctx.lc.state == "saving":
                return saving_refusal()
            fut, answer = await _checked_submit(body)
        if fut is not None:
            answer = await asyncio.wrap_future(fut)
        status, payload = answer
        return _json_response(status, payload, after_terminal())

    async def _checked_submit(body: dict):
        """Every check of a submit, then ``saving`` and the storage thread. Returns ``(future, None)`` once the
        save runs, else ``(None, (status, body))``."""
        ctx.audit.write("submitted", detail={"attempt": ctx.lc.failures + 1})
        chosen: Optional[str] = None
        try:
            try:
                sid = b64u_decode(body.get("sid"), length=32)
            except CryptoFormatError:
                sid = b""
            ctx.lc.check_submit(sid)
            if body.get("v") != PROTOCOL_VERSION:
                raise PayloadError("v")
            cpub = b64u_decode(body.get("client_public_key"), length=65)
            iv = b64u_decode(body.get("iv"), length=12)
            ct = b64u_decode(body.get("ciphertext"))
            if len(ct) < 17:
                raise PayloadError("ciphertext")
            ctx.lc.mark_seen(cpub, iv)
            plain = ctx.key.decrypt(cpub, sid, iv, ct, ctx.request_id.encode("utf-8"))
            try:
                payload = ctx.validate_plain(plain)
            finally:
                plain = b""
            chosen = payload["target_profile"]
            s = ctx.spec
            if s.kind == "otp_code":
                ctx.lc.succeed("delivered")
                storage = {"profile": chosen, "origin": None, "env_var": None, "item_id": None,
                           "type": "browser_page"}
                ctx.report_terminal(meta={"storage": {"type": "browser_page", "site": s.site}},
                                    code=payload["code"], profile=chosen)
                payload = None
                return None, (200, {"ok": True, "result": {"status": "delivered", "storage": storage,
                                                           "label": s.label}})
            masked_checked = False
            if s.kind == "api_key":  # plan 5.2: before saving, in this process, stdout kept for ready/done
                refuse = ctx.masked_check()
                if refuse is not None:
                    masked_checked = True
                    try:
                        with contextlib.redirect_stdout(sys.stderr):
                            refuse(s.env_var, payload["value"])
                    except ValueError:
                        payload = None
                        answer = ctx.fail("masked_value", chosen)
                        ctx.lc.note_failed_save()  # RC-2: a value was sent and not saved (opened only)
                        return None, answer
                    except Exception:  # health: allow BLE001 - the storage process checks again
                        masked_checked = False
            try:
                home = resolve_profile_home(chosen, s.hermes_root)
            except ProfileError:
                payload = None
                answer = ctx.fail("storage_failed", chosen, body_extra={"result_unknown": False, "stores": []})
                ctx.lc.note_failed_save()  # RC-2: a value was sent and not saved (opened only)
                return None, answer
            request = ctx.save_request(payload, masked_checked)
            stores = list(payload["stores"])
            payload = None
            ctx.lc.begin_saving()
            ctx.audit.write("saving", detail={"stores": stores}, profile=chosen)
            fut = ctx.start_save(home, request, stores, chosen)
            request = None
            return fut, None
        except LifecycleError as exc:
            failure = exc.code if exc.code in ("bad_sid", "replayed") else None
            if failure is None:
                ctx.report_end()
                return None, _error_body(exc.code)
            return None, ctx.fail(failure, chosen)
        except (CryptoFormatError, PayloadError):
            return None, ctx.fail("invalid_payload", chosen)
        except DecryptError:
            return None, ctx.fail("decrypt_failed", chosen)

    async def api_cancel(body: dict):
        try:
            sid = b64u_decode(body.get("sid"), length=32)
        except CryptoFormatError:
            sid = b""
        try:
            ctx.lc.cancel(sid)
        except LifecycleError as exc:
            return _error(exc.code)
        ctx.report_terminal()
        return _json_response(200, {"ok": True, "result": {"status": "cancelled"}}, after_terminal())

    def check_identity(request: Request) -> Optional[str]:
        """Error code when the Tailscale account that sent this API call may not use the link."""
        values = request.headers.getlist(IDENTITY_HEADER)
        if not values:
            return None if ctx.allow_no_identity_header else "identity_required"
        if len(values) != 1 or normalize_login(values[0]) not in ctx.allowed_logins:
            return "identity_not_allowed"
        return None

    async def app(scope, receive, send):
        if scope["type"] != "http":
            return
        request = Request(scope, receive)
        response = await dispatch(request)
        await response(scope, receive, send)

    async def dispatch(request: Request):
        try:
            path = request.scope.get("path", "")
            if not path.startswith(ctx.prefix):
                return _error("not_found")
            rel = path[len(ctx.prefix):]
            if rel.startswith("api/") or rel == "api":
                denied = check_identity(request)
                if denied is not None:
                    # Not consumed, not counted as a failed attempt; the account name is never logged.
                    if ctx.denials_logged < MAX_DENIAL_AUDIT_LINES:
                        ctx.denials_logged += 1
                        ctx.audit.write("open_denied", detail={"reason": denied})
                    return _error(denied)
                if request.method != "POST":
                    return _error("method_not_allowed")
                name = rel[len("api/"):]
                if name not in ("open", "submit", "cancel"):
                    return _error("not_found")
                body, err = await read_json(request)
                if err is not None:
                    return err
                if name == "open":
                    return await api_open()
                if name == "submit":
                    return await api_submit(body)
                return await api_cancel(body)
            if request.method not in ("GET", "HEAD"):
                return _error("method_not_allowed")
            return serve_static(unquote(rel))
        except Exception:  # never leak details (or values) through tracebacks
            return _error("internal_error")

    return SecurityHeaders(app)


def _bg(fn):
    from starlette.background import BackgroundTask

    return BackgroundTask(fn) if fn else None


# --- process entry point -------------------------------------------------------------------------

def _emit(obj: dict) -> None:
    """One result line for the parent. A parent that is gone (closed pipe) must not end the calling thread:
    the supervise loop then sees the missing parent and ends the request."""
    try:
        sys.stdout.write(json.dumps(obj) + "\n")
        sys.stdout.flush()
    except (OSError, ValueError):
        pass


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def main() -> int:
    import uvicorn

    from .serve import ServeError, ServeManager

    class _Server(uvicorn.Server):
        """uvicorn re-raises SIGTERM after shutdown (0.41.0 ``capture_signals``), so the process would die with
        -15 and no ``done`` line (A.2 "종료 신호 처리"). This server leaves the signals to :func:`main`."""

        @contextlib.contextmanager
        def capture_signals(self):
            yield

    sigterm = threading.Event()
    # The handler only raises a flag; the supervisor thread acts on it (no locks taken inside a signal handler).
    signal.signal(signal.SIGTERM, lambda signum, frame: sigterm.set())

    line = sys.stdin.readline()
    cfg = json.loads(line)
    line = ""
    spec = RequestSpec.from_dict(cfg["spec"])
    token, request_id = cfg["token"], cfg["request_id"]
    parent_pid = int(cfg["parent_pid"])
    active_file = Path(cfg["active_file"]) if cfg.get("active_file") else None
    serve = ServeManager(bin=cfg.get("tailscale_bin"))

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(64)
    port = sock.getsockname()[1]

    outcome: dict = {}
    stop = threading.Event()

    def on_terminal(status, meta, code):
        outcome.update(status=status, meta=meta, code=code)

    ctx = ServerContext(spec, token=token, request_id=request_id, static_dir=cfg["static_dir"],
                        public_host=cfg["public_host"], port=port, on_terminal=on_terminal,
                        python=cfg.get("python") or sys.executable, ttls=cfg.get("ttls"),
                        allowed_logins=[x for x in cfg.get("allowed_logins") or [] if isinstance(x, str)],
                        allow_no_identity_header=cfg.get("allow_no_identity_header") is True)

    config = uvicorn.Config(create_app(ctx, on_response_sent=stop.set), log_level="warning", access_log=False,
                            server_header=False, date_header=False, lifespan="off", ws="none",
                            timeout_graceful_shutdown=1, timeout_keep_alive=2)
    server = _Server(config)

    serve_added = False
    try:
        serve.add(token, port)
        serve_added = True
    except ServeError as exc:
        ctx.abort("failed", "serve_add_failed")
        sys.stderr.write(f"secure-input: {exc}\n")
    else:
        ctx.audit.write("created", detail={"port": port})
        ctx.run_create_preflight()  # before ready; the open window starts when it returns (A.6)

    stdin_closed = threading.Event()

    def watch_stdin():
        try:
            while sys.stdin.read(4096):
                pass
        except Exception:
            pass
        stdin_closed.set()

    def supervise():
        while not server.started and not server.should_exit and not sigterm.is_set():
            time.sleep(0.02)
        if server.started and not ctx.lc.is_terminal and not sigterm.is_set():
            _emit({"event": "ready", "url": f"https://{ctx.public_host}/{token}/", "request_id": request_id,
                   "port": port})
        while not server.should_exit:
            if stop.is_set():
                time.sleep(0.05)  # let the final response flush
                break
            # While saving, the three below only record the deferred reason (abort returns False).
            if sigterm.is_set() and ctx.abort("cancelled", "terminated"):
                break
            if ctx.tick():
                break
            if stdin_closed.is_set() or not _pid_alive(parent_pid) or os.getppid() != parent_pid:
                if ctx.abort("cancelled", "parent_gone"):
                    break
            if ctx.lc.is_terminal:
                break
            time.sleep(0.1)
        server.should_exit = True

    threading.Thread(target=watch_stdin, daemon=True).start()
    sup = threading.Thread(target=supervise, daemon=True)
    sup.start()
    if serve_added:
        try:
            server.run(sockets=[sock])
        except BaseException:
            pass
    server.should_exit = True
    if ctx.save_thread is not None:
        ctx.save_thread.join()  # the storage thread applies the result before done (A.2)
    if not ctx.lc.is_terminal:
        ctx.abort("cancelled", "terminated")
    removed = serve.remove(token) if serve_added else False
    ctx.audit.write("cleanup", detail={"serve_removed": removed, "by": "server"})
    if active_file is not None:
        try:
            active_file.unlink()
        except FileNotFoundError:
            pass
    done = {"event": "done", "status": outcome.get("status", ctx.lc.state), "meta": outcome.get("meta", {})}
    if outcome.get("code") is not None and done["status"] == "delivered":
        done["code"] = outcome["code"]
    _emit(done)
    outcome.clear()
    try:
        sock.close()
    except OSError:
        pass
    return 0


if __name__ == "__main__":
    code = main()
    sys.stdout.flush()
    os._exit(code)
