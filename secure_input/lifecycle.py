"""Request state machine (docs/protocol.md 3, 4, 6; plan 5.7, appendix A.2). Pure logic, injectable clock.

created -> opened -> saving -> saved | delivered | expired | cancelled | failed

``saving`` is not terminal. While saving, the submit-window watch (:meth:`Lifecycle.tick`), the parent going away
and SIGTERM (:meth:`Lifecycle.abort`) only record a *deferred end reason* (the first one is kept); the screen's
cancel and a second submit are refused with ``saving_in_progress``. :meth:`Lifecycle.end_saving` applies the
result of the storage process (A.2 "저장 프로세스가 끝났을 때의 갈림").
"""

from __future__ import annotations

import hmac
import threading
from typing import Callable, Optional

from .config import MAX_SUBMIT_ATTEMPTS, OPEN_TTL_S, SUBMIT_TTL_S

TERMINAL = frozenset({"saved", "delivered", "expired", "cancelled", "failed"})

HTTP_STATUS = {
    "already_opened": 410,
    "expired": 410,
    "bad_sid": 403,
    "decrypt_failed": 400,
    "invalid_payload": 400,
    "storage_failed": 422,
    "masked_value": 422,
    "replayed": 409,
    "deadline_passed": 410,
    "too_many_attempts": 429,
    "already_submitted": 409,
    "saving_in_progress": 409,
    "store_unavailable": 422,
}


class LifecycleError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code
        self.status = HTTP_STATUS[code]


class Lifecycle:
    def __init__(self, clock: Callable[[], float], open_ttl: float = OPEN_TTL_S, submit_ttl: float = SUBMIT_TTL_S):
        self._clock = clock
        self.open_ttl = open_ttl
        self.submit_ttl = submit_ttl
        self._lock = threading.RLock()
        self.created_at = clock()
        self.opened_at: Optional[float] = None
        self.state = "created"
        self.failures = 0
        self.detail: Optional[str] = None
        self.deferred: Optional[tuple[str, str]] = None  # (expired|cancelled, detail) recorded while saving
        # RC-2: a value sent was not saved and the request stayed opened (end_saving "retry", note_failed_save)
        self.failed_save = False
        self._sid: Optional[bytes] = None
        self._seen: set[tuple[bytes, bytes]] = set()

    # -- queries --------------------------------------------------------------
    @property
    def is_terminal(self) -> bool:
        return self.state in TERMINAL

    def _open_window_ok(self, now: float) -> bool:
        return now - self.created_at <= self.open_ttl

    def _submit_window_ok(self, now: float) -> bool:
        return self.opened_at is not None and now - self.opened_at <= self.submit_ttl

    def _window_reason(self) -> str:
        """End reason of an opened request whose submit window passed: a value sent was not saved and could be
        sent again (``end_saving("retry")`` went back to ``opened``, or ``note_failed_save``: the server refused a
        submit with ``masked_value`` or a profile error ``storage_failed`` before saving) and no other submit
        reached saving (RC-2), or no such submit at all."""
        return "window_passed_after_failed_save" if self.failed_save else "submit_window_passed"

    def restart_open_clock(self) -> None:
        """Start the 60 s open window now (A.6: after the create-time check, just before ``ready``)."""
        with self._lock:
            if self.state == "created":
                self.created_at = self._clock()

    def tick(self) -> bool:
        """Expire if a window has passed. Returns True when this call made the state terminal. While saving, a
        passed submit window is only recorded as the deferred reason."""
        with self._lock:
            now = self._clock()
            if self.state == "created" and not self._open_window_ok(now):
                return self._finish("expired", "open_window_passed")
            if self.state == "opened" and not self._submit_window_ok(now):
                return self._finish("expired", self._window_reason())
            if self.state == "saving" and not self._submit_window_ok(now):
                self._defer("expired", "submit_window_passed")
            return False

    def page_allowed(self) -> bool:
        self.tick()
        return self.state in ("created", "opened", "saving")

    # -- transitions -----------------------------------------------------------
    def _finish(self, state: str, detail: Optional[str] = None) -> bool:
        if self.is_terminal:
            return False
        self.state = state
        self.detail = detail
        self._sid = None
        return True

    def _defer(self, state: str, detail: str) -> None:
        if self.deferred is None:
            self.deferred = (state, detail)

    def open(self, sid: bytes) -> float:
        with self._lock:
            if self.state == "expired" and self.opened_at is None:
                raise LifecycleError("expired")
            if self.state != "created":
                raise LifecycleError("already_opened")
            now = self._clock()
            if not self._open_window_ok(now):
                self._finish("expired", "open_window_passed")
                raise LifecycleError("expired")
            self.state = "opened"
            self.opened_at = now
            self._sid = sid
            return now

    def _sid_ok(self, sid: bytes) -> bool:
        return self._sid is not None and isinstance(sid, bytes) and hmac.compare_digest(self._sid, sid)

    def check_submit(self, sid: bytes) -> None:
        with self._lock:
            if self.state == "saving":
                raise LifecycleError("saving_in_progress")
            if self.state in ("saved", "delivered"):
                raise LifecycleError("already_submitted")
            if self.state == "failed":
                raise LifecycleError("too_many_attempts")
            if self.state in ("expired", "cancelled"):
                raise LifecycleError("deadline_passed")
            if self.state == "created":
                raise LifecycleError("bad_sid")
            if not self._submit_window_ok(self._clock()):
                self._finish("expired", self._window_reason())
                raise LifecycleError("deadline_passed")
            if not self._sid_ok(sid):
                raise LifecycleError("bad_sid")

    def mark_seen(self, client_public: bytes, iv: bytes) -> None:
        with self._lock:
            pair = (bytes(client_public), bytes(iv))
            if pair in self._seen:
                raise LifecycleError("replayed")
            self._seen.add(pair)

    def record_failure(self, code: str) -> str:
        """Count a failed submit. Returns the code to answer with (``too_many_attempts`` on the 5th)."""
        with self._lock:
            if self.state != "opened":
                return code
            self.failures += 1
            if self.failures >= MAX_SUBMIT_ATTEMPTS:
                self._finish("failed", "too_many_attempts")
                return "too_many_attempts"
            return code

    def note_failed_save(self) -> None:
        """RC-2: the server answered a submit with ``masked_value`` or ``storage_failed`` (not result unknown)
        before saving began, and the request stays ``opened``: the user sent a value that was not saved, as after
        ``end_saving("retry")``. Marks only an ``opened`` request."""
        with self._lock:
            if self.state == "opened":
                self.failed_save = True

    def begin_saving(self) -> None:
        """``opened`` -> ``saving``: the submit passed every check and the storage process is about to start."""
        with self._lock:
            if self.state != "opened":
                raise LifecycleError("deadline_passed" if self.is_terminal else "bad_sid")
            self.state = "saving"
            self.deferred = None

    def end_saving(self, result: str, detail: Optional[str] = None) -> str:
        """Apply the storage process' result (A.2). ``result``: ``saved`` (one store or more saved), ``failed``
        (nothing saved for sure and one result unknown; ``detail`` ``store_timeout`` or ``no_result``) or
        ``retry`` (nothing saved: pre-write check failed, masked value, every store refused). ``retry`` goes
        back to ``opened`` inside the window; outside it (a deferred reason, or the submit window passed) the
        request ends with a deferred cancel (``cancelled``), else ``expired``/``window_passed_while_saving``: the
        user did submit in time, the window passed while saving. Returns the new state."""
        assert result in ("saved", "failed", "retry")
        with self._lock:
            if self.state != "saving":
                return self.state
            self.state = "opened"  # every branch leaves saving; _finish below needs a non-terminal state
            if result == "saved":
                self._finish("saved")
            elif result == "failed":
                self._finish("failed", detail)
            elif self.deferred is not None and self.deferred[0] == "cancelled":
                self._finish(*self.deferred)
            elif self.deferred is not None or not self._submit_window_ok(self._clock()):
                self._finish("expired", "window_passed_while_saving")
            else:
                self.failed_save = True  # back in opened: a passed window now ends window_passed_after_failed_save
            return self.state

    def succeed(self, status: str) -> None:
        assert status in ("saved", "delivered")
        with self._lock:
            self._finish(status)

    def cancel(self, sid: bytes) -> None:
        with self._lock:
            if self.state == "saving":
                raise LifecycleError("saving_in_progress")
            if self.is_terminal:
                raise LifecycleError("deadline_passed")
            if not self._sid_ok(sid):
                raise LifecycleError("bad_sid")
            self._finish("cancelled", "user_cancelled")

    def abort(self, state: str, detail: Optional[str] = None) -> bool:
        """Force a terminal state (parent gone, signal, internal error). While saving only the deferred reason
        (``expired`` or ``cancelled``) is recorded and False is returned."""
        assert state in TERMINAL
        with self._lock:
            if self.state == "saving":
                if state in ("expired", "cancelled") and detail:
                    self._defer(state, detail)
                return False
            return self._finish(state, detail)
