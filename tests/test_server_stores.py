"""The server with several stores and the ``saving`` state (plan 2.6, 5, appendix A.2-A.9, A.13).

In-process tests drive the ASGI app with a fake clock and a fake storage function (the dict
:func:`secure_input.storage.run_storage` returns). The real-process tests at the end start the real server
(``start_request``) with a fake ``tailscale`` binary and a python wrapper that slows the storage grandchild or puts
the fake keychain module (tests/helpers/fake_keychain.py) in it.
"""

from __future__ import annotations

import json
import os
import signal
import threading
import time
from pathlib import Path

import pytest

from helpers import fake_keychain
from helpers.browser_client import BrowserClient
from helpers.fake_tailscale import FAKE_OWNER_LOGIN
from secure_input import storage
from secure_input.audit import AUDIT_FIELDS, EVENTS
from secure_input.spec import RequestSpec, resolve_keychain
from test_lifecycle import FakeClock
from starlette.testclient import TestClient
from test_server_app import Harness

ALLOW = [{"id": "example-vault-password", "service": "example-unlock-item", "account": "example-unlock-item",
          "label": "Example Vault 비밀번호", "used_by": "Example Vault 자동 잠금 해제 스크립트"}]
KC_SERVICE = "hermes-secure-input.exa-api-key"


class FakeStorage:
    """Stands in for ``run_storage``. ``preflight``: per-store preflight line overrides; ``rows``: per-store
    ``store`` line (missing store = no line); ``during``: called inside the save, before it answers."""

    def __init__(self, *, preflight=None, rows=None, done=None, timed_out=False, during=None, create=None):
        self.preflight = preflight or {}
        self.rows = rows
        self.done = done
        self.timed_out = timed_out
        self.during = during
        self.create = create
        self.calls: list[dict] = []

    def __call__(self, home, request):
        self.calls.append({k: v for k, v in request.items() if k not in ("value", "password", "identifier",
                                                                            "otp_secret")})
        chosen = request["stores"]
        if request["phase"] == "preflight":
            if self.create is not None:
                return self.create(request)
            pre = {s: dict({"available": True, "reason": None, "exists": False}, **self.preflight.get(s, {}))
                   for s in chosen}
            return {"preflight": pre, "stores": {}, "done": {"event": "done", "ok": True}, "timed_out": False}
        if self.during is not None:
            self.during()
        if self.done and self.done.get("error") == "masked_value":
            return {"preflight": {}, "stores": {}, "done": self.done, "timed_out": False}
        pre = {s: dict({"available": True, "reason": None, "exists": False}, **self.preflight.get(s, {}))
               for s in chosen}
        if not all(p["available"] for p in pre.values()):
            return {"preflight": pre, "stores": {}, "done": {"event": "done", "ok": False,
                                                             "error": "store_unavailable"}, "timed_out": False}
        rows = self.rows if self.rows is not None else {s: {"saved": True, "replaced": False, "error": None}
                                                       for s in chosen}
        got = {s: dict(rows[s]) for s in chosen if s in rows}
        for s, r in got.items():
            if s == "env":
                r.setdefault("env_var", request.get("env_var"))
            elif s == "hermes_vault":
                r.setdefault("origin", request.get("origin"))
                r.setdefault("item_id", "item-1")
            else:
                r.update({k: (request.get("keychain") or {}).get(k) for k in ("service", "account", "listed")})
                r.setdefault("new_item", True)
                r.setdefault("tmp_left", False)
                r.setdefault("main_touched", r.get("saved") is True)
                r.setdefault("main_created", False)
        done = self.done if self.done is not None else ({"event": "done", "ok": True} if not self.timed_out
                                                         else None)
        return {"preflight": pre, "stores": got, "done": done, "timed_out": self.timed_out}


def spec_of(spec_dict, kind="api_key", **over):
    if kind == "secret":
        d = spec_dict(kind="secret", profile_editable=False, env_var=None,
                      keychain=resolve_keychain("secret", over.pop("keychain_item", "example-vault-password"),
                                                allow=ALLOW))
    elif kind == "api_key" and "stores" not in over:
        d = spec_dict()
        d["stores"] = [{"store": "env", "selected": True, "fixed": False, "by": "default", "reason": None,
                        "needed": False},
                       {"store": "keychain", "selected": True, "fixed": False, "by": "agent",
                        "reason": "이 Mac의 배포 스크립트가 키체인에서 읽습니다", "needed": True}]
    else:
        d = spec_dict(kind=kind)
    d.update(over)
    return RequestSpec.from_dict(d)


def harness(spec_dict, static_dir, store=None, kind="api_key", clock=None, **kw):
    h = Harness(spec_of(spec_dict, kind, **kw), static_dir, clock=clock, store=store)
    return h


def audit(root: Path, profile="default") -> list[dict]:
    p = root / ("" if profile == "default" else f"profiles/{profile}") / "logs" / "secure-input.jsonl"
    return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []


def plain(kind="api_key", value="v", stores=("env", "keychain"), profile="default", **extra):
    d = {"kind": kind, "target_profile": profile}
    if kind in ("api_key", "secret"):
        d["value"] = value
    if stores is not None:
        d["stores"] = list(stores)
    d.update(extra)
    return d


def wait_until(pred, timeout=5.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(0.01)
    return False


# --- open answer (A.6) -----------------------------------------------------------------------------------------

def test_open_answer_lists_every_store_of_the_kind(spec_dict, static_dir):
    h = harness(spec_dict, static_dir, store=FakeStorage(preflight={"env": {"exists": True}}))
    h.ctx.run_create_preflight()
    body = h.client.open().json()
    assert body["v"] == 2
    assert body["target"]["stores"] == [
        {"store": "env", "selected": True, "fixed": False, "by": "default", "reason": None, "needed": False,
         "scope": "profile", "ident": "EXA_API_KEY", "available": True, "unavailable_reason": None, "exists": True},
        {"store": "keychain", "selected": True, "fixed": False, "by": "agent",
         "reason": "이 Mac의 배포 스크립트가 키체인에서 읽습니다", "needed": True, "scope": "mac", "ident": KC_SERVICE,
         "available": True, "unavailable_reason": None, "exists": False}]
    assert body["target"]["keychain"] == {"id": "exa-api-key", "service": KC_SERVICE,
                                          "account": "hermes-secure-input", "listed": False, "new_item": True,
                                          "label": None, "used_by": None}


def test_open_answer_for_a_listed_secret(spec_dict, static_dir):
    h = harness(spec_dict, static_dir, kind="secret", store=FakeStorage(preflight={"keychain": {"exists": True}}))
    h.ctx.run_create_preflight()
    t = h.client.open().json()["target"]
    assert t["stores"] == [{"store": "keychain", "selected": True, "fixed": True, "by": "default", "reason": None,
                            "needed": False, "scope": "mac", "ident": "example-unlock-item", "available": True,
                            "unavailable_reason": None, "exists": True}]
    assert t["keychain"] == {"id": "example-vault-password", "service": "example-unlock-item",
                             "account": "example-unlock-item", "listed": True, "new_item": False,
                             "label": "Example Vault 비밀번호", "used_by": "Example Vault 자동 잠금 해제 스크립트"}


def test_open_answer_login_and_otp(spec_dict, static_dir):
    h = harness(spec_dict, static_dir, kind="login", store=FakeStorage())
    h.ctx.run_create_preflight()
    t = h.client.open().json()["target"]
    assert [(r["store"], r["fixed"], r["scope"], r["ident"], r["exists"]) for r in t["stores"]] == [
        ("hermes_vault", True, "profile", "https://example.com", None)]
    assert "keychain" not in t
    h2 = harness(spec_dict, static_dir, kind="otp_code", store=FakeStorage())
    h2.ctx.run_create_preflight()
    t2 = h2.client.open().json()["target"]
    assert t2["stores"] == [] and "keychain" not in t2


def test_unusable_default_keychain_name(spec_dict, static_dir):
    h = harness(spec_dict, static_dir, env_var="_PRIVATE_KEY", stores=None,
                store=FakeStorage(preflight={"keychain": {"available": False, "reason": "keychain_name_invalid",
                                                          "exists": None}}))
    h.ctx.run_create_preflight()
    t = h.client.open().json()["target"]
    kc_row = t["stores"][1]
    assert kc_row["ident"] is None and kc_row["exists"] is None and kc_row["available"] is False
    assert kc_row["unavailable_reason"] == "keychain_name_invalid"
    assert t["keychain"] == {"id": None, "service": None, "account": None, "listed": False, "new_item": False,
                             "label": None, "used_by": None}
    assert h.ctx.store.calls[0]["keychain"] is None


def test_create_time_check_failure_and_time_out_show_on_the_page(spec_dict, static_dir):
    def create(request):
        return {"preflight": {"env": {"available": True, "reason": None, "exists": False}}, "stores": {},
                "done": None, "timed_out": True}

    h = harness(spec_dict, static_dir, store=FakeStorage(create=create))
    h.ctx.run_create_preflight()
    rows = h.client.open().json()["target"]["stores"]
    assert (rows[1]["available"], rows[1]["unavailable_reason"], rows[1]["exists"]) == (False, "store_timeout", None)
    req = h.ctx.store.calls[0]
    assert req == {"phase": "preflight", "kind": "api_key", "stores": ["env", "keychain"],
                   "request_id": h.ctx.request_id, "env_var": "EXA_API_KEY",
                   "keychain": {"service": KC_SERVICE, "account": "hermes-secure-input", "listed": False}}


@pytest.mark.parametrize("late", [59, 61])
def test_open_window_is_60_s_after_ready_even_with_a_slow_check(spec_dict, static_dir, late):
    clock = FakeClock()

    def slow(request):
        clock.advance(9.8)  # the create-time check used almost its 10 s
        return {"preflight": {s: {"available": True, "reason": None, "exists": False} for s in request["stores"]},
                "stores": {}, "done": {"event": "done", "ok": True}, "timed_out": False}

    h = harness(spec_dict, static_dir, store=FakeStorage(create=slow), clock=clock)
    h.ctx.run_create_preflight()
    clock.advance(late)
    r = h.client.open()
    assert r.status_code == (200 if late == 59 else 410)


# --- submitted store list (plan 2.6, A.7) ------------------------------------------------------------------------

@pytest.mark.parametrize("kind,stores", [
    ("api_key", None),                       # missing
    ("api_key", []),                         # empty
    ("api_key", ["env", "env"]),             # twice
    ("api_key", ["example_vault"]),            # unknown
    ("api_key", ["hermes_vault"]),           # not in the open answer
    ("api_key", "env"),                      # not a list
    ("secret", []),                          # the fixed store left out
    ("secret", ["env"]),
    ("login", ["keychain"]),
])
def test_bad_store_list_is_invalid_payload(spec_dict, static_dir, canary, kind, stores):
    fake = FakeStorage()
    h = harness(spec_dict, static_dir, kind=kind, store=fake)
    h.client.open()
    extra = {"identifier_type": "email", "identifier": "me@example.com", "password": canary} if kind == "login" else {}
    r = h.client.submit(plain(kind, canary, stores=stores, **extra), auto_stores=False)
    assert r.status_code == 400 and r.json()["error_code"] == "invalid_payload"
    assert [c["phase"] for c in fake.calls] == []
    assert h.ctx.lc.failures == 1 and h.ctx.lc.state == "opened"


def test_login_without_the_fixed_store_is_invalid_payload(spec_dict, static_dir, canary):
    h = harness(spec_dict, static_dir, kind="login", store=FakeStorage())
    h.client.open()
    r = h.client.submit({"kind": "login", "target_profile": "default", "identifier_type": "email",
                         "identifier": "me@example.com", "password": canary, "stores": []}, auto_stores=False)
    assert r.json()["error_code"] == "invalid_payload"


def test_unavailable_store_may_still_be_sent_and_goes_to_the_pre_write_check(spec_dict, static_dir, canary):
    fake = FakeStorage(preflight={"keychain": {"available": False, "reason": "keychain_unavailable"}})
    h = harness(spec_dict, static_dir, store=fake)
    h.ctx.run_create_preflight()
    h.client.open()
    r = h.client.submit(plain(value=canary))
    assert r.status_code == 422 and r.json()["error_code"] == "store_unavailable"


@pytest.mark.parametrize("value", ["한글비밀번호", "x" * 1025, " lead", "trail ", "tab\there", ""])
def test_secret_value_rule_is_invalid_payload(spec_dict, static_dir, value):
    fake = FakeStorage()
    h = harness(spec_dict, static_dir, kind="secret", store=fake)
    h.client.open()
    r = h.client.submit(plain("secret", value, stores=["keychain"]))
    assert r.status_code == 400 and r.json()["error_code"] == "invalid_payload"
    assert [c["phase"] for c in fake.calls] == []


def test_secret_target_profile_is_the_requested_one(spec_dict, static_dir, canary):
    h = harness(spec_dict, static_dir, kind="secret", store=FakeStorage())
    h.client.open()
    r = h.client.submit(plain("secret", canary, stores=["keychain"], profile="worker"))
    assert r.json()["error_code"] == "invalid_payload"


# --- results (5.3, A.8, A.13) ----------------------------------------------------------------------------------

def test_all_saved_answer_result_and_log(spec_dict, static_dir, hermes_root, canary):
    fake = FakeStorage()
    h = harness(spec_dict, static_dir, store=fake)
    h.client.open()
    r = h.client.submit(plain(value=canary))
    assert r.status_code == 200, r.text
    env_row = {"store": "env", "saved": True, "replaced": False, "error": None, "env_var": "EXA_API_KEY",
               "profile": "default"}
    kc_row = {"store": "keychain", "saved": True, "replaced": False, "error": None, "service": KC_SERVICE,
              "account": "hermes-secure-input", "listed": False, "new_item": True, "tmp_left": False,
              "main_touched": True, "main_created": False}
    storage_ = {"profile": "default", "origin": None, "env_var": "EXA_API_KEY", "item_id": None, "type": "env"}
    assert r.json() == {"ok": True, "result": {"status": "saved", "partial": False, "stores": [env_row, kc_row],
                                               "storage": storage_, "label": "Exa API key"}}
    status, meta, _code = h.terminal[0]
    assert status == "saved" and meta["partial"] is False and meta["stores"] == [env_row, kc_row]
    assert meta["storage"] == storage_
    save_req = fake.calls[-1]
    assert save_req == {"phase": "save", "kind": "api_key", "stores": ["env", "keychain"],
                        "request_id": h.ctx.request_id, "env_var": "EXA_API_KEY", "masked_check": True,
                        "keychain": {"service": KC_SERVICE, "account": "hermes-secure-input", "listed": False}}
    lines = audit(hermes_root)
    events = [x["event"] for x in lines]
    assert events[-3:] == ["submitted", "saving", "saved"]
    saving_line, saved_line = lines[-2], lines[-1]
    assert saving_line["detail"] == {"stores": ["env", "keychain"]}
    assert saved_line["detail"] == {"stores": [
        {"store": "env", "saved": True, "replaced": False, "error": None},
        {"store": "keychain", "saved": True, "replaced": False, "error": None, "main_touched": True,
         "main_created": False,          "tmp_left": False}],
        "partial": False}
    assert all(set(x) == set(AUDIT_FIELDS) for x in lines) and "saving" in EVENTS
    assert lines[-1]["stores"] == [
        {"store": "env", "selected": True, "by": "default", "reason": None, "needed": False, "env_var": "EXA_API_KEY"},
        {"store": "keychain", "selected": True, "by": "agent", "reason": "이 Mac의 배포 스크립트가 키체인에서 읽습니다",
         "needed": True, "service": KC_SERVICE, "account": "hermes-secure-input"}]
    assert canary not in json.dumps(lines) and canary not in r.text


def test_partial_save_answer_result_and_log(spec_dict, static_dir, hermes_root, canary):
    fake = FakeStorage(rows={"env": {"saved": True, "replaced": True, "error": None},
                             "keychain": {"saved": False, "replaced": None, "error": "keychain_write_failed",
                                          "main_touched": True}})
    h = harness(spec_dict, static_dir, store=fake)
    h.client.open()
    r = h.client.submit(plain(value=canary))
    res = r.json()["result"]
    assert r.status_code == 200 and res["status"] == "saved" and res["partial"] is True
    assert [(x["store"], x["saved"], x["replaced"], x["error"]) for x in res["stores"]] == [
        ("env", True, True, None), ("keychain", False, None, "keychain_write_failed")]
    assert res["storage"]["type"] == "env"
    status, meta, _ = h.terminal[0]
    assert status == "saved" and meta["partial"] is True
    assert meta["stores"][1] == {"store": "keychain", "saved": False, "replaced": None,
                                 "error": "keychain_write_failed", "service": KC_SERVICE,
                                 "account": "hermes-secure-input", "listed": False, "new_item": True,
                                 "tmp_left": False, "main_touched": True, "main_created": False}
    assert audit(hermes_root)[-1]["detail"]["partial"] is True


def test_keychain_only_api_key_points_storage_at_the_keychain(spec_dict, static_dir, canary):
    h = harness(spec_dict, static_dir, store=FakeStorage())
    h.client.open()
    res = h.client.submit(plain(value=canary, stores=["keychain"])).json()["result"]
    assert res["storage"] == {"profile": "default", "origin": None, "env_var": None, "item_id": None,
                              "type": "keychain", "service": KC_SERVICE, "account": "hermes-secure-input"}
    assert [x["store"] for x in res["stores"]] == ["keychain"]


def test_vault_row_keeps_parent_only_fields_out_of_the_page_answer(spec_dict, static_dir, canary):
    fake = FakeStorage(rows={"hermes_vault": {"saved": True, "replaced": True, "error": None, "has_otp": True,
                                              "removed_count": 1, "replace_error": False}})
    h = harness(spec_dict, static_dir, kind="login", store=fake)
    h.client.open()
    res = h.client.submit({"kind": "login", "target_profile": "default", "identifier_type": "email",
                           "identifier": "me@example.com", "password": canary}).json()["result"]
    assert res["stores"] == [{"store": "hermes_vault", "saved": True, "replaced": True, "error": None,
                              "origin": "https://example.com", "item_id": "item-1", "profile": "default"}]
    assert res["storage"] == {"profile": "default", "origin": "https://example.com", "env_var": None,
                              "item_id": "item-1", "type": "vault"}
    meta = h.terminal[0][1]
    assert meta["stores"][0]["has_otp"] is True and meta["stores"][0]["removed_count"] == 1
    assert meta["storage"]["has_otp"] is True and meta["storage"]["replaced"] is True


def test_pre_write_check_failure_writes_nothing_and_is_not_counted(spec_dict, static_dir, hermes_root, canary):
    fake = FakeStorage(preflight={"keychain": {"available": False, "reason": "keychain_acl_denied", "exists": True}})
    h = harness(spec_dict, static_dir, store=fake)
    h.client.open()
    for _ in range(6):  # more than five: none of them counts
        r = h.client.submit(plain(value=canary))
        assert r.status_code == 422 and r.json() == {
            "ok": False, "error_code": "store_unavailable", "message": r.json()["message"],
            "stores": [{"store": "keychain", "reason": "keychain_acl_denied"}]}
    assert h.ctx.lc.state == "opened" and h.ctx.lc.failures == 0 and not h.terminal
    failed = [x for x in audit(hermes_root) if x["event"] == "failed"]
    assert failed[-1]["detail"] == {"error_code": "store_unavailable",
                                    "stores": [{"store": "keychain", "reason": "keychain_acl_denied"}],
                                    "attempt": 0, "final": False}
    fake.preflight = {}
    r = h.client.submit(plain(value=canary, stores=["env"]))  # the user turned the keychain off
    assert r.status_code == 200 and r.json()["result"]["stores"][0]["store"] == "env"


def test_pre_write_check_failure_writes_nowhere_through_the_real_storage_process(
        spec_dict, static_dir, hermes_root, canary, tmp_path, monkeypatch):
    monkeypatch.setenv("FAKE_KEYCHAIN_CONFIG", json.dumps(
        {"preflight": {"available": False, "reason": "keychain_acl_denied", "exists": True},
         "log": str(tmp_path / "kc.jsonl")}))
    python = fake_keychain.storage_python(tmp_path / "py")
    from secure_input.server import ServerContext, create_app  # noqa: F401
    h = harness(spec_dict, static_dir)
    h.ctx.store = lambda home, req: storage.run_storage(str(python), home, req)
    h.client.open()
    r = h.client.submit(plain(value=canary))
    assert r.json()["error_code"] == "store_unavailable" and h.ctx.lc.failures == 0
    assert not (hermes_root / ".env").exists()
    calls = [json.loads(x)["fn"] for x in (tmp_path / "kc.jsonl").read_text().splitlines()]
    assert calls == ["preflight"]


def test_nothing_saved_is_storage_failed_counted_and_retryable(spec_dict, static_dir, hermes_root, canary):
    fake = FakeStorage(rows={"env": {"saved": False, "error": "env_write_failed"},
                             "keychain": {"saved": False, "error": "keychain_write_failed", "main_touched": True}})
    h = harness(spec_dict, static_dir, store=fake)
    h.client.open()
    r = h.client.submit(plain(value=canary))
    body = r.json()
    assert r.status_code == 422 and body["error_code"] == "storage_failed" and body["result_unknown"] is False
    assert [(x["store"], x["saved"]) for x in body["stores"]] == [("env", False), ("keychain", False)]
    assert h.ctx.lc.state == "opened" and h.ctx.lc.failures == 1
    failed = [x for x in audit(hermes_root) if x["event"] == "failed"][-1]
    assert failed["detail"]["error_code"] == "storage_failed" and failed["detail"]["stores"][1]["main_touched"] is True


def test_result_unknown_ends_the_request_failed(spec_dict, static_dir, hermes_root, canary):
    fake = FakeStorage(rows={"env": {"saved": False, "error": "env_write_failed"}}, timed_out=True)
    h = harness(spec_dict, static_dir, store=fake)
    h.client.open()
    r = h.client.submit(plain(value=canary))
    body = r.json()
    assert r.status_code == 422 and body["error_code"] == "storage_failed" and body["result_unknown"] is True
    assert body["stores"][1]["saved"] is None and body["stores"][1]["error"] == "store_timeout"
    status, meta, _ = h.terminal[0]
    assert status == "failed" and meta["reason"] == "store_timeout" and meta["stores"][1]["error"] == "store_timeout"
    last = audit(hermes_root)[-1]
    assert last["event"] == "failed" and last["detail"]["reason"] == "store_timeout"


def test_profile_error_answer_has_result_unknown_and_empty_stores(spec_dict, static_dir, canary, monkeypatch):
    import secure_input.server as srv
    from secure_input.profiles import ProfileError

    def broken(*a, **k):
        raise ProfileError("x")

    h = harness(spec_dict, static_dir, store=FakeStorage())
    h.client.open()
    monkeypatch.setattr(srv, "resolve_profile_home", broken)
    r = h.client.submit(plain(value=canary))
    assert r.status_code == 422 and r.json()["error_code"] == "storage_failed"
    assert r.json()["result_unknown"] is False and r.json()["stores"] == []


def test_server_masked_check_answers_before_saving(spec_dict, static_dir, canary):
    fake = FakeStorage()
    h = harness(spec_dict, static_dir, store=fake)
    h.client.open()
    r = h.client.submit(plain(value="sk-abc...wxyz"))
    assert r.status_code == 422 and r.json()["error_code"] == "masked_value"
    assert [c["phase"] for c in fake.calls] == [] and h.ctx.lc.failures == 1


def test_masked_check_falls_to_the_storage_process_when_the_server_cannot(spec_dict, static_dir, canary):
    fake = FakeStorage(done={"event": "done", "ok": False, "error": "masked_value"})
    h = harness(spec_dict, static_dir, store=fake)
    h.ctx.masked_check = lambda: None
    h.client.open()
    r = h.client.submit(plain(value="sk-abc...wxyz"))
    assert r.status_code == 422 and r.json()["error_code"] == "masked_value"
    assert fake.calls[-1]["masked_check"] is False and h.ctx.lc.failures == 1 and h.ctx.lc.state == "opened"


def test_placements_record_saved_stores_without_values(spec_dict, static_dir, hermes_root, canary):
    h = harness(spec_dict, static_dir, store=FakeStorage(rows={"env": {"saved": True, "error": None},
                                                               "keychain": {"saved": False, "error": "x"}}))
    h.client.open()
    h.client.submit(plain(value=canary))
    text = (hermes_root / "secure-input" / "placements.json").read_text()
    data = json.loads(text)
    assert list(data) == ["api_key|EXA_API_KEY"] and list(data["api_key|EXA_API_KEY"]) == ["env"]
    assert canary not in text


# --- saving against the clock and the parent (5.7, criterion "저장 도중 시한 3가지") ---------------------------------

def test_a_submit_just_before_the_deadline_is_saved(spec_dict, static_dir, hermes_root, canary):
    clock = FakeClock()
    h = None

    def slow():
        clock.advance(25)  # the save outlives the submit window
        h.ctx.tick()       # the supervisor's tick sees the passed window while saving

    h = harness(spec_dict, static_dir, store=FakeStorage(during=slow), clock=clock)
    h.client.open()
    clock.advance(299)
    r = h.client.submit(plain(value=canary))
    assert r.status_code == 200 and r.json()["result"]["status"] == "saved"
    assert h.terminal[0][0] == "saved"
    last = audit(hermes_root)[-1]
    assert last["event"] == "saved" and last["detail"]["deferred"] == "expired"


def test_a_parent_cancel_while_saving_ends_saved(spec_dict, static_dir, hermes_root, canary):
    h = None

    def parent_gone():
        assert h.ctx.abort("cancelled", "parent_gone") is False

    h = harness(spec_dict, static_dir, store=FakeStorage(during=parent_gone))
    h.client.open()
    r = h.client.submit(plain(value=canary))
    assert r.status_code == 200 and h.terminal[0][0] == "saved"
    assert audit(hermes_root)[-1]["detail"]["deferred"] == "cancelled"


def test_a_retry_with_a_deferred_reason_ends_with_that_reason(spec_dict, static_dir, hermes_root, canary):
    h = None

    def parent_gone():
        h.ctx.abort("cancelled", "parent_gone")

    fake = FakeStorage(during=parent_gone, rows={"env": {"saved": False, "error": "env_write_failed"},
                                                 "keychain": {"saved": False, "error": "keychain_write_failed",
                                                              "main_touched": True}})
    h = harness(spec_dict, static_dir, store=fake)
    h.client.open()
    r = h.client.submit(plain(value=canary))
    assert r.status_code == 410 and r.json()["error_code"] == "deadline_passed"
    status, meta, _ = h.terminal[0]
    assert status == "cancelled" and meta["reason"] == "parent_gone"
    assert meta["stores"][1]["main_touched"] is True  # A.13: the write phase had started
    assert audit(hermes_root)[-1]["detail"]["stores"][1]["main_touched"] is True


def test_a_pre_write_failure_after_the_window_expires_without_stores(spec_dict, static_dir, canary):
    clock = FakeClock()
    fake = FakeStorage(preflight={"keychain": {"available": False, "reason": "keychain_unavailable"}},
                       during=lambda: clock.advance(400))
    h = harness(spec_dict, static_dir, store=fake, clock=clock)
    h.client.open()
    r = h.client.submit(plain(value=canary))
    assert r.status_code == 410
    status, meta, _ = h.terminal[0]
    assert (status, meta["reason"]) == ("expired", "window_passed_while_saving") and "stores" not in meta


def test_cancel_and_second_submit_while_saving_are_409_at_once(spec_dict, static_dir, hermes_root, canary):
    release = threading.Event()
    fake = FakeStorage(during=lambda: release.wait(20))
    h = harness(spec_dict, static_dir, store=fake)
    h.client.open()
    first = {}
    t = threading.Thread(target=lambda: first.update(r=h.client.submit(plain(value=canary))))
    t.start()
    try:
        assert wait_until(lambda: h.ctx.lc.state == "saving")
        t0 = time.monotonic()
        rc = h.client.cancel()
        r2 = h.client.submit(plain(value=canary + "-2"))
        took = time.monotonic() - t0
        assert (rc.status_code, rc.json()["error_code"]) == (409, "saving_in_progress")
        assert (r2.status_code, r2.json()["error_code"]) == (409, "saving_in_progress")
        assert took < 2.0 and t.is_alive()  # answered while the first save still runs
        assert h.ctx.lc.failures == 0 and h.ctx.lc.deferred is None
        r3 = h.client.post("api/open", {})
        assert (r3.status_code, r3.json()["error_code"]) == (410, "already_opened")
        assert h.client.get("").status_code == 200  # page reload while saving
    finally:
        release.set()
        t.join(20)
    assert first["r"].status_code == 200 and h.terminal[0][0] == "saved"


def test_the_save_thread_reports_without_the_request_coroutine(spec_dict, static_dir, hermes_root, canary):
    """A.2: the storage thread, not the submit coroutine, applies the result (a dropped connection still ends the
    request). The thread is started directly; nothing awaits its answer."""
    h = harness(spec_dict, static_dir, store=FakeStorage())
    h.client.open()
    h.ctx.lc.check_submit(h.ctx.lc._sid)
    h.ctx.lc.begin_saving()
    request = h.ctx.save_request(plain(value=canary), masked_checked=True)
    h.ctx.start_save(hermes_root, request, ["env", "keychain"], "default")
    h.ctx.save_thread.join(10)
    assert h.ctx.lc.state == "saved" and h.terminal and h.terminal[0][0] == "saved"
    assert audit(hermes_root)[-1]["event"] == "saved"


def test_secret_round_trip_with_the_fake_keychain(spec_dict, static_dir, hermes_root, canary, tmp_path, monkeypatch):
    db = tmp_path / "kc-db.json"
    monkeypatch.setenv("FAKE_KEYCHAIN_CONFIG", json.dumps({"db": str(db), "log": str(tmp_path / "kc.jsonl"),
                                                           "save": {"new_item": False, "replaced": True}}))
    python = fake_keychain.storage_python(tmp_path / "py")
    h = harness(spec_dict, static_dir, kind="secret")
    h.ctx.store = lambda home, req: storage.run_storage(str(python), home, req)
    h.ctx.run_create_preflight()
    h.client.open()
    r = h.client.submit(plain("secret", canary, stores=["keychain"]))
    assert r.status_code == 200, r.text
    assert r.json()["result"]["stores"][0]["service"] == "example-unlock-item"
    assert json.loads(db.read_text()) == {"example-unlock-item|example-unlock-item": canary}
    keys = [json.loads(x)["keys"] for x in (tmp_path / "kc.jsonl").read_text().splitlines()]
    assert keys[-1] == ["account", "listed", "request_id", "service", "value"]
    log_text = (hermes_root / "logs" / "secure-input.jsonl").read_text()
    assert canary not in log_text and canary not in r.text and canary not in json.dumps(h.terminal[0][1])


# --- launcher: the wait after a cancel is the kind's (A.1) ----------------------------------------------------

def test_cancel_grace_per_kind():
    from secure_input.launcher import cancel_grace_s

    assert {k: cancel_grace_s(k) for k in ("api_key", "login", "secret", "otp_code")} == {
        "api_key": 35.0, "login": 35.0, "secret": 25.0, "otp_code": 5.0}


def test_cancel_without_grace_waits_the_kinds_time_before_sigterm(spec_dict, hermes_root, tmp_path, monkeypatch):
    import subprocess

    from secure_input import launcher
    from secure_input.launcher import RequestHandle
    from secure_input.serve import ServeManager

    asked = []
    monkeypatch.setattr(launcher, "cancel_grace_s", lambda kind: asked.append(kind) or 0.5)
    spec = RequestSpec.from_dict(spec_dict(kind="otp_code"))
    proc = subprocess.Popen(["/bin/sleep", "60"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    fake_ts = tmp_path / "ts"
    fake_ts.write_text("#!/bin/sh\nexit 0\n")
    fake_ts.chmod(0o755)
    h = RequestHandle(spec, proc, "tok", "rid", "host", tmp_path / "active.json", ServeManager(bin=str(fake_ts)))
    t0 = time.monotonic()
    out = h.cancel()
    took = time.monotonic() - t0
    assert asked == ["otp_code"] and 0.4 <= took < 3.0  # the kind's wait, then SIGTERM ends `sleep`
    assert out.status == "failed" and out.meta["reason"] == "child_exited"
    assert h.returncode == -signal.SIGTERM


# === real server process (criteria: SIGTERM in created/opened/saving, parent cancel, 409, server killed) ============

from secure_input.launcher import start_request  # noqa: E402
from secure_input.serve import ServeManager  # noqa: E402


@pytest.fixture
def real(spec_dict, static_dir, fake_tailscale, hermes_root, tmp_path, monkeypatch):
    """Start real requests whose storage grandchild runs through the fake-keychain wrapper."""
    handles = []
    python = fake_keychain.storage_python(tmp_path / "py")

    def _start(config=None, **over):
        config = dict(config or {})
        if config.pop("gated", False):
            config["wrapper_gate_save"] = str(tmp_path / "release-save")
        monkeypatch.setenv("FAKE_KEYCHAIN_CONFIG", json.dumps(config))
        spec = RequestSpec.from_dict(spec_dict(**over))
        h = start_request(spec, static_dir=static_dir, serve=ServeManager(bin=str(fake_tailscale.bin)),
                          python=str(python))
        handles.append(h)
        return h, BrowserClient(h.local_url, identity=FAKE_OWNER_LOGIN, timeout=60.0)

    yield _start
    for h in handles:
        if not h.done:
            h.cancel(grace=1.0)


def release_save(root: Path, after: float = 1.0) -> None:
    """Let the gated save go on (``real(gated=True)``), after giving the server time to act on a signal."""
    time.sleep(after)
    (root.parent / "release-save").write_text("go")


def saving_started(root: Path) -> bool:
    return any(x["event"] == "saving" for x in audit(root))


def submit_in_background(client, value):
    box = {}

    def run():
        try:
            box["r"] = client.submit({"kind": "api_key", "target_profile": "default", "value": value})
        except Exception as exc:  # noqa: BLE001 - the connection may close when the server ends
            box["error"] = type(exc).__name__

    t = threading.Thread(target=run)
    t.start()
    return t, box


@pytest.mark.parametrize("state", ["created", "opened"])
def test_sigterm_before_saving_exits_0_with_done_and_cancelled(real, hermes_root, state):
    h, c = real()
    if state == "opened":
        assert c.open().status_code == 200
    os.kill(h.pid, signal.SIGTERM)
    out = h.wait(timeout=20)
    assert h.returncode == 0
    assert [e["event"] for e in h.events if e.get("event") == "done"] == ["done"]
    assert out.status == "cancelled" and out.meta["reason"] == "terminated"
    ended = [x for x in audit(hermes_root) if x["event"] == "cancelled"]
    assert len(ended) == 1 and ended[0]["detail"]["reason"] == "terminated"


def test_sigterm_while_saving_ends_saved_with_done_and_deferred_cancelled(real, hermes_root, canary):
    h, c = real({"gated": True})
    c.open()
    t, box = submit_in_background(c, canary)
    assert wait_until(lambda: saving_started(hermes_root), 10)
    os.kill(h.pid, signal.SIGTERM)
    release_save(hermes_root)
    out = h.wait(timeout=30)
    t.join(30)
    assert h.returncode == 0 and any(e.get("event") == "done" for e in h.events)
    assert out.status == "saved" and out.meta["stores"][0]["saved"] is True
    saved = [x for x in audit(hermes_root) if x["event"] == "saved"]
    assert len(saved) == 1 and saved[0]["detail"]["deferred"] == "cancelled"
    assert f"EXA_API_KEY={canary}" in (hermes_root / ".env").read_text()
    assert canary not in (hermes_root / "logs" / "secure-input.jsonl").read_text()
    assert canary not in h.stderr_text and canary not in json.dumps(h.events)


def test_parent_cancel_while_saving_ends_saved(real, hermes_root, canary):
    h, c = real({"gated": True})
    c.open()
    t, box = submit_in_background(c, canary)
    assert wait_until(lambda: saving_started(hermes_root), 10)
    t0 = time.monotonic()
    threading.Thread(target=release_save, args=(hermes_root, 2.0)).start()
    out = h.cancel()  # grace None: the kind's 35 s; the server ends as soon as the save is applied
    t.join(30)
    assert time.monotonic() - t0 < 15
    assert out.status == "saved" and h.returncode == 0
    assert [x for x in audit(hermes_root) if x["event"] == "saved"][0]["detail"]["deferred"] == "cancelled"
    assert box["r"].status_code == 200


def test_screen_cancel_and_second_submit_while_saving_are_409_at_once_on_the_real_server(real, hermes_root, canary):
    h, c = real({"gated": True})
    c.open()
    t, box = submit_in_background(c, canary)
    assert wait_until(lambda: saving_started(hermes_root), 10)
    t0 = time.monotonic()
    rc = c.cancel()
    r2 = c.submit({"kind": "api_key", "target_profile": "default", "value": canary + "-again"})
    took = time.monotonic() - t0
    assert (rc.status_code, rc.json()["error_code"]) == (409, "saving_in_progress")
    assert (r2.status_code, r2.json()["error_code"]) == (409, "saving_in_progress")
    assert took < 1.5 and t.is_alive()
    release_save(hermes_root, 0)
    out = h.wait(timeout=30)
    t.join(30)
    assert out.status == "saved" and box["r"].status_code == 200


def test_server_killed_while_saving_is_failed_child_exited(real, hermes_root, canary):
    h, c = real({"gated": True})
    c.open()
    t, box = submit_in_background(c, canary)
    assert wait_until(lambda: saving_started(hermes_root), 10)
    os.kill(h.pid, signal.SIGKILL)
    out = h.wait(timeout=20)
    release_save(hermes_root, 0)
    t.join(30)
    assert out.status == "failed" and out.meta["reason"] == "child_exited"
    assert not any(e.get("event") == "done" for e in h.events)
    time.sleep(1)  # the storage process lives on its own and may still write (A.2 last row)


def test_store_time_limit_through_the_server_leaves_no_child(spec_dict, static_dir, hermes_root, canary, tmp_path,
                                                             monkeypatch):
    pidfile = tmp_path / "child.pid"
    monkeypatch.setenv("FAKE_KEYCHAIN_CONFIG", json.dumps({"save_sleep": 60, "save_child_pidfile": str(pidfile)}))
    monkeypatch.setattr(storage, "STORE_TIMEOUT_S", {"env": 2.0, "hermes_vault": 2.0, "keychain": 2.0})
    python = fake_keychain.storage_python(tmp_path / "py")
    h = harness(spec_dict, static_dir)
    h.ctx.store = lambda home, req: storage.run_storage(str(python), home, req)
    h.client.open()
    r = h.client.submit(plain(value=canary))
    res = r.json()["result"]
    assert r.status_code == 200 and res["partial"] is True
    kc = res["stores"][1]
    assert (kc["saved"], kc["error"], kc["tmp_left"], kc["main_touched"]) == (None, "store_timeout", None, None)
    child = int(pidfile.read_text())
    assert wait_until(lambda: not _alive(child), 3)


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


# === scripts/e2e_real_driver.py speaks protocol 2 and handles secret ===============================================

import subprocess  # noqa: E402
import sys  # noqa: E402

from conftest import REPO_ROOT  # noqa: E402


def run_driver(kind, tmp_path, monkeypatch, submit, extra_args=()):
    db = tmp_path / "kc-db.json"
    monkeypatch.setenv("FAKE_KEYCHAIN_CONFIG", json.dumps({"db": str(db)}))
    python = fake_keychain.storage_python(tmp_path / "py")
    security = fake_keychain.fake_security(tmp_path / "sec", db)
    proc = subprocess.Popen([sys.executable, str(REPO_ROOT / "scripts" / "e2e_real_driver.py"), "--kind", kind,
                             "--python", str(python), "--security", str(security), *extra_args],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    ready = json.loads(proc.stdout.readline())
    assert ready["event"] == "ready", proc.stderr.read()
    client = BrowserClient(ready["local_url"], identity=FAKE_OWNER_LOGIN)
    opened = client.open().json()
    expect = submit(client, opened)
    proc.stdin.write(json.dumps({"expect": expect}) + "\n")
    proc.stdin.flush()
    out, err = proc.communicate(timeout=120)
    result = json.loads(out.splitlines()[-1])
    return result, opened, db, out + err


def test_driver_secret_round_trip(tmp_path, monkeypatch, canary):
    def submit(client, opened):
        assert opened["v"] == 2 and opened["kind"] == "secret"
        assert opened["target"]["stores"][0]["store"] == "keychain" and opened["target"]["stores"][0]["fixed"]
        assert opened["target"]["keychain"]["listed"] is True
        assert opened["target"]["keychain"]["service"].startswith("hermes-secure-input-test-")
        r = client.submit({"kind": "secret", "target_profile": "default", "value": canary, "stores": ["keychain"]})
        assert r.status_code == 200, r.text
        return {"value": canary}

    result, opened, db, text = run_driver("secret", tmp_path, monkeypatch, submit)
    assert result["status"] == "saved" and result["checks"] and all(result["checks"].values()), result
    assert {"keychain_value_matches", "keychain_item_removed", "no_canary_outside_env_and_vault"} <= set(
        result["checks"])
    assert json.loads(db.read_text()) == {}  # the driver removed its test item
    assert canary not in text


def test_driver_api_key_sends_stores(tmp_path, monkeypatch, canary):
    sent = {}

    def submit(client, opened):
        body = client.build_submit({"kind": "api_key", "target_profile": "default", "value": canary})
        sent["v"] = body["v"]
        r = client.post("api/submit", body)
        assert r.status_code == 200, r.text
        return {"value": canary}

    result, opened, db, text = run_driver("api_key", tmp_path, monkeypatch, submit)
    assert sent["v"] == 2 and result["status"] == "saved" and all(result["checks"].values()), result
    assert [r["store"] for r in opened["target"]["stores"]] == ["env", "keychain"]


# --- the supervisor's tick/abort cannot take the storage thread's report (review round 1) -----------------------

def _tick_inside_record_placements(h, monkeypatch, also_abort=False):
    """Wedge the supervisor into the gap between ``end_saving`` and the storage thread's report: every call of
    ``_record_placements`` first runs ``ctx.tick()`` (and ``ctx.abort()``) as the supervisor thread would."""
    original = h.ctx._record_placements
    seen = []

    def wedged(rows):
        t = threading.Thread(target=lambda: (seen.append(h.ctx.tick()),
                                             also_abort and seen.append(h.ctx.abort("cancelled", "parent_gone"))))
        t.start()
        t.join(0.5)
        original(rows)

    monkeypatch.setattr(h.ctx, "_record_placements", wedged)
    return seen


@pytest.mark.parametrize("partial", [False, True])
def test_a_tick_between_end_saving_and_the_report_cannot_drop_the_result(spec_dict, static_dir, hermes_root, canary,
                                                                         monkeypatch, partial):
    rows = None
    if partial:
        rows = {"env": {"saved": True, "replaced": False, "error": None},
                "keychain": {"saved": False, "replaced": None, "error": "keychain_write_failed", "main_touched": True}}
    h = harness(spec_dict, static_dir, store=FakeStorage(rows=rows))
    _tick_inside_record_placements(h, monkeypatch, also_abort=True)
    h.client.open()
    r = h.client.submit(plain(value=canary, profile="worker"))
    assert r.status_code == 200, r.text
    assert len(h.terminal) == 1
    status, meta, _ = h.terminal[0]
    assert status == "saved"
    assert meta["partial"] is partial and meta["storage"]["type"] == "env"
    assert [x["store"] for x in meta["stores"]] == ["env", "keychain"]
    assert meta["target_profile"] == "worker"
    saved = [x for x in audit(hermes_root, "worker") if x["event"] == "saved"]
    assert len(saved) == 1 and saved[0]["detail"]["partial"] is partial
    assert [x["store"] for x in saved[0]["detail"]["stores"]] == ["env", "keychain"]
    assert canary not in json.dumps(h.terminal)


def _http_inside_record_placements(h, monkeypatch, call):
    """Wedge one HTTP call of the page (static GET, open again, second submit) into the gap between
    ``end_saving`` and the storage thread's report. It runs on its own client and thread, like a browser tab."""
    original = h.ctx._record_placements
    answers = []

    def wedged(rows):
        other = BrowserClient(h.base, client=TestClient(h.app, base_url=str(h.http.base_url)),
                              identity=FAKE_OWNER_LOGIN)
        other.opened = h.client.opened
        t = threading.Thread(target=lambda: answers.append(call(other).status_code))
        t.start()
        t.join(0.5)
        original(rows)

    monkeypatch.setattr(h.ctx, "_record_placements", wedged)
    return answers


HTTP_WEDGES = {
    "static_get": lambda c: c.get(""),
    "open_again": lambda c: c.open(),
    "second_submit": lambda c: c.post("api/submit", {"v": 2, "sid": c.opened["sid"]}),
}


@pytest.mark.parametrize("partial", [False, True])
@pytest.mark.parametrize("wedge", sorted(HTTP_WEDGES))
def test_a_page_call_between_end_saving_and_the_report_cannot_drop_the_result(spec_dict, static_dir, hermes_root,
                                                                             canary, monkeypatch, wedge, partial):
    rows = None
    if partial:
        rows = {"env": {"saved": True, "replaced": False, "error": None},
                "keychain": {"saved": False, "replaced": None, "error": "keychain_write_failed", "main_touched": True}}
    h = harness(spec_dict, static_dir, store=FakeStorage(rows=rows))
    answers = _http_inside_record_placements(h, monkeypatch, HTTP_WEDGES[wedge])
    h.client.open()
    r = h.client.submit(plain(value=canary, profile="worker"))
    assert r.status_code == 200, r.text
    assert wait_until(lambda: len(answers) == 1)
    assert len(h.terminal) == 1
    status, meta, _ = h.terminal[0]
    assert status == "saved"
    assert meta["partial"] is partial and meta["storage"]["type"] == "env"
    assert [x["store"] for x in meta["stores"]] == ["env", "keychain"]
    assert meta["target_profile"] == "worker"
    assert canary not in json.dumps(h.terminal)
