"""Plugin integration: tools, command, hook, notifications, against a real child server.

Real ``start_request`` + real server/storage processes + a fake ``tailscale`` binary + a temp
hermes_root. The browser side is the protocol client in ``helpers.browser_client``. Slack is a fake
Web API client that records every payload; ``ctx.post_message`` is recorded the same way.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

import pytest

from conftest import FAKE_DNS
from helpers.browser_client import BrowserClient
from helpers.fake_tailscale import FAKE_OWNER_LOGIN
from secure_input import plugin as plugin_mod
from secure_input.notify import SlackNotifier, SlackTarget, TextNotifier
from secure_input.plugin import (BLOCK_CODE_MESSAGE, BLOCK_SAVE_LOGIN_MESSAGE, ENTER_CODE_SCHEMA, REQUEST_SCHEMA,
                                 SecureInput)
from secure_input.serve import ServeManager


class FakeHandle:
    def __init__(self, ok=True):
        self.ok, self.error, self.edits = ok, (None if ok else "no_conversation"), []

    def edit(self, text):
        self.edits.append(text)
        return {"ok": True}


class FakeCtx:
    plugin_id = "secure-input"

    def __init__(self, profile="default", post_ok=True):
        self.profile_name = profile
        self.posts: list[str] = []
        self.handles: list[FakeHandle] = []
        self.post_ok = post_ok
        self.dispatched: list[tuple] = []

    def post_message(self, text):
        self.posts.append(text)
        h = FakeHandle(self.post_ok)
        self.handles.append(h)
        return h

    def get_config(self, key, default=None):
        return default

    def dispatch_tool(self, name, args, **kw):
        from tools.registry import registry
        self.dispatched.append((name, dict(args), dict(kw)))
        return registry.dispatch(name, args, **kw)


class FakeSlack:
    def __init__(self):
        self.calls: list[tuple[str, dict]] = []

    def __call__(self, method, kwargs):
        self.calls.append((method, json.loads(json.dumps(kwargs))))
        return {"ok": True, "ts": f"1795000000.{len(self.calls):06d}", "channel": kwargs["channel"]}


@pytest.fixture
def env(hermes_root, static_dir, fake_tailscale, monkeypatch):
    monkeypatch.setenv("HERMES_SESSION_PLATFORM", "slack")
    monkeypatch.setenv("HERMES_SESSION_KEY", "agent:main:slack:thread:C1:1795.1")
    monkeypatch.setenv("HERMES_SESSION_USER_ID", "U123")
    made = []

    def make(profile="default", post_ok=True, slack=True, **kw):
        ctx = FakeCtx(profile, post_ok)
        fake = FakeSlack()
        factory = ((lambda c: SlackNotifier(SlackTarget("C1", "1795.1", fake), TextNotifier(c.post_message)))
                   if slack else (lambda c: TextNotifier(c.post_message)))
        svc = SecureInput(ctx, notifier_factory=factory, hermes_root=lambda: str(hermes_root),
                          start_kwargs={"static_dir": static_dir, "serve": ServeManager(bin=str(fake_tailscale.bin))},
                          **kw)
        svc.fake_slack = fake
        made.append(svc)
        return svc

    yield make
    for svc in made:
        svc.cancel_all()


def live_handle(svc, timeout=20.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        with svc._lock:
            hs = list(svc._live.values())
        if hs:
            return hs[0]
        time.sleep(0.05)
    raise AssertionError("no live request appeared")


def run_bg(fn, *a, **kw):
    box = {}
    t = threading.Thread(target=lambda: box.setdefault("r", fn(*a, **kw)), daemon=True)
    t.start()
    return t, box


def browser_side(svc, action, plaintext=None, bad_submits=0):
    h = live_handle(svc)
    c = BrowserClient(h.local_url, identity=FAKE_OWNER_LOGIN)
    if action == "none":
        return h
    assert c.open().status_code == 200
    for _ in range(bad_submits):
        c.post("api/submit", {"v": 1, "sid": "x" * 43, "client_public_key": "AA", "iv": "AA", "ciphertext": "AA"})
    if action == "submit":
        r = c.submit(plaintext)
        assert r.status_code == 200, r.text
    elif action == "cancel":
        assert c.cancel().status_code == 200
    return h


def everything_sent(svc, results):
    return json.dumps([svc.fake_slack.calls, svc.ctx.posts, [h.edits for h in svc.ctx.handles], results],
                      ensure_ascii=False)


# --- schema / description (criterion 12 part) -----------------------------------------------------------

def test_request_description_names_three_blocked_cases_and_no_chat():
    d = REQUEST_SCHEMA["description"]
    for needle in ("no saved login", "one-time code", "API key", "secure_input_enter_code",
                   "사용자에게 채팅으로 비밀번호, API 키, 인증 코드를 물어보지 말고 이 도구를 쓴다",
                   "SSH 안내", "결과에는 값이 없다"):
        assert needle in d
    assert "결과에는 값이 없다" in ENTER_CODE_SCHEMA["description"]
    assert "enter_code without a handle" not in ENTER_CODE_SCHEMA["description"]
    assert "with or without a handle" in ENTER_CODE_SCHEMA["description"]
    assert set(REQUEST_SCHEMA["parameters"]["required"]) == {"kind", "purpose", "label"}


# --- criterion 7: default profile rule ------------------------------------------------------------------

def test_default_target_is_session_profile(env, hermes_root, canary):
    svc = env(profile="worker")
    t, box = run_bg(svc.tool_request, {"kind": "api_key", "purpose": "검색 키", "label": "Exa", "env_var": "EXA_API_KEY"})
    h = browser_side(svc, "submit", {"kind": "api_key", "target_profile": "worker", "value": canary})
    assert h.spec.target_profile == "worker"
    t.join(30)
    res = json.loads(box["r"])
    assert res["success"] and res["status"] == "saved" and res["target_profile"] == "worker"
    assert res["storage"] == {"type": "env", "env_var": "EXA_API_KEY", "item_id": None}
    assert f"EXA_API_KEY={canary}" in (hermes_root / "profiles" / "worker" / ".env").read_text()
    assert not (hermes_root / ".env").exists()
    assert canary not in everything_sent(svc, [box["r"]])


def test_explicit_target_profile_is_used(env, hermes_root, canary):
    svc = env(profile="worker")
    t, box = run_bg(svc.tool_request, {"kind": "api_key", "purpose": "p", "label": "l", "env_var": "K1",
                                       "target_profile": "default"})
    h = browser_side(svc, "submit", {"kind": "api_key", "target_profile": "default", "value": canary})
    assert h.spec.target_profile == "default"
    t.join(30)
    assert json.loads(box["r"])["target_profile"] == "default"
    assert f"K1={canary}" in (hermes_root / ".env").read_text()


def test_missing_profile_creates_no_request(env, hermes_root, fake_tailscale):
    svc = env()
    res = json.loads(svc.tool_request({"kind": "api_key", "purpose": "p", "label": "l", "env_var": "K",
                                       "target_profile": "nope"}))
    assert res["success"] is False and res["status"] == "failed" and res["request_id"] is None
    assert "프로필" in res["note"]
    assert svc.ctx.posts == [] and svc.fake_slack.calls == []
    assert not list(hermes_root.rglob("secure-input/active/*.json"))
    assert not any(c and c[0] == "serve" for c in fake_tailscale.calls())


@pytest.mark.parametrize("args,needle", [
    ({"kind": "otp_code", "purpose": "p", "label": "l"}, "secure_input_enter_code"),
    ({"kind": "api_key", "purpose": "p", "label": "l", "env_var": "lower"}, "env_var"),
    ({"kind": "login", "purpose": "p", "label": "l", "origin": "http://x.example.com"}, "origin"),
    ({"kind": "api_key", "purpose": "", "label": "l", "env_var": "A"}, "purpose"),
])
def test_bad_tool_args_create_no_request(env, args, needle):
    svc = env()
    res = json.loads(svc.tool_request(args))
    assert res["success"] is False and needle in res["note"] and svc.fake_slack.calls == []


# --- criterion 3/4 (python side): login, profile switch, all four endings, no leaks ------------------------

def test_login_saved_with_user_profile_switch(env, hermes_root, canary):
    svc = env(profile="default")
    ident = "user-" + canary[-8:] + "@example.com"
    t, box = run_bg(svc.tool_request, {"kind": "login", "purpose": "관리자 점검", "label": "관리자",
                                       "origin": "https://admin.example.com/login"})
    browser_side(svc, "submit", {"kind": "login", "target_profile": "worker", "identifier_type": "email",
                                 "identifier": ident, "password": canary, "otp_secret": ""})
    t.join(30)
    res = json.loads(box["r"])
    assert res["status"] == "saved" and res["target_profile"] == "worker"
    assert res["storage"]["type"] == "vault" and res["storage"]["origin"] == "https://admin.example.com"
    assert res["storage"]["item_id"] and "worker" in res["note"]
    sent = everything_sent(svc, [box["r"]])
    assert canary not in sent and ident not in sent
    assert not (hermes_root / "vault").exists() or not any((hermes_root / "vault").rglob("*"))
    assert any((hermes_root / "profiles" / "worker" / "vault").rglob("*"))
    # Slack: one post with the button, then one update without it
    (m1, post), (m2, upd) = svc.fake_slack.calls
    assert m1 == "chat_postMessage" and post["blocks"][-1]["elements"][0]["action_id"] == "secure_input_open"
    assert m2 == "chat_update" and "actions" not in json.dumps(upd["blocks"]) and "저장 완료" in upd["text"]
    assert post["thread_ts"] == "1795.1" and FAKE_DNS in post["text"]
    # Saved in another profile than this session's: the session cannot read that vault, so no fill instruction.
    assert "fill 을 시도하지 말고" in res["note"] and "로 입력하세요" not in res["note"]
    assert "이 세션은 default 프로필이라" in res["note"]
    assert "사용자가 페이지에서 프로필을 default 에서 worker 로 바꿨습니다." in res["note"]


def test_login_saved_in_session_profile_keeps_fill_note(env, hermes_root, canary):
    svc = env(profile="default")
    ident = "user-" + canary[-8:] + "@example.com"
    t, box = run_bg(svc.tool_request, {"kind": "login", "purpose": "관리자 점검", "label": "관리자",
                                       "origin": "https://admin.example.com/login"})
    browser_side(svc, "submit", {"kind": "login", "target_profile": "default", "identifier_type": "email",
                                 "identifier": ident, "password": canary, "otp_secret": ""})
    t.join(30)
    res = json.loads(box["r"])
    assert res["status"] == "saved" and res["target_profile"] == "default"
    assert res["note"] == plugin_mod.VAULT_NOTE.format(profile="default")
    assert "로 입력하세요" in res["note"] and "fill 을 시도하지 말고" not in res["note"]
    sent = everything_sent(svc, [box["r"]])
    assert canary not in sent and ident not in sent


def test_login_saved_in_agent_named_other_profile_says_do_not_fill(env, hermes_root, canary):
    # The agent itself named another profile (target_profile) and the user kept it: same note as a page switch,
    # without the "user switched" sentence.
    svc = env(profile="default")
    ident = "user-" + canary[-8:] + "@example.com"
    t, box = run_bg(svc.tool_request, {"kind": "login", "purpose": "관리자 점검", "label": "관리자",
                                       "origin": "https://admin.example.com/login", "target_profile": "worker"})
    browser_side(svc, "submit", {"kind": "login", "target_profile": "worker", "identifier_type": "email",
                                 "identifier": ident, "password": canary, "otp_secret": ""})
    t.join(30)
    res = json.loads(box["r"])
    assert res["status"] == "saved" and res["target_profile"] == "worker"
    assert res["note"] == plugin_mod.VAULT_OTHER_PROFILE_NOTE.format(profile="worker", session="default")
    assert "로 입력하세요" not in res["note"] and "바꿨습니다" not in res["note"]
    sent = everything_sent(svc, [box["r"]])
    assert canary not in sent and ident not in sent


def test_api_key_saved_in_other_profile_says_session_cannot_use(env, hermes_root, canary):
    svc = env(profile="default")
    t, box = run_bg(svc.tool_request, {"kind": "api_key", "purpose": "p", "label": "l", "env_var": "SI_TEST_KEY"})
    browser_side(svc, "submit", {"kind": "api_key", "target_profile": "worker", "value": canary})
    t.join(30)
    res = json.loads(box["r"])
    assert res["status"] == "saved" and res["target_profile"] == "worker"
    assert res["note"].startswith(plugin_mod.ENV_NOTE.format(profile="worker") + " 이 세션은 default 프로필이라 이 값을 쓰지 못합니다.")
    assert "/reload" not in res["note"]
    assert "다시 요청" in res["note"]
    assert canary not in everything_sent(svc, [box["r"]])


def test_expired_cancelled_failed_endings_leak_nothing(env, canary):
    results = []
    # expired (shortened windows, test-only)
    svc = env(start=lambda spec, **kw: plugin_mod.start_request(spec, _test_ttls={"open": 1.0, "submit": 2.0}, **kw))
    results.append(svc.tool_request({"kind": "api_key", "purpose": "p", "label": "l", "env_var": "K"}))
    assert json.loads(results[-1])["status"] == "expired"
    assert "만료" in svc.fake_slack.calls[-1][1]["text"]
    # cancelled by the user on the page
    svc2 = env()
    t, box = run_bg(svc2.tool_request, {"kind": "api_key", "purpose": "p", "label": "l", "env_var": "K"})
    browser_side(svc2, "cancel")
    t.join(30)
    results.append(box["r"])
    assert json.loads(box["r"])["status"] == "cancelled" and "취소" in svc2.fake_slack.calls[-1][1]["text"]
    # failed: five bad submits
    svc3 = env()
    t, box = run_bg(svc3.tool_request, {"kind": "api_key", "purpose": "p", "label": "l", "env_var": "K"})
    browser_side(svc3, "bad", bad_submits=5)
    t.join(30)
    results.append(box["r"])
    res = json.loads(box["r"])
    assert res["status"] == "failed" and res["success"] is False and "실패" in svc3.fake_slack.calls[-1][1]["text"]
    for s in (svc, svc2, svc3):
        assert canary not in everything_sent(s, results)
        for r in results:
            assert "TOKEN" not in r and FAKE_DNS not in r and "https://" + FAKE_DNS not in r


def test_interrupt_cancels_request(env):
    flag = {"stop": False}
    svc = env(interrupted=lambda: flag["stop"])
    t, box = run_bg(svc.tool_request, {"kind": "api_key", "purpose": "p", "label": "l", "env_var": "K"})
    live_handle(svc)
    flag["stop"] = True
    t.join(30)
    res = json.loads(box["r"])
    assert res["status"] == "cancelled" and svc._live == {}


def test_no_conversation_cancels_and_reports(env, hermes_root):
    svc = env(post_ok=False, slack=False)
    res = json.loads(svc.tool_request({"kind": "api_key", "purpose": "p", "label": "l", "env_var": "K"}))
    assert res["status"] == "failed" and "링크를 보낼 수 없어" in res["note"]
    time.sleep(0.5)
    assert not list(hermes_root.rglob("secure-input/active/*.json"))


def test_result_never_contains_link_token_or_url(env, canary):
    svc = env()
    t, box = run_bg(svc.tool_request, {"kind": "api_key", "purpose": "p", "label": "l", "env_var": "K"})
    h = browser_side(svc, "submit", {"kind": "api_key", "target_profile": "default", "value": canary})
    t.join(30)
    token = h.url.rstrip("/").rsplit("/", 1)[1]
    assert token not in box["r"] and h.url not in box["r"]


# --- criterion 5: audit log context for agent and user requests --------------------------------------------

def _audit(home: Path) -> list[dict]:
    return [json.loads(x) for x in (home / "logs" / "secure-input.jsonl").read_text().splitlines() if x.strip()]


def test_audit_log_records_context_without_values(env, hermes_root, canary):
    svc = env(profile="worker")
    t, box = run_bg(svc.tool_request, {"kind": "api_key", "purpose": "에이전트 요청 목적", "label": "에이전트 키",
                                       "env_var": "AGENT_KEY"})
    h1 = browser_side(svc, "submit", {"kind": "api_key", "target_profile": "worker", "value": canary})
    t.join(30)
    svc.command("key USER_KEY --purpose 사용자요청 --label 사용자키", session_key="sk-user", platform="slack")
    h2 = browser_side(svc, "submit", {"kind": "api_key", "target_profile": "worker", "value": canary + "2"})
    end = time.monotonic() + 20
    while svc._live and time.monotonic() < end:
        time.sleep(0.05)
    lines = _audit(hermes_root / "profiles" / "worker")
    for h, rtype, purpose, label in ((h1, "agent", "에이전트 요청 목적", "에이전트 키"), (h2, "user", "사용자요청", "사용자키")):
        mine = [x for x in lines if x["request_id"] == h.request_id]
        events = [x["event"] for x in mine]
        assert [e for e in events if e in ("created", "opened", "submitted", "saved")] == \
            ["created", "opened", "submitted", "saved"]
        for x in mine:
            assert x["requester"]["type"] == rtype and x["requester"]["profile"] == "worker"
            assert x["requester"]["platform"] == "slack" and x["requester"]["user_id"] in ("U123", "")
            assert x["purpose"] == purpose and x["label"] == label and x["kind"] == "api_key"
            assert x["target_profile"] == "worker" and x["storage"]["type"] == "env" and x["ts"]
    assert lines[0]["requester"]["session_key"] == "agent:main:slack:thread:C1:1795.1"
    raw = (hermes_root / "profiles" / "worker" / "logs" / "secure-input.jsonl").read_text()
    assert canary not in raw and h1.url.rstrip("/").rsplit("/", 1)[1] not in raw


# --- command (5.2) ----------------------------------------------------------------------------------------

def test_command_usage_on_bad_args_starts_nothing(env):
    svc = env()
    out = svc.command("key lower")
    assert "사용법" in out and svc.fake_slack.calls == [] and svc._live == {}
    assert "사용법" in svc.command("help")


def test_command_returns_at_once_and_updates_message_later(env, hermes_root, canary):
    svc = env(profile="worker")
    started = time.monotonic()
    out = svc.command('key EXA_API_KEY --profile default --label "Exa 키"', session_key="sk", platform="slack")
    assert time.monotonic() - started < 15 and "입력 링크를 보냈습니다" in out and canary not in out
    h = live_handle(svc)
    assert h.spec.requester["type"] == "user" and h.spec.target_profile == "default"
    assert h.spec.purpose == "EXA_API_KEY 값을 직접 등록합니다"
    c = BrowserClient(h.local_url, identity=FAKE_OWNER_LOGIN)
    assert c.open().status_code == 200
    assert c.submit({"kind": "api_key", "target_profile": "default", "value": canary}).status_code == 200
    end = time.monotonic() + 20
    while len(svc.fake_slack.calls) < 2 and time.monotonic() < end:
        time.sleep(0.05)
    assert svc.fake_slack.calls[-1][0] == "chat_update"
    assert "저장 완료: EXA_API_KEY, 프로필 default" in svc.fake_slack.calls[-1][1]["text"]
    assert canary not in everything_sent(svc, [out])


# --- hook (criteria 6 and 12) -------------------------------------------------------------------------------

def test_hook_blocks_every_core_enter_code_and_save_login_only(env):
    svc = env()
    assert svc.pre_tool_call(tool_name="browser_vault", args={"action": "enter_code"}) == \
        {"action": "block", "message": BLOCK_CODE_MESSAGE}
    assert svc.pre_tool_call(tool_name="browser_vault", args={"action": "enter_code", "handle": "  "})["action"] == "block"
    with_handle = svc.pre_tool_call(tool_name="browser_vault", args={"action": "enter_code", "handle": "v1"})
    assert with_handle == {"action": "block", "message": BLOCK_CODE_MESSAGE}
    assert "secure_input_enter_code" in BLOCK_CODE_MESSAGE and "handle" in BLOCK_CODE_MESSAGE
    assert "enter_code without a handle" not in BLOCK_CODE_MESSAGE
    assert "with or without a handle" in BLOCK_CODE_MESSAGE
    assert svc.pre_tool_call(tool_name="browser_vault", args={"action": "fill", "handle": "v1"}) is None
    assert svc.pre_tool_call(tool_name="browser_vault", args={"action": "list"}) is None
    assert svc.pre_tool_call(tool_name="terminal", args={"command": "enter_code"}) is None
    blocked = svc.pre_tool_call(tool_name="browser_vault", args={"action": "save_login"})
    assert blocked == {"action": "block", "message": BLOCK_SAVE_LOGIN_MESSAGE}
    assert "secure_input_request" in blocked["message"] and "kind='login'" in blocked["message"]
    assert "follow the note" in blocked["message"]


def test_hook_settings_turn_interception_off(env):
    off = env(settings=lambda key, default: False)
    assert off.pre_tool_call(tool_name="browser_vault", args={"action": "enter_code"}) is None
    assert off.pre_tool_call(tool_name="browser_vault", args={"action": "enter_code", "handle": "v1"}) is None
    assert off.pre_tool_call(tool_name="browser_vault", args={"action": "save_login"}) is None
    only_code = env(settings=lambda key, default: key != "intercept_core_code_prompt")
    assert only_code.pre_tool_call(tool_name="browser_vault", args={"action": "enter_code"}) is None
    assert only_code.pre_tool_call(tool_name="browser_vault", args={"action": "enter_code", "handle": "v1"}) is None
    assert only_code.pre_tool_call(tool_name="browser_vault", args={"action": "save_login"})["action"] == "block"
