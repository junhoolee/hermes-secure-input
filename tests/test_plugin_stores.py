"""Card 3 (plan 7.3 "작업 3"): the agent tool, its description, results and waits with stores and the keychain.

Refusals are checked without a server (nothing is launched). Results are checked against a real server whose
storage grandchild runs the fake keychain module (``helpers.fake_keychain``); the real keychain is never touched.
The allow list is a fake plugin setting.
"""

from __future__ import annotations

import json
import os
import signal
import time

import pytest

from helpers import fake_keychain
from helpers.browser_client import BrowserClient
from helpers.fake_tailscale import FAKE_OWNER_LOGIN
from secure_input import plugin as plugin_mod
from secure_input.notify import SlackNotifier, SlackTarget, TextNotifier
from secure_input.plugin import SecureInput
from secure_input.serve import ServeManager

from test_plugin import FakeCtx, FakeSlack, everything_sent, live_handle, run_bg

ALLOW = [{"id": "example-cred", "service": "Example-Service", "account": "example-account",
          "label": "예시 비밀번호", "used_by": "예시 잠금 해제 스크립트"}]
OWN_PREFIX_ITEM = {"id": "own-item", "service": "hermes-secure-input.own", "account": "x",
                   "label": "숨길 항목", "used_by": "아무도"}


def settings_with(items):
    return lambda key, default: items if key == "keychain_items" else default


@pytest.fixture
def svc_factory(hermes_root, static_dir, fake_tailscale, tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_SESSION_PLATFORM", "slack")
    monkeypatch.setenv("HERMES_SESSION_KEY", "agent:main:slack:thread:C1:1795.1")
    monkeypatch.setenv("HERMES_SESSION_USER_ID", "U123")
    python = fake_keychain.storage_python(tmp_path / "py")
    made = []

    def make(items=ALLOW, keychain=None, profile="default", **kw):
        monkeypatch.setenv("FAKE_KEYCHAIN_CONFIG", json.dumps(keychain or {}))
        ctx = FakeCtx(profile)
        fake = FakeSlack()
        svc = SecureInput(ctx, notifier_factory=lambda c: SlackNotifier(SlackTarget("C1", "1795.1", fake),
                                                                        TextNotifier(c.post_message)),
                          hermes_root=lambda: str(hermes_root), settings=settings_with(items),
                          start_kwargs={"static_dir": static_dir, "python": str(python),
                                        "serve": ServeManager(bin=str(fake_tailscale.bin))}, **kw)
        svc.fake_slack = fake
        made.append(svc)
        return svc

    yield make
    for svc in made:
        svc.cancel_all()


def refused(svc, args):
    res = json.loads(svc.tool_request(args))
    assert res["success"] is False and res["status"] == "failed" and res["request_id"] is None
    assert svc.fake_slack.calls == [] and svc.ctx.posts == [] and svc._live == {}
    return res


SECRET = {"kind": "secret", "purpose": "잠금 해제 스크립트가 읽을 비밀번호입니다", "label": "예시 비밀번호"}
API = {"kind": "api_key", "purpose": "검색 도구 키", "label": "Exa 키", "env_var": "EXA_API_KEY"}


# --- plan 3.2 rule 4: a name of an allow-list item's service or account (case ignored) ------------------------

@pytest.mark.parametrize("name", ["Example-Service", "example-service", "EXAMPLE-ACCOUNT", "example-account"])
def test_name_of_listed_service_or_account_creates_no_request_and_names_the_id(svc_factory, hermes_root, name):
    svc = svc_factory()
    res = refused(svc, dict(SECRET, keychain_item=name))
    assert f"`{name}`은 허용 목록의 항목 `example-cred`가 쓰는 이름입니다. keychain_item에 `example-cred`를 넘기세요." \
        in res["note"]
    assert not list(hermes_root.rglob("secure-input/active/*.json"))


def test_name_of_listed_account_is_refused_for_api_key_too(svc_factory):
    res = refused(svc_factory(), dict(API, keychain_item="example-account"))
    assert "허용 목록의 항목 `example-cred`가 쓰는 이름입니다" in res["note"]


# --- plan 3.2 rule 3: an allow-list id is for kind secret only ------------------------------------------------

def test_api_key_with_allow_list_id_creates_no_request(svc_factory):
    res = refused(svc_factory(), dict(API, keychain_item="example-cred"))
    assert "허용 목록의 항목 `example-cred`는 kind `secret`으로만 쓸 수 있습니다." in res["note"]


# --- plan 3.2 rule 7: api_key default name ------------------------------------------------------------------------

def test_api_key_default_name_unusable_with_keychain_in_stores_is_refused(svc_factory):
    args = dict(API, env_var="_X", stores=[{"store": "keychain", "reason": "스크립트가 읽습니다", "needed": True}])
    res = refused(svc_factory(), args)
    assert "keychain_item을 직접 넘기세요." in res["note"]


def test_api_key_default_name_equal_to_listed_id_with_keychain_in_stores_is_refused(svc_factory):
    args = dict(API, env_var="EXAMPLE_CRED", stores=[{"store": "keychain"}])
    assert "keychain_item을 직접 넘기세요." in refused(svc_factory(), args)["note"]


# --- plan 3.2 rule 8 and the other argument refusals --------------------------------------------------------------

@pytest.mark.parametrize("name", ["Upper", "under_score", "dot.name", "has space", "x" * 41, ""])
def test_bad_keychain_item_shape_creates_no_request(svc_factory, name):
    res = refused(svc_factory(), dict(SECRET, keychain_item=name))
    assert "^[a-z0-9][a-z0-9-]{0,39}$" in res["note"]


def test_secret_without_keychain_item_creates_no_request(svc_factory):
    assert "keychain_item" in refused(svc_factory(), dict(SECRET))["note"]


def test_login_with_keychain_item_creates_no_request(svc_factory):
    args = {"kind": "login", "purpose": "p", "label": "l", "origin": "https://admin.example.com",
            "keychain_item": "anything"}
    assert "keychain_item" in refused(svc_factory(), args)["note"]


@pytest.mark.parametrize("reason", ["첫 줄\n둘째 줄", "보이지 않는\u200b문자", "방향\u202e바꿈", "x" * 121, " "])
def test_reason_with_newline_or_format_character_creates_no_request(svc_factory, reason):
    args = dict(SECRET, keychain_item="new-name", stores=[{"store": "keychain", "reason": reason, "needed": True}])
    res = refused(svc_factory(), args)
    assert "stores" in res["note"]


@pytest.mark.parametrize("stores", [[{"store": "env"}], [{"store": "example_vault"}], [],
                                    [{"store": "keychain"}, {"store": "keychain"}], "keychain"])
def test_bad_stores_argument_creates_no_request(svc_factory, stores):
    assert "stores" in refused(svc_factory(), dict(SECRET, keychain_item="new-name", stores=stores))["note"]


# --- plan 2.2, 3.2 rule 2: the tool description carries the allow list -----------------------------------------

def schema_of(items):
    return SecureInput(FakeCtx(), settings=settings_with(items)).request_schema()


def test_description_lists_id_label_used_by_and_never_service_or_account():
    schema = schema_of(ALLOW)
    text = json.dumps(schema, ensure_ascii=False)
    prop = schema["parameters"]["properties"]["keychain_item"]["description"]
    assert "`example-cred`: 예시 비밀번호 (쓰는 곳: 예시 잠금 해제 스크립트)" in prop
    assert "Example-Service" not in text and "example-account" not in text
    assert plugin_mod.NO_ALLOWED_ITEMS not in text


def test_description_with_empty_allow_list_says_none_allowed():
    for items in ([], None):
        prop = schema_of(items)["parameters"]["properties"]["keychain_item"]["description"]
        assert "허용된 기존 항목 없음" in prop


def test_description_leaves_out_items_with_plugin_prefix_service(caplog):
    with caplog.at_level("WARNING"):
        text = json.dumps(schema_of([OWN_PREFIX_ITEM]), ensure_ascii=False)
    assert "own-item" not in text and "숨길 항목" not in text and "hermes-secure-input.own" not in text
    assert "허용된 기존 항목 없음" in text
    assert "hermes-secure-input.own" not in caplog.text and "숨길 항목" not in caplog.text


def test_description_one_line_per_item_in_order():
    second = {"id": "second-item", "service": "Svc2", "account": "acct2", "label": "둘째", "used_by": "둘째 스크립트"}
    prop = schema_of(ALLOW + [second])["parameters"]["properties"]["keychain_item"]["description"]
    lines = [x for x in prop.splitlines() if x.startswith("- `")]
    assert lines == ["- `example-cred`: 예시 비밀번호 (쓰는 곳: 예시 잠금 해제 스크립트)",
                     "- `second-item`: 둘째 (쓰는 곳: 둘째 스크립트)"]


def test_schema_has_kind_secret_stores_and_keychain_item_but_no_service_account_or_lock():
    schema = schema_of(ALLOW)
    props = schema["parameters"]["properties"]
    assert props["kind"]["enum"] == ["api_key", "login", "secret"]
    item = props["stores"]["items"]
    assert item["properties"]["store"]["enum"] == ["env", "hermes_vault", "keychain"]
    assert set(item["properties"]) == {"store", "reason", "needed"}
    assert not {"service", "account", "locked", "lock", "required_stores"} & set(props)
    d = schema["description"]
    assert "waits up to about 400 s" in d and "370 s" not in d
    assert "kind='secret'" in d and "keychain_item" in d


def test_register_uses_the_description_built_from_settings(monkeypatch, hermes_root):
    monkeypatch.setattr(plugin_mod, "sweep_stale", lambda root: 0)
    monkeypatch.setattr(plugin_mod, "_default_hermes_root", lambda: str(hermes_root))
    class Ctx(FakeCtx):
        def __init__(self):
            super().__init__()
            self.tools, self.commands = {}, {}

        def get_config(self, key, default=None):
            return ALLOW if key == "keychain_items" else default

        def register_tool(self, name, toolset, schema, handler, **kw):
            self.tools[name] = schema

        def register_command(self, name, handler, **kw):
            self.commands[name] = kw

        def register_hook(self, *a, **kw):
            pass

        def register_slack_action_handler(self, *a, **kw):
            pass

        def on_unload(self, fn):
            pass

    ctx = Ctx()
    plugin_mod.register(ctx)
    prop = ctx.tools["secure_input_request"]["parameters"]["properties"]["keychain_item"]["description"]
    assert "`example-cred`" in prop
    assert "secret <keychain_item>" in ctx.commands["secure-input"]["args_hint"]


# --- results and notes (plan 5.3, appendix A.12, A.13) against a real server + fake keychain ------------------

def submit_via_page(svc, plaintext, auto_stores=True):
    h = live_handle(svc)
    c = BrowserClient(h.local_url, identity=FAKE_OWNER_LOGIN, timeout=60.0)
    assert c.open().status_code == 200
    r = c.submit(plaintext, auto_stores=auto_stores)
    return h, c, r


def finish(t, box):
    t.join(60)
    assert "r" in box, "tool call did not return"
    return json.loads(box["r"])


def audit_text(root):
    p = root / "logs" / "secure-input.jsonl"
    return p.read_text() if p.exists() else ""


def test_secret_new_item_result_has_new_item_note_and_keychain_names(svc_factory, hermes_root, canary, caplog):
    svc = svc_factory()
    with caplog.at_level("DEBUG"):
        t, box = run_bg(svc.tool_request, dict(SECRET, keychain_item="test-new-item"))
        h, _c, r = submit_via_page(svc, {"kind": "secret", "target_profile": "default", "value": canary})
        assert r.status_code == 200, r.text
        res = finish(t, box)
    assert res["status"] == "saved" and res["success"] is True and res["partial"] is False
    assert res["kind"] == "secret"
    assert res["storage"] == {"type": "keychain", "service": "hermes-secure-input.test-new-item",
                              "account": "hermes-secure-input"}
    (row,) = res["stores"]
    assert row["store"] == "keychain" and row["saved"] is True and row["new_item"] is True
    assert plugin_mod.NEW_ITEM_NOTE in res["note"]
    assert "hermes-secure-input.test-new-item" in res["note"]
    sent = everything_sent(svc, [box["r"]])
    assert canary not in sent and canary not in audit_text(hermes_root) and canary not in caplog.text
    keys = {k for r in res["stores"] for k in r} | set(res) | set(res["storage"])
    assert not keys & {"value", "length", "value_length", "identifier", "password"}


def test_secret_listed_item_has_no_new_item_note(svc_factory, canary):
    svc = svc_factory(keychain={"save": {"new_item": False, "replaced": True}})
    t, box = run_bg(svc.tool_request, dict(SECRET, keychain_item="example-cred"))
    h, _c, r = submit_via_page(svc, {"kind": "secret", "target_profile": "default", "value": canary})
    res = finish(t, box)
    assert h.spec.keychain["listed"] is True and h.spec.keychain["service"] == "Example-Service"
    assert res["status"] == "saved" and plugin_mod.NEW_ITEM_NOTE not in res["note"]
    assert res["storage"] == {"type": "keychain", "service": "Example-Service", "listed": True,
                              "allow_list_id": "example-cred", "label": "예시 비밀번호"}  # R3-5: no account
    (m1, link), (m2, done) = svc.fake_slack.calls
    assert m1 == "chat_postMessage" and "저장 위치: Mac 키체인" in link["text"]
    assert ("키체인 항목: Example-Service (허용 목록 항목 example-cred: 예시 비밀번호, 쓰는 곳: 예시 잠금 해제 스크립트)"
            in link["text"]) and "example-account" not in json.dumps(link)
    assert m2 == "chat_update" and done["text"] == "저장 완료: Mac 키체인 Example-Service"
    assert canary not in everything_sent(svc, [box["r"]])


def test_api_key_saved_only_in_keychain_says_secrets_command_with_service_and_account(svc_factory, canary):
    svc = svc_factory()
    args = dict(API, stores=[{"store": "keychain", "reason": "백업 스크립트가 이 키를 키체인에서 읽습니다", "needed": True}])
    t, box = run_bg(svc.tool_request, args)
    h, _c, r = submit_via_page(svc, {"kind": "api_key", "target_profile": "default", "value": canary})
    assert r.status_code == 200, r.text
    res = finish(t, box)
    assert [s["store"] for s in res["stores"]] == ["keychain"]
    assert res["status"] == "saved" and res["storage"]["type"] == "keychain"
    note = res["note"]
    assert plugin_mod.SECRETS_COMMAND_NOTE in note
    assert "hermes-secure-input.exa-api-key" in note.split(plugin_mod.SECRETS_COMMAND_NOTE, 1)[1]
    assert "account `hermes-secure-input`" in note.split(plugin_mod.SECRETS_COMMAND_NOTE, 1)[1]
    assert plugin_mod.ENV_NOTE.format(profile="default") not in note
    assert canary not in everything_sent(svc, [box["r"]])


def test_api_key_saved_in_env_and_keychain_has_no_secrets_command_note(svc_factory, canary):
    svc = svc_factory()
    args = dict(API, stores=[{"store": "env"}, {"store": "keychain"}])
    t, box = run_bg(svc.tool_request, args)
    submit_via_page(svc, {"kind": "api_key", "target_profile": "default", "value": canary})
    res = finish(t, box)
    assert res["status"] == "saved" and [s["saved"] for s in res["stores"]] == [True, True]
    assert plugin_mod.SECRETS_COMMAND_NOTE not in res["note"]
    assert plugin_mod.ENV_NOTE.format(profile="default") in res["note"]


def test_partial_save_is_status_partial_with_rows_and_main_touched_note(svc_factory, hermes_root, canary):
    svc = svc_factory(keychain={"save": {"saved": False, "replaced": None, "error": "keychain_verify_failed",
                                         "new_item": False, "main_touched": True}})
    args = dict(API, stores=[{"store": "env"}, {"store": "keychain"}])
    t, box = run_bg(svc.tool_request, args)
    submit_via_page(svc, {"kind": "api_key", "target_profile": "default", "value": canary})
    res = finish(t, box)
    assert res["status"] == "partial" and res["success"] is False and res["partial"] is True, res
    env_row, kc_row = res["stores"]
    assert env_row["store"] == "env" and env_row["saved"] is True
    assert kc_row["store"] == "keychain" and kc_row["saved"] is False and kc_row["error"] == "keychain_verify_failed"
    note = res["note"]
    assert "키체인 항목 `hermes-secure-input.exa-api-key`의 기존 값이 바뀌었을 수 있습니다." in note
    assert "keychain_verify_failed" in note and "실패한 저장소만 다시 요청하세요" in note
    final = svc.fake_slack.calls[-1][1]["text"]
    assert "일부만 저장" in final and "EXA_API_KEY" in final and "Mac 키체인" in final
    assert "keychain_verify_failed" in final
    assert canary not in everything_sent(svc, [box["r"]]) and canary not in audit_text(hermes_root)


def test_user_turning_a_store_off_is_reported(svc_factory, canary):
    svc = svc_factory()
    t, box = run_bg(svc.tool_request, dict(API, stores=[{"store": "env"}, {"store": "keychain"}]))
    submit_via_page(svc, {"kind": "api_key", "target_profile": "default", "value": canary, "stores": ["env"]})
    res = finish(t, box)
    assert res["status"] == "saved" and "사용자가 페이지에서 Mac 키체인 저장을 껐습니다." in res["note"]


@pytest.mark.parametrize("kind_args,plain", [
    (dict(API), None),
    (dict(SECRET, keychain_item="test-dies"), None),
])
def test_server_dying_without_done_says_result_unknown_in_tool_and_slack(svc_factory, kind_args, plain):
    svc = svc_factory()
    t, box = run_bg(svc.tool_request, kind_args)
    h = live_handle(svc)
    c = BrowserClient(h.local_url, identity=FAKE_OWNER_LOGIN)
    assert c.open().status_code == 200
    os.kill(h.pid, signal.SIGKILL)
    res = finish(t, box)
    assert h.wait(timeout=10).meta["reason"] == "child_exited"
    assert res["status"] == "failed" and res["success"] is False
    assert res["note"].startswith("저장 여부를 확인하지 못했습니다.")
    assert "저장 여부를 확인하지 못했습니다." in svc.fake_slack.calls[-1][1]["text"]


# --- /secure-input secret and key (plan 7.1, 7.3) ---------------------------------------------------------------

def command_refused(svc, raw):
    out = svc.command(raw, session_key="sk", platform="slack")
    assert svc.fake_slack.calls == [] and svc._live == {}
    return out


def test_command_secret_opens_a_secret_request_on_the_listed_item(svc_factory, canary, hermes_root):
    svc = svc_factory()
    out = svc.command('secret example-cred --label "예시 비밀번호"', session_key="sk", platform="slack")
    assert "입력 링크를 보냈습니다" in out and "Example-Service" in out
    h = live_handle(svc)
    assert h.spec.kind == "secret" and h.spec.requester["type"] == "user"
    assert h.spec.keychain == dict(ALLOW[0], listed=True)
    assert [(r["store"], r["selected"], r["fixed"]) for r in h.spec.stores] == [("keychain", True, True)]
    c = BrowserClient(h.local_url, identity=FAKE_OWNER_LOGIN, timeout=60.0)
    assert c.open().status_code == 200
    assert c.submit({"kind": "secret", "target_profile": "default", "value": canary}).status_code == 200
    end = time.monotonic() + 20
    while len(svc.fake_slack.calls) < 2 and time.monotonic() < end:
        time.sleep(0.05)
    assert svc.fake_slack.calls[-1][1]["text"] == "저장 완료: Mac 키체인 Example-Service"
    assert canary not in everything_sent(svc, [out]) and canary not in audit_text(hermes_root)


def test_command_secret_new_name_becomes_plugin_item(svc_factory):
    svc = svc_factory()
    svc.command("secret test-cmd-item", session_key="sk", platform="slack")
    h = live_handle(svc)
    assert h.spec.keychain["service"] == "hermes-secure-input.test-cmd-item"
    assert h.spec.keychain["account"] == "hermes-secure-input" and h.spec.keychain["listed"] is False


@pytest.mark.parametrize("name", ["Example-Service", "EXAMPLE-ACCOUNT"])
def test_command_secret_with_listed_service_or_account_is_refused_like_the_tool(svc_factory, name):
    svc = svc_factory()
    out = command_refused(svc, f"secret {name}")
    assert plugin_mod.LISTED_NAME_NOTE.format(name=name, id="example-cred") in out
    tool = json.loads(svc.tool_request(dict(SECRET, keychain_item=name)))
    assert plugin_mod.LISTED_NAME_NOTE.format(name=name, id="example-cred") in tool["note"]


@pytest.mark.parametrize("name", ["Bad_Name", "x" * 41, "dot.name"])
def test_command_secret_with_bad_name_is_refused_like_the_tool(svc_factory, name):
    out = command_refused(svc_factory(), f"secret {name}")
    assert "^[a-z0-9][a-z0-9-]{0,39}$" in out


def test_command_key_opens_with_env_only_preselected(svc_factory):
    svc = svc_factory()
    out = svc.command("key EXA_API_KEY", session_key="sk", platform="slack")
    assert "입력 링크를 보냈습니다" in out
    h = live_handle(svc)
    assert [(r["store"], r["selected"]) for r in h.spec.stores] == [("env", True), ("keychain", False)]
    opened = BrowserClient(h.local_url, identity=FAKE_OWNER_LOGIN).open().json()
    assert [r["store"] for r in opened["target"]["stores"] if r["selected"]] == ["env"]


# --- waits (plan 5.7 6, appendix A.1) ---------------------------------------------------------------------------

from types import SimpleNamespace  # noqa: E402

from secure_input.launcher import Outcome, cancel_grace_s  # noqa: E402

PARENT_WAIT = {"api_key": 400.0, "login": 400.0, "secret": 390.0, "otp_code": 370.0}
CANCEL_WAIT = {"api_key": 35.0, "login": 35.0, "secret": 25.0, "otp_code": 5.0}


class ClockHandle:
    """Never ends by itself; every wait() slice moves the fake clock by its timeout."""

    def __init__(self, kind, clock):
        self.spec = SimpleNamespace(kind=kind)
        self.request_id = "r" * 32
        self.clock = clock
        self.cancel_args = []
        self.wait_timeouts = []

    def wait(self, timeout=None, heartbeat=None):
        self.wait_timeouts.append(timeout)
        self.clock["now"] += timeout or 0
        raise TimeoutError

    def cancel(self, *args, **kwargs):
        self.cancel_args.append((args, kwargs, self.clock["now"]))
        return Outcome(status="cancelled", meta={"reason": "parent_gone"})


@pytest.mark.parametrize("kind", ["api_key", "login", "secret", "otp_code"])
def test_parent_wait_and_cancel_wait_per_kind(kind):
    assert plugin_mod.parent_wait_s(kind) == PARENT_WAIT[kind]
    assert cancel_grace_s(kind) == CANCEL_WAIT[kind]


@pytest.mark.parametrize("kind", ["api_key", "login", "secret", "otp_code"])
def test_tool_wait_gives_up_after_the_kind_budget_and_cancels_without_grace(kind, monkeypatch):
    clock = {"now": 1000.0}
    monkeypatch.setattr(plugin_mod.time, "monotonic", lambda: clock["now"])
    svc = SecureInput(FakeCtx(), interrupted=lambda: False)
    h = ClockHandle(kind, clock)
    out = svc.wait(h)
    assert out.status == "cancelled"
    ((args, kwargs, at),) = h.cancel_args
    assert args == () and kwargs == {}  # the handle uses cancel_grace_s(kind)
    assert at - 1000.0 == PARENT_WAIT[kind]


def test_interrupt_cancel_and_unload_cancel_pass_no_grace(monkeypatch):
    svc = SecureInput(FakeCtx(), interrupted=lambda: True)
    h = ClockHandle("secret", {"now": 0.0})
    svc.wait(h)
    assert h.cancel_args[0][:2] == ((), {})
    others = [ClockHandle(k, {"now": 0.0}) for k in ("api_key", "otp_code")]
    for o in others:
        svc._live[o.request_id + o.spec.kind] = o
    svc.cancel_all()
    assert [o.cancel_args[0][:2] for o in others] == [((), {}), ((), {})]


@pytest.mark.parametrize("raw,kind", [("key EXA_API_KEY", "api_key"), ("login https://admin.example.com", "login"),
                                      ("secret test-wait", "secret")])
def test_command_waits_the_kind_budget_then_cancels_without_grace(raw, kind, hermes_root, fake_tailscale):
    clock = {"now": 0.0}
    made = []

    def start(spec, **kw):
        h = ClockHandle(spec.kind, clock)
        h.url = "https://example.invalid/x/"
        made.append(h)
        return h

    class Notifier:
        def __init__(self):
            self.updates = []

        def post_link(self, card):
            return "ref"

        def update(self, ref, text):
            self.updates.append(text)

    note = Notifier()
    svc = SecureInput(FakeCtx(), start=start, notifier_factory=lambda c: note, hermes_root=lambda: str(hermes_root),
                      start_kwargs={"serve": ServeManager(bin=str(fake_tailscale.bin))}, settings=settings_with([]))
    assert "입력 링크를 보냈습니다" in svc.command(raw)
    end = time.monotonic() + 10
    while not note.updates and time.monotonic() < end:
        time.sleep(0.02)
    (h,) = made
    assert h.wait_timeouts == [PARENT_WAIT[kind]] and h.cancel_args[0][:2] == ((), {})
