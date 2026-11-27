"""``secure_input_enter_code`` (card 5.4, criterion 6), against Hermes' real browser_vault handler.

The browser page is faked at Hermes' two page primitives (``_eval_js`` for inspection/origin and
``_eval_js_secret`` for the write). The gateway's Slack code card is simulated by a previous
code-prompt callback that would call ``adapter.send_vault_code_prompt``; it must never run.
"""

from __future__ import annotations

import json
import threading

import pytest

from helpers.browser_client import BrowserClient
from helpers.fake_tailscale import FAKE_OWNER_LOGIN
from test_plugin import FakeCtx, env, everything_sent, live_handle, run_bg  # noqa: F401  (fixture reuse)

SITE = "https://accounts.example.com"


class FakeAdapter:
    def __init__(self):
        self.code_prompts = 0

    def send_vault_code_prompt(self, *a, **kw):
        self.code_prompts += 1
        return "000000"


@pytest.fixture
def page(monkeypatch):
    import tools.browser_vault_tool as bvt

    state = {"controls": [{"index": 0, "type": "text", "name": "otc", "autocomplete": "one-time-code",
                           "label": "", "formIndex": 0}],
             "secret_exprs": [], "evals": []}

    def fake_eval(task_id, expression):
        state["evals"].append(expression)
        if expression == "window.location.href":
            return {"success": True, "result": SITE + "/login/verify"}
        return {"success": True, "result": json.dumps(state["controls"])}

    def fake_secret(task_id, expression):
        state["secret_exprs"].append(expression)
        return {"success": True, "result": json.dumps({"filled": 1})}

    monkeypatch.setattr(bvt, "_eval_js", fake_eval)
    monkeypatch.setattr(bvt, "_eval_js_secret", fake_secret)
    monkeypatch.setattr(bvt, "_page_backend", lambda task_id: None)
    monkeypatch.setattr(bvt, "_ensure_supervisor", lambda task_id: None)
    return state


def run_enter_code(svc, adapter, args=None):
    """Run the tool on its own thread, with the gateway's Slack code card installed first."""
    from agent.vault_backends import unlock
    from secure_input import otp_flow

    box = {}

    def body():
        def slack_card(site, hint):
            return adapter.send_vault_code_prompt(site, hint)

        unlock.set_code_prompt_callback(slack_card)
        box["result"] = otp_flow.enter_code(svc, args or {}, task_id="task-otp")
        box["restored"] = unlock.get_code_prompt_callback() is slack_card
        unlock.set_code_prompt_callback(None)

    t = threading.Thread(target=body, daemon=True)
    t.start()
    return t, box


def test_code_goes_through_our_page_into_the_page_write(env, page, canary):  # noqa: F811
    svc = env()
    adapter = FakeAdapter()
    t, box = run_enter_code(svc, adapter)
    h = live_handle(svc)
    assert h.spec.kind == "otp_code" and h.spec.site == "accounts.example.com" and h.spec.profile_editable is False
    c = BrowserClient(h.local_url, identity=FAKE_OWNER_LOGIN)
    assert c.open().status_code == 200
    assert c.submit({"kind": "otp_code", "code": canary}).status_code == 200
    t.join(30)
    res = json.loads(box["result"])
    assert res["success"] is True and res["filled_fields"] == 1 and res["source"] == "user"
    assert res["secure_input"]["request_id"] == h.request_id
    assert adapter.code_prompts == 0  # the Slack modal never ran
    assert box["restored"] is True  # previous slot callback put back
    entered = canary.replace("-", "")  # Hermes strips spaces and dashes before writing
    assert len(page["secret_exprs"]) == 1 and entered in page["secret_exprs"][0]
    sent = everything_sent(svc, [box["result"]])
    assert canary not in sent and entered not in sent
    assert len([c for c in svc.fake_slack.calls if c[0] == "chat_postMessage"]) == 1
    assert "전달 완료" in svc.fake_slack.calls[-1][1]["text"]


def test_expired_code_request_returns_code_declined(env, page):  # noqa: F811
    from secure_input import plugin as plugin_mod
    svc = env(start=lambda spec, **kw: plugin_mod.start_request(spec, _test_ttls={"open": 1.0, "submit": 2.0}, **kw))
    adapter = FakeAdapter()
    t, box = run_enter_code(svc, adapter)
    t.join(30)
    res = json.loads(box["result"])
    assert res["success"] is False and res["error_type"] == "code_declined"
    assert adapter.code_prompts == 0 and page["secret_exprs"] == []
    assert "만료" in svc.fake_slack.calls[-1][1]["text"]


def test_no_code_field_is_passed_through_with_korean_note(env, page):  # noqa: F811
    page["controls"] = [{"index": 0, "type": "text", "name": "OnetimeCode", "label": "일회용 번호"}]
    svc = env()
    adapter = FakeAdapter()
    t, box = run_enter_code(svc, adapter)
    t.join(30)
    res = json.loads(box["result"])
    assert res["error_type"] == "no_code_field"
    assert res["note"] == (
        "Hermes가 이 페이지의 코드 입력칸을 인식하지 못했습니다. 일회용 코드를 채팅으로 묻지 마세요. "
        "사용자에게는 이 사이트의 코드 칸은 자동 입력이 되지 않는다는 사실만 알리세요. "
        "일회용 코드가 필요 없는 다른 로그인 방법이 있으면 그것을 쓰고, 없으면 이 로그인을 멈추세요."
    )
    assert res["secure_input"]["request_id"] is None and svc.fake_slack.calls == []


def test_no_code_field_note_forbids_asking_for_the_code_in_chat(env, page):  # noqa: F811
    # The login browser runs on the Hermes machine, so the user in Slack cannot type into that field.
    # Asking for the code would make the model request it in chat, sending it through Slack.
    page["controls"] = [{"index": 0, "type": "text", "name": "OnetimeCode", "label": "일회용 번호"}]
    svc = env()
    adapter = FakeAdapter()
    t, box = run_enter_code(svc, adapter)
    t.join(30)
    res = json.loads(box["result"])
    assert res["error_type"] == "no_code_field"
    assert "채팅으로 묻지 마세요" in res["note"]
    assert "직접 입력을 부탁" not in res["note"]
    assert res["secure_input"]["request_id"] is None and svc.fake_slack.calls == []
    assert adapter.code_prompts == 0


# --- saved-login handles (review round 1): Hermes' enter_code with a handle but no authenticator key falls
# back to the gateway's Slack code modal, so the hook blocks every core enter_code and our tool covers both.

@pytest.fixture
def saved_login(env):  # noqa: F811
    """Add a login to the (temp) vault Hermes' real handler reads, optionally with an authenticator key."""
    from agent.vault_store import VaultStore

    def add(otp_secret=None):
        secret = {"identifier_type": "username", "identifier": "si-user", "password": "pw-not-used"}
        if otp_secret:
            secret["otp_secret"] = otp_secret
        return VaultStore().add_item(kind="login", label="example", secret=secret, origin=SITE).id

    return add


def test_handle_without_authenticator_key_goes_through_our_page(env, page, canary, saved_login):  # noqa: F811
    handle = saved_login()
    svc = env()
    adapter = FakeAdapter()
    t, box = run_enter_code(svc, adapter, {"handle": handle})
    h = live_handle(svc)
    assert h.spec.kind == "otp_code" and h.spec.site == "accounts.example.com"
    c = BrowserClient(h.local_url, identity=FAKE_OWNER_LOGIN)
    assert c.open().status_code == 200
    assert c.submit({"kind": "otp_code", "code": canary}).status_code == 200
    t.join(30)
    res = json.loads(box["result"])
    assert res["success"] is True and res["source"] == "user"
    assert res["secure_input"]["request_id"] == h.request_id
    assert adapter.code_prompts == 0  # the Slack modal never ran
    entered = canary.replace("-", "")
    assert len(page["secret_exprs"]) == 1 and entered in page["secret_exprs"][0]
    assert canary not in everything_sent(svc, [box["result"]])


def test_handle_with_authenticator_key_needs_no_page(env, page, saved_login):  # noqa: F811
    handle = saved_login(otp_secret="JBSWY3DPEHPK3PXP")
    svc = env()
    adapter = FakeAdapter()
    t, box = run_enter_code(svc, adapter, {"handle": handle})
    t.join(30)
    res = json.loads(box["result"])
    assert res["success"] is True and res["source"] != "user"
    assert res["secure_input"]["request_id"] is None and svc.fake_slack.calls == []
    assert adapter.code_prompts == 0 and len(page["secret_exprs"]) == 1
