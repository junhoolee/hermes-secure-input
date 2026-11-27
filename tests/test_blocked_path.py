"""Criterion 12 (card 5.6): a login page with no saved login in a Slack turn.

Without the plugin, Hermes' ``save_login`` answers ``prompt_unavailable`` and tells the agent to send the
user to ``hermes vault add`` (SSH). With the plugin (mechanism b), the ``pre_tool_call`` hook blocks the
call and points the agent at ``secure_input_request(kind='login', origin=...)``; with the setting off it
does not intervene.
"""

from __future__ import annotations

import json
import threading

import pytest

from test_plugin import env  # noqa: F401  (fixture reuse)


@pytest.fixture
def login_page(monkeypatch):
    import tools.browser_vault_tool as bvt

    monkeypatch.setattr(bvt, "_eval_js", lambda task_id, expr: {"success": True,
                                                                "result": "https://shop.example.com/login"})
    monkeypatch.setattr(bvt, "_page_backend", lambda task_id: None)
    monkeypatch.setattr(bvt, "_ensure_supervisor", lambda task_id: None)


def core_save_login_in_slack_turn():
    """Hermes' browser_vault handler as a Slack turn runs it: no save-login prompt in the slot."""
    from agent.vault_backends import unlock
    from tools.registry import registry
    box = {}

    def body():
        unlock.set_save_login_prompt_callback(None)  # the gateway installs none for messaging turns
        box["r"] = registry.dispatch("browser_vault", {"action": "save_login"}, task_id="t-login")

    t = threading.Thread(target=body)
    t.start()
    t.join(30)
    return json.loads(box["r"])


def test_without_plugin_core_answers_prompt_unavailable_with_ssh_advice(login_page):
    res = core_save_login_in_slack_turn()
    assert res["error_type"] == "prompt_unavailable" and "hermes vault add" in res["error"]


def test_plugin_hook_blocks_and_points_at_secure_input_request(env, login_page):  # noqa: F811
    svc = env()
    blocked = svc.pre_tool_call(tool_name="browser_vault", args={"action": "save_login"})
    assert blocked["action"] == "block"
    msg = blocked["message"]
    assert "secure_input_request" in msg and "kind='login'" in msg and "storage.item_id" in msg
    assert "hermes vault add" in msg and "Do not" in msg  # names the SSH advice only to forbid it
    assert svc.fake_slack.calls == [] and svc._live == {}  # the hook itself never starts a request


def test_setting_off_does_not_intervene(env, login_page):  # noqa: F811
    svc = env(settings=lambda key, default: False if key == "intercept_core_save_login" else default)
    assert svc.pre_tool_call(tool_name="browser_vault", args={"action": "save_login"}) is None
    assert core_save_login_in_slack_turn()["error_type"] == "prompt_unavailable"
