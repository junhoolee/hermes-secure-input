"""Security review 3: R3-5 (tool result side), N-3 and N-4.

R3-5: an allow-list item's keychain account name (often an e-mail or a login id) never reaches the AI model in a
tool result, in any end state; the page's open answer still has it. The plugin's own item keeps its fixed account.
N-3: ``keychain_acl_denied`` carries a short gloss in the Slack result and the tool note.
N-4: ``keychain_items`` keeps at most ``MAX_KEYCHAIN_ITEMS`` items.
"""

from __future__ import annotations

import json

import pytest

from helpers.browser_client import BrowserClient
from helpers.fake_tailscale import FAKE_OWNER_LOGIN
from secure_input import notify as notify_mod
from secure_input import plugin as plugin_mod
from secure_input import config as config_mod
from secure_input.launcher import Outcome
from secure_input.notify import LinkCard, result_text
from secure_input.spec import parse_keychain_items

from test_plugin import live_handle, run_bg
from test_plugin_stores import SECRET, finish, svc_factory  # noqa: F401 - fixture

CANARY_ACCOUNT = "acct-canary@example.com"
LISTED = {"id": "canary-cred", "service": "Canary-Service", "account": CANARY_ACCOUNT,
          "label": "카나리 비밀번호", "used_by": "카나리 잠금 해제 스크립트"}
ACL_GLOSS = "접근 허용 목록에 /usr/bin/security 없음"


def kc_row(**over):
    row = {"store": "keychain", "saved": True, "replaced": True, "error": None, "service": LISTED["service"],
           "account": CANARY_ACCOUNT, "listed": True, "new_item": False, "tmp_left": False, "main_touched": False}
    row.update(over)
    return row


SAVED_META = {"stores": [kc_row()], "target_profile": "default",
              "storage": {"type": "keychain", "service": LISTED["service"], "account": CANARY_ACCOUNT,
                          "profile": "default", "origin": None, "env_var": None, "item_id": None}}
END_STATES = {
    "saved": Outcome("saved", SAVED_META),
    "partial": Outcome("saved", {
        "stores": [{"store": "env", "saved": True, "env_var": "X_KEY", "profile": "default", "error": None},
                   kc_row(saved=False, replaced=None, error="keychain_acl_denied")],
        "partial": True, "target_profile": "default",
        "storage": {"type": "env", "env_var": "X_KEY", "profile": "default"}}),
    "failed": Outcome("failed", {"reason": "none_saved",
                                 "stores": [kc_row(saved=False, replaced=None, error="keychain_write_failed",
                                                   main_touched=True)]}),
    "unknown": Outcome("failed", {"reason": "store_timeout",
                                  "stores": [kc_row(saved=None, replaced=None, error="store_timeout")]}),
    "expired": Outcome("expired", {"reason": "open_window_passed"}),
    "cancelled": Outcome("cancelled", {"reason": "user_cancelled",
                                       "stores": [kc_row(saved=False, replaced=None, error="keychain_write_failed")]}),
}


def listed_spec(svc):
    return svc.build_spec(kind="secret", purpose=SECRET["purpose"], label=SECRET["label"],
                          requester=svc.requester("agent"), target_profile=None, keychain_item="canary-cred")


def tool_result(svc, outcome):
    spec = listed_spec(svc)
    return svc.result(kind="secret", label=spec.label, target_profile=spec.target_profile, outcome=outcome,
                      request_id="r1", spec=spec)


# --- R3-5 ---------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("state", list(END_STATES))
def test_listed_item_account_is_not_in_the_tool_result_of_any_end_state(svc_factory, state):
    svc = svc_factory(items=[LISTED])
    text = tool_result(svc, END_STATES[state])
    assert CANARY_ACCOUNT not in text
    res = json.loads(text)
    assert res["storage"] == {"type": "keychain", "service": "Canary-Service", "listed": True,
                              "allow_list_id": "canary-cred", "label": "카나리 비밀번호"} or state == "partial"
    for row in res["stores"]:
        if row["store"] == "keychain":
            assert "account" not in row and row["listed"] is True


def test_listed_item_saved_note_names_service_and_allow_list_id(svc_factory):
    svc = svc_factory(items=[LISTED])
    res = json.loads(tool_result(svc, END_STATES["saved"]))
    assert "값은 Mac 키체인 항목(service `Canary-Service`, 허용 목록 항목 `canary-cred`)에 저장했습니다." in res["note"]


def test_listed_item_account_reaches_the_page_but_not_the_tool_result(svc_factory, canary):
    svc = svc_factory(items=[LISTED], keychain={"preflight": {"available": True, "reason": None, "exists": True},
                                                "save": {"new_item": False, "replaced": True}})
    t, box = run_bg(svc.tool_request, dict(SECRET, keychain_item="canary-cred"))
    h = live_handle(svc)
    c = BrowserClient(h.local_url, identity=FAKE_OWNER_LOGIN, timeout=60.0)
    opened = c.open()
    assert opened.status_code == 200 and CANARY_ACCOUNT in opened.text
    assert opened.json()["target"]["keychain"]["listed"] is True
    assert c.submit({"kind": "secret", "target_profile": "default", "value": canary}).status_code == 200
    res = finish(t, box)
    assert res["status"] == "saved"
    assert CANARY_ACCOUNT not in box["r"] and canary not in box["r"]
    assert res["storage"]["allow_list_id"] == "canary-cred" and "account" not in res["storage"]


def test_own_item_keeps_its_fixed_account_in_the_tool_result(svc_factory):
    svc = svc_factory(items=[LISTED])
    spec = svc.build_spec(kind="secret", purpose=SECRET["purpose"], label=SECRET["label"],
                          requester=svc.requester("agent"), target_profile=None, keychain_item="own-new")
    row = kc_row(service="hermes-secure-input.own-new", account="hermes-secure-input", listed=False, new_item=True,
                 replaced=False)
    meta = {"stores": [row], "storage": {"type": "keychain", "service": row["service"], "account": row["account"]}}
    res = json.loads(svc.result(kind="secret", label=spec.label, target_profile="default",
                                outcome=Outcome("saved", meta), request_id="r2", spec=spec))
    assert res["storage"] == {"type": "keychain", "service": "hermes-secure-input.own-new",
                              "account": "hermes-secure-input"}
    assert res["stores"][0]["account"] == "hermes-secure-input"
    assert "값은 Mac 키체인 항목(service `hermes-secure-input.own-new`, account `hermes-secure-input`)에 저장했습니다." \
        in res["note"]


def test_command_answer_for_a_listed_item_has_no_account(svc_factory):
    svc = svc_factory(items=[LISTED])
    out = svc.command('secret canary-cred --label "카나리"', session_key="sk", platform="slack")
    assert "입력 링크를 보냈습니다" in out and CANARY_ACCOUNT not in out
    svc.cancel_all()


# --- N-3 ----------------------------------------------------------------------------------------------------

def test_slack_row_failure_glosses_keychain_acl_denied():
    card = LinkCard(kind="secret", label="x", purpose="p", target_profile="default", url="https://x",
                    keychain={"id": "canary-cred", "service": "Canary-Service", "account": CANARY_ACCOUNT,
                              "listed": True, "label": "l", "used_by": "u"})
    row = kc_row(saved=False, replaced=None, error="keychain_acl_denied")
    assert f"(사유 keychain_acl_denied: {ACL_GLOSS})" in notify_mod._row_failure(row, card, "default")
    assert notify_mod.ERROR_WORD_GLOSS == {"keychain_acl_denied": ACL_GLOSS}
    other = notify_mod._row_failure(kc_row(saved=False, error="keychain_write_failed"), card, "default")
    assert other.endswith("(사유 keychain_write_failed)")


def test_slack_partial_result_glosses_keychain_acl_denied():
    card = LinkCard(kind="api_key", label="x", purpose="p", target_profile="default", url="https://x",
                    env_var="X_KEY")
    text = result_text(card, "saved", END_STATES["partial"].meta)
    assert f"keychain_acl_denied: {ACL_GLOSS}" in text


def test_tool_note_glosses_keychain_acl_denied(svc_factory):
    svc = svc_factory(items=[LISTED])
    res = json.loads(tool_result(svc, END_STATES["partial"]))
    assert f"Mac 키체인 에는 저장하지 못했습니다(사유 keychain_acl_denied: {ACL_GLOSS})." in res["note"]
    other = svc._saved_note("secret", [kc_row(saved=False, error="keychain_write_failed")], "default", False, False)
    assert other == "Mac 키체인 에는 저장하지 못했습니다(사유 keychain_write_failed)."


# --- N-4 ----------------------------------------------------------------------------------------------------

def items(n):
    return [{"id": f"item-{i}", "service": f"Svc-{i}", "account": f"acct-{i}", "label": "가" * 120,
             "used_by": "나" * 120} for i in range(n)]


def test_limit_is_twenty():
    assert config_mod.MAX_KEYCHAIN_ITEMS == 20


def test_twenty_items_all_stay():
    got, warnings = parse_keychain_items(items(20))
    assert len(got) == 20 and warnings == []


def test_twenty_one_items_keep_twenty_with_one_limit_warning():
    got, warnings = parse_keychain_items(items(21))
    assert [i["id"] for i in got] == [f"item-{i}" for i in range(20)]
    assert warnings == [{"index": 20, "field": "limit"}]


def test_limit_counts_only_valid_items():
    raw = [{"bad": 1}] + items(21)
    got, warnings = parse_keychain_items(raw)
    assert len(got) == 20 and warnings == [{"index": 0, "field": "item"}, {"index": 21, "field": "limit"}]


def test_ten_thousand_items_keep_twenty_and_a_short_description(caplog):
    got, warnings = parse_keychain_items(items(10_000))
    assert len(got) == 20 and warnings == [{"index": 20, "field": "limit"}]
    desc = plugin_mod.build_request_schema(got)["parameters"]["properties"]["keychain_item"]["description"]
    assert len(desc) <= 7000


def test_limit_warning_is_logged_like_other_warnings(svc_factory, caplog):
    svc = svc_factory(items=items(21))
    with caplog.at_level("WARNING"):
        assert len(svc.allow_list()) == 20
    assert "keychain_items item 20 left out (field limit)" in caplog.text
    assert "가" * 120 not in caplog.text
