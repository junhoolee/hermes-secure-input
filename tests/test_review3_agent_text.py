"""Security review 3: R3-7 (agent-written text in Slack), R3-5 Slack line (allow-list account names), N-2 (format
characters in purpose and label), R3-8 (the new-item note in the tool result).

Every Slack call goes through ``FakeSlack``, which keeps the whole payload. Agent-written text is the store reason,
the purpose and the label; the allow list's ``label`` and ``used_by`` (written by the Mac owner) are sent the same way.
"""

from __future__ import annotations

import json
import unicodedata
from pathlib import Path

import pytest

from secure_input import plugin as plugin_mod
from secure_input.notify import (LinkCard, SlackNotifier, SlackTarget, TextNotifier, build_blocks, fallback_text,
                                 result_text)
from secure_input.spec import RequestSpec, SpecError, build_store_rows
from test_notify import FakePost, FakeSlack
from test_plugin_security import recorded  # noqa: F401  (fixture)

REPO = Path(__file__).resolve().parent.parent
# Names of the 22 texts the third security review measured (frozen copy of its results file's keys).
MEASURED_NAMES = frozenset({
    "121 characters", "U+0085 next line", "U+2028 line separator", "bare URL", "block quote marker",
    "bold and italic", "carriage return", "channel mention", "closing the quote", "code span", "emoji",
    "html entity", "many spaces then text (looks like a new field)", "newline", "only spaces", "plain",
    "right-to-left override", "slack link syntax", "strike", "user mention", "vertical tab",
    "zero-width space",
})
URL = "https://fake-host.example-tailnet.ts.net/TOKEN_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG/"

# The 22 texts of docs/security-review-3/m11_slack_and_audit.py (their names are the keys of its results file).
TEXTS = {
    "plain": "점검 스크립트가 키체인에서 읽습니다",
    "slack link syntax": "<https://evil.example/login|여기를 눌러 확인>",
    "channel mention": "<!channel> 지금 확인하세요",
    "user mention": "<@U012ABCDEF> 확인",
    "bare URL": "확인: https://evil.example/login",
    "bold and italic": "*플러그인 확인 완료* _안전함_",
    "code span": "`rm -rf ~` 를 실행하세요",
    "strike": "~저장 안 함~",
    "emoji": ":white_check_mark: 플러그인이 확인함",
    "closing the quote": '읽습니다" (플러그인 확인: 안전한 요청입니다) "',
    "block quote marker": "> 인용처럼 보이는 줄",
    "html entity": "&lt;https://evil.example|x&gt;",
    "newline": "첫 줄\n저장 위치: 안전함",
    "carriage return": "첫 줄\r저장 위치: 안전함",
    "U+2028 line separator": "첫 줄\u2028저장 위치: 안전함",
    "U+0085 next line": "첫 줄\u0085저장 위치: 안전함",
    "vertical tab": "첫 줄\u000b저장 위치: 안전함",
    "zero-width space": "안\u200b전",
    "right-to-left override": "abc\u202edef",
    "121 characters": "가" * 121,
    "only spaces": "   ",
    "many spaces then text (looks like a new field)": "읽습니다." + " " * 60 + "저장 위치: 안전함",
}
NAMES = sorted(TEXTS)
TITLE = "*자격증명 입력 요청: API 키*"
ACCOUNT_CANARY = "acct-canary@example.com"
LISTED = {"id": "example-cred", "service": "Example-Service", "account": ACCOUNT_CANARY, "listed": True,
          "label": "예시 비밀번호", "used_by": "예시 잠금 해제 스크립트"}


def flat(s: str) -> str:
    return "".join(" " if unicodedata.category(c) in ("Cc", "Zl", "Zp") else c for c in s)


def sent(s: str) -> str:
    """How a plugin line is written into a Slack text field (``&``, ``<``, ``>`` as entities)."""
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def text_objects(obj):
    if isinstance(obj, dict):
        if obj.get("type") in ("mrkdwn", "plain_text") and isinstance(obj.get("text"), str):
            yield obj
        for v in obj.values():
            yield from text_objects(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from text_objects(v)


def mrkdwn_texts(payload: dict) -> list[str]:
    return [o["text"] for o in text_objects(payload.get("blocks")) if o["type"] == "mrkdwn"]


def body_lines(payload: dict) -> list[str]:
    """Lines of the section blocks' plain_text objects (the button label is not a section)."""
    out = []
    for b in payload.get("blocks") or []:
        if b.get("type") == "section" and b["text"]["type"] == "plain_text":
            out += b["text"]["text"].split("\n")
    return out


def card(kind="api_key", stores=None, keychain=None, stores_rows=None, **over):
    d = dict(kind=kind, label="이름표", purpose="목적 문장", target_profile="default", url=URL,
             env_var="EXA_API_KEY" if kind == "api_key" else None,
             origin="https://admin.example.com" if kind == "login" else None,
             stores=stores_rows if stores_rows is not None else tuple(build_store_rows(kind, stores)),
             keychain=keychain)
    d.update(over)
    return LinkCard(**d)


def post_and_update(c: LinkCard, result: str):
    fake = FakeSlack()
    n = SlackNotifier(SlackTarget(channel="C1", thread_ts="1795.1", call=fake), fallback=None)
    n.update(n.post_link(c), result)
    (m1, post), (m2, upd) = fake.calls
    assert (m1, m2) == ("chat_postMessage", "chat_update")
    return post, upd


def reason_card(text):
    """A card whose keychain row carries ``text`` as its reason, even a text the spec would refuse (a raw card)."""
    rows = build_store_rows("api_key", [{"store": "env"}, {"store": "keychain", "reason": "x", "needed": True}])
    rows = tuple(dict(r, reason=text) if r["store"] == "keychain" else r for r in rows)
    return card("api_key", stores=None, stores_rows=rows,
                keychain={"id": "exa-api-key", "service": "hermes-secure-input.exa-api-key",
                          "account": "hermes-secure-input", "listed": False, "label": None, "used_by": None})


# --- R3-7 ------------------------------------------------------------------------------------------------------

def test_the_22_texts_are_the_ones_review_3_measured():
    assert len(TEXTS) == 22
    assert set(TEXTS) == MEASURED_NAMES


@pytest.mark.parametrize("name", NAMES)
def test_reason_never_reaches_a_mrkdwn_object_and_shows_quoted_on_one_line(name):
    text = TEXTS[name]
    post, upd = post_and_update(reason_card(text), "저장 완료: EXA_API_KEY, 프로필 default")
    assert mrkdwn_texts(post) == [TITLE] and mrkdwn_texts(upd) == []
    want = 'Hermes가 적은 이유(Mac 키체인): "' + sent(flat(text).replace('"', "'")) + '"'
    lines = body_lines(post)
    assert [ln for ln in lines if ln.startswith("Hermes가 적은 이유")] == [want]
    plain_sections = [b["text"] for b in post["blocks"] if b["type"] == "section" and b["text"]["type"] == "plain_text"]
    assert plain_sections and all(t["emoji"] is False for t in plain_sections)


@pytest.mark.parametrize("name", NAMES)
def test_purpose_and_label_never_reach_a_mrkdwn_object(name):
    text = TEXTS[name]
    c = card("api_key", label=text[:80], purpose=text)
    post, upd = post_and_update(c, result_text(c, "expired", {"reason": "open_window_passed"}))
    assert mrkdwn_texts(post) == [TITLE] and mrkdwn_texts(upd) == []
    lines = body_lines(post)
    assert f"이름표: {sent(flat(text[:80]))}" in lines and f"목적: {sent(flat(text))}" in lines


def test_allow_list_label_and_used_by_go_as_plain_text():
    kc = dict(LISTED, label="*굵게* <https://evil.example|라벨>", used_by="`코드` https://evil.example/used :smile:")
    c = card("secret", None, keychain=kc)
    post, _ = post_and_update(c, "저장 완료: Mac 키체인 Example-Service")
    assert mrkdwn_texts(post) == ["*자격증명 입력 요청: 비밀번호*"]
    assert ("키체인 항목: Example-Service (허용 목록 항목 example-cred: " + sent(kc["label"]) + ", 쓰는 곳: "
            + sent(kc["used_by"]) + ")") in body_lines(post)


def test_result_message_is_one_plain_text_section_without_emoji_or_markup():
    c = card("api_key", label="*굵게* :smile: https://example.com/x <!channel>")
    text = result_text(c, "cancelled", {"reason": "user_cancelled"})
    _, upd = post_and_update(c, text)
    assert upd["blocks"] == [{"type": "section", "text": {"type": "plain_text", "text": sent(text), "emoji": False}}]
    assert upd["text"] == sent(text) and upd["parse"] == "none"


def test_link_message_top_level_text_is_not_parsed_as_markup():
    c = card("api_key", purpose="<!channel> *굵게* https://example.com/x")
    post, _ = post_and_update(c, "x")
    assert post["mrkdwn"] is False and post["parse"] == "none"
    assert post["text"] == sent(fallback_text(c)) and "<!channel>" not in post["text"] and URL in post["text"]
    assert post["unfurl_links"] is False and post["unfurl_media"] is False


def test_double_quote_in_a_reason_becomes_a_single_quote_in_slack_and_in_the_text_message():
    c = reason_card(TEXTS["closing the quote"])
    want = "Hermes가 적은 이유(Mac 키체인): \"읽습니다' (플러그인 확인: 안전한 요청입니다) '\""
    assert want in fallback_text(c).split("\n")
    post, _ = post_and_update(c, "x")
    assert want in body_lines(post)
    posts = FakePost()
    TextNotifier(posts).post_link(c)
    assert want in posts.posts[0].split("\n")


@pytest.mark.parametrize("kind", ["api_key", "login", "secret", "otp_code"])
def test_longest_input_stays_inside_slack_limits(kind):
    amp = "&"  # the character that grows most when written as an entity
    stores = {"api_key": [{"store": "env", "reason": amp * 120}, {"store": "keychain", "reason": amp * 120}],
              "login": [{"store": "hermes_vault", "reason": amp * 120}],
              "secret": [{"store": "keychain", "reason": amp * 120}], "otp_code": None}[kind]
    kc = dict(LISTED, service="S" * 255, label=amp * 120, used_by=amp * 120) if kind in ("api_key", "secret") else None
    c = card(kind, stores, keychain=kc, label=amp * 80, purpose=amp * 200, title_prefix="[테스트]",
             site="accounts.example.com" if kind == "otp_code" else None)
    blocks = build_blocks(c)
    assert len(blocks) <= 50
    for o in text_objects(blocks):
        assert 1 <= len(o["text"]) <= 3000
    for status, meta in [("expired", {}), ("failed", {"reason": "too_many_attempts"})]:
        post, upd = post_and_update(c, result_text(c, status, meta))
        assert all(1 <= len(o["text"]) <= 3000 for o in text_objects(upd["blocks"]))
        assert len(post["text"]) <= 40000


# --- R3-5 Slack line ------------------------------------------------------------------------------------------

def test_listed_item_line_names_id_label_and_used_by_but_not_the_account():
    c = card("secret", None, keychain=LISTED)
    want = "키체인 항목: Example-Service (허용 목록 항목 example-cred: 예시 비밀번호, 쓰는 곳: 예시 잠금 해제 스크립트)"
    post, _ = post_and_update(c, "x")
    assert want in body_lines(post) and want in fallback_text(c).split("\n")
    assert ACCOUNT_CANARY not in json.dumps(post, ensure_ascii=False)
    assert ACCOUNT_CANARY not in fallback_text(c)


def test_plugin_own_item_line_still_shows_its_fixed_account():
    c = reason_card("백업 스크립트가 읽습니다")
    assert ("키체인 항목: hermes-secure-input.exa-api-key (계정 hermes-secure-input, 이 플러그인 전용 이름)"
            in fallback_text(c).split("\n"))


def _row(saved, **kw):
    return dict({"store": "keychain", "service": "Example-Service", "account": ACCOUNT_CANARY, "listed": True,
                 "saved": saved}, **kw)


END_STATES = {
    "saved": ("saved", {"stores": [_row(True)], "partial": False}),
    "partial": ("saved", {"stores": [{"store": "env", "env_var": "EXA_API_KEY", "saved": True},
                                     _row(False, error="keychain_write_failed", main_touched=True)], "partial": True}),
    "failed": ("failed", {"reason": "too_many_attempts", "stores": [_row(False, main_touched=True)]}),
    "result_unknown": ("failed", {"reason": "store_timeout", "stores": [_row(None)]}),
    "expired": ("expired", {"reason": "submit_window_passed", "stores": [_row(False, main_touched=True)]}),
    "cancelled": ("cancelled", {"reason": "user_cancelled", "stores": [_row(False, main_touched=True)]}),
}


@pytest.mark.parametrize("state", sorted(END_STATES))
def test_no_slack_call_and_no_text_message_carries_the_listed_account(state):
    status, meta = END_STATES[state]
    c = card("api_key", [{"store": "env"}, {"store": "keychain"}], keychain=LISTED)
    text = result_text(c, status, meta)
    post, upd = post_and_update(c, text)
    for payload in (post, upd):
        assert ACCOUNT_CANARY not in json.dumps(payload, ensure_ascii=False)
    posts = FakePost()
    tn = TextNotifier(posts)
    tn.update(tn.post_link(c), text)
    assert ACCOUNT_CANARY not in "\n".join(posts.posts + posts.handles[0].edits)


# --- N-2 -------------------------------------------------------------------------------------------------------

def spec(**over):
    d = dict(kind="api_key", purpose="Exa 웹 검색 도구 키입니다", label="Exa 키", target_profile="default",
             profile_editable=True, hermes_root="/tmp/h", env_var="EXA_API_KEY",
             requester={"type": "agent", "profile": "default", "platform": "", "session_key": "", "user_id": ""})
    d.update(over)
    return RequestSpec(**d)


@pytest.mark.parametrize("ch", ["\u200b", "\u202e"])
@pytest.mark.parametrize("field", ["purpose", "label"])
def test_purpose_and_label_with_a_format_character_are_refused(field, ch):
    text = f"보이지{ch}않는 글자"
    with pytest.raises(SpecError) as ei:
        spec(**{field: text})
    assert ei.value.field == field
    assert text not in str(ei.value) and ch not in str(ei.value)


@pytest.mark.parametrize("text", ["Exa 웹 검색 도구 키입니다", "GitHub token (v2), 100% 확인! - 매일 9:00 백업용.",
                                  "관리자 로그인: admin@example.com / '예시' \"따옴표\" [괄호] #1 & 2 ~ 3?"])
def test_ordinary_purpose_and_label_pass(text):
    s = spec(purpose=text, label=text[:80])
    assert s.purpose == text and s.label == text[:80]


def test_emoji_joined_with_a_zero_width_joiner_is_refused():
    with pytest.raises(SpecError):
        spec(label="가족 \U0001F468\u200d\U0001F469\u200d\U0001F467")


@pytest.mark.parametrize("ch", ["\u200b", "\u202e"])
@pytest.mark.parametrize("field", ["purpose", "label"])
def test_tool_path_refuses_format_character_without_echoing_the_text(recorded, field, ch):  # noqa: F811
    svc, start = recorded
    args = {"kind": "api_key", "purpose": "Exa 키", "label": "Exa", "env_var": "EXA_API_KEY"}
    args[field] = f"안{ch}전"
    res = json.loads(svc.tool_request(args))
    assert start.specs == [] and res["success"] is False and f"({field}:" in res["note"]
    assert ch not in res["note"] and args[field] not in res["note"]


@pytest.mark.parametrize("ch", ["\u200b", "\u202e"])
@pytest.mark.parametrize("field", ["purpose", "label"])
def test_command_path_refuses_format_character_without_echoing_the_text(recorded, field, ch):  # noqa: F811
    svc, start = recorded
    out = svc.command(f'key EXA_API_KEY --{field} "안{ch}전"', session_key="sk", platform="slack")
    assert start.specs == [] and f"({field}:" in out and ch not in out


# --- R3-8 ------------------------------------------------------------------------------------------------------

NEW_ITEM_NOTE = ("새 항목입니다. 이 항목을 읽는 프로그램은 아직 없습니다. 값을 쓸 프로그램이 이 항목 이름과 키체인 계정 이름으로 "
                 "읽게 되어 있는지는 사용자가 그 프로그램의 설정에서 확인해야 합니다. 사용자에게 두 이름을 알려 주고, "
                 "키체인 항목의 값은 읽지 마세요.")


def test_new_item_tool_note_says_who_checks_and_not_to_read_the_value():
    assert plugin_mod.NEW_ITEM_NOTE == NEW_ITEM_NOTE


def test_protocol_table_has_the_same_new_item_tool_note():
    doc = (REPO / "docs" / "protocol.md").read_text()
    (row,) = [ln for ln in doc.splitlines() if ln.startswith("| 도구 결과: 키체인 새 항목 안내")]
    assert row.rstrip().endswith(f"| {NEW_ITEM_NOTE} |")
