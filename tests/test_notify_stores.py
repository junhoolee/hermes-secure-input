"""Card 3: the Slack link message and result message with stores and the keychain (plan 5.3, 6.3 R-1, A.12)."""

import json

from secure_input.notify import (LinkCard, SlackNotifier, SlackTarget, TextNotifier, build_blocks, fallback_text,
                                 result_text)
from secure_input.spec import build_store_rows

URL = "https://fake-host.example-tailnet.ts.net/TOKEN_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG/"
NEW_KC = {"id": "test-item", "service": "hermes-secure-input.test-item", "account": "hermes-secure-input",
          "listed": False, "label": None, "used_by": None}
LISTED_KC = {"id": "example-cred", "service": "Example-Service", "account": "example-account", "listed": True,
             "label": "예시 비밀번호", "used_by": "예시 잠금 해제 스크립트"}


def card(kind="api_key", stores=None, keychain=None, **over):
    d = dict(kind=kind, label="이름표", purpose="목적 문장", target_profile="default", url=URL,
             env_var="EXA_API_KEY" if kind == "api_key" else None,
             origin="https://admin.example.com" if kind == "login" else None,
             stores=tuple(build_store_rows(kind, stores)), keychain=keychain)
    d.update(over)
    return LinkCard(**d)


def section(c):
    """Every section's text of the link message, in order (review R3-7 split title and body)."""
    return "\n".join(b["text"]["text"] for b in build_blocks(c) if b["type"] == "section")


# --- link message ---------------------------------------------------------------------------------------------

def test_api_key_link_shows_stores_and_keychain_item_line():
    c = card("api_key", [{"store": "env"}, {"store": "keychain", "reason": "백업 스크립트가 읽습니다", "needed": True}],
             keychain=dict(NEW_KC, id="exa-api-key", service="hermes-secure-input.exa-api-key"))
    for text in (section(c), fallback_text(c)):
        assert "저장 위치: .env, Mac 키체인 (페이지에서 켜고 끌 수 있음)" in text
        assert "키체인 항목: hermes-secure-input.exa-api-key (계정 hermes-secure-input, 이 플러그인 전용 이름)" in text
        assert 'Hermes가 적은 이유(Mac 키체인): "백업 스크립트가 읽습니다"' in text


def test_api_key_default_link_shows_env_only_and_keychain_as_optional():
    c = card("api_key", None, keychain=dict(NEW_KC, id="exa-api-key", service="hermes-secure-input.exa-api-key"))
    text = section(c)
    assert "저장 위치: .env (페이지에서 켜고 끌 수 있음)" in text
    assert "키체인 항목(켜면 저장): hermes-secure-input.exa-api-key" in text


def test_secret_link_shows_fixed_keychain_listed_item_and_log_profile():
    c = card("secret", None, keychain=LISTED_KC)
    text = section(c)
    assert "자격증명 입력 요청: 비밀번호" in text
    assert "저장 위치: Mac 키체인\n" in text + "\n" and "켜고 끌 수 있음" not in text
    assert ("키체인 항목: Example-Service (허용 목록 항목 example-cred: 예시 비밀번호, "
            "쓰는 곳: 예시 잠금 해제 스크립트)") in text
    assert "로그를 남길 프로필: default (Mac 키체인은 프로필과 무관합니다)" in text
    assert "변수:" not in text and "사이트:" not in text


def test_login_link_shows_fixed_vault_and_no_keychain():
    text = section(card("login"))
    assert "저장 위치: Hermes vault" in text and "키체인" not in text


def test_agent_reason_is_escaped_and_flattened_in_slack():
    text = section(card("secret", [{"store": "keychain", "reason": "a<b>&c"}], keychain=NEW_KC))
    assert '"a&lt;b&gt;&amp;c"' in text


# --- result message -------------------------------------------------------------------------------------------

def env_row(saved=True, **kw):
    return dict({"store": "env", "saved": saved, "replaced": False, "error": None, "env_var": "EXA_API_KEY",
                 "profile": "default"}, **kw)


def kc_row(saved=True, **kw):
    return dict({"store": "keychain", "saved": saved, "replaced": False, "error": None,
                 "service": "hermes-secure-input.exa-api-key", "account": "hermes-secure-input", "listed": False,
                 "new_item": True, "tmp_left": False, "main_touched": True}, **kw)


def test_saved_single_env_keeps_the_old_text():
    meta = {"stores": [env_row()], "partial": False, "target_profile": "default"}
    assert result_text(card(), "saved", meta) == "저장 완료: EXA_API_KEY, 프로필 default"


def test_saved_two_stores_lists_each():
    meta = {"stores": [env_row(), kc_row()], "partial": False, "target_profile": "default"}
    text = result_text(card(), "saved", meta)
    assert text == "저장 완료: EXA_API_KEY, 프로필 default; Mac 키체인 hermes-secure-input.exa-api-key"


def test_partial_lists_saved_and_failed_stores_with_reason_word():
    meta = {"stores": [env_row(), kc_row(False, error="keychain_write_failed", main_touched=False)],
            "partial": True, "target_profile": "default"}
    text = result_text(card(), "saved", meta)
    assert text.startswith("일부만 저장: EXA_API_KEY, 프로필 default; 실패: Mac 키체인 "
                           "hermes-secure-input.exa-api-key(사유 keychain_write_failed)")
    assert "기존 값이 바뀌었을 수 있습니다" not in text


def test_partial_with_unknown_store_and_main_touched():
    meta = {"stores": [env_row(), kc_row(False, error="keychain_verify_failed")], "partial": True}
    text = result_text(card(), "saved", meta)
    assert "키체인 항목 `hermes-secure-input.exa-api-key`의 기존 값이 바뀌었을 수 있습니다." in text
    meta = {"stores": [env_row(), kc_row(None, error="store_timeout", main_touched=None)], "partial": True}
    assert "Mac 키체인 hermes-secure-input.exa-api-key(결과 확인 못 함)" in result_text(card(), "saved", meta)


def test_foreign_error_text_never_reaches_slack():
    meta = {"stores": [env_row(), kc_row(False, error="security: SecKeychainItemModify: secret-ish text")],
            "partial": True}
    text = result_text(card(), "saved", meta)
    assert "SecKeychain" not in text and "secret-ish" not in text and "실패: Mac 키체인" in text


def test_child_exited_says_result_unknown_except_for_otp_code():
    meta = {"reason": "child_exited", "returncode": -9}
    for kind in ("api_key", "login", "secret"):
        assert result_text(card(kind, keychain=NEW_KC if kind == "secret" else None), "failed", meta).startswith(
            "저장 여부를 확인하지 못했습니다.")
    otp = LinkCard(kind="otp_code", label="코드", purpose="p", target_profile="default", url=URL, site="x.example.com",
                   profile_editable=False)
    assert "저장 여부" not in result_text(otp, "failed", meta)


def test_store_timeout_failure_says_result_unknown():
    meta = {"reason": "store_timeout", "stores": [kc_row(None, error="store_timeout", main_touched=None)]}
    assert result_text(card("secret", keychain=NEW_KC), "failed", meta).startswith("저장 여부를 확인하지 못했습니다.")


def test_whole_slack_payload_of_a_secret_request_has_no_value(canary):
    calls = []

    def call(method, kwargs):
        calls.append((method, json.loads(json.dumps(kwargs))))
        return {"ok": True, "ts": "1.1", "channel": "C1"}

    n = SlackNotifier(SlackTarget("C1", None, call), TextNotifier(lambda t: None))
    c = card("secret", keychain=LISTED_KC)
    ref = n.post_link(c)
    n.update(ref, result_text(c, "saved", {"stores": [kc_row(service="Example-Service", account="example-account",
                                                            listed=True, new_item=False)], "partial": False}))
    sent = json.dumps(calls, ensure_ascii=False)
    assert canary not in sent and "Example-Service" in sent
