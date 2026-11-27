"""Second recheck of security review 3 (docs/security-review-3-recheck-2.md section 5, RC2-1):

A request that sent a value more than once ends with a report (Slack result message, tool result, last audit line)
that also says what the earlier attempts left in the keychain: an earlier value that may have changed
(``main_touched``), an item that was made (``main_created``) and a temporary item that may be left (``tmp_left``).
The server keeps the three facts for the request (``ServerContext.kc_left``) and puts them in the end report as
``keychain_left`` (never the account of an allow-list item).

The case names are the second recheck's (``r11_real_browser_cases.py``); the storage process is the fake one.
"""

from __future__ import annotations

import json

import pytest

from secure_input.launcher import Outcome
from secure_input.notify import (MAIN_CREATED_TEXT, MAIN_TOUCHED_TEXT, SECTION_MAX_CHARS, TMP_LEFT_TEXT, LinkCard,
                                 _esc, result_blocks, result_text)
from secure_input.plugin import MAIN_CREATED_NOTE, MAIN_TOUCHED_NOTE, TMP_LEFT_NOTE, SecureInput
from secure_input.spec import RequestSpec, resolve_keychain
from test_lifecycle import FakeClock
from test_plugin import FakeCtx
from test_recheck_fix import SeqStorage
from test_server_app import Harness
from test_server_stores import audit, plain

LISTED_SVC = "hermes-secure-input-test-listed-rc2"
LISTED_ACCT = "rc2-owner@example.com"  # an allow-list account, often a login id: never in Slack or the tool result
ALLOW = [{"id": "rc2-listed", "service": LISTED_SVC, "account": LISTED_ACCT, "label": "점검용 기존 항목",
          "used_by": "점검 스크립트"}]
OWN_SVC = "hermes-secure-input.rc2-own"
KEY_SVC = "hermes-secure-input.exa-api-key"


def _spec(spec_dict, kind):
    if kind == "secret_listed":
        d = spec_dict(kind="secret", profile_editable=False, env_var=None,
                      keychain=resolve_keychain("secret", "rc2-listed", allow=ALLOW))
    elif kind == "secret_own":
        d = spec_dict(kind="secret", profile_editable=False, env_var=None,
                      keychain=resolve_keychain("secret", "rc2-own", allow=ALLOW))
    else:
        d = spec_dict()
        d["stores"] = [{"store": "env", "selected": True, "fixed": False, "by": "default", "reason": None,
                        "needed": False},
                       {"store": "keychain", "selected": True, "fixed": False, "by": "agent",
                        "reason": "이 Mac의 배포 스크립트가 키체인에서 읽습니다", "needed": True}]
    return RequestSpec.from_dict(d)


def kc(saved=False, error="keychain_verify_failed", touched=False, created=False, tmp=False, new_item=False):
    return {"keychain": {"saved": saved, "replaced": True if saved else None, "error": None if saved else error,
                         "new_item": new_item, "main_touched": touched, "main_created": created, "tmp_left": tmp}}


ENV_SAVED = {"env": {"saved": True, "replaced": False, "error": None}}
TOUCHED = kc(touched=True)                                   # the main read-back of an existing item differs
WRITE_FAILED = kc(error="keychain_write_failed")             # the temp item write fails: nothing touched
CREATED = kc(created=True, new_item=True)                    # the read-back of a new item differs
TMP_KEPT = kc(tmp=True)                                      # the temp item's read-back differs, its delete fails
ACL_FAILED = kc(error="keychain_acl_denied")                 # fails before the temp step
SAVED = kc(saved=True, touched=True)


class Run:
    """One request through the in-process server: the sends, then how it ends."""

    def __init__(self, spec_dict, static_dir, hermes_root, canary, kind, sends, end=None):
        self.spec = _spec(spec_dict, kind)
        self.clock = FakeClock()
        self.h = Harness(self.spec, static_dir, clock=self.clock, store=SeqStorage([s for s, _ in sends] or [{}]))
        self.h.client.open()
        self.answers = []
        for _, stores in sends:
            p = plain(kind=self.spec.kind, value=canary, stores=stores)
            self.answers.append(self.h.client.submit(p))
        if end == "cancel":
            assert self.h.client.cancel().status_code == 200
        elif end == "time_out":
            self.clock.advance(400)
            assert self.h.ctx.tick() is True
        self.status, self.meta, _ = self.h.terminal[0]
        self.canary = canary
        self.root = hermes_root
        card = LinkCard(kind=self.spec.kind, label=self.spec.label, purpose=self.spec.purpose,
                        target_profile=self.spec.target_profile, url="https://x/", env_var=self.spec.env_var,
                        stores=tuple(self.spec.stores or ()), keychain=self.spec.keychain)
        self.slack = result_text(card, self.status, self.meta)
        self.tool = json.loads(SecureInput(FakeCtx(), interrupted=lambda: False).result(
            kind=self.spec.kind, label=self.spec.label, target_profile="default", env_var=self.spec.env_var,
            outcome=Outcome(status=self.status, meta=self.meta), spec=self.spec))
        lines = audit(hermes_root)
        self.last_audit = [x for x in lines if x["event"] in ("saved", "failed", "expired", "cancelled")][-1]
        self.all_audit = lines

    def no_secret_or_account(self):
        out = json.dumps([self.slack, self.tool, self.meta.get("keychain_left")], ensure_ascii=False)
        assert self.canary not in out and self.canary not in json.dumps(self.all_audit)
        assert LISTED_ACCT not in out


def _left(service, listed, touched=False, created=False, tmp=False):
    return {"service": service, "listed": listed, "main_touched": touched, "main_created": created,
            "tmp_left": tmp}


SECRET = ("keychain",)


# --- the six cases of the second recheck -------------------------------------------------------------------------

def test_rc2_l_touched_then_fails_earlier_then_time_out(spec_dict, static_dir, hermes_root, canary):
    r = Run(spec_dict, static_dir, hermes_root, canary, "secret_listed", [(TOUCHED, SECRET), (WRITE_FAILED, SECRET)],
            end="time_out")
    assert (r.status, r.meta["reason"]) == ("expired", "window_passed_after_failed_save")
    sentence = MAIN_TOUCHED_TEXT.format(service=LISTED_SVC)
    assert r.slack == ("만료: 보낸 값은 저장하지 못했고, 다시 보내지 않은 채 제출 시간이 지났습니다 "
                       f"(비밀번호 '{r.spec.label}') {sentence}")
    assert r.tool["note"].endswith(" " + MAIN_TOUCHED_NOTE.format(service=LISTED_SVC))
    assert r.tool["keychain_left"] == _left(LISTED_SVC, True, touched=True)
    assert r.meta["keychain_left"] == _left(LISTED_SVC, True, touched=True)
    assert r.last_audit["detail"]["keychain_left"] == _left(LISTED_SVC, True, touched=True)
    r.no_secret_or_account()


def test_rc2_m_touched_then_fails_earlier_then_cancel(spec_dict, static_dir, hermes_root, canary):
    r = Run(spec_dict, static_dir, hermes_root, canary, "secret_listed", [(TOUCHED, SECRET), (WRITE_FAILED, SECRET)],
            end="cancel")
    sentence = MAIN_TOUCHED_TEXT.format(service=LISTED_SVC)
    assert r.slack == f"취소: 사용자가 입력 페이지에서 취소했습니다 (비밀번호 '{r.spec.label}') {sentence}"
    assert r.tool["note"] == ("요청이 취소되었습니다. 같은 턴에 다시 요청하지 마세요. "
                              + MAIN_TOUCHED_NOTE.format(service=LISTED_SVC))
    assert r.last_audit["event"] == "cancelled"
    assert r.last_audit["detail"]["keychain_left"] == _left(LISTED_SVC, True, touched=True)
    r.no_secret_or_account()


def test_rc3_c_temp_item_left_then_fails_before_the_temp_step_then_cancel(spec_dict, static_dir, hermes_root, canary):
    r = Run(spec_dict, static_dir, hermes_root, canary, "secret_listed", [(TMP_KEPT, SECRET), (ACL_FAILED, SECRET)],
            end="cancel")
    assert r.slack == f"취소: 사용자가 입력 페이지에서 취소했습니다 (비밀번호 '{r.spec.label}') {TMP_LEFT_TEXT}"
    assert r.tool["note"].endswith(" " + TMP_LEFT_NOTE)
    assert r.tool["keychain_left"] == _left(LISTED_SVC, True, tmp=True)
    assert r.last_audit["detail"]["keychain_left"] == _left(LISTED_SVC, True, tmp=True)
    r.no_secret_or_account()


def test_rc1_g_keychain_only_made_the_item_then_env_only_saves(spec_dict, static_dir, hermes_root, canary):
    r = Run(spec_dict, static_dir, hermes_root, canary, "api_key", [(CREATED, ("keychain",)), (ENV_SAVED, ("env",))])
    assert r.status == "saved"
    sentence = MAIN_CREATED_TEXT.format(service=KEY_SVC)
    assert r.slack == f"저장 완료: EXA_API_KEY, 프로필 default {sentence}"
    note = r.tool["note"]
    assert MAIN_CREATED_NOTE.format(service=KEY_SVC) in note
    assert note.index(MAIN_CREATED_NOTE.format(service=KEY_SVC)) < note.index("사용자가 페이지에서 Mac 키체인 저장을 껐습니다.")
    assert r.tool["success"] is True and r.tool["keychain_left"] == _left(KEY_SVC, False, created=True)
    assert r.last_audit["event"] == "saved"
    assert r.last_audit["detail"]["keychain_left"] == _left(KEY_SVC, False, created=True)
    r.no_secret_or_account()


def test_rc1_i_keychain_only_touched_the_item_then_env_only_saves(spec_dict, static_dir, hermes_root, canary):
    r = Run(spec_dict, static_dir, hermes_root, canary, "api_key", [(TOUCHED, ("keychain",)), (ENV_SAVED, ("env",))])
    sentence = MAIN_TOUCHED_TEXT.format(service=KEY_SVC)
    assert r.slack == f"저장 완료: EXA_API_KEY, 프로필 default {sentence}"
    assert MAIN_TOUCHED_NOTE.format(service=KEY_SVC) in r.tool["note"]
    assert r.tool["keychain_left"] == _left(KEY_SVC, False, touched=True)
    r.no_secret_or_account()


def test_rc1_h_five_failed_sends_say_the_made_item_once(spec_dict, static_dir, hermes_root, canary):
    again = kc(touched=True)  # the item is there now; _mark_made_items reports it as made
    r = Run(spec_dict, static_dir, hermes_root, canary, "secret_own",
            [(CREATED, SECRET)] + [(again, SECRET)] * 4)
    assert r.answers[-1].json()["error_code"] == "too_many_attempts"
    assert (r.status, r.meta["reason"]) == ("failed", "too_many_attempts")
    sentence = MAIN_CREATED_TEXT.format(service=OWN_SVC)
    assert r.slack.count(sentence) == 1 and r.slack.endswith(" " + sentence)
    assert "기존 값이 바뀌었을 수 있습니다" not in r.slack
    assert r.tool["note"].count(MAIN_CREATED_NOTE.format(service=OWN_SVC)) == 1
    assert r.tool["keychain_left"] == _left(OWN_SVC, False, created=True)
    assert r.last_audit["detail"]["keychain_left"] == _left(OWN_SVC, False, created=True)
    assert r.last_audit["detail"]["final"] is True


# --- the other side ----------------------------------------------------------------------------------------------

def test_failed_then_saved_to_the_keychain_says_no_old_value_and_no_made_item(spec_dict, static_dir, hermes_root,
                                                                              canary):
    for first in (TOUCHED, CREATED):
        r = Run(spec_dict, static_dir, hermes_root, canary, "secret_listed", [(first, SECRET), (SAVED, SECRET)])
        assert r.status == "saved"
        assert "기존 값이 바뀌었을 수 있습니다" not in r.slack and "새로 만들어졌고" not in r.slack
        assert "기존 값이 바뀌었을 수 있습니다" not in r.tool["note"] and "새로 만들어졌고" not in r.tool["note"]
        assert r.tool["keychain_left"] is None and "keychain_left" not in r.meta
        assert "keychain_left" not in r.last_audit["detail"]
        r.no_secret_or_account()


def test_a_temp_item_left_before_a_keychain_save_is_still_said(spec_dict, static_dir, hermes_root, canary):
    r = Run(spec_dict, static_dir, hermes_root, canary, "secret_listed", [(TMP_KEPT, SECRET), (SAVED, SECRET)])
    assert r.status == "saved"
    assert r.slack.endswith(" " + TMP_LEFT_TEXT) and r.slack.count(TMP_LEFT_TEXT) == 1
    assert r.tool["keychain_left"] == _left(LISTED_SVC, True, tmp=True)


def test_one_send_that_saves_keeps_the_old_words(spec_dict, static_dir, hermes_root, canary):
    r = Run(spec_dict, static_dir, hermes_root, canary, "secret_listed", [(SAVED, SECRET)])
    assert r.slack == f"저장 완료: Mac 키체인 {LISTED_SVC}"
    assert r.tool["keychain_left"] is None
    assert "keychain_left" not in r.meta and "keychain_left" not in r.last_audit["detail"]


def test_nothing_sent_keeps_the_old_words(spec_dict, static_dir, hermes_root, canary):
    r = Run(spec_dict, static_dir, hermes_root, canary, "secret_listed", [], end="cancel")
    assert r.slack == f"취소: 사용자가 입력 페이지에서 취소했습니다 (비밀번호 '{r.spec.label}')"
    assert r.tool["keychain_left"] is None and "keychain_left" not in r.last_audit["detail"]


def test_the_last_failure_and_the_memory_give_one_sentence(spec_dict, static_dir, hermes_root, canary):
    r = Run(spec_dict, static_dir, hermes_root, canary, "secret_listed", [(TOUCHED, SECRET), (TOUCHED, SECRET)],
            end="cancel")
    sentence = MAIN_TOUCHED_TEXT.format(service=LISTED_SVC)
    assert r.slack.count(sentence) == 1
    assert r.tool["note"].count(MAIN_TOUCHED_NOTE.format(service=LISTED_SVC)) == 1


# --- Slack's section limit ---------------------------------------------------------------------------------------

def test_the_longest_result_with_every_keychain_sentence_fits_one_section():
    label = "&" * 80
    svc = "hermes-secure-input." + "a" * 40
    rows = [{"store": "env", "saved": False, "error": "env_write_failed", "env_var": "A" * 128},
            {"store": "keychain", "saved": False, "error": "keychain_verify_failed", "service": svc,
             "main_touched": True, "main_created": True, "tmp_left": True}]
    card = LinkCard(kind="api_key", label=label, purpose="p", target_profile="p" * 64, url="https://x/",
                    env_var="A" * 128, title_prefix="[" + "&" * 30 + "]")
    left = _left(svc, False, touched=True, created=True, tmp=True)
    for status, meta in [("failed", {"reason": "store_timeout", "stores": rows, "keychain_left": left}),
                         ("expired", {"reason": "window_passed_after_failed_save", "keychain_left": left}),
                         ("saved", {"partial": True, "stores": [dict(rows[0], saved=True)] + rows[1:],
                                    "keychain_left": left})]:
        for block in result_blocks(result_text(card, status, meta)):
            assert len(block["text"]["text"]) <= SECTION_MAX_CHARS
    assert len(_esc(label)) == 400


@pytest.mark.parametrize("meta", [{"keychain_left": None}, {}])
def test_no_keychain_left_adds_nothing(meta):
    card = LinkCard(kind="api_key", label="L", purpose="p", target_profile="default", url="https://x/", env_var="K")
    assert result_text(card, "cancelled", dict(meta, reason="user_cancelled")) == "취소: 사용자가 입력 페이지에서 취소했습니다 (API 키 'L')"
