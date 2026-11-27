"""Findings of the recheck of security review 3 (docs/security-review-3-recheck.md section 5, "새 지적"):

RC-1: a keychain item that was not there before the main write may hold the value sent although the save failed
(``main_created``); a later submit of the same request that saves to it is a new item, not a replaced one.
RC-2: after a retryable failure the submit window passes without another submit
(``window_passed_after_failed_save``).
RC-6: the tool's ``purpose`` and ``label`` descriptions say which characters are refused.
"""

from __future__ import annotations

import json
import os

import pytest

from secure_input.launcher import Outcome
from secure_input.lifecycle import Lifecycle
from secure_input.notify import result_text
from secure_input.plugin import TOOL_ROW_KEYS, SecureInput, _tool_row, build_request_schema
from secure_input.server import _audit_row
from test_lifecycle import FakeClock
from test_notify import card
from test_plugin import FakeCtx
from test_server_stores import FakeStorage, audit, harness, plain
from test_store_keychain import ACCT, SVC, canary as kc_canary, fake, req, run_save  # noqa: F401 - fixture

SID = os.urandom(32)
KC = "hermes-secure-input.exa-api-key"
CREATED_SLACK = f"키체인에 `{KC}` 항목이 새로 만들어졌고 이번에 넣은 값이 들어 있을 수 있습니다."
TOUCHED_SLACK = f"키체인 항목 `{KC}`의 기존 값이 바뀌었을 수 있습니다."
TMP_SLACK = ("임시 키체인 항목에 이번에 넣은 값이 남아 있을 수 있습니다. "
             "Hermes가 도는 컴퓨터에서 README의 '남은 임시 키체인 항목' 절의 명령으로 확인해 지우세요.")
TMP_TOOL = ("임시 키체인 항목에 이번에 넣은 값이 남아 있을 수 있습니다. "
            "사용자에게 README의 '남은 임시 키체인 항목' 절의 명령으로 확인해 지우라고 알리세요.")
AFTER_FAILED_SLACK = "만료: 보낸 값은 저장하지 못했고, 다시 보내지 않은 채 제출 시간이 지났습니다"
AFTER_FAILED_TOOL = "사용자가 값을 보냈지만 저장하지 못했고, 다시 보내지 않은 채 제출 시간이 지났습니다."
NAME = "(API 키 'Exa <키>')"


def kc_row(**over):
    row = {"store": "keychain", "saved": False, "replaced": None, "error": "keychain_verify_failed", "service": KC,
           "account": "hermes-secure-input", "listed": False, "new_item": True, "tmp_left": False,
           "main_touched": False, "main_created": True}
    row.update(over)
    return row


def _tool_note(status, meta, kind="api_key"):
    out = SecureInput(FakeCtx(), interrupted=lambda: False).result(
        kind=kind, label="Exa API key", target_profile="default", env_var="EXA_API_KEY",
        outcome=Outcome(status=status, meta=meta))
    return json.loads(out)["note"]


# --- RC-1: the keychain module says whether the main write made the item -----------------------------------------

def test_rc1_failed_readback_of_a_new_item_is_main_created(fake):
    fake.set(main_readback="garbled")
    res = run_save(fake, req(kc_canary()))
    assert res["saved"] is False and res["error"] == "keychain_verify_failed"
    assert res["main_created"] is True
    assert res["main_touched"] is False


def test_rc1_failed_readback_of_an_existing_item_is_not_main_created(fake):
    fake.add_item(SVC, ACCT, "old-value")
    fake.set(main_readback="garbled")
    res = run_save(fake, req(kc_canary()))
    assert res["saved"] is False and res["main_touched"] is True
    assert res["main_created"] is False


def test_rc1_a_check_before_the_main_write_is_not_main_created(fake):
    fake.add_item(SVC, ACCT, "old-value")
    fake.set(tmp_readback="garbled")  # stops at the temporary item, the main item is never written
    res = run_save(fake, req(kc_canary()))
    assert res["saved"] is False and res["main_created"] is False and res["main_touched"] is False


def test_rc1_saved_new_item_is_main_created_and_saved_existing_item_is_not(fake):
    res = run_save(fake, req(kc_canary()))
    assert res["saved"] is True and res["main_created"] is True
    res = run_save(fake, req(kc_canary()))
    assert res["saved"] is True and res["main_created"] is False


# --- RC-1: the sentence in Slack and in the tool result ----------------------------------------------------------

@pytest.mark.parametrize("status,reason", [("expired", "window_passed_while_saving"), ("cancelled", "user_cancelled"),
                                           ("failed", "too_many_attempts"),
                                           ("expired", "window_passed_after_failed_save")])
def test_rc1_slack_text_says_the_item_was_made(status, reason):
    text = result_text(card(), status, {"reason": reason, "stores": [kc_row()]})
    assert text.endswith(" " + CREATED_SLACK) and text.count(CREATED_SLACK) == 1
    assert TOUCHED_SLACK not in text


def test_rc1_slack_text_of_an_existing_item_has_no_made_sentence():
    rows = [kc_row(new_item=False, main_touched=True, main_created=False)]
    text = result_text(card(), "cancelled", {"reason": "user_cancelled", "stores": rows})
    assert "새로 만들어졌고" not in text and text.endswith(" " + TOUCHED_SLACK)


def test_rc1_slack_partial_save_says_the_item_was_made():
    env = {"store": "env", "saved": True, "replaced": False, "error": None, "env_var": "EXA_API_KEY",
           "profile": "default"}
    text = result_text(card(), "saved", {"stores": [env, kc_row()], "partial": True})
    assert text.endswith(" " + CREATED_SLACK)


def test_rc1_saved_row_has_no_made_sentence():
    rows = [kc_row(saved=True, replaced=False, error=None)]
    assert "새로 만들어졌고" not in result_text(card(), "saved", {"stores": rows, "partial": False})
    assert "새로 만들어졌고" not in _tool_note("saved", {"stores": rows, "partial": False})


def test_rc1_tool_note_says_the_item_was_made():
    note = _tool_note("cancelled", {"reason": "user_cancelled", "stores": [kc_row()]})
    assert note == "요청이 취소되었습니다. 같은 턴에 다시 요청하지 마세요. " + CREATED_SLACK


def test_rc1_tool_note_of_an_existing_item_has_no_made_sentence():
    rows = [kc_row(new_item=False, main_touched=True, main_created=False)]
    note = _tool_note("cancelled", {"reason": "user_cancelled", "stores": rows})
    assert "새로 만들어졌고" not in note and note.endswith(TOUCHED_SLACK)


def test_rc1_made_sentence_comes_before_the_temp_item_sentence():
    rows = [kc_row(tmp_left=True)]
    assert result_text(card(), "cancelled", {"reason": "user_cancelled", "stores": rows}).endswith(
        f" {CREATED_SLACK} {TMP_SLACK}")
    assert _tool_note("cancelled", {"reason": "user_cancelled", "stores": rows}).endswith(
        f" {CREATED_SLACK} {TMP_TOOL}")


def test_rc1_audit_row_and_tool_row_keep_main_created():
    assert _audit_row(kc_row())["main_created"] is True
    assert "main_created" not in _audit_row({"store": "env", "saved": True, "replaced": False, "error": None})
    assert "main_created" in TOOL_ROW_KEYS
    assert _tool_row(kc_row())["main_created"] is True


# --- RC-1: through the server ------------------------------------------------------------------------------------

class SeqStorage(FakeStorage):
    """A FakeStorage whose save answers ``seq[0]``, then ``seq[1]``, ... (the last one repeats)."""

    def __init__(self, seq, **kw):
        super().__init__(rows=seq[0], **kw)
        self.seq = list(seq)
        self.saves = 0

    def __call__(self, home, request):
        if request["phase"] == "save":
            self.rows = self.seq[min(self.saves, len(self.seq) - 1)]
            self.saves += 1
        return super().__call__(home, request)


FAILED_NEW = {"env": {"saved": False, "error": "env_write_failed"},
              "keychain": {"saved": False, "error": "keychain_verify_failed", "new_item": True,
                           "main_touched": False, "main_created": True}}
# The second submit finds the item made by the first one: the keychain module itself says replaced, not new.
SAVED_AGAIN = {"env": {"saved": True, "replaced": False, "error": None},
               "keychain": {"saved": True, "replaced": True, "error": None, "new_item": False,
                            "main_touched": True, "main_created": False}}


def _kc(rows):
    return next(r for r in rows if r["store"] == "keychain")


def test_rc1_failed_answer_carries_main_created(spec_dict, static_dir, hermes_root, canary):
    h = harness(spec_dict, static_dir, store=SeqStorage([FAILED_NEW]))
    h.client.open()
    r = h.client.submit(plain(value=canary))
    assert r.status_code == 422 and r.json()["error_code"] == "storage_failed"
    assert _kc(r.json()["stores"])["main_created"] is True
    failed = [x for x in audit(hermes_root) if x["event"] == "failed"][-1]
    assert _kc(failed["detail"]["stores"])["main_created"] is True


def test_rc1_retry_that_saves_to_the_item_the_first_try_made_is_a_new_item(spec_dict, static_dir, hermes_root,
                                                                           canary):
    h = harness(spec_dict, static_dir, store=SeqStorage([FAILED_NEW, SAVED_AGAIN]))
    h.client.open()
    assert h.client.submit(plain(value=canary)).status_code == 422
    r = h.client.submit(plain(value=canary))
    assert r.status_code == 200
    row = _kc(r.json()["result"]["stores"])
    assert row["replaced"] is False and row["new_item"] is True
    status, meta, _ = h.terminal[0]
    assert status == "saved"
    row = _kc(meta["stores"])
    assert row["replaced"] is False and row["new_item"] is True
    saved = [x for x in audit(hermes_root) if x["event"] == "saved"][-1]
    assert _kc(saved["detail"]["stores"])["replaced"] is False


def test_rc1_retry_of_an_existing_item_stays_replaced(spec_dict, static_dir, canary):
    failed_old = {"env": FAILED_NEW["env"],
                  "keychain": {"saved": False, "error": "keychain_verify_failed", "new_item": False,
                               "main_touched": True, "main_created": False}}
    h = harness(spec_dict, static_dir, store=SeqStorage([failed_old, SAVED_AGAIN]))
    h.client.open()
    assert h.client.submit(plain(value=canary)).status_code == 422
    row = _kc(h.client.submit(plain(value=canary)).json()["result"]["stores"])
    assert row["replaced"] is True and row["new_item"] is False


def test_rc1_retry_of_a_listed_item_made_by_the_first_try_is_not_replaced_and_not_new(spec_dict, static_dir,
                                                                                       canary):
    failed = {"keychain": dict(FAILED_NEW["keychain"], new_item=False)}
    again = {"keychain": dict(SAVED_AGAIN["keychain"])}
    h = harness(spec_dict, static_dir, store=SeqStorage([failed, again]), kind="secret")
    h.client.open()
    assert h.client.submit(plain(kind="secret", value=canary, stores=("keychain",))).status_code == 422
    r = h.client.submit(plain(kind="secret", value=canary, stores=("keychain",)))
    assert r.status_code == 200
    row = _kc(r.json()["result"]["stores"])
    assert row["listed"] is True
    assert row["replaced"] is False and row["new_item"] is False


# --- RC-2: the submit window passes after a retryable failure ---------------------------------------------------

def _failed_once(clock, submit_ttl=300):
    lc = Lifecycle(clock, submit_ttl=submit_ttl)
    lc.open(SID)
    lc.check_submit(SID)
    lc.begin_saving()
    assert lc.end_saving("retry") == "opened"
    return lc


def test_rc2_tick_after_a_failed_save_ends_window_passed_after_failed_save():
    clock = FakeClock()
    lc = _failed_once(clock, submit_ttl=6)
    clock.advance(7)
    assert lc.tick() is True
    assert (lc.state, lc.detail) == ("expired", "window_passed_after_failed_save")


def test_rc2_tick_without_a_submit_is_still_submit_window_passed():
    clock = FakeClock()
    lc = Lifecycle(clock, submit_ttl=6)
    lc.open(SID)
    clock.advance(7)
    assert lc.tick() is True
    assert (lc.state, lc.detail) == ("expired", "submit_window_passed")


def test_rc2_a_refused_submit_that_never_reached_saving_is_still_submit_window_passed():
    clock = FakeClock()
    lc = Lifecycle(clock, submit_ttl=6)
    lc.open(SID)
    lc.check_submit(SID)
    assert lc.record_failure("invalid_payload") == "invalid_payload"  # 400 before saving
    clock.advance(7)
    lc.tick()
    assert (lc.state, lc.detail) == ("expired", "submit_window_passed")


def test_rc2_late_submit_after_a_failed_save_ends_window_passed_after_failed_save():
    clock = FakeClock()
    lc = _failed_once(clock, submit_ttl=6)
    clock.advance(7)
    with pytest.raises(Exception) as exc:
        lc.check_submit(SID)
    assert getattr(exc.value, "code", None) == "deadline_passed"  # the page's answer is unchanged
    assert (lc.state, lc.detail) == ("expired", "window_passed_after_failed_save")


def test_rc2_slack_text():
    assert result_text(card(), "expired", {"reason": "window_passed_after_failed_save"}) == (
        f"{AFTER_FAILED_SLACK} {NAME}")


def test_rc2_slack_text_keeps_the_keychain_sentences():
    touched = kc_row(new_item=False, main_touched=True, main_created=False, tmp_left=True)
    text = result_text(card(), "expired", {"reason": "window_passed_after_failed_save", "stores": [touched]})
    assert text == f"{AFTER_FAILED_SLACK} {NAME} {TOUCHED_SLACK} {TMP_SLACK}"
    text = result_text(card(), "expired", {"reason": "window_passed_after_failed_save", "stores": [kc_row()]})
    assert text == f"{AFTER_FAILED_SLACK} {NAME} {CREATED_SLACK}"


def test_rc2_tool_note():
    assert _tool_note("expired", {"reason": "window_passed_after_failed_save"}) == (
        AFTER_FAILED_TOOL + " 다시 필요하면 사용자에게 알리고 새 요청을 만드세요.")


def test_rc2_tool_note_keeps_the_keychain_sentences():
    touched = kc_row(new_item=False, main_touched=True, main_created=False, tmp_left=True)
    note = _tool_note("expired", {"reason": "window_passed_after_failed_save", "stores": [touched]})
    assert note.startswith(AFTER_FAILED_TOOL) and note.endswith(f" {TOUCHED_SLACK} {TMP_TOOL}")


def test_rc2_five_minute_sentence_stays_on_submit_window_passed_only():
    assert "5분 안에" in result_text(card(), "expired", {"reason": "submit_window_passed"})
    assert "5분 안에" not in result_text(card(), "expired", {"reason": "window_passed_after_failed_save"})
    assert "5분 안에" in _tool_note("expired", {"reason": "submit_window_passed"})
    assert "5분 안에" not in _tool_note("expired", {"reason": "window_passed_after_failed_save"})


def test_rc2_through_the_server_the_last_failure_rows_reach_the_end(spec_dict, static_dir, hermes_root, canary):
    clock = FakeClock()
    touched = {"env": FAILED_NEW["env"],
               "keychain": {"saved": False, "error": "keychain_verify_failed", "new_item": False,
                            "main_touched": True, "main_created": False, "tmp_left": True}}
    h = harness(spec_dict, static_dir, store=SeqStorage([touched]), clock=clock)
    h.client.open()
    assert h.client.submit(plain(value=canary)).status_code == 422
    clock.advance(400)
    assert h.ctx.tick() is True
    status, meta, _ = h.terminal[0]
    assert (status, meta["reason"]) == ("expired", "window_passed_after_failed_save")
    assert _kc(meta["stores"])["main_touched"] is True
    text = result_text(card(), status, meta)
    assert text.startswith(AFTER_FAILED_SLACK) and text.endswith(f" {TOUCHED_SLACK} {TMP_SLACK}")
    last = [x for x in audit(hermes_root) if x["event"] == "expired"][-1]
    assert last["detail"]["reason"] == "window_passed_after_failed_save"
    assert canary not in json.dumps(audit(hermes_root))


def test_rc2_through_the_server_no_submit_is_submit_window_passed(spec_dict, static_dir, hermes_root):
    clock = FakeClock()
    h = harness(spec_dict, static_dir, store=SeqStorage([FAILED_NEW]), clock=clock)
    h.client.open()
    clock.advance(400)
    h.ctx.tick()
    status, meta, _ = h.terminal[0]
    assert (status, meta["reason"]) == ("expired", "submit_window_passed")


# --- RC-6: the tool says which characters purpose and label refuse ----------------------------------------------

@pytest.mark.parametrize("arg", ["purpose", "label"])
def test_rc6_purpose_and_label_descriptions_name_the_refused_characters(arg):
    desc = build_request_schema([])["parameters"]["properties"][arg]["description"]
    assert "invisible" in desc and "emoji" in desc


# --- review round 1, item 1: a main write that failed for sure made no item -------------------------------------

def test_r1_new_item_whose_write_failed_is_not_main_created(fake):
    fake.set(write_rc={"main": 1})  # exit code not 0 and the read back finds nothing
    res = run_save(fake, req(kc_canary()))
    assert res["saved"] is False and res["error"] == "keychain_write_failed"
    assert res["main_created"] is False and res["main_touched"] is False
    row = dict(res, store="keychain")
    for status, meta in [("cancelled", {"reason": "user_cancelled", "stores": [row]}),
                         ("expired", {"reason": "window_passed_after_failed_save", "stores": [row]})]:
        assert "새로 만들어졌고" not in result_text(card(), status, meta)
        assert "새로 만들어졌고" not in _tool_note(status, meta)


def test_r1_new_item_whose_write_timed_out_is_main_created(fake, monkeypatch):
    from secure_input.stores import keychain
    v = kc_canary()
    keychain.preflight(req(v), security_path=str(fake.path))
    original = keychain._run

    def main_write_times_out(security_path, argv, **kw):
        if argv == ["-i"] and keychain.TMP_PREFIX not in kw.get("stdin", b"").decode():
            return {"rc": None, "out": b"", "timeout": True}
        return original(security_path, argv, **kw)

    monkeypatch.setattr(keychain, "_run", main_write_times_out)
    res = keychain.save(req(v), security_path=str(fake.path))
    assert res["error"] == "keychain_timeout" and res["saved"] is None
    assert res["main_created"] is True and res["main_touched"] is False


# --- review round 1, item 2: a retry that fails again on the item the first try made ----------------------------

FAILED_AGAIN = {"env": FAILED_NEW["env"],
                "keychain": {"saved": False, "error": "keychain_verify_failed", "new_item": False,
                             "main_touched": True, "main_created": False}}
NOT_TOUCHED_AGAIN = {"env": FAILED_NEW["env"],
                     "keychain": {"saved": False, "error": "keychain_acl_denied", "new_item": False,
                                  "main_touched": False, "main_created": False}}


def _made_then_failed_again(spec_dict, static_dir, canary, second, clock=None):
    h = harness(spec_dict, static_dir, store=SeqStorage([FAILED_NEW, second]), clock=clock)
    h.client.open()
    assert h.client.submit(plain(value=canary)).status_code == 422
    r = h.client.submit(plain(value=canary))
    assert r.status_code == 422 and r.json()["error_code"] == "storage_failed"
    return h, _kc(r.json()["stores"])


def _says_made_not_touched(status, meta):
    text, note = result_text(card(), status, meta), _tool_note(status, meta)
    for words in (text, note):
        assert CREATED_SLACK in words
        assert "기존 값이 바뀌었을 수 있습니다" not in words


def test_r1_second_failure_on_the_made_item_answers_main_created(spec_dict, static_dir, canary):
    _, row = _made_then_failed_again(spec_dict, static_dir, canary, FAILED_AGAIN)
    assert row["main_created"] is True and row["main_touched"] is False


def test_r1_second_failure_on_the_made_item_then_cancel_says_made(spec_dict, static_dir, hermes_root, canary):
    h, _ = _made_then_failed_again(spec_dict, static_dir, canary, FAILED_AGAIN)
    assert h.client.cancel().status_code == 200
    status, meta, _ = h.terminal[0]
    assert status == "cancelled"
    _says_made_not_touched(status, meta)
    failed = [x for x in audit(hermes_root) if x["event"] == "failed"][-1]
    assert _kc(failed["detail"]["stores"])["main_created"] is True
    assert _kc(failed["detail"]["stores"])["main_touched"] is False


def test_r1_second_failure_on_the_made_item_then_time_out_says_made(spec_dict, static_dir, canary):
    clock = FakeClock()
    h, _ = _made_then_failed_again(spec_dict, static_dir, canary, FAILED_AGAIN, clock=clock)
    clock.advance(400)
    assert h.ctx.tick() is True
    status, meta, _ = h.terminal[0]
    assert (status, meta["reason"]) == ("expired", "window_passed_after_failed_save")
    _says_made_not_touched(status, meta)


def test_r1_second_failure_before_the_main_write_keeps_the_made_fact(spec_dict, static_dir, canary):
    h, row = _made_then_failed_again(spec_dict, static_dir, canary, NOT_TOUCHED_AGAIN)
    assert row["main_touched"] is False and row["main_created"] is True
    assert h.client.cancel().status_code == 200
    status, meta, _ = h.terminal[0]
    _says_made_not_touched(status, meta)


# --- review round 1, item 3: the failed-save mark follows the error code of the answer --------------------------

def _time_out(h, clock):
    clock.advance(400)
    assert h.ctx.tick() is True
    status, meta, _ = h.terminal[0]
    assert (status, meta["reason"]) == ("expired", "window_passed_after_failed_save")
    assert result_text(card(), status, meta).startswith(AFTER_FAILED_SLACK)
    assert _tool_note(status, meta).startswith(AFTER_FAILED_TOOL)


def test_r1_server_masked_value_then_time_out_is_after_failed_save(spec_dict, static_dir):
    clock = FakeClock()
    h = harness(spec_dict, static_dir, store=FakeStorage(), clock=clock)
    h.client.open()
    r = h.client.submit(plain(value="sk-abc...wxyz"))
    assert r.status_code == 422 and r.json()["error_code"] == "masked_value"
    _time_out(h, clock)


def test_r1_storage_masked_value_then_time_out_is_after_failed_save(spec_dict, static_dir, canary):
    clock = FakeClock()
    h = harness(spec_dict, static_dir, store=FakeStorage(done={"event": "done", "ok": False, "error": "masked_value"}),
                clock=clock)
    h.client.open()
    r = h.client.submit(plain(value=canary))
    assert r.status_code == 422 and r.json()["error_code"] == "masked_value"
    _time_out(h, clock)


def test_r1_profile_error_then_time_out_is_after_failed_save(spec_dict, static_dir, canary, monkeypatch):
    import secure_input.server as srv
    from secure_input.profiles import ProfileError

    def broken(*a, **k):
        raise ProfileError("x")

    clock = FakeClock()
    h = harness(spec_dict, static_dir, store=FakeStorage(), clock=clock)
    h.client.open()
    monkeypatch.setattr(srv, "resolve_profile_home", broken)
    r = h.client.submit(plain(value=canary))
    assert r.status_code == 422 and r.json()["error_code"] == "storage_failed" and r.json()["stores"] == []
    _time_out(h, clock)


def test_r1_invalid_payload_then_time_out_is_still_submit_window_passed(spec_dict, static_dir):
    clock = FakeClock()
    h = harness(spec_dict, static_dir, store=FakeStorage(), clock=clock)
    h.client.open()
    r = h.client.submit(b"not json")
    assert r.status_code == 400 and r.json()["error_code"] == "invalid_payload"
    clock.advance(400)
    h.ctx.tick()
    status, meta, _ = h.terminal[0]
    assert (status, meta["reason"]) == ("expired", "submit_window_passed")


def test_r1_note_failed_save_only_marks_an_opened_request():
    clock = FakeClock()
    lc = Lifecycle(clock, submit_ttl=6)
    lc.note_failed_save()  # created: nothing to mark
    assert lc.failed_save is False
    lc.open(SID)
    lc.note_failed_save()
    assert lc.failed_save is True
