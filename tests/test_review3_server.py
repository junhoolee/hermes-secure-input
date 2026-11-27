"""Findings of the third security review (docs/security-review-3.md section 2) owned by the server side:
R3-6 (a server whose parent is gone before ``ready``), R3-1 (the submit window passes while saving and the save
fails), R3-3 (a temporary keychain item may hold the new value) and N-1 (``main_touched`` of a brand-new item).
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time

import pytest

from helpers import fake_keychain
from secure_input.launcher import PLUGIN_ROOT, Outcome, hermes_agent_dir
from secure_input.lifecycle import Lifecycle
from secure_input.notify import result_text
from secure_input.plugin import SecureInput
from secure_input.spec import RequestSpec
from test_lifecycle import FakeClock
from test_notify import card
from test_plugin import FakeCtx
from test_server_stores import FakeStorage, audit, harness, plain

SID = os.urandom(32)

# --- R3-6: the parent's read end of stdout is closed before "ready" ----------------------------------------------


def _start_server(spec_dict, static_dir, fake_tailscale, tmp_path, monkeypatch, ttls):
    """``python -m secure_input.server`` started the way the launcher does, with its stdout read end closed right
    after the config line: the parent (gateway) died before it could read ``ready``."""
    python = fake_keychain.storage_python(tmp_path / "py")
    monkeypatch.setenv("FAKE_KEYCHAIN_CONFIG", json.dumps({"log": str(tmp_path / "keychain-calls.jsonl")}))
    env = dict(os.environ)
    agent_dir = hermes_agent_dir()
    env["PYTHONPATH"] = os.pathsep.join([str(PLUGIN_ROOT)] + ([str(agent_dir)] if agent_dir else []))
    env["PYTHONUNBUFFERED"] = "1"
    proc = subprocess.Popen([sys.executable, "-P", "-m", "secure_input.server"], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, cwd=str(PLUGIN_ROOT))
    token = "r36OrphanToken0123456789abcdefghijklmnopq"
    cfg = {"spec": RequestSpec.from_dict(spec_dict()).to_dict(), "token": token, "request_id": os.urandom(16).hex(),
           "static_dir": str(static_dir), "public_host": "orphan.example-tailnet.ts.net",
           "tailscale_bin": str(fake_tailscale.bin), "parent_pid": os.getpid(), "active_file": None,
           "python": str(python), "allowed_logins": ["owner@example.test"], "allow_no_identity_header": True,
           "ttls": ttls}
    proc.stdin.write((json.dumps(cfg) + "\n").encode())
    proc.stdin.flush()
    proc.stdout.close()  # the parent's end of the pipe is gone before "ready"
    return proc, token


def _wait_exit(proc, timeout: float):
    try:
        return proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        return None


def _finish(proc) -> str:
    if proc.poll() is None:
        proc.kill()
        proc.wait()
    err = proc.stderr.read().decode("utf-8", "replace")
    proc.stdin.close()
    proc.stderr.close()
    return err


def test_r3_6_server_whose_parent_is_gone_before_ready_ends_itself_and_removes_serve(
        spec_dict, static_dir, fake_tailscale, tmp_path, monkeypatch):
    proc, token = _start_server(spec_dict, static_dir, fake_tailscale, tmp_path, monkeypatch, {"open": 1, "submit": 1})
    try:
        code = _wait_exit(proc, 15.0)  # open window 1 s: a supervised server expires and ends well before this
    finally:
        err = _finish(proc)
    assert code == 0, err[-500:]
    assert "BrokenPipeError" not in err
    assert fake_tailscale.off_calls(token), fake_tailscale.calls()


def test_r3_6_server_whose_parent_is_gone_before_ready_ends_on_sigterm(
        spec_dict, static_dir, fake_tailscale, tmp_path, monkeypatch):
    proc, token = _start_server(spec_dict, static_dir, fake_tailscale, tmp_path, monkeypatch,
                                {"open": 60, "submit": 300})
    try:
        calls = tmp_path / "keychain-calls.jsonl"  # the create-time check runs just before "ready"
        deadline = time.monotonic() + 15.0
        while not (calls.exists() and "preflight" in calls.read_text()) and time.monotonic() < deadline:
            time.sleep(0.05)
        time.sleep(1.0)  # past "ready": the write failed already
        assert proc.poll() is None  # open window of 60 s, parent alive, stdin open: only SIGTERM ends it now
        proc.send_signal(signal.SIGTERM)
        code = _wait_exit(proc, 5.0)
    finally:
        err = _finish(proc)
    assert code == 0, err[-500:]
    assert fake_tailscale.off_calls(token), fake_tailscale.calls()


# --- R3-1: the submit window passes while saving and nothing was saved ------------------------------------------

def _saving(clock, submit_ttl=300):
    lc = Lifecycle(clock, submit_ttl=submit_ttl)
    lc.open(SID)
    lc.check_submit(SID)
    lc.begin_saving()
    return lc


def test_r3_1_retry_after_the_window_passed_while_saving_ends_window_passed_while_saving():
    clock = FakeClock()
    lc = _saving(clock, submit_ttl=6)
    clock.advance(7)  # no tick saw it: no deferred reason
    assert lc.end_saving("retry") == "expired"
    assert lc.detail == "window_passed_while_saving"


def test_r3_1_retry_with_the_deferred_submit_window_ends_window_passed_while_saving():
    clock = FakeClock()
    lc = _saving(clock)
    clock.advance(400)
    lc.tick()
    assert lc.deferred == ("expired", "submit_window_passed")
    assert lc.end_saving("retry") == "expired"
    assert lc.detail == "window_passed_while_saving"


@pytest.mark.parametrize("reason", ["parent_gone", "terminated"])
def test_r3_1_retry_with_a_deferred_cancel_keeps_the_cancel(reason):
    clock = FakeClock()
    lc = _saving(clock)
    lc.abort("cancelled", reason)
    clock.advance(400)
    assert lc.end_saving("retry") == "cancelled"
    assert lc.detail == reason


def test_r3_1_submit_window_passed_still_means_no_submit_reached_saving():
    clock = FakeClock()
    lc = Lifecycle(clock, submit_ttl=6)
    lc.open(SID)
    clock.advance(7)
    lc.tick()
    assert (lc.state, lc.detail) == ("expired", "submit_window_passed")


def test_r3_1_slack_text_for_window_passed_while_saving():
    text = result_text(card(), "expired", {"reason": "window_passed_while_saving"})
    assert text == "만료: 저장하는 동안 제출 시간이 지났고 저장하지 못했습니다 (API 키 'Exa <키>')"


def test_r3_1_slack_text_keeps_the_main_touched_sentence():
    rows = [{"store": "keychain", "saved": False, "error": "keychain_verify_failed", "main_touched": True,
             "service": "hermes-secure-input.exa-api-key"}]
    text = result_text(card(), "expired", {"reason": "window_passed_while_saving", "stores": rows})
    assert text == ("만료: 저장하는 동안 제출 시간이 지났고 저장하지 못했습니다 (API 키 'Exa <키>') "
                    "키체인 항목 `hermes-secure-input.exa-api-key`의 기존 값이 바뀌었을 수 있습니다.")


def test_r3_1_slack_text_for_submit_window_passed_is_unchanged():
    text = result_text(card(), "expired", {"reason": "submit_window_passed"})
    assert text == "만료: 연 뒤 5분 안에 제출되지 않았습니다 (API 키 'Exa <키>')"


def _tool_note(status, meta, kind="api_key"):
    out = SecureInput(FakeCtx(), interrupted=lambda: False).result(
        kind=kind, label="Exa API key", target_profile="default", env_var="EXA_API_KEY",
        outcome=Outcome(status=status, meta=meta))
    return json.loads(out)["note"]


def test_r3_1_tool_note_for_window_passed_while_saving():
    assert _tool_note("expired", {"reason": "window_passed_while_saving"}) == (
        "사용자는 시간 안에 제출했지만 저장하는 동안 제출 시간이 지났고 저장은 실패했습니다. "
        "다시 필요하면 사용자에게 알리고 새 요청을 만드세요.")


def test_r3_1_tool_note_for_submit_window_passed_is_unchanged():
    assert _tool_note("expired", {"reason": "submit_window_passed"}) == (
        "사용자가 연 뒤 5분 안에 제출하지 않았습니다. 다시 필요하면 사용자에게 알리고 새 요청을 만드세요.")


def test_r3_1_audit_and_parent_reason_through_the_server(spec_dict, static_dir, hermes_root, canary):
    clock = FakeClock()
    h = None

    def slow():
        clock.advance(400)  # the save outlives the submit window
        h.ctx.tick()        # the supervisor sees it while saving: deferred

    fake = FakeStorage(during=slow, rows={"env": {"saved": False, "error": "env_write_failed"},
                                          "keychain": {"saved": False, "error": "keychain_verify_failed",
                                                       "main_touched": True}})
    h = harness(spec_dict, static_dir, store=fake, clock=clock)
    h.client.open()
    r = h.client.submit(plain(value=canary))
    assert r.status_code == 410 and r.json()["error_code"] == "deadline_passed"  # the page's answer is unchanged
    status, meta, _ = h.terminal[0]
    assert (status, meta["reason"]) == ("expired", "window_passed_while_saving")
    last = [x for x in audit(hermes_root) if x["event"] == "expired"][-1]
    assert last["detail"]["reason"] == "window_passed_while_saving"


# --- N-1: main_touched is about an item that was there before the write -----------------------------------------

from test_store_keychain import ACCT, SVC, canary as kc_canary, fake, req, run_save  # noqa: E402,F401


def test_n_1_failed_write_of_a_new_item_is_not_main_touched(fake):
    fake.set(write_rc={"main": 1})
    res = run_save(fake, req(kc_canary()))
    assert res["saved"] is False and res["error"] == "keychain_write_failed"
    assert res["new_item"] is True
    assert res["main_touched"] is False  # there was no earlier value to change


def test_n_1_failed_readback_of_a_new_item_is_not_main_touched(fake):
    fake.set(main_readback="garbled")
    res = run_save(fake, req(kc_canary()))
    assert res["saved"] is False and res["error"] == "keychain_verify_failed"
    assert res["main_touched"] is False


def test_n_1_failed_write_of_an_existing_item_is_main_touched(fake):
    fake.add_item(SVC, ACCT, "old-value")
    fake.set(main_readback="garbled")
    res = run_save(fake, req(kc_canary()))
    assert res["saved"] is False and res["error"] == "keychain_verify_failed"
    assert res["main_touched"] is True


# --- R3-3: a temporary keychain item may still hold the new value -----------------------------------------------

from secure_input.server import _audit_row  # noqa: E402

TMP_SLACK = ("임시 키체인 항목에 이번에 넣은 값이 남아 있을 수 있습니다. "
             "Hermes가 도는 컴퓨터에서 README의 '남은 임시 키체인 항목' 절의 명령으로 확인해 지우세요.")
TMP_TOOL = ("임시 키체인 항목에 이번에 넣은 값이 남아 있을 수 있습니다. "
            "사용자에게 README의 '남은 임시 키체인 항목' 절의 명령으로 확인해 지우라고 알리세요.")
KC = "hermes-secure-input.exa-api-key"


def kc_row(**over):
    row = {"store": "keychain", "saved": True, "replaced": True, "error": None, "service": KC,
           "account": "hermes-secure-input", "listed": False, "new_item": False, "tmp_left": False,
           "main_touched": True}
    row.update(over)
    return row


def env_row(**over):
    row = {"store": "env", "saved": True, "replaced": False, "error": None, "env_var": "EXA_API_KEY",
           "profile": "default"}
    row.update(over)
    return row


TMP_CASES = {
    "saved": ("saved", {"stores": [env_row(), kc_row(tmp_left=True)], "partial": False}),
    "partial": ("saved", {"stores": [env_row(saved=False, error="env_write_failed"), kc_row(tmp_left=True)],
                          "partial": True}),
    "unknown": ("failed", {"reason": "store_timeout",
                           "stores": [env_row(saved=False, error="env_write_failed"),
                                      kc_row(saved=None, replaced=None, error="store_timeout", tmp_left=None,
                                             main_touched=None)]}),
    "expired": ("expired", {"reason": "window_passed_while_saving",
                            "stores": [kc_row(saved=False, replaced=None, error="keychain_verify_failed",
                                              tmp_left=True)]}),
    "cancelled": ("cancelled", {"reason": "parent_gone",
                                "stores": [kc_row(saved=False, replaced=None, error="keychain_write_failed",
                                                  tmp_left=True, main_touched=False)]}),
    "failed": ("failed", {"reason": "too_many_attempts",
                          "stores": [kc_row(saved=False, replaced=None, error="keychain_write_failed",
                                            tmp_left=True, main_touched=False)]}),
}


@pytest.mark.parametrize("case", sorted(TMP_CASES))
def test_r3_3_slack_text_ends_with_the_temp_item_sentence(case):
    status, meta = TMP_CASES[case]
    text = result_text(card(), status, meta)
    assert text.endswith(" " + TMP_SLACK) and text.count(TMP_SLACK) == 1


def test_r3_3_slack_text_saved_with_tmp_left():
    status, meta = TMP_CASES["saved"]
    assert result_text(card(), status, meta) == (
        f"저장 완료: EXA_API_KEY, 프로필 default; Mac 키체인 {KC} {TMP_SLACK}")


@pytest.mark.parametrize("error", ["store_timeout", "no_result"])
def test_r3_3_slack_text_for_a_keychain_row_made_without_an_answer(error):
    rows = [kc_row(saved=None, replaced=None, error=error, tmp_left=None, main_touched=None)]
    text = result_text(card(), "failed", {"reason": error, "stores": rows})
    assert text.endswith(" " + TMP_SLACK)


@pytest.mark.parametrize("case", sorted(TMP_CASES))
def test_r3_3_tool_note_ends_with_the_temp_item_sentence(case):
    status, meta = TMP_CASES[case]
    note = _tool_note(status, meta)
    assert note.endswith(TMP_TOOL) and note.count(TMP_TOOL) == 1


def test_r3_3_tool_note_for_store_timeout():
    rows = [kc_row(saved=None, replaced=None, error="store_timeout", tmp_left=None, main_touched=None)]
    assert _tool_note("failed", {"reason": "store_timeout", "stores": rows}) == (
        "저장 여부를 확인하지 못했습니다. " + TMP_TOOL)


@pytest.mark.parametrize("rows", [
    [env_row(), kc_row()],                                                       # saved, temp item deleted
    [kc_row(saved=False, replaced=None, error="keychain_timeout", tmp_left=False)],  # module deleted it
    [env_row(saved=None, error="store_timeout"), kc_row()],                      # only .env without an answer
    [env_row()],                                                                 # no keychain row
])
def test_r3_3_no_temp_item_sentence_when_the_condition_is_false(rows):
    saved = any(r["saved"] is True for r in rows)
    meta = {"stores": rows, "partial": saved and not all(r["saved"] is True for r in rows)}
    status = "saved" if saved else "failed"
    if not saved:
        meta["reason"] = "too_many_attempts"
    assert "임시 키체인 항목" not in result_text(card(), status, meta)
    assert "임시 키체인 항목" not in _tool_note(status, meta)


def test_r3_3_audit_row_keeps_tmp_left_for_the_keychain_only():
    assert _audit_row(kc_row(tmp_left=True))["tmp_left"] is True
    assert _audit_row(kc_row(saved=None, error="store_timeout", tmp_left=None))["tmp_left"] is None
    assert "tmp_left" not in _audit_row(env_row())


def test_r3_3_audit_log_line_has_tmp_left_through_the_server(spec_dict, static_dir, hermes_root, canary):
    fake = FakeStorage(rows={"env": {"saved": True, "error": None},
                             "keychain": {"saved": True, "replaced": True, "error": None, "tmp_left": True,
                                          "new_item": False}})
    h = harness(spec_dict, static_dir, store=fake)
    h.client.open()
    r = h.client.submit(plain(value=canary))
    assert r.status_code == 200
    saved = [x for x in audit(hermes_root) if x["event"] == "saved"][-1]
    assert [row.get("tmp_left") for row in saved["detail"]["stores"]] == [None, True]
    assert "tmp_left" not in saved["detail"]["stores"][0]
