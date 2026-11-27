"""The ``saving`` state and the deferred end reason (plan 5.7, appendix A.2), one test per row of the A.2 table.

Rows of "들어가고 나가는 길" (ways in and out) are named ``row_<n>`` in the order of the table; the rows of
"저장 프로세스가 끝났을 때의 갈림" (the branch when the storage process ends) are ``branch_<n>``. The server-level
answers for the same rows (HTTP codes, logs, results) are in ``tests/test_server_stores.py``.
"""

from __future__ import annotations

import os

import pytest

from secure_input.lifecycle import HTTP_STATUS, Lifecycle, LifecycleError
from test_lifecycle import FakeClock

SID = os.urandom(32)


@pytest.fixture
def clock():
    return FakeClock()


def opened(clock, submit_ttl=300):
    lc = Lifecycle(clock, submit_ttl=submit_ttl)
    lc.open(SID)
    return lc


def saving(clock, submit_ttl=300):
    lc = opened(clock, submit_ttl)
    lc.check_submit(SID)
    lc.begin_saving()
    return lc


def code_of(fn, *a):
    with pytest.raises(LifecycleError) as ei:
        fn(*a)
    return ei.value.code, ei.value.status


def test_new_http_words():
    assert HTTP_STATUS["saving_in_progress"] == 409 and HTTP_STATUS["store_unavailable"] == 422


# --- ways in and out ---------------------------------------------------------------------------------------------

def test_row_1_created_open_request_opens(clock):
    lc = Lifecycle(clock)
    lc.open(SID)
    assert lc.state == "opened"


def test_row_2_created_open_window_passes(clock):
    lc = Lifecycle(clock)
    clock.advance(61)
    lc.tick()
    assert (lc.state, lc.detail) == ("expired", "open_window_passed")


def test_row_3_opened_checked_submit_enters_saving(clock):
    lc = saving(clock)
    assert lc.state == "saving" and not lc.is_terminal and lc.deferred is None


def test_row_4_otp_code_goes_straight_to_delivered(clock):
    lc = opened(clock)
    lc.check_submit(SID)
    lc.succeed("delivered")
    assert lc.state == "delivered"


def test_row_5_opened_failed_check_stays_opened_and_counts(clock):
    lc = opened(clock)
    assert lc.record_failure("invalid_payload") == "invalid_payload"
    assert lc.state == "opened" and lc.failures == 1


@pytest.mark.parametrize("event,expect", [("submit_window", ("expired", "submit_window_passed")),
                                          ("parent_gone", ("cancelled", "parent_gone")),
                                          ("screen_cancel", ("cancelled", "user_cancelled"))])
def test_row_6_opened_window_parent_and_screen_cancel_unchanged(clock, event, expect):
    lc = opened(clock)
    if event == "submit_window":
        clock.advance(301)
        lc.tick()
    elif event == "parent_gone":
        lc.abort("cancelled", "parent_gone")
    else:
        lc.cancel(SID)
    assert (lc.state, lc.detail) == expect


@pytest.mark.parametrize("start", ["created", "opened"])
def test_row_7_sigterm_before_saving_cancels(clock, start):
    lc = Lifecycle(clock) if start == "created" else opened(clock)
    assert lc.abort("cancelled", "terminated") is True
    assert (lc.state, lc.detail) == ("cancelled", "terminated")


def test_row_8_saving_tick_after_the_window_only_defers(clock):
    lc = saving(clock)
    clock.advance(400)
    assert lc.tick() is False
    assert lc.state == "saving" and lc.deferred == ("expired", "submit_window_passed")


def test_row_9_saving_parent_gone_only_defers(clock):
    lc = saving(clock)
    assert lc.abort("cancelled", "parent_gone") is False
    assert lc.state == "saving" and lc.deferred == ("cancelled", "parent_gone")


def test_row_10_saving_sigterm_only_defers(clock):
    lc = saving(clock)
    assert lc.abort("cancelled", "terminated") is False
    assert lc.state == "saving" and lc.deferred == ("cancelled", "terminated")


def test_row_11_saving_screen_cancel_is_409_not_counted_not_deferred(clock):
    lc = saving(clock)
    assert code_of(lc.cancel, SID) == ("saving_in_progress", 409)
    assert lc.state == "saving" and lc.failures == 0 and lc.deferred is None


def test_row_12_saving_second_submit_is_409_not_counted(clock):
    lc = saving(clock)
    assert code_of(lc.check_submit, SID) == ("saving_in_progress", 409)
    assert lc.record_failure("saving_in_progress") == "saving_in_progress"
    assert lc.state == "saving" and lc.failures == 0


def test_row_13_saving_open_request_is_already_opened(clock):
    lc = saving(clock)
    assert code_of(lc.open, SID) == ("already_opened", 410)


def test_row_14_saving_page_reload_serves_the_page(clock):
    lc = saving(clock)
    assert lc.page_allowed() is True


def test_row_16_server_death_is_not_a_lifecycle_state(clock):
    """Row 16 (the server ends without ``done``) has no lifecycle transition: the parent's launcher ends the
    request as ``failed``/``child_exited`` (tests/test_server_stores.py::test_server_killed_while_saving_*)."""
    lc = saving(clock)
    assert lc.state == "saving"


def test_only_the_first_deferred_reason_is_kept(clock):
    lc = saving(clock)
    lc.abort("cancelled", "terminated")
    clock.advance(400)
    lc.tick()
    lc.abort("cancelled", "parent_gone")
    assert lc.deferred == ("cancelled", "terminated")


# --- the branch when the storage process ends (row 15) -----------------------------------------------------------

def test_branch_saved_inside_and_outside_the_window(clock):
    lc = saving(clock)
    assert lc.end_saving("saved") == "saved" and lc.state == "saved"
    lc2 = saving(clock, submit_ttl=6)
    clock.advance(10)
    lc2.tick()
    assert lc2.end_saving("saved") == "saved" and lc2.deferred == ("expired", "submit_window_passed")
    lc3 = saving(clock)
    lc3.abort("cancelled", "parent_gone")
    assert lc3.end_saving("saved") == "saved"


def test_branch_retry_inside_the_window_goes_back_to_opened(clock):
    lc = saving(clock)
    clock.advance(5)
    assert lc.end_saving("retry") == "opened"
    assert lc.state == "opened" and lc.failures == 0
    lc.check_submit(SID)  # the same page may send again, the window still counts from the first open


def test_branch_retry_keeps_the_original_submit_window(clock):
    lc = saving(clock, submit_ttl=6)
    clock.advance(5)
    assert lc.end_saving("retry") == "opened"
    clock.advance(2)
    assert code_of(lc.check_submit, SID) == ("deadline_passed", 410)


def test_branch_retry_after_the_window_expires(clock):
    lc = saving(clock, submit_ttl=6)
    clock.advance(7)  # the window passed while saving, before any tick saw it
    assert lc.end_saving("retry") == "expired"
    assert lc.detail == "window_passed_while_saving"


@pytest.mark.parametrize("reason", [("cancelled", "parent_gone"), ("cancelled", "terminated"),
                                    ("expired", "submit_window_passed")])
def test_branch_retry_with_a_deferred_reason_ends_with_that_reason(clock, reason):
    lc = saving(clock)
    if reason[0] == "expired":
        clock.advance(400)
        lc.tick()
    else:
        lc.abort(*reason)
    assert lc.end_saving("retry") == reason[0]
    # R3-1: a deferred submit window ends the request with its own word, the user did submit in time
    assert (lc.state, lc.detail) == (reason if reason[0] == "cancelled" else ("expired", "window_passed_while_saving"))


@pytest.mark.parametrize("detail", ["store_timeout", "no_result"])
def test_branch_unknown_result_fails_inside_and_outside(clock, detail):
    lc = saving(clock)
    assert lc.end_saving("failed", detail) == "failed" and lc.detail == detail
    lc2 = saving(clock)
    lc2.abort("cancelled", "terminated")
    assert lc2.end_saving("failed", detail) == "failed" and lc2.deferred == ("cancelled", "terminated")


def test_counted_retry_fifth_failure_ends_the_request(clock):
    lc = opened(clock)
    for _ in range(4):
        lc.record_failure("storage_failed")
    lc.check_submit(SID)
    lc.begin_saving()
    assert lc.end_saving("retry") == "opened"
    assert lc.record_failure("storage_failed") == "too_many_attempts"
    assert (lc.state, lc.detail) == ("failed", "too_many_attempts")


# --- A.6 last item: the open window starts after the create-time check -------------------------------------------

def test_open_clock_restarts_after_the_create_time_check(clock):
    lc = Lifecycle(clock)
    clock.advance(9.5)  # the create-time preflight took 9.5 s
    lc.restart_open_clock()
    clock.advance(59)
    lc.open(SID)
    assert lc.state == "opened"


def test_open_clock_restart_keeps_the_60_s_limit(clock):
    lc = Lifecycle(clock)
    clock.advance(9.5)
    lc.restart_open_clock()
    clock.advance(61)
    assert code_of(lc.open, SID) == ("expired", 410)
