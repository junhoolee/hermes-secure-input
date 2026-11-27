import os

import pytest

from secure_input.lifecycle import Lifecycle, LifecycleError


class FakeClock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, s):
        self.t += s


@pytest.fixture
def clock():
    return FakeClock()


def err(fn, *a):
    with pytest.raises(LifecycleError) as ei:
        fn(*a)
    return ei.value.code, ei.value.status


def test_open_at_59s_succeeds(clock):
    lc = Lifecycle(clock)
    clock.advance(59)
    lc.open(os.urandom(32))
    assert lc.state == "opened"


def test_open_at_61s_is_expired_410(clock):
    lc = Lifecycle(clock)
    clock.advance(61)
    assert err(lc.open, os.urandom(32)) == ("expired", 410)
    assert lc.state == "expired" and lc.is_terminal


def test_second_open_is_410_already_opened(clock):
    lc = Lifecycle(clock)
    lc.open(os.urandom(32))
    assert err(lc.open, os.urandom(32)) == ("already_opened", 410)
    assert lc.state == "opened"


def test_submit_299s_after_open_allowed(clock):
    lc = Lifecycle(clock)
    sid = os.urandom(32)
    clock.advance(30)
    lc.open(sid)
    clock.advance(299)
    lc.check_submit(sid)
    lc.succeed("saved")
    assert lc.state == "saved" and lc.is_terminal


def test_submit_301s_after_open_is_410(clock):
    lc = Lifecycle(clock)
    sid = os.urandom(32)
    lc.open(sid)
    clock.advance(301)
    assert err(lc.check_submit, sid) == ("deadline_passed", 410)
    assert lc.state == "expired"


def test_submit_before_open_or_wrong_sid_is_403(clock):
    lc = Lifecycle(clock)
    assert err(lc.check_submit, os.urandom(32)) == ("bad_sid", 403)
    lc.open(os.urandom(32))
    assert err(lc.check_submit, os.urandom(32)) == ("bad_sid", 403)


def test_success_is_once(clock):
    lc = Lifecycle(clock)
    sid = os.urandom(32)
    lc.open(sid)
    lc.succeed("delivered")
    assert err(lc.check_submit, sid) == ("already_submitted", 409)


def test_replay_pair_rejected_regardless_of_outcome(clock):
    lc = Lifecycle(clock)
    lc.open(os.urandom(32))
    lc.mark_seen(b"k", b"iv")
    assert err(lc.mark_seen, b"k", b"iv") == ("replayed", 409)
    lc.mark_seen(b"k", b"iv2")


def test_five_failures_end_in_too_many_attempts(clock):
    lc = Lifecycle(clock)
    sid = os.urandom(32)
    lc.open(sid)
    for i in range(4):
        assert lc.record_failure("decrypt_failed") == "decrypt_failed"
        assert lc.state == "opened"
    assert lc.record_failure("decrypt_failed") == "too_many_attempts"
    assert lc.state == "failed"
    assert err(lc.check_submit, sid) == ("too_many_attempts", 429)


def test_tick_expires_unopened_and_open_windows(clock):
    lc = Lifecycle(clock)
    assert lc.page_allowed()
    clock.advance(60)
    assert lc.tick() is False and lc.page_allowed()
    clock.advance(1)
    assert lc.tick() is True and lc.state == "expired" and not lc.page_allowed()

    lc2 = Lifecycle(clock)
    lc2.open(os.urandom(32))
    clock.advance(300)
    assert lc2.tick() is False and lc2.page_allowed()
    clock.advance(1)
    assert lc2.tick() is True and lc2.state == "expired"


def test_cancel_requires_sid(clock):
    lc = Lifecycle(clock)
    sid = os.urandom(32)
    assert err(lc.cancel, sid) == ("bad_sid", 403)
    lc.open(sid)
    assert err(lc.cancel, os.urandom(32)) == ("bad_sid", 403)
    lc.cancel(sid)
    assert lc.state == "cancelled"


def test_abort_sets_terminal_state_once(clock):
    lc = Lifecycle(clock)
    lc.abort("cancelled")
    assert lc.state == "cancelled"
    lc.abort("failed")
    assert lc.state == "cancelled"


def test_open_after_tick_expired_unopened_is_expired(clock):
    # Real server: the supervisor thread ticks before the browser's open arrives.
    lc = Lifecycle(clock)
    clock.advance(61)
    lc.tick()
    assert lc.state == "expired"
    assert err(lc.open, os.urandom(32)) == ("expired", 410)
