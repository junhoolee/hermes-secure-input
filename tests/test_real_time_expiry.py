"""Criterion 10: real clock, no shortened windows. A request nobody opens for 60 s expires, its Serve
path is removed, and the link message is replaced by the expiry text (fake Slack client).
Takes about 61 s."""

from __future__ import annotations

import json
import time

from test_plugin import env, live_handle, run_bg  # noqa: F401  (fixture reuse)


def test_unopened_request_expires_after_60s_real_time(env, fake_tailscale):  # noqa: F811
    svc = env()
    started = time.monotonic()
    t, box = run_bg(svc.tool_request, {"kind": "api_key", "purpose": "만료 확인", "label": "만료 시험",
                                       "env_var": "EXPIRY_TEST_KEY"})
    h = live_handle(svc)
    token = h.url.rstrip("/").rsplit("/", 1)[1]
    assert fake_tailscale.add_calls(token), "Serve path was never added"
    t.join(90)
    elapsed = time.monotonic() - started
    res = json.loads(box["r"])
    assert res["status"] == "expired" and res["success"] is False
    assert elapsed >= 60.0, elapsed
    assert fake_tailscale.off_calls(token), "Serve path was not removed"
    (m1, post), (m2, upd) = svc.fake_slack.calls
    assert m1 == "chat_postMessage" and m2 == "chat_update"
    assert upd["text"] == "만료: 60초 안에 열리지 않았습니다 (API 키 '만료 시험')"
    assert "actions" not in json.dumps(upd["blocks"]) and token not in json.dumps(upd)
