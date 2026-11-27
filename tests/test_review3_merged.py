"""Security review 3, after the four fix branches were merged: checks no single branch could make alone.

R3-5 has two halves fixed on two branches: the Slack lines (notify.py) and the tool result (plugin.py). Here one
request goes through both: the plugin's own card and notifier post the link and the result to a recording fake
Slack, and the same outcome becomes the tool result. An allow-list item's account must be in neither, in every
end state.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from secure_input.launcher import Outcome

from test_review3_disclosure import CANARY_ACCOUNT, END_STATES, LISTED, kc_row, listed_spec
from test_plugin_stores import svc_factory  # noqa: F401 - fixture

URL = "https://fake-host.example-tailnet.ts.net/TOKEN_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG/"

MERGED_STATES = dict(END_STATES)
# Expired with a keychain line that has the account: the window passed while saving (R3-1) after a touch (N-1).
MERGED_STATES["expired"] = Outcome("expired", {
    "reason": "window_passed_while_saving",
    "stores": [kc_row(saved=False, replaced=None, error="keychain_write_failed", main_touched=True, tmp_left=True)]})


@pytest.mark.parametrize("state", list(MERGED_STATES))
def test_one_request_keeps_the_listed_account_out_of_every_slack_call_and_the_tool_result(svc_factory, state):
    svc = svc_factory(items=[LISTED])
    spec = listed_spec(svc)
    outcome = MERGED_STATES[state]
    card = svc._card(spec, URL)
    assert card.keychain["account"] == CANARY_ACCOUNT  # the card itself knows it; only what is sent is checked
    notifier = svc._notifier_factory(svc.ctx)
    ref = notifier.post_link(card)
    svc.finish(SimpleNamespace(request_id="r1"), notifier, ref, card, outcome)
    tool = svc.result(kind="secret", label=spec.label, target_profile=spec.target_profile, outcome=outcome,
                      request_id="r1", spec=spec)

    methods = [m for m, _ in svc.fake_slack.calls]
    assert methods == ["chat_postMessage", "chat_update"]
    slack = json.dumps(svc.fake_slack.calls, ensure_ascii=False)
    assert CANARY_ACCOUNT not in slack
    assert CANARY_ACCOUNT not in json.dumps(svc.ctx.posts, ensure_ascii=False, default=str)
    assert CANARY_ACCOUNT not in tool
    assert LISTED["service"] in slack  # the item is still named by its service
