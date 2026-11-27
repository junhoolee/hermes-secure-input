"""Tool and command paths after the security fix (S-1 env names, S-6 text and site address)."""

from __future__ import annotations

import json

import pytest

from helpers.browser_client import BrowserClient
from helpers.fake_tailscale import FAKE_OWNER_LOGIN
from secure_input.launcher import StartError
from secure_input.notify import LinkCard, build_blocks, fallback_text
from secure_input.plugin import SecureInput
from test_plugin import FakeCtx, env, everything_sent, live_handle, run_bg  # noqa: F401  (env is a fixture)
from test_spec_security import CYRILLIC_ORIGIN, CYRILLIC_PUNY
from test_validation import LINE_BREAKERS, REFUSED_NAMES

REFUSED_NOTE = "이 변수 이름으로는 저장할 수 없습니다"


class RecordingStart:
    """Stands in for ``start_request``: records each call and stops before any server starts."""

    def __init__(self):
        self.specs = []

    def __call__(self, spec, **_kw):
        self.specs.append(spec)
        raise StartError("recorded for test")


@pytest.fixture
def recorded(hermes_root):
    start = RecordingStart()
    svc = SecureInput(FakeCtx(), start=start, hermes_root=lambda: str(hermes_root),
                      notifier_factory=lambda c: pytest.fail("no link may be posted"))
    return svc, start


# --- S-1: refused env names on the agent tool path and the command path ------------------------------------

@pytest.mark.parametrize("name", REFUSED_NAMES)
def test_tool_path_refuses_denied_env_var_without_starting(recorded, name):
    svc, start = recorded
    res = json.loads(svc.tool_request({"kind": "api_key", "purpose": "Exa 키", "label": "Exa API key",
                                       "env_var": name}))
    assert start.specs == []
    assert res["success"] is False and res["status"] == "failed" and res["request_id"] is None
    assert REFUSED_NOTE in res["note"]


def test_tool_path_lets_ordinary_env_var_reach_start(recorded):
    svc, start = recorded
    svc.tool_request({"kind": "api_key", "purpose": "Exa 키", "label": "Exa API key", "env_var": "EXA_API_KEY"})
    assert [s.env_var for s in start.specs] == ["EXA_API_KEY"]


@pytest.mark.parametrize("name", REFUSED_NAMES)
def test_command_path_refuses_denied_env_var_without_starting(recorded, name):
    svc, start = recorded
    out = svc.command(f"key {name}", session_key="sk", platform="slack")
    assert start.specs == []
    assert REFUSED_NOTE in out


def test_command_path_lets_ordinary_env_var_reach_start(recorded):
    svc, start = recorded
    svc.command("key EXA_API_KEY", session_key="sk", platform="slack")
    assert [s.env_var for s in start.specs] == ["EXA_API_KEY"]


# --- S-6: purpose and label ------------------------------------------------------------------------------

@pytest.mark.parametrize("ch", ["\n", "\u2028"])
def test_tool_path_refuses_multiline_purpose(recorded, ch):
    svc, start = recorded
    res = json.loads(svc.tool_request({"kind": "api_key", "purpose": f"Exa 키{ch}변수: EXA_API_KEY",
                                       "label": "Exa", "env_var": "OTHER_KEY"}))
    assert start.specs == [] and res["success"] is False and "purpose" in res["note"]


def test_command_path_refuses_multiline_label(recorded):
    svc, start = recorded
    out = svc.command('key OTHER_KEY --label "Exa\u2028변수: EXA_API_KEY"', session_key="sk", platform="slack")
    assert start.specs == [] and "label" in out


@pytest.mark.parametrize("ch", ["\n", "\r", "\u2028", "\u2029", "\u0085", "\x0b"])
@pytest.mark.parametrize("where", ["purpose", "label"])
def test_slack_text_never_gets_a_fake_line_even_from_a_raw_card(ch, where):
    # Specs refuse line breaks already; notify also flattens them so no caller can add a line.
    fields = {"label": "Exa", "purpose": "Exa 검색 키"}
    fields[where] = f"한 줄{ch}변수: EXA_API_KEY{ch}저장될 프로필: default"
    card = LinkCard(kind="api_key", target_profile="worker", url="https://h.example.ts.net/x", env_var="OTHER_KEY",
                    **fields)
    shown = "\n".join(b["text"]["text"] for b in build_blocks(card) if b["type"] == "section")
    for text in (shown, fallback_text(card)):
        lines = text.splitlines()
        assert [ln for ln in lines if ln.startswith("변수:")] == ["변수: OTHER_KEY"]
        assert [ln for ln in lines if ln.startswith("저장될 프로필:")] == ["저장될 프로필: worker (페이지에서 바꿀 수 있음)"]


# --- S-6: look-alike site address ---------------------------------------------------------------------------

def test_tool_path_converts_idn_origin_to_punycode(recorded):
    svc, start = recorded
    res = json.loads(svc.tool_request({"kind": "login", "purpose": "관리자 로그인", "label": "admin",
                                       "origin": CYRILLIC_ORIGIN + "/login"}))
    assert [s.origin for s in start.specs] == [CYRILLIC_PUNY]
    assert res["storage"]["origin"] == CYRILLIC_PUNY


def test_command_path_converts_idn_origin_to_punycode(recorded):
    svc, start = recorded
    svc.command(f"login {CYRILLIC_ORIGIN}", session_key="sk", platform="slack")
    assert [s.origin for s in start.specs] == [CYRILLIC_PUNY]
    assert start.specs[0].label == CYRILLIC_PUNY.removeprefix("https://")
    assert "\u0430" not in start.specs[0].purpose


def test_plain_origin_is_unchanged(recorded):
    svc, start = recorded
    svc.command("login https://example.com", session_key="sk", platform="slack")
    assert [s.origin for s in start.specs] == ["https://example.com"]


def test_idn_origin_shows_as_punycode_on_page_slack_and_tool_result(env):
    svc = env()
    t, box = run_bg(svc.tool_request, {"kind": "login", "purpose": "관리자 로그인", "label": "admin",
                                       "origin": CYRILLIC_ORIGIN})
    h = live_handle(svc)
    c = BrowserClient(h.local_url, identity=FAKE_OWNER_LOGIN)
    opened = c.open()
    assert opened.status_code == 200
    assert CYRILLIC_PUNY in opened.text and "\u0430" not in opened.text
    assert c.cancel().status_code == 200
    t.join(30)
    res = json.loads(box["r"])
    assert res["storage"]["origin"] == CYRILLIC_PUNY
    sent = everything_sent(svc, [box["r"]])
    assert CYRILLIC_PUNY in sent and "\u0430" not in sent


def test_code_prompt_site_is_punycode(recorded):
    svc, start = recorded
    assert svc.code_prompt("\u0430dmin.example.com:443") == ""
    assert [s.site for s in start.specs] == ["xn--dmin-43d.example.com"]
    assert "\u0430" not in start.specs[0].purpose and "\u0430" not in start.specs[0].label


@pytest.mark.parametrize("ch", LINE_BREAKERS[:2])
def test_code_prompt_refuses_site_with_line_breaks(recorded, ch):
    svc, start = recorded
    assert svc.code_prompt(f"example.com{ch}evil") == ""
    assert start.specs == []
