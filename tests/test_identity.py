"""Who opened the link (security review S-4, card t_95bf30b2 section 3).

The server answers every ``api/`` request only when ``Tailscale-User-Login`` is on the allow list
(owner account from ``tailscale status --json`` plus the ``allowed_tailscale_logins`` setting).
"""

from __future__ import annotations

import json
import os

import pytest
from starlette.testclient import TestClient

from helpers.browser_client import BrowserClient
from helpers.fake_tailscale import FAKE_OWNER_LOGIN, FakeTailscale
from secure_input.serve import ServeError, ServeManager
from secure_input.server import ServerContext, create_app
from secure_input.spec import RequestSpec
from test_lifecycle import FakeClock

PORT = 45679
HOST = "box.example-tailnet.ts.net"
H = "Tailscale-User-Login"


class Box:
    """One in-process request server; ``client(identity)`` talks to it as that Tailscale account."""

    def __init__(self, spec, static_dir, *, allowed=(FAKE_OWNER_LOGIN,), allow_no_header=False, store=None):
        self.clock = FakeClock()
        self.terminal = []
        self.token = "T" + os.urandom(24).hex()
        self.ctx = ServerContext(spec, token=self.token, request_id=os.urandom(16).hex(), static_dir=static_dir,
                                 public_host=HOST, port=PORT, clock=self.clock, store=store,
                                 allowed_logins=list(allowed), allow_no_identity_header=allow_no_header,
                                 on_terminal=lambda status, meta, code: self.terminal.append((status, meta, code)))
        self.http = TestClient(create_app(self.ctx), base_url=f"http://127.0.0.1:{PORT}")
        self.base = f"http://127.0.0.1:{PORT}/{self.token}/"

    def client(self, identity=None) -> BrowserClient:
        return BrowserClient(self.base, client=self.http, identity=identity)


@pytest.fixture
def box(spec_dict, static_dir):
    return lambda **kw: Box(RequestSpec.from_dict(spec_dict(**kw.pop("spec", {}))), static_dir, **kw)


def audit_lines(hermes_root):
    p = hermes_root / "logs" / "secure-input.jsonl"
    return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []


# --- test 1: no header with the default setting -------------------------------------------------

def test_open_without_header_is_403_identity_required_and_link_not_consumed(box):
    b = box()
    r = b.client(None).open()
    assert r.status_code == 403
    assert r.json()["ok"] is False and r.json()["error_code"] == "identity_required"
    assert r.json()["message"]
    assert b.ctx.lc.state == "created" and b.terminal == []
    assert b.client(FAKE_OWNER_LOGIN).open().status_code == 200


# --- test 2: allowed account, case and surrounding spaces ignored --------------------------------

@pytest.mark.parametrize("sent", [FAKE_OWNER_LOGIN, FAKE_OWNER_LOGIN.upper(), f"  {FAKE_OWNER_LOGIN}\t"])
def test_open_with_allowed_login_is_200(box, sent):
    b = box(allowed=[f" {FAKE_OWNER_LOGIN.title()} "])
    r = b.client(sent).open()
    assert r.status_code == 200, r.text
    assert b.ctx.lc.state == "opened"


# --- test 3: other account first, then the allowed one -------------------------------------------

def test_foreign_login_is_403_then_allowed_login_still_opens(box):
    b = box()
    r = b.client("someone-else@example.com").open()
    assert r.status_code == 403 and r.json()["error_code"] == "identity_not_allowed"
    assert b.ctx.lc.state == "created"
    assert b.client(FAKE_OWNER_LOGIN).open().status_code == 200


# --- test 4: two identity headers --------------------------------------------------------------

@pytest.mark.parametrize("pair", [(FAKE_OWNER_LOGIN, FAKE_OWNER_LOGIN), (FAKE_OWNER_LOGIN, "x@example.com")])
def test_two_identity_headers_are_403(box, pair):
    b = box()
    headers = [("Content-Type", "application/json"), (H, pair[0]), (H, pair[1])]
    r = b.http.post(b.base + "api/open", content="{}", headers=headers)
    assert r.status_code == 403 and r.json()["error_code"] == "identity_not_allowed"
    assert b.ctx.lc.state == "created"


# --- test 5: submit and cancel from a foreign account -------------------------------------------

def test_foreign_submit_and_cancel_are_403_and_change_nothing(box, canary):
    b = box()
    owner = b.client(FAKE_OWNER_LOGIN)
    assert owner.open().status_code == 200
    intruder = b.client("someone-else@example.com")
    intruder.opened = owner.opened  # even with the sid and the server key in hand
    plain = {"kind": "api_key", "target_profile": "default", "value": canary}
    r = intruder.submit(plain)
    assert r.status_code == 403 and r.json()["error_code"] == "identity_not_allowed"
    assert canary not in r.text
    r = intruder.cancel()
    assert r.status_code == 403 and r.json()["error_code"] == "identity_not_allowed"
    r = b.client(None).cancel()
    assert r.status_code == 403 and r.json()["error_code"] == "identity_required"
    assert b.ctx.lc.failures == 0 and b.ctx.lc.state == "opened" and b.terminal == []
    assert owner.cancel().status_code == 200


def test_every_api_path_is_checked_but_page_files_are_not(box):
    b = box()
    c = b.client("someone-else@example.com")
    assert c.post("api/other", {}).json()["error_code"] == "identity_not_allowed"
    assert b.http.get(b.base + "api/open", headers={H: "someone-else@example.com"}).status_code == 403
    assert c.get().status_code == 200 and c.get("assets/app.js").status_code == 200
    assert b.ctx.lc.state == "created"


def test_identity_denial_carries_security_headers(box):
    from secure_input import config

    r = box().client(None).open()
    for k, v in config.SECURITY_HEADERS.items():
        assert r.headers.get(k) == v, k


# --- test 6: the test-only setting -----------------------------------------------------------

def test_allow_no_identity_header_lets_headerless_open_through(box):
    b = box(allow_no_header=True)
    assert b.client(None).open().status_code == 200


def test_allow_no_identity_header_still_refuses_foreign_login(box):
    b = box(allow_no_header=True)
    assert b.client("someone-else@example.com").open().json()["error_code"] == "identity_not_allowed"


# --- test 7: audit lines for denials ---------------------------------------------------------

def test_seven_denials_write_five_open_denied_lines_without_login(box, hermes_root):
    b = box()
    for i in range(7):
        who = None if i % 2 else f"intruder-{i}@example.com"
        assert b.client(who).open().status_code == 403
    lines = audit_lines(hermes_root)
    denied = [x for x in lines if x["event"] == "open_denied"]
    assert len(denied) == 5
    assert {x["detail"]["reason"] for x in denied} == {"identity_required", "identity_not_allowed"}
    assert all(set(x["detail"]) == {"reason"} for x in denied)
    raw = (hermes_root / "logs" / "secure-input.jsonl").read_text()
    assert "intruder" not in raw and "example.com" not in raw.replace("https://example.com", "")


# --- the list reaches the real child server through the stdin config ------------------------------

@pytest.fixture
def launched(spec_dict, static_dir, fake_tailscale):
    from secure_input.launcher import start_request

    handles = []

    def _go(**kw):
        h = start_request(RequestSpec.from_dict(spec_dict()), static_dir=static_dir,
                          serve=ServeManager(bin=str(fake_tailscale.bin)), **kw)
        handles.append(h)
        return h

    yield _go
    for h in handles:
        h.cancel()


def test_start_request_without_list_allows_the_tailscale_owner(launched):
    h = launched()
    assert BrowserClient(h.local_url).open().json()["error_code"] == "identity_required"
    assert BrowserClient(h.local_url, identity="someone-else@example.com").open().status_code == 403
    assert BrowserClient(h.local_url, identity=FAKE_OWNER_LOGIN).open().status_code == 200


def test_start_request_with_explicit_list_uses_only_that_list(launched):
    h = launched(allowed_logins=["someone-else@example.com"])
    assert BrowserClient(h.local_url, identity=FAKE_OWNER_LOGIN).open().json()["error_code"] == "identity_not_allowed"
    assert BrowserClient(h.local_url, identity="Someone-Else@example.com").open().status_code == 200


def test_start_request_passes_allow_no_identity_header(launched):
    h = launched(allow_no_identity_header=True)
    assert BrowserClient(h.local_url).open().status_code == 200


def test_start_request_list_and_flag_are_not_in_argv_or_env(launched, monkeypatch):
    import subprocess as sp

    from secure_input import launcher as L

    seen = []
    real = sp.Popen

    def spy(argv, *a, **kw):
        seen.append((list(argv), dict(kw.get("env") or {})))
        return real(argv, *a, **kw)

    monkeypatch.setattr(L.subprocess, "Popen", spy)
    launched(allowed_logins=["marker-login@example.com"], allow_no_identity_header=True)
    argv, env = seen[0]
    assert "marker-login" not in " ".join(argv)
    assert not any("marker-login" in v for v in env.values())
    assert not any("IDENTITY" in k.upper() or "LOGIN" in k.upper() for k in env if k.startswith("SECURE_INPUT"))


def test_start_request_owner_lookup_failure_is_start_error(spec_dict, static_dir, tmp_path):
    from secure_input.launcher import StartError, start_request

    ts = FakeTailscale(tmp_path / "ts-bad", dns_name="box.example-tailnet.ts.net", status_mode="no_user")
    with pytest.raises(StartError):
        start_request(RequestSpec.from_dict(spec_dict()), static_dir=static_dir, serve=ServeManager(bin=str(ts.bin)))


# --- tests 9, 10: the plugin computes the list for every request ----------------------------------

def make_plugin(hermes_root, static_dir, ts, settings=None, start=None):
    from secure_input import plugin as plugin_mod
    from secure_input.notify import SlackNotifier, SlackTarget, TextNotifier
    from test_plugin import FakeCtx, FakeSlack

    values = dict(settings or {})
    kw = {"start": start} if start else {}
    return plugin_mod.SecureInput(
        FakeCtx(), notifier_factory=lambda c: SlackNotifier(SlackTarget("C1", "1795.1", FakeSlack()),
                                                            TextNotifier(c.post_message)),
        hermes_root=lambda: str(hermes_root), settings=lambda key, default: values.get(key, default),
        start_kwargs={"static_dir": static_dir, "serve": ServeManager(bin=str(ts.bin))}, **kw)


def run_tool_in_background(svc, args):
    import threading

    box = {}
    t = threading.Thread(target=lambda: box.setdefault("r", svc.tool_request(args)), daemon=True)
    t.start()
    return t, box


API_ARGS = {"kind": "api_key", "purpose": "Exa 검색 도구 키 등록", "label": "Exa API key", "env_var": "EXA_API_KEY"}


def test_owner_unreadable_and_no_setting_means_no_request_and_no_server(hermes_root, static_dir, tmp_path):
    from secure_input import plugin as plugin_mod

    ts = FakeTailscale(tmp_path / "ts-bad", dns_name="box.example-tailnet.ts.net", status_mode="exit_1")
    started = []
    svc = make_plugin(hermes_root, static_dir, ts, start=lambda spec, **kw: started.append(kw))
    out = json.loads(svc.tool_request(dict(API_ARGS)))
    assert started == [] and svc._live == {}
    assert out["success"] is False and out["status"] == "failed"
    assert out["note"].startswith(plugin_mod.NO_IDENTITY_NOTE)
    assert "Tailscale 계정을 확인하지 못해" in plugin_mod.NO_IDENTITY_NOTE
    assert not list(hermes_root.rglob("secure-input/active/*.json"))
    assert svc.command("key EXA_API_KEY") == plugin_mod.NO_IDENTITY_NOTE and started == []


def test_owner_unreadable_with_setting_uses_only_the_setting(hermes_root, static_dir, tmp_path):
    from test_plugin import live_handle

    ts = FakeTailscale(tmp_path / "ts-bad", dns_name="box.example-tailnet.ts.net", status_mode="no_user")
    svc = make_plugin(hermes_root, static_dir, ts, settings={"allowed_tailscale_logins": ["Friend@Example.com "]})
    t, box = run_tool_in_background(svc, dict(API_ARGS))
    try:
        h = live_handle(svc)
        assert BrowserClient(h.local_url, identity=FAKE_OWNER_LOGIN).open().status_code == 403
        assert BrowserClient(h.local_url, identity="friend@example.com").open().status_code == 200
    finally:
        svc.cancel_all()
        t.join(15)
    assert json.loads(box["r"])["status"] == "cancelled"


def test_setting_login_is_allowed_next_to_the_owner(hermes_root, static_dir, fake_tailscale):
    from test_plugin import live_handle

    seen = []
    from secure_input.launcher import start_request

    def spy(spec, **kw):
        seen.append({k: kw.get(k) for k in ("allowed_logins", "allow_no_identity_header")})
        return start_request(spec, **kw)

    svc = make_plugin(hermes_root, static_dir, fake_tailscale, start=spy,
                      settings={"allowed_tailscale_logins": ["friend@example.com"]})
    t, box = run_tool_in_background(svc, dict(API_ARGS))
    try:
        h = live_handle(svc)
        assert BrowserClient(h.local_url, identity="stranger@example.com").open().status_code == 403
        assert BrowserClient(h.local_url, identity="friend@example.com").open().status_code == 200
    finally:
        svc.cancel_all()
        t.join(15)
    assert seen == [{"allowed_logins": [FAKE_OWNER_LOGIN, "friend@example.com"], "allow_no_identity_header": False}]


@pytest.mark.parametrize("value,expected", [(True, True), (False, False), ("true", False), (1, False)])
def test_allow_no_identity_header_setting_only_true_bool(hermes_root, static_dir, fake_tailscale, value, expected):
    svc = make_plugin(hermes_root, static_dir, fake_tailscale, settings={"allow_no_identity_header": value})
    assert svc.identity_kwargs()["allow_no_identity_header"] is expected


def test_allow_no_identity_header_cannot_be_set_from_environment(hermes_root, static_dir, fake_tailscale,
                                                                 monkeypatch):
    for name in ("ALLOW_NO_IDENTITY_HEADER", "SECURE_INPUT_ALLOW_NO_IDENTITY_HEADER",
                 "HERMES_PLUGIN_SECURE_INPUT_ALLOW_NO_IDENTITY_HEADER"):
        monkeypatch.setenv(name, "true")
    from secure_input import plugin as plugin_mod
    from test_plugin import FakeCtx

    svc = plugin_mod.SecureInput(FakeCtx(), hermes_root=lambda: str(hermes_root),
                                 start_kwargs={"serve": ServeManager(bin=str(fake_tailscale.bin))})
    assert svc.identity_kwargs()["allow_no_identity_header"] is False


# --- test tools stay in step with the fake owner ---------------------------------------------------

def test_ui_specs_send_the_fake_owner_login():
    from conftest import REPO_ROOT

    text = (REPO_ROOT / "ui" / "e2e" / "real-server.spec.ts").read_text()
    assert f"extraHTTPHeaders: {{ 'Tailscale-User-Login': '{FAKE_OWNER_LOGIN}' }}" in text
    # the protocol 2 captures talk to the page mock (harness.ts), not the real server: no owner header needed
    shots = (REPO_ROOT / "ui" / "e2e" / "screenshots.spec.ts").read_text()
    assert "mockServer" in shots and "Tailscale-User-Login" not in shots
    live = (REPO_ROOT / "ui" / "e2e" / "live-tailscale.spec.ts").read_text()
    assert "Tailscale-User-Login" not in live  # through the real Serve the header comes from Tailscale


# --- test 8: owner_login() ---------------------------------------------------------------------

def test_owner_login_reads_self_user_from_fake_status(tmp_path):
    ts = FakeTailscale(tmp_path / "ts", dns_name="box.example-tailnet.ts.net")
    assert ServeManager(bin=str(ts.bin)).owner_login() == FAKE_OWNER_LOGIN
    assert ["status", "--json"] in ts.calls()


@pytest.mark.parametrize("mode", ["no_user", "exit_1", "not_json"])
def test_owner_login_failure_raises_serve_error(tmp_path, mode):
    ts = FakeTailscale(tmp_path / "ts", dns_name="box.example-tailnet.ts.net", status_mode=mode)
    with pytest.raises(ServeError):
        ServeManager(bin=str(ts.bin)).owner_login()
