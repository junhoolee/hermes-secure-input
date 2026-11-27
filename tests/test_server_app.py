"""In-process tests of the ASGI app with a fake clock (no subprocess, no Tailscale)."""

import json
import os

import pytest
from starlette.testclient import TestClient

from helpers.browser_client import BrowserClient, encrypt_submission
from helpers.fake_tailscale import FAKE_OWNER_LOGIN
from secure_input import config
from secure_input.spec import RequestSpec
from secure_input.server import ServerContext, create_app
from test_lifecycle import FakeClock

PORT = 45678
HOST = "box.tailnet.ts.net"


class Harness:
    def __init__(self, spec, static_dir, clock=None, store=None):
        self.clock = clock or FakeClock()
        self.terminal = []
        self.token = "T" + os.urandom(24).hex()
        self.ctx = ServerContext(spec, token=self.token, request_id=os.urandom(16).hex(), static_dir=static_dir,
                                 public_host=HOST, port=PORT, clock=self.clock, store=store,
                                 allowed_logins=[FAKE_OWNER_LOGIN],
                                 on_terminal=lambda status, meta, code: self.terminal.append((status, meta, code)))
        self.app = create_app(self.ctx)
        self.http = TestClient(self.app, base_url=f"http://127.0.0.1:{PORT}", raise_server_exceptions=True)
        self.base = f"http://127.0.0.1:{PORT}/{self.token}/"
        # As if Tailscale Serve forwarded the call for the allowed account (tests/test_identity.py covers the rest).
        self.client = BrowserClient(self.base, client=self.http, identity=FAKE_OWNER_LOGIN)


@pytest.fixture
def make(spec_dict, static_dir):
    def _make(clock=None, store=None, **over):
        return Harness(RequestSpec.from_dict(spec_dict(**over)), static_dir, clock=clock, store=store)
    return _make


def api_key_plain(value, profile="default"):
    return {"kind": "api_key", "target_profile": profile, "value": value}


# --- criterion 1: fake clock windows ---------------------------------------------

def test_open_at_59s_ok_and_at_61s_410(make):
    h = make()
    h.clock.advance(59)
    assert h.client.open().status_code == 200
    h2 = make()
    h2.clock.advance(61)
    r = h2.client.open()
    assert r.status_code == 410 and r.json()["error_code"] == "expired"
    assert h2.terminal and h2.terminal[0][0] == "expired"


def test_second_open_410_already_opened(make):
    h = make()
    assert h.client.open().status_code == 200
    r = h.client.post("api/open", {})
    assert r.status_code == 410 and r.json() == {"ok": False, "error_code": "already_opened",
                                                  "message": r.json()["message"]}


def test_submit_299s_ok_301s_410(make, canary):
    h = make()
    h.client.open()
    h.clock.advance(299)
    r = h.client.submit(api_key_plain(canary))
    assert r.status_code == 200, r.text
    h2 = make()
    h2.client.open()
    h2.clock.advance(301)
    r = h2.client.submit(api_key_plain(canary))
    assert r.status_code == 410 and r.json()["error_code"] == "deadline_passed"


# --- open response shape ------------------------------------------------------------

def test_open_response_matches_contract(make, hermes_root):
    h = make()
    body = h.client.open().json()
    assert set(body) == {"v", "request_id", "kind", "purpose", "label", "requester", "target", "server_public_key",
                         "sid", "submit_deadline_s", "opened_at"}
    assert body["v"] == 2 and body["kind"] == "api_key" and body["submit_deadline_s"] == 300
    assert body["requester"] == {"type": "agent", "profile": "default"}
    stores = body["target"].pop("stores")
    keychain = body["target"].pop("keychain")
    assert body["target"] == {"profile": "default", "profiles": ["default", "worker"], "profile_editable": True,
                              "env_var": "EXA_API_KEY", "origin": None, "site": None}
    assert [r["store"] for r in stores] == ["env", "keychain"] and keychain["id"] == "exa-api-key"
    assert len(body["sid"]) == 43 and "=" not in body["sid"]
    assert len(body["server_public_key"]) == 87
    assert "T" in body["opened_at"] and ("+" in body["opened_at"] or body["opened_at"].endswith("Z"))


# --- routing and static files ----------------------------------------------------------

def test_paths_outside_token_are_404(make):
    h = make()
    for path in ["/", "/index.html", f"/{h.token}", f"/{h.token}x/", "/other/api/open"]:
        assert h.http.get(path).status_code == 404, path
    assert h.http.post(f"/{h.token}x/api/open", json={}).status_code == 404


def test_static_index_and_assets(make):
    h = make()
    r = h.client.get()
    assert r.status_code == 200 and "dummy" in r.text and r.headers["content-type"].startswith("text/html")
    assert h.client.get("assets/app.js").status_code == 200
    assert h.client.get("assets/missing.js").status_code == 404
    assert h.client.get("../" + "conftest.py").status_code == 404
    assert h.client.get("assets/%2e%2e/index.html").status_code == 404


def test_page_gone_after_windows(make):
    h = make()
    h.clock.advance(61)
    assert h.client.get().status_code == 410


# --- criterion 8: headers, origin, content type, size ----------------------------------------

def test_security_headers_on_every_response(make, canary):
    h = make()
    responses = [h.client.get(), h.client.get("assets/app.js"), h.client.get("nope"), h.http.get("/"),
                 h.client.open(), h.client.post("api/open", {}), h.client.submit(api_key_plain(canary))]
    for r in responses:
        for k, v in config.SECURITY_HEADERS.items():
            assert r.headers.get(k) == v, (r.request.url, k)


@pytest.mark.parametrize("origin", ["https://evil.example", "null", f"http://127.0.0.1:{PORT + 1}", f"http://{HOST}"])
def test_foreign_origin_post_is_403(make, origin):
    h = make()
    r = h.client.post("api/open", {}, headers={"Content-Type": "application/json", "Origin": origin})
    assert r.status_code == 403
    assert h.client.open().status_code == 200  # the foreign attempt did not consume the open


@pytest.mark.parametrize("origin", [None, f"https://{HOST}", f"http://127.0.0.1:{PORT}"])
def test_allowed_origins(make, origin):
    h = make()
    headers = {"Content-Type": "application/json"}
    if origin:
        headers["Origin"] = origin
    assert h.client.post("api/open", {}, headers=headers).status_code == 200


def test_non_json_content_type_is_415(make):
    h = make()
    r = h.client.post("api/open", "{}", headers={"Content-Type": "text/plain", "Origin": f"https://{HOST}"})
    assert r.status_code == 415
    r = h.client.post("api/open", "{}", headers={"Content-Type": "application/json; charset=utf-8"})
    assert r.status_code == 200


def test_body_over_64kb_is_413(make):
    h = make()
    h.client.open()
    big = {"pad": "x" * (64 * 1024)}
    assert h.client.post("api/submit", big).status_code == 413


# --- criterion 4: replay, sid, tamper, attempts ------------------------------------------------

def test_same_body_twice_second_is_409(make, canary):
    h = make()
    h.client.open()
    body = h.client.build_submit(api_key_plain(canary))
    assert h.client.post("api/submit", body).status_code == 200
    r = h.client.post("api/submit", body)
    assert r.status_code == 409 and r.json()["error_code"] == "already_submitted"


def test_replay_of_failed_body_is_409_replayed(make):
    h = make()
    h.client.open()
    body = h.client.build_submit({"kind": "login"})  # wrong kind -> invalid_payload
    assert h.client.post("api/submit", body).json()["error_code"] == "invalid_payload"
    r = h.client.post("api/submit", body)
    assert r.status_code == 409 and r.json()["error_code"] == "replayed"


def test_wrong_sid_is_403(make, canary):
    h = make()
    h.client.open()
    body = h.client.build_submit(api_key_plain(canary))
    body["sid"] = encrypt_submission({**h.client.opened, "sid": "A" * 43}, b"x")["sid"]
    r = h.client.post("api/submit", body)
    assert r.status_code == 403 and r.json()["error_code"] == "bad_sid"


def test_tampered_ciphertext_is_400(make, canary):
    h = make()
    h.client.open()
    body = h.client.build_submit(api_key_plain(canary))
    ct = bytearray(body["ciphertext"].encode())
    ct[5] = ord("A") if ct[5] != ord("A") else ord("B")
    body["ciphertext"] = ct.decode()
    r = h.client.post("api/submit", body)
    assert r.status_code == 400 and r.json()["error_code"] == "decrypt_failed"


def test_five_failures_then_429(make, canary):
    h = make()
    h.client.open()
    codes = []
    for _ in range(5):
        codes.append(h.client.submit({"kind": "otp_code", "code": "1"}).status_code)
    assert codes == [400, 400, 400, 400, 429]
    r = h.client.submit(api_key_plain(canary))
    assert r.status_code == 429 and r.json()["error_code"] == "too_many_attempts"
    assert [t[0] for t in h.terminal] == ["failed"]


def test_error_messages_are_korean_and_value_free(make, canary):
    h = make()
    h.client.open()
    r = h.client.submit({"kind": "api_key", "target_profile": "nope", "value": canary})
    j = r.json()
    assert r.status_code == 400 and j["error_code"] == "invalid_payload"
    assert canary not in r.text and any("\uac00" <= ch <= "\ud7a3" for ch in j["message"])


# --- payload validation ---------------------------------------------------------------------

@pytest.mark.parametrize("plain", [
    {"kind": "api_key", "target_profile": "default"},
    {"kind": "api_key", "target_profile": "default", "value": ""},
    {"kind": "api_key", "target_profile": "default", "value": "a\nb"},
    {"kind": "api_key", "target_profile": "default", "value": "x", "extra": 1},
    {"kind": "api_key", "target_profile": "ghost", "value": "x"},
    ["not", "an", "object"],
])
def test_invalid_api_key_payloads(make, plain):
    h = make()
    h.client.open()
    assert h.client.submit(plain).json()["error_code"] == "invalid_payload"


def test_non_editable_profile_must_match(make, canary):
    h = make(profile_editable=False)
    h.client.open()
    assert h.client.submit(api_key_plain(canary, "worker")).json()["error_code"] == "invalid_payload"
    assert h.client.submit(api_key_plain(canary, "default")).status_code == 200


# --- storage outcomes --------------------------------------------------------------------------

def test_api_key_saved_to_changed_profile_and_audited_in_both(make, hermes_root, canary):
    h = make()
    h.client.open()
    r = h.client.submit(api_key_plain(canary, "worker"))
    assert r.status_code == 200
    assert r.json() == {"ok": True, "result": {"status": "saved", "label": "Exa API key", "partial": False,
                                               "stores": [{"store": "env", "saved": True, "replaced": False,
                                                           "error": None, "env_var": "EXA_API_KEY",
                                                           "profile": "worker"}],
                                               "storage": {"type": "env", "profile": "worker", "origin": None,
                                                           "env_var": "EXA_API_KEY", "item_id": None}}}
    assert (hermes_root / "profiles" / "worker" / ".env").read_text() == f"EXA_API_KEY={canary}\n"
    assert not (hermes_root / ".env").exists()
    main = [json.loads(x)["event"] for x in (hermes_root / "logs" / "secure-input.jsonl").read_text().splitlines()]
    other = [json.loads(x)["event"] for x in
             (hermes_root / "profiles" / "worker" / "logs" / "secure-input.jsonl").read_text().splitlines()]
    assert main == ["opened", "submitted", "saving", "saved"] and other == ["saving", "saved"]
    status, meta, code = h.terminal[0]
    assert status == "saved" and code is None and meta["target_profile"] == "worker"


def test_storage_failure_is_422_and_retry_allowed(make, canary):
    calls = []

    def flaky(home, request):
        calls.append(1)
        ok = len(calls) > 1
        return {"preflight": {}, "stores": {"env": {"saved": ok, "replaced": False if ok else None,
                                                    "error": None if ok else "env_write_failed"}},
                "done": {"event": "done", "ok": True}, "timed_out": False}

    h = make(store=flaky)
    h.client.open()
    r = h.client.submit(api_key_plain(canary))
    assert r.status_code == 422 and r.json()["error_code"] == "storage_failed" and canary not in r.text
    assert h.client.submit(api_key_plain(canary)).status_code == 200


def test_otp_code_delivered_not_stored(make, hermes_root, canary):
    h = make(kind="otp_code")
    body = h.client.open().json()
    assert body["target"]["site"] == "example.com" and body["target"]["profile_editable"] is False
    r = h.client.submit({"kind": "otp_code", "code": canary})
    assert r.status_code == 200
    assert r.json()["result"]["status"] == "delivered"
    assert r.json()["result"]["storage"]["type"] == "browser_page"
    status, meta, code = h.terminal[0]
    assert (status, code) == ("delivered", canary) and canary not in json.dumps(meta)
    assert not (hermes_root / ".env").exists() and not (hermes_root / "vault").exists()


def test_cancel(make):
    h = make()
    h.client.open()
    assert h.client.post("api/cancel", {"sid": "A" * 43}).status_code == 403
    r = h.client.cancel()
    assert r.status_code == 200 and r.json() == {"ok": True, "result": {"status": "cancelled"}}
    assert [t[0] for t in h.terminal] == ["cancelled"]
    assert h.client.get().status_code == 410


def test_open_after_supervisor_tick_is_expired(make):
    h = make()
    h.clock.advance(61)
    h.ctx.tick()
    r = h.client.open()
    assert r.status_code == 410 and r.json()["error_code"] == "expired"


def test_ttls_cannot_extend_contract_windows(spec_dict, static_dir, canary):
    clock = FakeClock()
    ctx = ServerContext(RequestSpec.from_dict(spec_dict()), token="T" + os.urandom(24).hex(),
                        request_id=os.urandom(16).hex(), static_dir=static_dir, public_host=HOST, port=PORT,
                        clock=clock, ttls={"open": 1000, "submit": 1000})
    assert ctx.lc.open_ttl == config.OPEN_TTL_S and ctx.lc.submit_ttl == config.SUBMIT_TTL_S
    clock.advance(61)
    assert ctx.lc.page_allowed() is False and ctx.lc.state == "expired"
