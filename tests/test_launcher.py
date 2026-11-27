"""Subprocess tests: real child server, fake ``tailscale`` binary, temp hermes_root."""

import json
import logging
import os
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

import httpx
import pytest

from conftest import FAKE_DNS, HERMES_AGENT_DIR, REPO_ROOT
from helpers.browser_client import BrowserClient
from helpers.fake_tailscale import FAKE_OWNER_LOGIN
from secure_input.audit import AUDIT_FIELDS
from secure_input.launcher import (Outcome, TooManyActive, new_token, sweep_stale, start_request)
from secure_input.serve import ServeManager
from secure_input.spec import RequestSpec
from secure_input.storage import hermes_agent_dir


@pytest.fixture
def launch(spec_dict, static_dir, fake_tailscale):
    handles = []

    def _launch(**over):
        ttls = over.pop("_test_ttls", None)
        spec = RequestSpec.from_dict(spec_dict(**over))
        h = start_request(spec, static_dir=static_dir, serve=ServeManager(bin=str(fake_tailscale.bin)),
                          _test_ttls=ttls)
        handles.append(h)
        return h

    yield _launch
    for h in handles:
        h.cancel()


def token_of(h) -> str:
    return h.url.rstrip("/").rsplit("/", 1)[1]


def active_files(root: Path) -> list[Path]:
    return sorted(root.rglob("secure-input/active/*.json"))


def scan_for(root: Path, needle: str, skip=lambda p: False) -> list[str]:
    hits = []
    for p in root.rglob("*"):
        if p.is_file() and not skip(p) and needle.encode() in p.read_bytes():
            hits.append(str(p))
    return hits


# --- criterion 2 --------------------------------------------------------------------------

def test_tokens_unique_and_long():
    toks = [new_token() for _ in range(100)]
    assert len(set(toks)) == 100 and min(len(t) for t in toks) >= 43


# --- criterion 3/6/7: round trips through a real child process ---------------------------------

def test_api_key_roundtrip_saves_env_and_cleans_up(launch, hermes_root, fake_tailscale, canary):
    (hermes_root / ".env").write_text("OTHER=keep me\n")
    h = launch()
    assert h.url == f"https://{FAKE_DNS}/{token_of(h)}/"
    assert len(active_files(hermes_root)) == 1
    af = active_files(hermes_root)[0]
    assert stat.S_IMODE(af.stat().st_mode) == 0o600
    assert set(json.loads(af.read_text())) >= {"token", "pid", "port", "created_at"}
    c = BrowserClient(h.local_url, identity=FAKE_OWNER_LOGIN)
    assert c.get().status_code == 200
    assert c.open().status_code == 200
    r = c.submit({"kind": "api_key", "target_profile": "default", "value": canary})
    t0 = time.monotonic()
    assert r.status_code == 200, r.text
    out = h.wait(timeout=10)
    assert time.monotonic() - t0 < 2.0
    assert h.returncode is not None
    assert out.status == "saved" and out.code is None
    assert out.meta["storage"]["env_var"] == "EXA_API_KEY"
    env = hermes_root / ".env"
    assert env.read_text() == f"OTHER=keep me\nEXA_API_KEY={canary}\n"
    assert stat.S_IMODE(env.stat().st_mode) == 0o600
    assert fake_tailscale.add_calls(token_of(h)) and len(fake_tailscale.off_calls(token_of(h))) >= 2
    assert active_files(hermes_root) == []
    # criterion 6: audit fields present, canary nowhere but .env
    rows = [json.loads(x) for x in (hermes_root / "logs" / "secure-input.jsonl").read_text().splitlines()]
    assert {"created", "opened", "submitted", "saved", "cleanup"} <= {r["event"] for r in rows}
    for row in rows:
        assert set(AUDIT_FIELDS) <= set(row)
    assert scan_for(hermes_root, canary, skip=lambda p: p.name == ".env") == []
    assert canary not in h.stderr_text and canary not in json.dumps(h.events)
    assert token_of(h) not in h.stderr_text
    assert token_of(h) not in (hermes_root / "logs" / "secure-input.jsonl").read_text()


def test_login_roundtrip_adds_vault_item(launch, hermes_root, canary):
    h = launch(kind="login", target_profile="worker")
    c = BrowserClient(h.local_url, identity=FAKE_OWNER_LOGIN)
    c.open()
    r = c.submit({"kind": "login", "target_profile": "worker", "identifier_type": "email",
                  "identifier": "me@example.com", "password": canary, "otp_secret": "JBSWY3DPEHPK3PXP"})
    assert r.status_code == 200, r.text
    out = h.wait(timeout=10)
    assert out.status == "saved" and out.meta["storage"]["has_otp"] is True
    item_id = out.meta["storage"]["item_id"]
    sys.path.insert(0, str(hermes_agent_dir()))
    try:
        from agent.vault_store import VaultStore
        vs = VaultStore(base_dir=hermes_root / "profiles" / "worker" / "vault")
        secret = vs.resolve_secret(item_id)
        assert secret["password"] == canary  # compared, never printed
        assert bool(secret.get("otp_secret")) is True
        assert vs.get_meta(item_id).origin == "https://example.com"
    finally:
        sys.path.remove(str(hermes_agent_dir()))
    assert scan_for(hermes_root, canary, skip=lambda p: p.name == "vault.json.enc") == []
    assert scan_for(hermes_root, "me@example.com",
                    skip=lambda p: p.name == "vault.json.enc") == []  # identifier not in logs
    assert canary not in h.stderr_text


def test_otp_code_delivered_only_to_parent(launch, hermes_root, canary, caplog):
    caplog.set_level(logging.DEBUG)
    h = launch(kind="otp_code")
    c = BrowserClient(h.local_url, identity=FAKE_OWNER_LOGIN)
    c.open()
    assert c.submit({"kind": "otp_code", "code": canary}).status_code == 200
    out = h.wait(timeout=10)
    assert out.status == "delivered" and out.code == canary
    assert canary not in repr(out) and canary not in str(out.meta)
    assert scan_for(hermes_root, canary) == []
    assert canary not in h.stderr_text
    assert canary not in json.dumps(h.events)  # the done line is parsed, code kept only on Outcome
    assert canary not in caplog.text
    assert not (hermes_root / ".env").exists() and not list(hermes_root.rglob("vault"))


# --- criterion 7: cleanup in every ending ----------------------------------------------------

def _assert_cleaned(h, root, ts):
    assert len(ts.off_calls(token_of(h))) >= 1
    assert active_files(root) == []


def test_cleanup_on_expiry(launch, hermes_root, fake_tailscale):
    h = launch(_test_ttls={"open": 1, "submit": 2})
    out = h.wait(timeout=10)
    assert out.status == "expired"
    _assert_cleaned(h, hermes_root, fake_tailscale)


def test_cleanup_on_user_cancel(launch, hermes_root, fake_tailscale):
    h = launch()
    c = BrowserClient(h.local_url, identity=FAKE_OWNER_LOGIN)
    c.open()
    assert c.cancel().status_code == 200
    assert h.wait(timeout=10).status == "cancelled"
    _assert_cleaned(h, hermes_root, fake_tailscale)


def test_cleanup_after_five_failures(launch, hermes_root, fake_tailscale):
    h = launch()
    c = BrowserClient(h.local_url, identity=FAKE_OWNER_LOGIN)
    c.open()
    codes = [c.submit({"kind": "login"}).status_code for _ in range(5)]
    assert codes == [400, 400, 400, 400, 429]
    out = h.wait(timeout=10)
    assert out.status == "failed" and out.meta["reason"] == "too_many_attempts"
    _assert_cleaned(h, hermes_root, fake_tailscale)


def test_cleanup_when_child_sigkilled(launch, hermes_root, fake_tailscale):
    h = launch()
    os.kill(h.pid, signal.SIGKILL)
    out = h.wait(timeout=10)
    assert out.status == "failed" and out.meta["reason"] == "child_exited"
    _assert_cleaned(h, hermes_root, fake_tailscale)
    rows = [json.loads(x) for x in (hermes_root / "logs" / "secure-input.jsonl").read_text().splitlines()]
    assert rows[-1]["event"] == "cleanup" and rows[-1]["detail"]["by"] == "launcher"


def test_cleanup_on_handle_cancel(launch, hermes_root, fake_tailscale):
    h = launch()
    out = h.cancel()
    assert out.status == "cancelled"
    _assert_cleaned(h, hermes_root, fake_tailscale)


PARENT_SCRIPT = r"""
import json, sys, time
sys.path.insert(0, {repo!r})
sys.path.append({agent!r})  # like the gateway: hermes_cli importable (RequestSpec checks env names with it)
from secure_input.launcher import start_request
from secure_input.serve import ServeManager
from secure_input.spec import RequestSpec
spec = RequestSpec.from_dict(json.loads({spec!r}))
h = start_request(spec, static_dir={static!r}, serve=ServeManager(bin={ts!r}))
print(json.dumps({{"pid": h.pid, "url": h.url}}), flush=True)
time.sleep(60)
"""


def test_cleanup_when_parent_killed(spec_dict, static_dir, fake_tailscale, hermes_root):
    script = PARENT_SCRIPT.format(repo=str(REPO_ROOT), spec=json.dumps(spec_dict()), static=str(static_dir),
                                  ts=str(fake_tailscale.bin), agent=str(HERMES_AGENT_DIR))
    parent = subprocess.Popen([sys.executable, "-c", script], stdout=subprocess.PIPE, text=True)
    info = json.loads(parent.stdout.readline())
    assert len(active_files(hermes_root)) == 1
    os.kill(parent.pid, signal.SIGKILL)
    parent.wait()
    token = info["url"].rstrip("/").rsplit("/", 1)[1]
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline and (active_files(hermes_root) or not fake_tailscale.off_calls(token)):
        time.sleep(0.1)
    assert fake_tailscale.off_calls(token)
    assert active_files(hermes_root) == []
    with pytest.raises(ProcessLookupError):
        for _ in range(40):
            os.kill(info["pid"], 0)
            time.sleep(0.05)


# --- limits and sweeping --------------------------------------------------------------------

def test_fourth_active_request_rejected(launch):
    hs = [launch() for _ in range(3)]
    with pytest.raises(TooManyActive):
        launch()
    hs[0].cancel()
    launch().cancel()


def test_sweep_stale_removes_dead_entries(hermes_root, fake_tailscale):
    dead = subprocess.Popen([sys.executable, "-c", "pass"])
    dead.wait()
    d = hermes_root / "profiles" / "worker" / "secure-input" / "active"
    d.mkdir(parents=True)
    tok = new_token()
    (d / "abc.json").write_text(json.dumps({"token": tok, "pid": dead.pid, "port": 1,
                                            "created_at": time.time(), "request_id": "abc"}))
    live = d / "live.json"
    live.write_text(json.dumps({"token": new_token(), "pid": os.getpid(), "port": 2, "created_at": time.time(),
                                "request_id": "live"}))
    n = sweep_stale(str(hermes_root), serve=ServeManager(bin=str(fake_tailscale.bin)))
    assert n == 1 and fake_tailscale.off_calls(tok) and live.exists() and not (d / "abc.json").exists()


# --- criterion 5: no plaintext on the wire ----------------------------------------------------

class RecordingRelay:
    def __init__(self, target_port):
        self.target = target_port
        self.buf = bytearray()
        self.lock = threading.Lock()
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True).start()

    def _pump(self, a, b):
        try:
            while True:
                data = a.recv(65536)
                if not data:
                    break
                with self.lock:
                    self.buf += data
                b.sendall(data)
        except OSError:
            pass
        finally:
            for s in (a, b):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def _accept(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            u = socket.create_connection(("127.0.0.1", self.target))
            threading.Thread(target=self._pump, args=(c, u), daemon=True).start()
            threading.Thread(target=self._pump, args=(u, c), daemon=True).start()


def test_no_plaintext_canary_on_the_wire(launch, canary):
    h = launch()
    relay = RecordingRelay(h.port)
    c = BrowserClient(f"http://127.0.0.1:{relay.port}/{token_of(h)}/", origin=None, identity=FAKE_OWNER_LOGIN)
    assert c.get().status_code == 200
    c.open()
    assert c.submit({"kind": "api_key", "target_profile": "default", "value": canary}).status_code == 200
    assert h.wait(timeout=10).status == "saved"
    relay.sock.close()
    with relay.lock:
        wire = bytes(relay.buf)
    assert b"api/submit" in wire and b"ciphertext" in wire
    assert canary.encode() not in wire


def test_active_file_write_failure_kills_child(spec_dict, static_dir, fake_tailscale, hermes_root, monkeypatch):
    from secure_input import launcher as L
    (hermes_root / "secure-input").mkdir(parents=True, exist_ok=True)
    (hermes_root / "secure-input" / "active").write_text("not a dir")
    procs = []
    real = subprocess.Popen

    def spy(*a, **kw):
        p = real(*a, **kw)
        procs.append(p)
        return p

    monkeypatch.setattr(L.subprocess, "Popen", spy)
    spec = RequestSpec.from_dict(spec_dict())
    with pytest.raises(L.StartError):
        start_request(spec, static_dir=static_dir, serve=ServeManager(bin=str(fake_tailscale.bin)))
    assert procs and all(p.poll() is not None for p in procs)
