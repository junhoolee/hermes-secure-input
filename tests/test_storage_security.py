"""The .env writer after the security fix (S-1, S-2, S-3) and the server's value check (S-2).

Every write happens in a temp HERMES_HOME (card item 10); the conftest guard also fails the run if
anything touches the real ~/.hermes.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

from conftest import HERMES_AGENT_DIR, REPO_ROOT
from helpers.browser_client import BrowserClient
from helpers.fake_tailscale import FAKE_OWNER_LOGIN
from secure_input.server import PayloadError, ServerContext
from secure_input.spec import RequestSpec
from secure_input.stores.base import StoreError as StorageError
from secure_input.stores.env import write_env
from test_validation import LINE_BREAKERS, REFUSED_NAMES


def mode(p: Path) -> int:
    return stat.S_IMODE(p.stat().st_mode)


def core_read(home: Path) -> dict:
    """Read .env exactly the way Hermes does (agent.secret_scope.load_env_file)."""
    from agent.secret_scope import invalidate_env_file_cache, load_env_file

    invalidate_env_file_cache()
    return load_env_file(home / ".env")


def tree(root: Path) -> dict:
    return {str(p.relative_to(root)): (p.read_bytes() if p.is_file() else None) for p in sorted(root.rglob("*"))}


@pytest.fixture
def home(tmp_path, monkeypatch) -> Path:
    h = tmp_path / "profile-home"
    h.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(h))
    return h


# --- item 1: refused names -----------------------------------------------------------------------------

@pytest.mark.parametrize("name", REFUSED_NAMES)
def test_write_env_refuses_denied_name_and_touches_nothing(home, canary, name):
    (home / ".env").write_text("KEEP=1\n")
    before = tree(home)
    with pytest.raises(StorageError) as exc:
        write_env(home, name, canary)
    assert exc.value.reason == "invalid_env_var"
    assert tree(home) == before


def test_write_env_refused_name_creates_no_file(home, canary):
    with pytest.raises(StorageError):
        write_env(home, "HERMES_YOLO_MODE", canary)
    assert not (home / ".env").exists()


def test_write_env_accepts_ordinary_name(home, canary):
    assert write_env(home, "EXA_API_KEY", canary) == {"type": "env", "env_var": "EXA_API_KEY"}
    assert core_read(home)["EXA_API_KEY"] == canary


# --- item 2: line breakers, control characters, non-ASCII ------------------------------------------------

@pytest.mark.parametrize("ch", LINE_BREAKERS)
def test_write_env_refuses_line_breakers(home, ch):
    (home / ".env").write_text("KEEP=1\n")
    before = tree(home)
    with pytest.raises(StorageError) as exc:
        write_env(home, "EXA_API_KEY", f"앞{ch}INJECTED_VAR=x")
    assert exc.value.reason == "invalid_value"
    assert tree(home) == before


def test_write_env_refuses_non_ascii_value(home, canary):
    with pytest.raises(StorageError) as exc:
        write_env(home, "EXA_API_KEY", canary + "한글")
    assert exc.value.reason == "invalid_value"
    assert not (home / ".env").exists()


def test_core_writer_reader_does_not_split_on_u2028(home):
    # Hermes' writer reads lines with readlines(); U+2028 must not start a new line there.
    from hermes_cli.config import _read_env_lines

    (home / ".env").write_text("A=x\u2028INJECTED_VAR=y\nB=2\n", encoding="utf-8")
    assert len(_read_env_lines(home / ".env")) == 2


# --- item 4: quoting follows the Hermes rule -------------------------------------------------------------

@pytest.mark.parametrize("shape", ["{c} #not-a-comment", '"{c}', "  {c}  "])
def test_write_env_values_read_back_identically(home, canary, shape):
    value = shape.format(c=canary)
    write_env(home, "EXA_API_KEY", value)
    assert core_read(home)["EXA_API_KEY"] == value


# --- item 5: the Hermes .env lock ------------------------------------------------------------------------

LOCK_HOLDER = r"""
import os, sys, time
sys.path.insert(0, {agent!r})
os.environ["HERMES_HOME"] = {home!r}
from hermes_cli.config import _env_write_lock, get_env_path, save_env_value
with _env_write_lock(get_env_path()):
    print("locked", flush=True)
    time.sleep(1.5)
    save_env_value("CORE_KEY", {core!r})
print("released", flush=True)
"""


def test_write_env_waits_for_hermes_lock_and_keeps_both_lines(home, canary):
    (home / ".env").write_text("KEEP=1\n")
    core_value = "SECRET-CANARY-core-" + os.urandom(4).hex()
    holder = subprocess.Popen([sys.executable, "-c", LOCK_HOLDER.format(agent=str(HERMES_AGENT_DIR), home=str(home),
                                                                         core=core_value)],
                              stdout=subprocess.PIPE, text=True)
    try:
        assert holder.stdout.readline().strip() == "locked"
        started = time.monotonic()
        write_env(home, "EXA_API_KEY", canary)
        waited = time.monotonic() - started
    finally:
        holder.wait(20)
    assert waited >= 1.0
    got = core_read(home)
    assert got["KEEP"] == "1" and got["CORE_KEY"] == core_value and got["EXA_API_KEY"] == canary


# --- item 6: other lines kept, one line per variable, mode 0600 ------------------------------------------

def test_write_env_keeps_other_lines_and_leaves_one_line(home, canary):
    p = home / ".env"
    p.write_text("# comment\nA=1\nexport EXA_API_KEY=old\nexport B=two\nEXA_API_KEY=dup\nC=3\n")
    os.chmod(p, 0o644)
    write_env(home, "EXA_API_KEY", canary)
    lines = p.read_text().splitlines()
    assert [ln for ln in lines if "EXA_API_KEY" in ln] == [f"EXA_API_KEY={canary}"]
    for kept in ("# comment", "A=1", "export B=two", "C=3"):
        assert kept in lines
    assert core_read(home)["EXA_API_KEY"] == canary
    assert mode(p) == 0o600


def test_write_env_replaces_in_place_when_defined_once(home, canary):
    p = home / ".env"
    p.write_text("A=1\nexport EXA_API_KEY=old\nC=3\n")
    write_env(home, "EXA_API_KEY", canary)
    assert p.read_text() == f"A=1\nEXA_API_KEY={canary}\nC=3\n"


# --- item 7: home must be the folder Hermes computes ------------------------------------------------------

def test_write_env_bad_home_changes_no_file(home, tmp_path, canary):
    other = tmp_path / "other-home"
    other.mkdir()
    (other / ".env").write_text("KEEP=1\n")
    (home / ".env").write_text("KEEP=2\n")
    before = (tree(home), tree(other))
    with pytest.raises(StorageError) as exc:
        write_env(other, "EXA_API_KEY", canary)
    assert exc.value.reason == "bad_home"
    assert (tree(home), tree(other)) == before


# --- storage grandchild: one JSON line on stdout -----------------------------------------------------------

def test_storage_grandchild_prints_only_json_lines_without_the_value(hermes_root, canary):
    from secure_input.storage import PLUGIN_ROOT, hermes_agent_dir

    env = dict(os.environ, HERMES_HOME=str(hermes_root),
               PYTHONPATH=os.pathsep.join([str(PLUGIN_ROOT), str(hermes_agent_dir())]))
    proc = subprocess.run([sys.executable, "-P", "-m", "secure_input.storage"], cwd=str(PLUGIN_ROOT), env=env,
                          input=json.dumps({"phase": "save", "kind": "api_key", "stores": ["env"],
                                            "request_id": "0" * 32, "env_var": "EXA_API_KEY", "value": canary,
                                            "masked_check": True}).encode(),
                          capture_output=True, timeout=60)
    out = proc.stdout.decode()
    assert [json.loads(x) for x in out.splitlines()] == [
        {"event": "preflight", "store": "env", "available": True, "reason": None, "exists": False},
        {"event": "store", "store": "env", "saved": True, "replaced": False, "error": None, "env_var": "EXA_API_KEY"},
        {"event": "done", "ok": True}]
    assert canary not in out and canary not in proc.stderr.decode()


# --- server value check (S-2) ------------------------------------------------------------------------------

def server_ctx(spec_dict, static_dir, **over):
    return ServerContext(RequestSpec.from_dict(spec_dict(**over)), token="T" + os.urandom(24).hex(),
                         request_id=os.urandom(16).hex(), static_dir=static_dir, public_host="h.example.ts.net",
                         port=1)


@pytest.mark.parametrize("ch", LINE_BREAKERS + ["\t", "\x1b"])
def test_validate_plain_refuses_line_breakers_in_api_key(spec_dict, static_dir, ch):
    ctx = server_ctx(spec_dict, static_dir)
    raw = json.dumps({"kind": "api_key", "target_profile": "default", "value": f"앞{ch}INJECTED_VAR=x"}).encode()
    with pytest.raises(PayloadError):
        ctx.validate_plain(raw)


def test_validate_plain_refuses_non_ascii_api_key(spec_dict, static_dir, canary):
    ctx = server_ctx(spec_dict, static_dir)
    with pytest.raises(PayloadError):
        ctx.validate_plain(json.dumps({"kind": "api_key", "target_profile": "default",
                                       "value": canary + "키"}).encode())


@pytest.mark.parametrize("field_name", ["identifier", "password", "otp_secret"])
def test_validate_plain_refuses_line_breakers_in_login_fields(spec_dict, static_dir, canary, field_name):
    ctx = server_ctx(spec_dict, static_dir, kind="login")
    data = {"kind": "login", "target_profile": "default", "identifier_type": "email",
            "identifier": "u@example.com", "password": canary, "otp_secret": ""}
    data[field_name] = canary + "\u2028X=y"
    with pytest.raises(PayloadError):
        ctx.validate_plain(json.dumps(data).encode())


def test_validate_plain_still_accepts_empty_otp_secret_and_non_ascii_password(spec_dict, static_dir, canary):
    ctx = server_ctx(spec_dict, static_dir, kind="login")
    out = ctx.validate_plain(json.dumps({"kind": "login", "target_profile": "default", "identifier_type": "email",
                                         "identifier": "u@example.com", "password": canary + "비번",
                                         "otp_secret": "", "stores": ["hermes_vault"]}).encode())
    assert out["otp_secret"] == "" and out["password"] == canary + "비번"


def test_validate_plain_accepts_ordinary_api_key(spec_dict, static_dir, canary):
    ctx = server_ctx(spec_dict, static_dir)
    out = ctx.validate_plain(json.dumps({"kind": "api_key", "target_profile": "default", "value": canary,
                                         "stores": ["env"]}).encode())
    assert out["value"] == canary


# --- item 3: through a real server process ------------------------------------------------------------------

def test_u2028_submit_through_real_server_is_refused_and_env_unchanged(hermes_root, static_dir, fake_tailscale,
                                                                       spec_dict, canary):
    from secure_input.launcher import start_request
    from secure_input.serve import ServeManager

    (hermes_root / ".env").write_text("KEEP=1\n")
    before = (hermes_root / ".env").read_bytes()
    h = start_request(RequestSpec.from_dict(spec_dict()), static_dir=static_dir,
                      serve=ServeManager(bin=str(fake_tailscale.bin)))
    try:
        c = BrowserClient(h.local_url, identity=FAKE_OWNER_LOGIN)
        assert c.open().status_code == 200
        r = c.submit({"kind": "api_key", "target_profile": "default", "value": canary + "\u2028INJECTED_VAR=x"})
        assert r.status_code != 200
        assert r.json()["error_code"] == "invalid_payload"
    finally:
        h.cancel()
    assert (hermes_root / ".env").read_bytes() == before
    assert "INJECTED_VAR" not in (hermes_root / ".env").read_text()
