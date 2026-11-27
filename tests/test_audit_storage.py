import hashlib
import json
import os
import stat
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import pytest

from secure_input.audit import AUDIT_FIELDS, AuditLog
from secure_input.spec import RequestSpec
from helpers.storage_calls import save_one
from secure_input.storage import hermes_agent_dir
from secure_input.stores.base import StoreError
from secure_input.stores.env import write_env

TOKEN = "tok_" + "A" * 40


def _lines(p: Path) -> list[dict]:
    return [json.loads(x) for x in p.read_text().splitlines()]


def mode(p: Path) -> int:
    return stat.S_IMODE(p.stat().st_mode)


# --- audit ---------------------------------------------------------------------

def test_audit_line_has_all_fields_and_0600(spec_dict, hermes_root):
    spec = RequestSpec.from_dict(spec_dict())
    log = AuditLog(spec, TOKEN, "rid1")
    log.write("created")
    log.write("failed", detail={"error_code": "decrypt_failed"})
    p = hermes_root / "logs" / "secure-input.jsonl"
    rows = _lines(p)
    assert mode(p) == 0o600
    assert [r["event"] for r in rows] == ["created", "failed"]
    for r in rows:
        assert set(AUDIT_FIELDS) <= set(r)
        assert datetime.fromisoformat(r["ts"]).tzinfo is not None
        assert r["path_fp"] == hashlib.sha256(TOKEN.encode()).hexdigest()[:8]
        assert r["requester"] == spec.requester
        assert r["storage"] == {"type": "env", "env_var": "EXA_API_KEY"}
    assert rows[1]["detail"] == {"error_code": "decrypt_failed"}
    assert TOKEN not in p.read_text()


def test_audit_storage_shape_per_kind(spec_dict, hermes_root):
    for kind, expect in (("login", {"type": "vault", "origin": "https://example.com"}),
                         ("otp_code", {"type": "browser_page", "site": "example.com"})):
        spec = RequestSpec.from_dict(spec_dict(kind=kind))
        AuditLog(spec, TOKEN, "r-" + kind).write("created")
    rows = _lines(hermes_root / "logs" / "secure-input.jsonl")
    assert [r["storage"] for r in rows] == [{"type": "vault", "origin": "https://example.com"},
                                            {"type": "browser_page", "site": "example.com"}]


def test_audit_changed_profile_written_to_both(spec_dict, hermes_root):
    spec = RequestSpec.from_dict(spec_dict())
    AuditLog(spec, TOKEN, "rid").write("saved", profile="worker")
    a = _lines(hermes_root / "logs" / "secure-input.jsonl")
    b = _lines(hermes_root / "profiles" / "worker" / "logs" / "secure-input.jsonl")
    assert a == b and a[0]["target_profile"] == "worker"
    assert a[0]["detail"]["requested_profile"] == "default"


# --- .env ------------------------------------------------------------------------

def test_write_env_creates_0600(tmp_path, canary, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))  # write_env only writes where Hermes points
    write_env(tmp_path, "EXA_API_KEY", canary)
    p = tmp_path / ".env"
    assert p.read_text() == f"EXA_API_KEY={canary}\n" and mode(p) == 0o600


def test_write_env_replaces_and_keeps_other_lines(tmp_path, canary, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    p = tmp_path / ".env"
    p.write_text("# comment\nA=1\nEXA_API_KEY=old\nB=two words\nEXA_API_KEY=dup\nC=3")
    os.chmod(p, 0o644)
    write_env(tmp_path, "EXA_API_KEY", canary)
    # Two lines defined the variable: Hermes' remove_env_value drops both, save_env_value appends one.
    assert p.read_text() == f"# comment\nA=1\nB=two words\nC=3\nEXA_API_KEY={canary}\n"
    assert mode(p) == 0o600
    assert not [x.name for x in tmp_path.iterdir() if x.name.startswith((".env_", ".env.secure-input"))]


@pytest.mark.parametrize("bad", ["a\nb", "a\rb", "a\x00b", ""])
def test_write_env_rejects_bad_values(tmp_path, bad):
    with pytest.raises(StoreError) as ei:
        write_env(tmp_path, "X", bad)
    assert bad not in str(ei.value) or bad == ""
    assert not (tmp_path / ".env").exists()


# --- storage subprocess ---------------------------------------------------------------

def test_storage_subprocess_api_key(hermes_root, canary):
    (hermes_root / ".env").write_text("KEEP=1\n")
    out = save_one(sys.executable, hermes_root,
                   {"kind": "api_key", "env_var": "EXA_API_KEY", "value": canary})
    assert out["saved"] is True and out["env_var"] == "EXA_API_KEY" and out["replaced"] is False
    assert (hermes_root / ".env").read_text() == f"KEEP=1\nEXA_API_KEY={canary}\n"


def test_storage_subprocess_login_adds_new_vault_item(hermes_root, canary):
    target = hermes_root / "profiles" / "worker"
    req = {"kind": "login", "label": "Example", "origin": "https://example.com",
           "identifier_type": "email", "identifier": "me@example.com", "password": canary,
           "otp_secret": "JBSWY3DPEHPK3PXP"}
    a = save_one(sys.executable, target, req)
    # A different id: the same id would replace item a (tests/test_login_replace.py).
    b = save_one(sys.executable, target, dict(req, otp_secret="", identifier="you@example.com"))
    assert a["saved"] is True and a["origin"] == "https://example.com" and a["has_otp"] is True
    assert b["has_otp"] is False and a["item_id"] != b["item_id"]
    assert canary not in json.dumps([a, b])

    sys.path.insert(0, str(hermes_agent_dir()))
    try:
        from agent.vault_store import VaultStore
        vs = VaultStore(base_dir=target / "vault")
        ids = [m.id for m in vs.list_items()]
        assert ids == [a["item_id"], b["item_id"]]
        assert vs.resolve_secret(a["item_id"])["password"] == canary
        assert bool(vs.resolve_secret(a["item_id"]).get("otp_secret")) is True
        assert bool(vs.resolve_secret(b["item_id"]).get("otp_secret")) is False
    finally:
        sys.path.remove(str(hermes_agent_dir()))
    assert not (hermes_root / "vault").exists()  # only the target profile got a vault


def test_storage_failure_message_has_no_value(hermes_root, canary):
    with pytest.raises(StoreError) as ei:
        save_one(sys.executable, hermes_root,
                 {"kind": "login", "label": "x", "origin": "https://example.com",
                     "identifier_type": "email", "identifier": "me@example.com", "password": canary,
                     "otp_secret": "not base32 " + canary})
    assert canary not in str(ei.value) and str(len(canary)) not in str(ei.value)


def test_storage_value_never_in_argv_or_env(hermes_root, canary, monkeypatch):
    seen = {}
    real = subprocess.Popen

    def spy(args, **kw):
        seen["args"], seen["env"] = args, kw.get("env")
        return real(args, **kw)

    monkeypatch.setattr("secure_input.storage.subprocess.Popen", spy)
    save_one(sys.executable, hermes_root, {"kind": "api_key", "env_var": "K", "value": canary})
    assert canary not in json.dumps(seen["args"]) and canary not in json.dumps(seen["env"])
    assert seen["env"]["HERMES_HOME"] == str(hermes_root)


def test_storage_ignores_modules_planted_in_profile_home(hermes_root, canary):
    # python -m puts cwd on sys.path[0]; a json.py in the profile home must not run.
    (hermes_root / "json.py").write_text("raise SystemExit(99)\n")
    (hermes_root / "tempfile.py").write_text("raise SystemExit(99)\n")
    out = save_one(sys.executable, hermes_root, {"kind": "api_key", "env_var": "K", "value": canary})
    assert out["saved"] is True and out["env_var"] == "K"
