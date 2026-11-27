"""Saving a login again for the same site and the same id removes the older item (card t_95bf30b2 section 4).

Everything runs against Hermes' real ``VaultStore`` in a temp profile home.
"""

from __future__ import annotations

import json
import os
import sys
import time

import pytest

from helpers.storage_calls import save_one as run_storage
from secure_input.storage import hermes_agent_dir
from secure_input.stores.base import StoreError as StorageError

ORIGIN = "https://example.com"


@pytest.fixture
def vault_home(hermes_root):
    return hermes_root / "profiles" / "worker"


@pytest.fixture
def vault(vault_home):
    sys.path.insert(0, str(hermes_agent_dir()))
    try:
        from agent.vault_store import VaultStore
        yield VaultStore(base_dir=vault_home / "vault")
    finally:
        sys.path.remove(str(hermes_agent_dir()))


def pw() -> str:
    return "SECRET-CANARY-" + os.urandom(12).hex()


def login(identifier="me@example.com", password=None, origin=ORIGIN, otp="", identifier_type="email"):
    return {"kind": "login", "label": "Example", "origin": origin, "identifier_type": identifier_type,
            "identifier": identifier, "password": password or pw(), "otp_secret": otp}


# --- test 11 ------------------------------------------------------------------------------------

def test_same_site_same_id_twice_leaves_one_item_with_second_password(vault_home, vault):
    first, second = pw(), pw()
    a = run_storage(sys.executable, vault_home, login(password=first))
    b = run_storage(sys.executable, vault_home, login(password=second, identifier=" me@example.com ",
                                                       identifier_type="username"))
    assert a["replaced"] is False and a["removed_count"] == 0 and a["replace_error"] is False
    assert b["replaced"] is True and b["removed_count"] == 1 and b["replace_error"] is False
    items = vault.list_items()
    assert [m.id for m in items] == [b["item_id"]]
    assert vault.resolve_secret(b["item_id"])["password"] == second
    assert first not in json.dumps([a, b]) and second not in json.dumps([a, b])


# --- test 12, 13 ----------------------------------------------------------------------------------

def test_same_site_other_id_is_kept(vault_home, vault):
    run_storage(sys.executable, vault_home, login(identifier="me@example.com"))
    b = run_storage(sys.executable, vault_home, login(identifier="you@example.com"))
    assert b["replaced"] is False and b["removed_count"] == 0
    assert len(vault.list_items()) == 2


def test_id_comparison_is_case_sensitive(vault_home, vault):
    run_storage(sys.executable, vault_home, login(identifier="Me@example.com"))
    run_storage(sys.executable, vault_home, login(identifier="me@example.com"))
    assert len(vault.list_items()) == 2


def test_same_id_other_site_is_kept(vault_home, vault):
    run_storage(sys.executable, vault_home, login(origin="https://example.com"))
    b = run_storage(sys.executable, vault_home, login(origin="https://other.example.com"))
    assert b["replaced"] is False
    assert sorted(m.origin for m in vault.list_items()) == ["https://example.com", "https://other.example.com"]


def test_other_kinds_with_same_origin_are_kept(vault_home, vault):
    vault.add_item(kind="address", label="home", secret={"address_line1": "1", "city": "c", "postal_code": "1",
                                                          "country": "KR"}, origin=ORIGIN)
    b = run_storage(sys.executable, vault_home, login())
    assert b["replaced"] is False and len(vault.list_items()) == 2


# --- test 14 ---------------------------------------------------------------------------------------

def test_failed_new_save_keeps_old_item(vault_home, vault):
    first = pw()
    a = run_storage(sys.executable, vault_home, login(password=first))
    with pytest.raises(StorageError) as ei:
        run_storage(sys.executable, vault_home, login(otp="not base32 !!"))
    assert ei.value.reason == "vault_rejected"
    assert [m.id for m in vault.list_items()] == [a["item_id"]]
    assert vault.resolve_secret(a["item_id"])["password"] == first


# --- test 15 -----------------------------------------------------------------------------------------

@pytest.mark.parametrize("broken", ["remove_item", "list_items"])
def test_failure_while_removing_keeps_both_and_reports_replace_error(vault_home, vault, monkeypatch, broken):
    from agent import vault_store
    from secure_input.stores import hermes_vault as storage

    a = run_storage(sys.executable, vault_home, login())
    real = vault_store.VaultStore

    class Broken(real):
        def __init__(self, base_dir=None):
            super().__init__(base_dir=base_dir or vault_home / "vault")

    def boom(self, *a, **kw):
        raise OSError("disk went away")

    monkeypatch.setattr(Broken, broken, boom)
    monkeypatch.setattr(vault_store, "VaultStore", Broken)
    b = storage.add_login(login())
    assert b["replace_error"] is True and b["replaced"] is False and b["removed_count"] == 0
    assert sorted(m.id for m in vault.list_items()) == sorted([a["item_id"], b["item_id"]])


# --- test 17 -------------------------------------------------------------------------------------------

def _save_through_server(spec_dict, static_dir, plain):
    from starlette.testclient import TestClient

    from helpers.browser_client import BrowserClient
    from helpers.fake_tailscale import FAKE_OWNER_LOGIN
    from secure_input.server import ServerContext, create_app
    from secure_input.spec import RequestSpec

    ctx = ServerContext(RequestSpec.from_dict(spec_dict(kind="login", target_profile="worker")),
                        token="T" + os.urandom(24).hex(), request_id=os.urandom(16).hex(), static_dir=static_dir,
                        public_host="h.example.ts.net", port=1, allowed_logins=[FAKE_OWNER_LOGIN])
    http = TestClient(create_app(ctx), base_url="http://127.0.0.1:1")
    c = BrowserClient(f"http://127.0.0.1:1/{ctx.token}/", client=http, identity=FAKE_OWNER_LOGIN)
    assert c.open().status_code == 200
    r = c.submit(plain)
    assert r.status_code == 200, r.text
    return r.json()


def test_saved_audit_line_has_replaced_and_no_id_or_value(spec_dict, static_dir, hermes_root):
    first, second = pw(), pw()
    plain = {"kind": "login", "target_profile": "worker", "identifier_type": "email",
             "identifier": "me@example.com", "otp_secret": ""}
    r1 = _save_through_server(spec_dict, static_dir, dict(plain, password=first))
    r2 = _save_through_server(spec_dict, static_dir, dict(plain, password=second))
    # The page's answer keeps its shape (the UI is not changed in this card).
    for r in (r1, r2):
        assert set(r["result"]["storage"]) == {"type", "profile", "origin", "env_var", "item_id"}
    log = hermes_root / "profiles" / "worker" / "logs" / "secure-input.jsonl"
    saved = [json.loads(x) for x in log.read_text().splitlines() if json.loads(x)["event"] == "saved"]
    assert [s["detail"]["stores"][0]["replaced"] for s in saved] == [False, True]
    raw = log.read_text()
    assert "me@example.com" not in raw and first not in raw and second not in raw
    assert r1["result"]["storage"]["item_id"] not in raw


def test_tool_result_carries_replaced(hermes_root, static_dir, fake_tailscale):
    from helpers.browser_client import BrowserClient
    from helpers.fake_tailscale import FAKE_OWNER_LOGIN
    from test_identity import make_plugin, run_tool_in_background
    from test_plugin import live_handle

    svc = make_plugin(hermes_root, static_dir, fake_tailscale)
    args = {"kind": "login", "purpose": "관리자 로그인", "label": "admin", "origin": ORIGIN}
    results = []
    for _ in range(2):
        t, box = run_tool_in_background(svc, dict(args))
        h = live_handle(svc)
        c = BrowserClient(h.local_url, identity=FAKE_OWNER_LOGIN)
        assert c.open().status_code == 200
        assert c.submit({"kind": "login", "target_profile": "default", "identifier_type": "email",
                         "identifier": "me@example.com", "password": pw(), "otp_secret": ""}).status_code == 200
        t.join(20)
        results.append(json.loads(box["r"]))
        end = time.monotonic() + 10
        while svc._live and time.monotonic() < end:  # the first request leaves the live table
            time.sleep(0.05)
    assert [r["status"] for r in results] == ["saved", "saved"]
    assert [r["storage"]["replaced"] for r in results] == [False, True]
    assert "me@example.com" not in json.dumps(results)


# --- test 16 -------------------------------------------------------------------------------------------

def test_authenticator_key_of_old_item_is_not_carried_over(vault_home, vault):
    a = run_storage(sys.executable, vault_home, login(otp="JBSWY3DPEHPK3PXP"))
    assert a["has_otp"] is True
    b = run_storage(sys.executable, vault_home, login(otp=""))
    assert b["replaced"] is True and b["has_otp"] is False
    (only,) = vault.list_items()
    assert only.id == b["item_id"] and only.has_otp is False
    assert not vault.resolve_secret(only.id).get("otp_secret")
