"""Integration (plan 7.3 "작업 5", 4.2 of the card): the real ``secure_input.stores.keychain`` module inside the real
storage process, with only ``security`` replaced.

The storage grandchild runs through a python wrapper that binds the real module's ``preflight`` and ``save`` to a
fake ``security`` executable through their ``security_path`` argument (the only way the module allows; no
environment variable or setting can change it). The fake (``test_store_keychain.Fake``) keeps its items in a JSON
state file and logs every call's argv, stdin and environment. The real keychain is never touched here.
"""

from __future__ import annotations

import json
import re
import stat
import sys
from pathlib import Path

import pytest

from helpers.browser_client import BrowserClient
from helpers.fake_tailscale import FAKE_OWNER_LOGIN
from secure_input import storage
from secure_input.notify import SlackNotifier, SlackTarget, TextNotifier
from secure_input.plugin import SecureInput
from secure_input.serve import ServeManager
from secure_input.stores import keychain

from test_plugin import FakeCtx, FakeSlack, live_handle, run_bg
from test_store_keychain import DEFAULT_KC, Fake

SVC = "hermes-secure-input.test-integration"
ACCT = "hermes-secure-input"
RID = "0123456789abcdef0123456789abcdef"
ROW_KEYS = {"saved", "replaced", "error", "service", "account", "listed", "new_item", "tmp_left", "main_touched",
            "main_created"}

BOOT = r"""
import functools, sys
from secure_input.stores import keychain
SEC = {sec!r}
keychain.preflight = functools.partial(keychain.preflight, security_path=SEC)
keychain.save = functools.partial(keychain.save, security_path=SEC)
from secure_input import storage
sys.exit(storage.main())
"""


def real_module_python(folder: Path, security: Path) -> Path:
    """A ``python`` stand-in: the storage grandchild runs the real keychain module bound to ``security``; anything
    else (the server) runs unchanged."""
    folder.mkdir(parents=True, exist_ok=True)
    boot = folder / "boot.py"
    boot.write_text(BOOT.format(sec=str(security)))
    wrapper = folder / "python-wrapper"
    wrapper.write_text("#!/bin/sh\n"
                       "case \"$*\" in\n"
                       f"  *secure_input.storage*) exec '{sys.executable}' -P '{boot}' ;;\n"
                       "esac\n"
                       f"exec '{sys.executable}' \"$@\"\n")
    wrapper.chmod(wrapper.stat().st_mode | stat.S_IXUSR)
    return wrapper


@pytest.fixture
def sec(tmp_path):
    (tmp_path / "security").mkdir()
    return Fake(tmp_path / "security")


@pytest.fixture
def python(tmp_path, sec):
    return real_module_python(tmp_path / "py", sec.path)


def save_req(value, service=SVC, account=ACCT, listed=False, kind="secret", stores=("keychain",)):
    r = {"phase": "save", "kind": kind, "stores": list(stores), "request_id": RID,
         "keychain": {"service": service, "account": account, "listed": listed}, "value": value}
    if "env" in stores:
        r.update(env_var="EXA_API_KEY", masked_check=True)
    return r


def verbs(calls):
    return [c["argv"][0] for c in calls]


def assert_value_never_in_args_or_env(calls, value):
    forms = [value, value.encode().hex(), value.encode().hex().upper()]
    assert calls
    for c in calls:
        joined = "\n".join(c["argv"])
        env = "\n".join(f"{k}={v}" for k, v in c["env"].items())
        for f in forms:
            assert f not in joined and f not in env


# --- storage process + real module ------------------------------------------------------------------------------

def test_new_item_save_makes_three_security_calls_after_a_two_call_check(python, sec, hermes_root, canary):
    out = storage.run_storage(str(python), hermes_root, save_req(canary))
    assert out["done"] == {"event": "done", "ok": True}
    calls = sec.calls()
    assert verbs(calls) == ["default-keychain", "find-generic-password",           # preflight
                            "find-generic-password", "-i", "find-generic-password"]  # save: 3 calls
    assert calls[3]["argv"] == ["-i"]
    assert sec.value_of(SVC, ACCT) == canary
    row = out["stores"]["keychain"]
    assert set(row) == ROW_KEYS
    assert row == {"saved": True, "replaced": False, "error": None, "service": SVC, "account": ACCT, "listed": False,
                   "new_item": True, "tmp_left": False, "main_touched": False,
                   "main_created": True}


def test_existing_item_save_makes_seven_security_calls_with_the_preflight_keychain_path(
        python, sec, hermes_root, canary):
    sec.add_item(SVC, ACCT, "old-fake-value")
    out = storage.run_storage(str(python), hermes_root, save_req(canary))
    calls = sec.calls()
    assert verbs(calls[:3]) == ["default-keychain", "find-generic-password", "dump-keychain"]  # preflight
    save_calls = calls[3:]
    assert verbs(save_calls) == ["find-generic-password", "dump-keychain", "-i", "find-generic-password", "-i",
                                 "find-generic-password", "delete-generic-password"]
    # (나) needs the default keychain path the same process' preflight saw with the same security_path
    assert save_calls[1]["argv"] == ["dump-keychain", "-a", DEFAULT_KC]
    # the temp item is named from the first 12 characters of request_id
    tmp = keychain.TMP_PREFIX + RID[:12]
    assert f'-s "{tmp}"' in save_calls[2]["stdin"]
    assert save_calls[6]["argv"][save_calls[6]["argv"].index("-s") + 1] == tmp
    assert sec.value_of(SVC, ACCT) == canary and sec.value_of(tmp, ACCT) is None
    row = out["stores"]["keychain"]
    assert set(row) == ROW_KEYS
    assert row == {"saved": True, "replaced": True, "error": None, "service": SVC, "account": ACCT, "listed": False,
                   "new_item": False, "tmp_left": False, "main_touched": True,
                   "main_created": False}


@pytest.mark.parametrize("existing", [False, True])
def test_value_and_its_hex_never_reach_security_arguments_or_environment(python, sec, hermes_root, canary,
                                                                         existing):
    if existing:
        sec.add_item(SVC, ACCT, "old-fake-value")
    out = storage.run_storage(str(python), hermes_root, save_req(canary))
    assert out["stores"]["keychain"]["saved"] is True
    calls = sec.calls()
    assert_value_never_in_args_or_env(calls, canary)
    assert any(canary.encode().hex() in c["stdin"] for c in calls if c["argv"] == ["-i"])


def test_existing_item_without_security_in_acl_is_denied_before_any_write(python, sec, hermes_root, canary):
    sec.add_item(SVC, ACCT, "old-fake-value", apps=("/bin/cat",))
    out = storage.run_storage(str(python), hermes_root, save_req(canary))
    assert out["preflight"]["keychain"] == {"available": False, "reason": "keychain_acl_denied", "exists": True}
    assert out["stores"] == {}
    assert out["done"]["ok"] is False and out["done"]["error"] == "store_unavailable"
    assert out["returncode"] == 2
    assert "-i" not in verbs(sec.calls())
    assert sec.value_of(SVC, ACCT) == "old-fake-value"
    outcome = storage.save_outcome(["keychain"], out)
    assert outcome["category"] == "unavailable" and outcome["wrote"] is False
    assert outcome["unavailable"] == [{"store": "keychain", "reason": "keychain_acl_denied"}]


def test_api_key_in_env_and_keychain_with_the_real_module(python, sec, hermes_root, canary):
    out = storage.run_storage(str(python), hermes_root, save_req(canary, kind="api_key", stores=("env", "keychain")))
    assert out["stores"]["env"]["saved"] is True and out["stores"]["keychain"]["saved"] is True
    assert f"EXA_API_KEY={canary}" in (hermes_root / ".env").read_text()
    assert sec.value_of(SVC, ACCT) == canary


def test_storage_calls_preflight_then_save_on_the_same_module_object():
    """A.9 item 3: the write phase runs only after every store's check passed, in the same process."""
    src = Path(storage.__file__).read_text()
    run = src[src.index("def _run("):src.index("def main(")]
    assert run.index("_preflight_line(modules[s]") < run.index("if not usable:") < run.index("modules[s].save(")


# --- real server + storage process + real module ----------------------------------------------------------------

def settings_with(items):
    return lambda key, default: items if key == "keychain_items" else default


@pytest.fixture
def svc(hermes_root, static_dir, fake_tailscale, python, monkeypatch):
    monkeypatch.setenv("HERMES_SESSION_PLATFORM", "slack")
    monkeypatch.setenv("HERMES_SESSION_KEY", "agent:main:slack:thread:C1:1795.1")
    monkeypatch.setenv("HERMES_SESSION_USER_ID", "U123")
    ctx = FakeCtx("default")
    fake = FakeSlack()
    s = SecureInput(ctx, notifier_factory=lambda c: SlackNotifier(SlackTarget("C1", "1795.1", fake),
                                                                  TextNotifier(c.post_message)),
                    hermes_root=lambda: str(hermes_root), settings=settings_with([]),
                    start_kwargs={"static_dir": static_dir, "python": str(python),
                                  "serve": ServeManager(bin=str(fake_tailscale.bin))})
    yield s
    s.cancel_all()


SECRET = {"kind": "secret", "purpose": "통합 시험", "label": "시험 비밀값", "keychain_item": "test-integration"}


@pytest.mark.parametrize("existing", [False, True])
def test_server_open_says_keychain_available_and_saves_through_the_real_module(svc, sec, canary, existing):
    if existing:
        sec.add_item(SVC, ACCT, "old-fake-value")
    t, box = run_bg(svc.tool_request, dict(SECRET))
    h = live_handle(svc)
    assert re.fullmatch(r"[0-9a-f]{32}", h.request_id)  # uuid4().hex from the launcher
    c = BrowserClient(h.local_url, identity=FAKE_OWNER_LOGIN, timeout=60.0)
    r = c.open()
    assert r.status_code == 200, r.text
    (row,) = r.json()["target"]["stores"]
    assert row["store"] == "keychain"
    assert row["available"] is True and row["unavailable_reason"] is None
    assert row["exists"] is existing
    sec.reset_log()
    r = c.submit({"kind": "secret", "target_profile": "default", "value": canary})
    assert r.status_code == 200, r.text
    t.join(60)
    res = json.loads(box["r"])
    assert res["status"] == "saved", res
    calls = sec.calls()
    if existing:
        # submit-time check (3 calls) then the 7-call replace; the temp item uses request_id[:12]
        assert len(calls) == 3 + 7
        tmp = keychain.TMP_PREFIX + h.request_id[:12]
        assert any(f'-s "{tmp}"' in x["stdin"] for x in calls if x["argv"] == ["-i"])
    else:
        assert len(calls) == 2 + 3
    assert_value_never_in_args_or_env(calls, canary)
    assert sec.value_of(SVC, ACCT) == canary
    assert not [k for k in sec.items() if k.startswith(keychain.TMP_PREFIX)]
