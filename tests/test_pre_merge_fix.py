"""Fixes found by the second security review before merge (docs/security-review-2.md T-1, T-2, T-3).

T-1: a failed ``.env`` save must leave the file byte-for-byte as it was (also with two lines of the same
variable). Masked-looking values (``***``, ``sk-abc...wxyz``) are refused before the file is touched,
with the reason ``masked_value``.
T-2: two overlapping saves of the same site and id leave exactly one login (the later ``(created_at, id)``).
T-3: names and other identifiers with a trailing line break are refused (``re.fullmatch``).

All writes happen in a temp HERMES_HOME; the conftest guard fails the run if the real ~/.hermes is touched.
"""

from __future__ import annotations

import json
import os
import shlex
import stat
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from secure_input import storage
from helpers.storage_calls import save_one
from secure_input.stores import hermes_vault
from secure_input.stores.base import StoreError as StorageError
from secure_input.stores.env import write_env

MASKS = {"three_stars": "***", "ellipsis_mask": "sk-abc...wxyz", "redacted_word": "[REDACTED]",
         "canary_shaped_mask": "SECR...9f3a"}
CRED_NAMES = ("REVIEW_DUP_API_KEY", "REVIEW_DUP_TOKEN")


def mode(p: Path) -> int:
    return stat.S_IMODE(p.stat().st_mode)


@pytest.fixture
def home(tmp_path, monkeypatch) -> Path:
    h = tmp_path / "profile-home"
    h.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(h))
    return h


def two_lines(home: Path, name: str, canary: str) -> Path:
    p = home / ".env"
    p.write_text(f"{name}={canary}-old1\nKEEP_ME=original\n{name}={canary}-old2\n")
    os.chmod(p, 0o600)
    return p


def no_precheck(monkeypatch):
    """Turn the masked-value pre-check off, as when Hermes' function cannot be imported."""
    monkeypatch.setattr(storage, "_masked_value_check", lambda: None)


# --- T-1 / masked value: refused before the file is touched -------------------------------------------------

@pytest.mark.parametrize("name", CRED_NAMES)
@pytest.mark.parametrize("mask", list(MASKS))
def test_masked_value_is_refused_by_the_check_the_storage_process_runs_first(home, canary, name, mask):
    """v2: the env module no longer runs the masked check; the server (or the storage process before any
    store, plan 5.2) calls Hermes' check, which refuses every mask here. The file is not touched."""
    p = two_lines(home, name, canary)
    before = p.read_bytes()
    with pytest.raises(ValueError):
        storage._masked_value_check()(name, MASKS[mask])
    assert p.read_bytes() == before and mode(p) == 0o600


@pytest.mark.parametrize("name", CRED_NAMES)
@pytest.mark.parametrize("mask", list(MASKS))
def test_masked_value_without_precheck_is_rolled_back(home, canary, monkeypatch, name, mask):
    """Hermes' own save_env_value refuses the mask after the duplicate lines were removed: roll back."""
    no_precheck(monkeypatch)
    p = two_lines(home, name, canary)
    before = p.read_bytes()
    with pytest.raises(StorageError) as exc:
        write_env(home, name, MASKS[mask])
    assert exc.value.reason == "env_write_failed"
    assert p.read_bytes() == before and mode(p) == 0o600


def test_masked_value_check_is_importable_from_hermes():
    assert storage._masked_value_check() is not None


def test_ordinary_value_passes_precheck_and_saves(home, canary):
    p = two_lines(home, "REVIEW_DUP_API_KEY", canary)
    write_env(home, "REVIEW_DUP_API_KEY", canary + "-new")
    lines = p.read_text().splitlines()
    assert [ln for ln in lines if ln.startswith("REVIEW_DUP_API_KEY=")] == [f"REVIEW_DUP_API_KEY={canary}-new"]
    assert "KEEP_ME=original" in lines and mode(p) == 0o600


def test_save_raises_after_removal_file_is_restored(home, canary, monkeypatch):
    from hermes_cli import config as core

    no_precheck(monkeypatch)
    p = two_lines(home, "REVIEW_DUP_API_KEY", canary)
    before = p.read_bytes()

    def boom(*a, **k):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(core, "save_env_value", boom)
    with pytest.raises(StorageError) as exc:
        write_env(home, "REVIEW_DUP_API_KEY", canary + "-new")
    assert exc.value.reason == "env_write_failed"
    assert p.read_bytes() == before and mode(p) == 0o600
    assert canary not in str(exc.value)


def test_save_returns_silently_after_removal_file_is_restored(home, canary, monkeypatch):
    """Hermes' save_env_value refuses some writes by returning (``_env_write_blocked``)."""
    from hermes_cli import config as core

    no_precheck(monkeypatch)
    p = two_lines(home, "REVIEW_DUP_API_KEY", canary)
    before = p.read_bytes()
    monkeypatch.setattr(core, "save_env_value", lambda *a, **k: None)
    with pytest.raises(StorageError) as exc:
        write_env(home, "REVIEW_DUP_API_KEY", canary + "-new")
    assert exc.value.reason == "verify_failed"
    assert p.read_bytes() == before and mode(p) == 0o600


@pytest.mark.parametrize("raw", [
    "\ufeffREVIEW_DUP_API_KEY={c}-a\r\nKEEP_ME=original\r\n  REVIEW_DUP_API_KEY={c}-b   \r\nLAST=1",
    "REVIEW_DUP_API_KEY={c}-a\nKEEP_ME=original   \n\tREVIEW_DUP_API_KEY={c}-b",
])
def test_failed_save_keeps_bom_crlf_no_final_newline_and_mode_0644(home, canary, monkeypatch, raw):
    from hermes_cli import config as core

    no_precheck(monkeypatch)
    p = home / ".env"
    p.write_bytes(raw.format(c=canary).encode("utf-8"))
    os.chmod(p, 0o644)
    before = p.read_bytes()
    monkeypatch.setattr(core, "save_env_value", lambda *a, **k: None)
    with pytest.raises(StorageError):
        write_env(home, "REVIEW_DUP_API_KEY", canary + "-new")
    assert p.read_bytes() == before and mode(p) == 0o644
    assert sorted(x.name for x in home.iterdir()) == [".env", ".env.lock"]  # no restore temp file left


def test_failed_save_on_missing_file_creates_no_file(home, canary, monkeypatch):
    from hermes_cli import config as core

    no_precheck(monkeypatch)
    real_save = core.save_env_value

    def writes_wrong_value(name, value):
        real_save(name, value + "-wrong")

    monkeypatch.setattr(core, "save_env_value", writes_wrong_value)
    with pytest.raises(StorageError) as exc:
        write_env(home, "REVIEW_DUP_API_KEY", canary)
    assert exc.value.reason == "verify_failed"
    assert not (home / ".env").exists()


def test_masked_value_on_missing_file_creates_no_file(home):
    with pytest.raises(StorageError) as exc:
        write_env(home, "REVIEW_DUP_API_KEY", "***")
    assert exc.value.reason in ("env_write_failed", "verify_failed")  # Hermes' writer refuses; nothing is left
    assert not (home / ".env").exists()


def test_failed_save_on_one_line_file_is_unchanged(home, canary, monkeypatch):
    from hermes_cli import config as core

    no_precheck(monkeypatch)
    p = home / ".env"
    p.write_text(f"A=1\nREVIEW_DUP_API_KEY={canary}-old\nKEEP_ME=original\n")
    before = p.read_bytes()
    monkeypatch.setattr(core, "save_env_value", lambda *a, **k: None)
    with pytest.raises(StorageError):
        write_env(home, "REVIEW_DUP_API_KEY", canary + "-new")
    assert p.read_bytes() == before


def test_masked_value_through_storage_process_prints_no_value(hermes_root, canary):
    """Through the real grandchild: reason masked_value, file unchanged, nothing of the value in the answer."""
    p = two_lines(hermes_root, "REVIEW_DUP_API_KEY", canary)
    before = p.read_bytes()
    with pytest.raises(StorageError) as exc:
        save_one(sys.executable, hermes_root,
                 {"kind": "api_key", "env_var": "REVIEW_DUP_API_KEY", "value": "sk-abc...wxyz"})
    assert exc.value.reason == "masked_value"
    assert p.read_bytes() == before


# --- masked value: server answer ------------------------------------------------------------------------------

MASKED_MESSAGE = "가려진 값처럼 보여 저장하지 않았습니다. 원래 키 전체를 붙여 넣어 주세요."


def test_server_masked_value_is_422_with_message_and_env_unchanged(hermes_root, spec_dict, static_dir, canary):
    from secure_input.spec import RequestSpec
    from test_server_app import Harness

    p = hermes_root / ".env"
    p.write_text(f"EXA_API_KEY={canary}-old\nKEEP_ME=original\nEXA_API_KEY={canary}-dup\n")
    before = p.read_bytes()
    h = Harness(RequestSpec.from_dict(spec_dict()), static_dir)
    h.client.open()
    r = h.client.submit({"kind": "api_key", "target_profile": "default", "value": "sk-abc...wxyz"})
    assert r.status_code == 422
    assert r.json() == {"ok": False, "error_code": "masked_value", "message": MASKED_MESSAGE}
    assert "sk-abc" not in r.text and "wxyz" not in r.text
    assert p.read_bytes() == before
    rows = [json.loads(x) for x in (hermes_root / "logs" / "secure-input.jsonl").read_text().splitlines()]
    failed = [x for x in rows if x["event"] == "failed"]
    assert failed and failed[-1]["detail"] == {"error_code": "masked_value", "attempt": 1, "final": False}
    assert "sk-abc" not in json.dumps(rows)
    # the form stays usable: a real key is accepted on the next submit
    r2 = h.client.submit({"kind": "api_key", "target_profile": "default", "value": canary + "-new"})
    assert r2.status_code == 200, r2.text


def test_server_masked_value_counts_toward_the_five_failures(spec_dict, static_dir, canary):
    from secure_input.spec import RequestSpec
    from test_server_app import Harness

    def masked(home, request):  # the storage process found the mask (the server could not check)
        return {"preflight": {}, "stores": {}, "done": {"event": "done", "ok": False, "error": "masked_value"},
                "timed_out": False}

    h = Harness(RequestSpec.from_dict(spec_dict()), static_dir, store=masked)
    h.client.open()
    codes = [h.client.submit({"kind": "api_key", "target_profile": "default", "value": canary}).json()["error_code"]
             for _ in range(5)]
    assert codes == ["masked_value"] * 4 + ["too_many_attempts"]


def test_other_storage_reasons_still_answer_storage_failed(spec_dict, static_dir, canary):
    from secure_input.spec import RequestSpec
    from test_server_app import Harness

    def failing(home, request):
        return {"preflight": {}, "stores": {"env": {"saved": False, "error": "verify_failed"}},
                "done": {"event": "done", "ok": True}, "timed_out": False}

    h = Harness(RequestSpec.from_dict(spec_dict()), static_dir, store=failing)
    h.client.open()
    r = h.client.submit({"kind": "api_key", "target_profile": "default", "value": canary})
    assert r.status_code == 422 and r.json()["error_code"] == "storage_failed"


# --- T-2: overlapping saves of the same login --------------------------------------------------------------------

class FakeStore:
    def __init__(self, items):
        self.items = list(items)

    def list_items(self):
        return list(self.items)

    def remove_item(self, item_id):
        before = len(self.items)
        self.items = [i for i in self.items if i.id != item_id]
        return len(self.items) < before


def item(id_, created_at, identifier="me@example.com", origin="https://example.com", kind="login"):
    return SimpleNamespace(id=id_, kind=kind, origin=origin, identifier=identifier, created_at=created_at)


T0, T1, T2 = ("2026-11-24T09:00:00.100000+00:00", "2026-11-24T09:00:00.110000+00:00",
              "2026-11-24T09:00:00.120000+00:00")


def test_overlap_both_new_items_present_then_each_removes_leaves_one():
    old, a, b = item("vault_old", T0), item("vault_aaa", T1), item("vault_bbb", T2)
    st = FakeStore([old, a, b])
    ra = hermes_vault._remove_older_logins(st, a, "me@example.com")
    rb = hermes_vault._remove_older_logins(st, b, "me@example.com")
    assert [i.id for i in st.items] == ["vault_bbb"]
    assert ra == (1, False) and rb == (1, False)


def test_overlap_in_reverse_order_also_leaves_the_later_item():
    old, a, b = item("vault_old", T0), item("vault_aaa", T1), item("vault_bbb", T2)
    st = FakeStore([old, a, b])
    hermes_vault._remove_older_logins(st, b, "me@example.com")
    hermes_vault._remove_older_logins(st, a, "me@example.com")
    assert [i.id for i in st.items] == ["vault_bbb"]


def test_same_created_at_is_ordered_by_id():
    a, b = item("vault_aaa", T1), item("vault_bbb", T1)
    st = FakeStore([a, b])
    hermes_vault._remove_older_logins(st, a, "me@example.com")
    assert [i.id for i in st.items] == ["vault_aaa", "vault_bbb"]  # a is not newer than b: removes nothing
    hermes_vault._remove_older_logins(st, b, "me@example.com")
    assert [i.id for i in st.items] == ["vault_bbb"]


def test_items_without_comparable_created_at_are_kept():
    st = FakeStore([item("vault_none", ""), item("vault_bad", "yesterday"), item("vault_naive", "2026-11-24T08:00:00"),
                    item("vault_new", T2)])
    removed, err = hermes_vault._remove_older_logins(st, st.items[-1], "me@example.com")
    assert (removed, err) == (0, False)
    assert len(st.items) == 4


def test_new_item_without_created_at_removes_nothing():
    st = FakeStore([item("vault_old", T0), item("vault_new", "")])
    assert hermes_vault._remove_older_logins(st, st.items[-1], "me@example.com") == (0, False)
    assert len(st.items) == 2


def test_newer_item_of_same_login_is_kept_and_other_ids_or_sites_untouched():
    new = item("vault_mid", T1)
    st = FakeStore([item("vault_old", T0), new, item("vault_later", T2), item("vault_other_id", T0, identifier="x"),
                    item("vault_other_site", T0, origin="https://other.example"),
                    item("vault_card", T0, kind="payment")])
    removed, _ = hermes_vault._remove_older_logins(st, new, " me@example.com ")
    assert removed == 1
    assert [i.id for i in st.items] == ["vault_mid", "vault_later", "vault_other_id", "vault_other_site", "vault_card"]


def test_created_at_is_taken_from_the_listing():
    """The new item's order comes from list_items(), not from the add_item answer."""
    listed = item("vault_new", T2)
    answer = item("vault_new", T0)  # stale answer
    st = FakeStore([item("vault_old", T1), listed])
    assert hermes_vault._remove_older_logins(st, answer, "me@example.com") == (1, False)
    assert [i.id for i in st.items] == ["vault_new"]


def test_overlap_with_real_vault_store_leaves_one(hermes_root):
    sys.path.insert(0, str(storage.hermes_agent_dir()))
    try:
        from agent.vault_store import VaultStore
    finally:
        sys.path.remove(str(storage.hermes_agent_dir()))
    vs = VaultStore(base_dir=hermes_root / "vault")

    def add():
        secret = {"identifier_type": "email", "identifier": "me@example.com",
                  "password": "SECRET-CANARY-" + os.urandom(8).hex()}
        return vs.add_item(kind="login", label="Example", secret=secret, origin="https://example.com")

    old = add()
    a, b = add(), add()  # both new items are in before either removal runs
    hermes_vault._remove_older_logins(vs, a, "me@example.com")
    hermes_vault._remove_older_logins(vs, b, "me@example.com")
    left = [m.id for m in vs.list_items()]
    assert len(left) == 1 and old.id not in left


def test_login_save_waits_for_the_plugin_login_lock(hermes_root):
    """Add, list and remove run under <home>/secure-input/login.lock, so overlapping saves are serialized."""
    import fcntl
    import threading
    import time

    home = hermes_root / "profiles" / "worker"
    lock_dir = home / "secure-input"
    lock_dir.mkdir(mode=0o700)
    fd = os.open(lock_dir / "login.lock", os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX)
    out: dict = {}
    req = {"kind": "login", "label": "Example", "origin": "https://example.com", "identifier_type": "email",
           "identifier": "me@example.com", "password": "SECRET-CANARY-" + os.urandom(8).hex(), "otp_secret": ""}
    t = threading.Thread(target=lambda: out.update(save_one(sys.executable, home, req)))
    t.start()
    try:
        time.sleep(2.0)
        assert t.is_alive()  # still waiting for the lock
    finally:
        os.close(fd)
    t.join(30)
    assert out.get("saved") is True and out.get("item_id")
    assert stat.S_IMODE((lock_dir / "login.lock").stat().st_mode) == 0o600


# --- T-3: trailing line breaks ---------------------------------------------------------------------------------

BAD_NAMES = {"trailing_lf": "REVIEW_KEY\n", "trailing_cr": "REVIEW_KEY\r", "trailing_crlf": "REVIEW_KEY\r\n",
             "embedded_lf": "A\nREVIEW_KEY", "path_lf": "PATH\n"}


@pytest.mark.parametrize("label", list(BAD_NAMES))
def test_check_env_var_name_refuses_line_breaks(label):
    from secure_input.validation import check_env_var_name

    with pytest.raises(ValueError):
        check_env_var_name(BAD_NAMES[label])


@pytest.mark.parametrize("label", list(BAD_NAMES))
def test_spec_refuses_line_break_names(spec_dict, label):
    from secure_input.spec import RequestSpec, SpecError

    with pytest.raises(SpecError):
        RequestSpec.from_dict(spec_dict(env_var=BAD_NAMES[label]))


@pytest.mark.parametrize("label", list(BAD_NAMES))
def test_write_env_refuses_line_break_names(home, canary, label):
    with pytest.raises(StorageError) as exc:
        write_env(home, BAD_NAMES[label], canary)
    assert exc.value.reason == "invalid_env_var"
    assert not (home / ".env").exists()


@pytest.mark.parametrize("own_texts", [False, True])
@pytest.mark.parametrize("label", list(BAD_NAMES))
def test_command_refuses_line_break_names(label, own_texts):
    from secure_input.command import CommandError, parse_command

    raw = "key " + shlex.quote(BAD_NAMES[label]) + (" --purpose 재점검 --label 재점검" if own_texts else "")
    with pytest.raises(CommandError):
        parse_command(raw)


def _plugin(root: Path):
    from secure_input.launcher import StartError
    from secure_input.plugin import SecureInput

    started: list = []

    def start(spec, **kw):
        started.append(spec.env_var)
        raise StartError("stopped by test")

    class Ctx:
        profile_name = "default"
        plugin_id = "secure-input"

        def get_config(self, key, default=None):
            return default

    class Serve:
        bin = "/nonexistent/tailscale"

        def owner_login(self):
            return "owner@example.test"

    svc = SecureInput(Ctx(), start=start, hermes_root=lambda: str(root), start_kwargs={"serve": Serve()},
                      settings=lambda k, d: d)
    return svc, started


@pytest.mark.parametrize("label", list(BAD_NAMES))
def test_plugin_tool_and_command_refuse_line_break_names(hermes_root, label):
    svc, started = _plugin(hermes_root)
    name = BAD_NAMES[label]
    svc.tool_request({"kind": "api_key", "purpose": "시험", "label": "시험", "env_var": name})
    svc.command("key " + shlex.quote(name), session_key="s", platform="slack")
    svc.command("key " + shlex.quote(name) + " --purpose 시험 --label 시험", session_key="s", platform="slack")
    assert started == []


@pytest.mark.parametrize("name", ["EXA_API_KEY", "_X", "A1", "REVIEW_KEY"])
def test_ordinary_names_still_reach_start(hermes_root, name):
    svc, started = _plugin(hermes_root)
    svc.tool_request({"kind": "api_key", "purpose": "시험", "label": "시험", "env_var": name})
    assert started == [name]


def test_profile_name_with_trailing_newline_is_refused(hermes_root):
    from secure_input.profiles import ProfileError, list_profiles, resolve_profile_home

    (hermes_root / "profiles" / "worker\n").mkdir()
    with pytest.raises(ProfileError):
        resolve_profile_home("worker\n", hermes_root)
    assert list_profiles(hermes_root) == ["default", "worker"]
    assert resolve_profile_home("worker", hermes_root) == hermes_root / "profiles" / "worker"


def test_spec_and_command_refuse_profile_with_trailing_newline(spec_dict):
    from secure_input.command import CommandError, parse_command
    from secure_input.spec import RequestSpec, SpecError

    with pytest.raises(SpecError):
        RequestSpec.from_dict(spec_dict(target_profile="worker\n"))
    bad_requester = dict(spec_dict()["requester"], profile="worker\n")
    with pytest.raises(SpecError):
        RequestSpec.from_dict(spec_dict(requester=bad_requester))
    with pytest.raises(CommandError):
        parse_command("key EXA_API_KEY --profile " + shlex.quote("worker\n"))


def test_serve_token_with_trailing_newline_is_refused():
    from secure_input.serve import ServeError, ServeManager

    ServeManager._check_token("abcdefgh")
    with pytest.raises(ServeError):
        ServeManager._check_token("abcdefgh\n")


def test_otp_site_with_trailing_newline_is_refused(spec_dict):
    from secure_input.spec import RequestSpec, SpecError

    RequestSpec.from_dict(spec_dict(kind="otp_code", site="example.com"))
    with pytest.raises(SpecError):
        RequestSpec.from_dict(spec_dict(kind="otp_code", site="example.com\n"))


@pytest.mark.parametrize("text", ["AAA\n", "AAAA\n", "AAAAAAA\n"])
def test_b64u_with_trailing_newline_is_refused(text):
    from secure_input.crypto import CryptoFormatError, b64u_decode

    with pytest.raises(CryptoFormatError):
        b64u_decode(text)
