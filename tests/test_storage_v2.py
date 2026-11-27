"""Protocol 2 storage targets: constants, store lists, keychain names (plan 2, 3.2, appendix A.1, A.5)."""

from __future__ import annotations

import pytest

from secure_input import config
from secure_input.spec import (KeychainItemError, RequestSpec, SpecError, build_store_rows, parse_keychain_items,
                               resolve_keychain)

ALLOW = [{"id": "example-vault-password", "service": "example-unlock-item", "account": "example-unlock-item",
          "label": "Example Vault 비밀번호", "used_by": "Example Vault 자동 잠금 해제 스크립트"}]


# --- A.1 constants ------------------------------------------------------------------------------------------

def test_config_constants_are_appendix_a1():
    assert config.PROTOCOL_VERSION == 2
    assert config.HKDF_INFO == b"hermes-secure-input/v1/submit"
    assert config.KINDS == ("api_key", "login", "otp_code", "secret")
    assert config.STORE_NAMES == ("env", "hermes_vault", "keychain")
    assert config.KIND_STORES == {"api_key": ("env", "keychain"), "login": ("hermes_vault",),
                                  "secret": ("keychain",), "otp_code": ()}
    assert config.KIND_DEFAULT_STORES == {"api_key": ("env",), "login": ("hermes_vault",),
                                          "secret": ("keychain",), "otp_code": ()}
    assert config.STORE_TIMEOUT_S == {"env": 10.0, "hermes_vault": 30.0, "keychain": 20.0}
    assert config.PREFLIGHT_AT_CREATE_TIMEOUT_S == 10.0
    assert config.WAIT_MARGIN_S == 10.0
    assert config.CANCEL_MARGIN_S == 5.0
    assert config.KEYCHAIN_ID_RE.pattern == r"^[a-z0-9][a-z0-9-]{0,39}$"
    assert config.KEYCHAIN_NAME_RE.pattern == r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$"
    assert not hasattr(config, "STORAGE_TIMEOUT_S")


# --- store lists (criterion: not allowed, empty, duplicate, unknown) ------------------------------------------

def rows_by_store(rows):
    return {r["store"]: r for r in rows}


def test_api_key_default_rows():
    rows = build_store_rows("api_key", None)
    assert [r["store"] for r in rows] == ["env", "keychain"]
    env, kc = rows
    assert env == {"store": "env", "selected": True, "fixed": False, "by": "default", "reason": None, "needed": False}
    assert kc == {"store": "keychain", "selected": False, "fixed": False, "by": None, "reason": None, "needed": False}


@pytest.mark.parametrize("kind,store", [("secret", "keychain"), ("login", "hermes_vault")])
def test_single_store_kinds_are_fixed_and_selected(kind, store):
    assert build_store_rows(kind, None) == [{"store": store, "selected": True, "fixed": True, "by": "default",
                                             "reason": None, "needed": False}]
    agent = build_store_rows(kind, [{"store": store, "reason": "잠금 해제 스크립트가 읽습니다", "needed": True}])
    assert agent == [{"store": store, "selected": True, "fixed": True, "by": "agent",
                      "reason": "잠금 해제 스크립트가 읽습니다", "needed": True}]


def test_otp_code_has_no_rows():
    assert build_store_rows("otp_code", None) == []


@pytest.mark.parametrize("kind,stores,why", [
    ("api_key", [{"store": "hermes_vault"}], "not allowed"),
    ("login", [{"store": "keychain"}], "not allowed"),
    ("secret", [{"store": "env"}], "not allowed"),
    ("otp_code", [{"store": "env"}], "not allowed"),
    ("api_key", [], "empty"),
    ("secret", [], "empty"),
    ("api_key", [{"store": "env"}, {"store": "env"}], "duplicate"),
    ("api_key", [{"store": "example_vault"}], "unknown"),
    ("api_key", [{"store": "ENV"}], "unknown"),
    ("api_key", "env", "not a list"),
    ("api_key", [{"store": "env", "extra": 1}], "unknown field"),
    ("api_key", [{"store": "env", "needed": "yes"}], "needed"),
    ("api_key", [{"store": "env", "reason": "두 줄\n이유"}], "reason"),
    ("api_key", [{"store": "env", "reason": "x" * 121}], "reason"),
    ("api_key", [{"store": "env", "reason": ""}], "reason"),
    ("api_key", [{"store": "env", "reason": "보이지 않는\u200b문자"}], "reason"),
    ("api_key", [{"store": "env", "reason": "방향\u202e바꿈"}], "reason"),
])
def test_store_list_is_refused(kind, stores, why):
    with pytest.raises(SpecError) as exc:
        build_store_rows(kind, stores)
    assert exc.value.field == "stores"


def test_reason_of_120_characters_is_accepted():
    rows = build_store_rows("api_key", [{"store": "keychain", "reason": "가" * 120}])
    assert rows_by_store(rows)["keychain"]["reason"] == "가" * 120


def test_agent_choice_replaces_the_default():
    rows = rows_by_store(build_store_rows("api_key", [{"store": "keychain", "needed": True}]))
    assert rows["env"]["selected"] is False and rows["env"]["by"] is None
    assert rows["keychain"]["selected"] is True and rows["keychain"]["by"] == "agent"
    assert rows["keychain"]["needed"] is True


def test_history_preselects_for_api_key_only():
    rows = rows_by_store(build_store_rows("api_key", None, history=("keychain",)))
    assert rows["env"]["by"] == "default" and rows["keychain"]["by"] == "history"
    rows = rows_by_store(build_store_rows("api_key", [{"store": "keychain"}], history=("env", "keychain")))
    assert rows["env"]["by"] == "history" and rows["keychain"]["by"] == "agent"
    assert build_store_rows("login", None, history=("hermes_vault",))[0]["by"] == "default"


# --- keychain names (plan 3.2; criterion: outside the allow list always the plugin prefix) ----------------------

def test_listed_id_uses_the_allow_list_item_for_secret():
    kc = resolve_keychain("secret", "example-vault-password", allow=ALLOW)
    assert kc == {"id": "example-vault-password", "service": "example-unlock-item", "account": "example-unlock-item",
                  "listed": True, "label": "Example Vault 비밀번호", "used_by": "Example Vault 자동 잠금 해제 스크립트"}


def test_listed_id_is_refused_for_api_key():
    with pytest.raises(KeychainItemError) as exc:
        resolve_keychain("api_key", "example-vault-password", env_var="X_KEY", allow=ALLOW)
    assert exc.value.rule == 3 and exc.value.listed_id == "example-vault-password"


@pytest.mark.parametrize("name", ["example-unlock-item", "EXAMPLE-UNLOCK-ITEM", "Example-Unlock-Item"])
def test_name_equal_to_a_listed_service_or_account_is_refused(name):
    with pytest.raises(KeychainItemError) as exc:
        resolve_keychain("secret", name, allow=ALLOW)
    assert exc.value.rule == 4 and exc.value.listed_id == "example-vault-password"


@pytest.mark.parametrize("name", ["example-vault", "x", "a" * 40, "0-db-password"])
def test_names_outside_the_allow_list_get_the_plugin_prefix(name):
    for kind in ("secret", "api_key"):
        kc = resolve_keychain(kind, name, env_var="X_KEY", allow=ALLOW)
        assert kc == {"id": name, "service": "hermes-secure-input." + name, "account": "hermes-secure-input",
                      "listed": False, "label": None, "used_by": None}


@pytest.mark.parametrize("name", ["Example", "a_b", "a.b", "a b", "a" * 41, "", "-a", "abc\n", None, 3])
def test_other_name_shapes_are_refused(name):
    with pytest.raises(KeychainItemError) as exc:
        resolve_keychain("secret", name, allow=ALLOW)
    assert exc.value.rule == 8


def test_login_never_takes_a_keychain_item():
    with pytest.raises(SpecError):
        resolve_keychain("login", "site-pw", allow=ALLOW)
    assert resolve_keychain("login", None, allow=ALLOW) is None


def test_secret_requires_a_keychain_item():
    with pytest.raises(KeychainItemError) as exc:
        resolve_keychain("secret", None, allow=ALLOW)
    assert exc.value.rule == 8


def test_api_key_default_name_comes_from_the_variable():
    kc = resolve_keychain("api_key", None, env_var="OPENAI_API_KEY", allow=ALLOW)
    assert kc["id"] == "openai-api-key" and kc["service"] == "hermes-secure-input.openai-api-key"


@pytest.mark.parametrize("env_var,allow", [
    ("_PRIVATE_KEY", ALLOW),
    ("A" * 41, ALLOW),
    ("EXAMPLE_UNLOCK_ITEM", ALLOW),          # rule 4: the listed service
    ("EXAMPLE_VAULT_PASSWORD", ALLOW),      # equal to a listed id: handled like rule 4
])
def test_unusable_api_key_default_name(env_var, allow):
    kc = resolve_keychain("api_key", None, env_var=env_var, allow=allow)
    assert kc == {"id": None, "service": None, "account": None, "listed": False, "label": None, "used_by": None}
    with pytest.raises(KeychainItemError) as exc:
        resolve_keychain("api_key", None, env_var=env_var, allow=allow, keychain_chosen=True)
    assert exc.value.rule == 7


# --- allow list reading (plan 3.2 rule 1) ------------------------------------------------------------------------

def test_allow_list_keeps_valid_items_and_drops_the_rest():
    raw = [
        ALLOW[0],
        {"id": "Bad_Id", "service": "s", "account": "a", "label": "l", "used_by": "u"},
        {"id": "plugin-own", "service": "hermes-secure-input.x", "account": "a", "label": "l", "used_by": "u"},
        {"id": "example-vault-password", "service": "other", "account": "other", "label": "l", "used_by": "u"},
        {"id": "two-words", "service": "has space", "account": "a", "label": "l", "used_by": "u"},
        {"id": "no-label", "service": "s", "account": "a", "label": "", "used_by": "u"},
        {"id": "extra", "service": "s", "account": "a", "label": "l", "used_by": "u", "x": 1},
        "not an object",
        {"id": "ok-two", "service": "svc.name@x", "account": "acct_1", "label": "둘째", "used_by": "스크립트"},
    ]
    items, warnings = parse_keychain_items(raw)
    assert [i["id"] for i in items] == ["example-vault-password", "ok-two"]
    assert [w["index"] for w in warnings] == [1, 2, 3, 4, 5, 6, 7]
    assert {w["field"] for w in warnings} <= {"id", "service", "account", "label", "used_by", "item"}
    assert all(set(w) == {"index", "field"} for w in warnings)  # never the value of the field


def test_allow_list_of_wrong_type_is_empty():
    assert parse_keychain_items(None) == ([], [])
    items, warnings = parse_keychain_items("[]")
    assert items == [] and warnings == [{"index": None, "field": "keychain_items"}]


# --- RequestSpec carries the rows and the keychain item (A.5) -------------------------------------------------------

def test_spec_fills_default_rows_and_keychain(spec_dict):
    spec = RequestSpec.from_dict(spec_dict(env_var="OPENAI_API_KEY"))
    assert [r["store"] for r in spec.stores] == ["env", "keychain"]
    assert spec.keychain["service"] == "hermes-secure-input.openai-api-key"
    login = RequestSpec.from_dict(spec_dict(kind="login"))
    assert login.keychain is None and login.stores[0]["fixed"] is True
    otp = RequestSpec.from_dict(spec_dict(kind="otp_code"))
    assert otp.stores == [] and otp.keychain is None


def secret_dict(spec_dict, **over):
    d = spec_dict(kind="secret", profile_editable=False, env_var=None,
                  keychain=resolve_keychain("secret", "example-vault-password", allow=ALLOW))
    d.update(over)
    return d


def test_secret_spec_round_trips(spec_dict):
    spec = RequestSpec.from_dict(secret_dict(spec_dict))
    again = RequestSpec.from_dict(spec.to_dict())
    assert again == spec and again.stores[0]["store"] == "keychain" and again.keychain["listed"] is True


@pytest.mark.parametrize("keychain", [
    None,
    {"id": "x", "service": "x", "account": "x", "listed": False, "label": None, "used_by": None},
    {"id": "x", "service": "hermes-secure-input.x", "account": "someone", "listed": False, "label": None,
     "used_by": None},
    {"id": "x", "service": "hermes-secure-input.y", "account": "hermes-secure-input", "listed": False, "label": None,
     "used_by": None},
    {"id": "x", "service": "hermes-secure-input.x", "account": "hermes-secure-input", "listed": False, "label": None,
     "used_by": None, "extra": 1},
    {"id": "example", "service": "hermes-secure-input.evil", "account": "a", "listed": True, "label": "l",
     "used_by": "u"},
])
def test_secret_spec_refuses_a_keychain_item_outside_the_rules(spec_dict, keychain):
    with pytest.raises(SpecError):
        RequestSpec.from_dict(secret_dict(spec_dict, keychain=keychain))


def test_listed_item_only_for_secret(spec_dict):
    with pytest.raises(SpecError):
        RequestSpec.from_dict(spec_dict(keychain=resolve_keychain("secret", "example-vault-password", allow=ALLOW)))


def test_spec_has_no_service_or_account_argument(spec_dict):
    for name in ("service", "account", "keychain_service"):
        with pytest.raises(SpecError):
            RequestSpec.from_dict(dict(secret_dict(spec_dict), **{name: "example-unlock-item"}))


@pytest.mark.parametrize("rows", [
    [],
    [{"store": "env", "selected": True, "fixed": True, "by": "default", "reason": None, "needed": False}],
    [{"store": "keychain", "selected": False, "fixed": True, "by": None, "reason": None, "needed": False}],
    [{"store": "keychain", "selected": True, "fixed": True, "by": "history", "reason": None, "needed": False}],
    [{"store": "keychain", "selected": True, "fixed": True, "by": "agent", "reason": "a\nb", "needed": False}],
])
def test_secret_spec_refuses_bad_rows(spec_dict, rows):
    with pytest.raises(SpecError):
        RequestSpec.from_dict(secret_dict(spec_dict, stores=rows))


def test_api_key_spec_needs_one_selected_row(spec_dict):
    rows = build_store_rows("api_key", None)
    rows[0] = dict(rows[0], selected=False, by=None)
    with pytest.raises(SpecError):
        RequestSpec.from_dict(spec_dict(stores=rows))


# === storage process (appendix A.9, A.10) ===========================================================================

import io  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import subprocess  # noqa: E402
import sys  # noqa: E402
import time  # noqa: E402

from helpers import fake_keychain  # noqa: E402
from secure_input import storage  # noqa: E402

RID = "0123456789abcdef0123456789abcdef"
KC_NEW = {"service": "hermes-secure-input.exa-api-key", "account": "hermes-secure-input", "listed": False}


@pytest.fixture
def kc(tmp_path, monkeypatch):
    """Configure the fake keychain for storage grandchildren; returns (python wrapper, config setter, log reader)."""
    log = tmp_path / "kc-log.jsonl"
    state = {"log": str(log)}

    def configure(**cfg):
        state.clear()
        state.update(log=str(log), **cfg)
        monkeypatch.setenv("FAKE_KEYCHAIN_CONFIG", json.dumps(state))

    configure()

    def calls():
        return [json.loads(x) for x in log.read_text().splitlines()] if log.exists() else []

    return fake_keychain.storage_python(tmp_path / "py"), configure, calls


def req(phase="save", kind="api_key", stores=("env", "keychain"), **over):
    r = {"phase": phase, "kind": kind, "stores": list(stores), "request_id": RID}
    if "env" in stores:
        r["env_var"] = "EXA_API_KEY"
    if "keychain" in stores:
        r["keychain"] = dict(KC_NEW)
    if "hermes_vault" in stores:
        r.update(label="Example", origin="https://example.com")
    r.update(over)
    return r


def raw_run(python, home, request):
    """The grandchild as the server starts it, returning (exit code, stdout lines)."""
    env = dict(os.environ, HERMES_HOME=str(home), PYTHONDONTWRITEBYTECODE="1",
               PYTHONPATH=os.pathsep.join([str(storage.PLUGIN_ROOT), str(storage.hermes_agent_dir())]))
    p = subprocess.run([str(python), "-P", "-m", "secure_input.storage"], input=json.dumps(request).encode(),
                       capture_output=True, env=env, cwd=str(storage.PLUGIN_ROOT), timeout=60)
    return p.returncode, p.stdout.decode(), p.stderr.decode()


def test_create_time_preflight_reports_every_store_and_writes_nothing(hermes_root, kc):
    python, configure, calls = kc
    (hermes_root / ".env").write_text("EXA_API_KEY=old\n")
    out = storage.run_storage(str(python), hermes_root, req("preflight"))
    assert out["done"] == {"event": "done", "ok": True} and out["timed_out"] is False
    assert out["preflight"] == {"env": {"available": True, "reason": None, "exists": True},
                                "keychain": {"available": True, "reason": None, "exists": False}}
    assert out["stores"] == {}
    assert (hermes_root / ".env").read_text() == "EXA_API_KEY=old\n"
    assert [c["fn"] for c in calls()] == ["preflight"]
    assert calls()[0]["keys"] == ["account", "listed", "request_id", "service"]  # no value at create time


def test_save_writes_in_store_order_and_reports_each_store(hermes_root, kc, canary):
    python, configure, calls = kc
    code, stdout, stderr = raw_run(python, hermes_root, req(value=canary, masked_check=True))
    lines = [json.loads(x) for x in stdout.splitlines()]
    assert code == 0
    assert [(x["event"], x.get("store")) for x in lines] == [("preflight", "env"), ("preflight", "keychain"),
                                                              ("store", "env"), ("store", "keychain"),
                                                              ("done", None)]
    assert lines[2] == {"event": "store", "store": "env", "saved": True, "replaced": False, "error": None,
                        "env_var": "EXA_API_KEY"}
    assert lines[3]["saved"] is True and lines[3]["service"] == KC_NEW["service"]
    assert lines[4] == {"event": "done", "ok": True}
    assert f"EXA_API_KEY={canary}" in (hermes_root / ".env").read_text()
    assert canary not in stdout and canary not in stderr
    assert [c["fn"] for c in calls()] == ["preflight", "save"]


def test_secret_value_never_reaches_the_output(hermes_root, kc, canary):
    python, configure, calls = kc
    code, stdout, stderr = raw_run(python, hermes_root, req(kind="secret", stores=("keychain",), value=canary))
    assert code == 0 and canary not in stdout and canary not in stderr
    assert [json.loads(x)["event"] for x in stdout.splitlines()] == ["preflight", "store", "done"]


def test_failed_preflight_writes_nowhere(hermes_root, kc, canary):
    python, configure, calls = kc
    configure(preflight={"available": False, "reason": "keychain_acl_denied", "exists": True})
    code, stdout, _ = raw_run(python, hermes_root, req(value=canary, masked_check=True))
    lines = [json.loads(x) for x in stdout.splitlines()]
    assert code == 2
    assert lines[-1] == {"event": "done", "ok": False, "error": "store_unavailable"}
    assert [x["event"] for x in lines] == ["preflight", "preflight", "done"]
    assert lines[1] == {"event": "preflight", "store": "keychain", "available": False,
                        "reason": "keychain_acl_denied", "exists": True}
    assert not (hermes_root / ".env").exists()
    assert [c["fn"] for c in calls()] == ["preflight"]


def test_env_preflight_reasons_come_from_the_closed_list(hermes_root, kc, canary):
    python, configure, calls = kc
    out = storage.run_storage(str(python), hermes_root, req("preflight", stores=("env",), env_var="HERMES_YOLO_MODE"))
    assert out["preflight"]["env"]["available"] is False
    assert out["preflight"]["env"]["reason"] in ("invalid_env_var", "env_not_writable")
    out = storage.run_storage(str(python), hermes_root / "missing", req("preflight", stores=("env",)))
    assert out["preflight"]["env"] == {"available": False, "reason": "bad_home", "exists": None}


def test_masked_value_check_runs_first_when_the_server_could_not(hermes_root, kc):
    python, configure, calls = kc
    code, stdout, _ = raw_run(python, hermes_root, req(value="sk-abc...wxyz", masked_check=False))
    assert code == 2 and [json.loads(x) for x in stdout.splitlines()] == [
        {"event": "done", "ok": False, "error": "masked_value"}]
    assert calls() == [] and not (hermes_root / ".env").exists()


def test_env_module_itself_does_not_run_the_masked_check(hermes_root, kc):
    """With ``masked_check: true`` the server already checked; Hermes' writer still refuses the mask and the
    env row is a plain write failure (v2: the masked check is not part of the env module)."""
    python, configure, calls = kc
    code, stdout, _ = raw_run(python, hermes_root, req(stores=("env",), value="sk-abc...wxyz", masked_check=True))
    lines = [json.loads(x) for x in stdout.splitlines()]
    assert code == 0 and lines[1]["store"] == "env" and lines[1]["saved"] is False
    assert lines[1]["error"] in ("env_write_failed", "verify_failed")


def test_store_module_exception_is_an_unknown_row(hermes_root, kc, canary):
    python, configure, calls = kc
    configure(save_raises=True)
    code, stdout, _ = raw_run(python, hermes_root, req(kind="secret", stores=("keychain",), value=canary))
    row = [json.loads(x) for x in stdout.splitlines()][1]
    assert row["saved"] is None and row["error"] == "internal_error" and row["service"] == KC_NEW["service"]


def test_missing_keychain_module_is_unavailable_not_a_crash(hermes_root, canary, monkeypatch):
    monkeypatch.setenv("FAKE_KEYCHAIN_CONFIG", json.dumps({"install": False}))
    python = fake_keychain.storage_python(hermes_root.parent / "py-nokc")
    out = storage.run_storage(str(python), hermes_root, req("preflight"))
    assert out["preflight"]["keychain"] == {"available": False, "reason": "internal_error", "exists": None}
    assert out["preflight"]["env"]["available"] is True


def test_unsupported_kind_is_unavailable(hermes_root, kc):
    python, configure, calls = kc
    out = storage.run_storage(str(python), hermes_root, req("preflight", kind="otp_code", stores=("env",)))
    assert out["preflight"]["env"]["reason"] == "unsupported_kind"
    assert out["done"]["error"] == "store_unavailable"


def run_in_process(request, monkeypatch, cfg=None):
    mod = fake_keychain.make_module(cfg or {})
    monkeypatch.setitem(sys.modules, "secure_input.stores.keychain", mod)
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(request)))
    out = io.StringIO()
    monkeypatch.setattr(sys, "stdout", out)
    code = storage.main()
    return code, [json.loads(x) for x in out.getvalue().splitlines()], mod


def test_keychain_module_gets_exactly_five_keys_on_save(hermes_root, monkeypatch, canary):
    monkeypatch.setenv("HERMES_HOME", str(hermes_root))
    request = req(kind="secret", stores=("keychain",), value=canary, env_var="IGNORED", label="x",
                  identifier="me@example.com")
    code, lines, mod = run_in_process(request, monkeypatch)
    assert code == 0
    assert mod.calls == [("preflight", ["account", "listed", "request_id", "service", "value"]),
                         ("save", ["account", "listed", "request_id", "service", "value"])]


def test_null_keychain_name_reaches_the_module_as_none(hermes_root, monkeypatch, canary):
    monkeypatch.setenv("HERMES_HOME", str(hermes_root))
    seen = {}
    mod = fake_keychain.make_module({})

    def capture(r, **kw):
        seen.update(r)
        return {"available": False, "reason": "keychain_name_invalid", "exists": None}

    mod.preflight = capture
    monkeypatch.setitem(sys.modules, "secure_input.stores.keychain", mod)
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(req("preflight", keychain=None))))
    out = io.StringIO()
    monkeypatch.setattr(sys, "stdout", out)
    assert storage.main() == 0
    assert seen == {"service": None, "account": None, "listed": False, "request_id": RID}
    lines = [json.loads(x) for x in out.getvalue().splitlines()]
    assert lines[1] == {"event": "preflight", "store": "keychain", "available": False,
                        "reason": "keychain_name_invalid", "exists": None}


def test_a_changed_parent_stops_the_writes(hermes_root, monkeypatch, canary):
    monkeypatch.setenv("HERMES_HOME", str(hermes_root))
    real = os.getppid()
    seq = iter([real, real])  # start value, then the check before the first store; later checks see another pid
    monkeypatch.setattr(os, "getppid", lambda: next(seq, real + 100000))
    code, lines, mod = run_in_process(req(value=canary, masked_check=True), monkeypatch)
    assert [x.get("store") for x in lines if x["event"] == "store"] == ["env"]
    assert [c[0] for c in mod.calls] == ["preflight"]  # keychain was never written


def test_timeout_ends_the_whole_group_and_keeps_the_rows_already_received(hermes_root, kc, canary, tmp_path):
    python, configure, calls = kc
    pidfile = tmp_path / "child.pid"
    configure(save_sleep=60, save_child_pidfile=str(pidfile))
    t0 = time.monotonic()
    out = storage.run_storage(str(python), hermes_root, req(value=canary, masked_check=True), timeout=4)
    assert time.monotonic() - t0 < 10
    assert out["timed_out"] is True and out["done"] is None
    assert out["stores"]["env"]["saved"] is True and "keychain" not in out["stores"]
    child = int(pidfile.read_text())
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        try:
            os.kill(child, 0)
        except ProcessLookupError:
            break
        time.sleep(0.05)
    with pytest.raises(ProcessLookupError):
        os.kill(child, 0)
    rows = storage.result_rows(["env", "keychain"], out)
    assert rows["keychain"]["saved"] is None and rows["keychain"]["error"] == "store_timeout"
    assert rows["keychain"]["tmp_left"] is None and rows["keychain"]["main_touched"] is None


def test_early_exit_without_rows_is_no_result(hermes_root, kc, canary):
    python, configure, calls = kc
    configure(save_exit=1)
    out = storage.run_storage(str(python), hermes_root, req(value=canary, masked_check=True))
    assert out["timed_out"] is False and out["done"] is None
    rows = storage.result_rows(["env", "keychain"], out)
    assert rows["env"]["saved"] is True
    assert rows["keychain"] == {"store": "keychain", "saved": None, "replaced": None, "error": "no_result",
                                "service": None, "account": None, "listed": None, "new_item": None,
                                "tmp_left": None, "main_touched": None, "main_created": None}


def test_timeout_before_any_line_marks_every_chosen_store(hermes_root, kc, canary):
    python, configure, calls = kc
    configure(wrapper_sleep_save=30)
    out = storage.run_storage(str(python), hermes_root, req(value=canary, masked_check=True), timeout=2)
    rows = storage.result_rows(["env", "keychain"], out)
    assert {k: (v["saved"], v["error"]) for k, v in rows.items()} == {"env": (None, "store_timeout"),
                                                                    "keychain": (None, "store_timeout")}


def test_save_timeout_is_the_sum_of_the_chosen_stores():
    assert storage.save_timeout(["env", "keychain"]) == 30.0
    assert storage.save_timeout(["hermes_vault"]) == 30.0
    assert storage.save_timeout(["keychain"]) == 20.0


# === copies record (plan 5.5) ========================================================================================

import stat as _stat  # noqa: E402

from secure_input.stores import placements  # noqa: E402


def test_placements_record_and_previous_stores(hermes_root):
    rows = [{"store": "env", "saved": True, "env_var": "EXA_API_KEY", "profile": "worker"},
            {"store": "keychain", "saved": False, "service": "hermes-secure-input.exa-api-key",
             "account": "hermes-secure-input"}]
    placements.record(hermes_root, "api_key|EXA_API_KEY", rows, when="2026-11-25T10:00:00+09:00")
    path = hermes_root / "secure-input" / "placements.json"
    assert _stat.S_IMODE(path.stat().st_mode) == 0o600
    data = json.loads(path.read_text())
    assert data == {"api_key|EXA_API_KEY": {"env": [{"profile": "worker", "env_var": "EXA_API_KEY",
                                                      "saved_at": "2026-11-25T10:00:00+09:00"}]}}
    assert placements.previous_stores(hermes_root, "api_key|EXA_API_KEY") == ("env",)
    rows[1]["saved"] = True
    placements.record(hermes_root, "api_key|EXA_API_KEY", rows, when="2026-11-25T11:00:00+09:00")
    data = json.loads(path.read_text())["api_key|EXA_API_KEY"]
    assert data["env"] == [{"profile": "worker", "env_var": "EXA_API_KEY", "saved_at": "2026-11-25T11:00:00+09:00"}]
    assert data["keychain"] == [{"service": "hermes-secure-input.exa-api-key", "account": "hermes-secure-input",
                                 "saved_at": "2026-11-25T11:00:00+09:00"}]
    assert placements.previous_stores(hermes_root, "api_key|EXA_API_KEY") == ("env", "keychain")
    assert placements.previous_stores(hermes_root, "api_key|OTHER") == ()


def test_placements_keep_one_entry_per_profile_and_item(hermes_root):
    key = "login|https://example.com"
    for prof, item in (("default", "a"), ("worker", "b"), ("default", "c")):
        placements.record(hermes_root, key, [{"store": "hermes_vault", "saved": True, "origin": "https://example.com",
                                              "item_id": item, "profile": prof}], when="t")
    entries = json.loads((hermes_root / "secure-input" / "placements.json").read_text())[key]["hermes_vault"]
    assert [(e["profile"], e["item_id"]) for e in entries] == [("worker", "b"), ("default", "c")]


def test_placements_key_names():
    assert placements.key_for("api_key", env_var="EXA_API_KEY") == "api_key|EXA_API_KEY"
    assert placements.key_for("login", origin="https://example.com") == "login|https://example.com"
    assert placements.key_for("secret", keychain_item="example-vault-password") == "secret|example-vault-password"


def test_unreadable_placements_file_is_empty(hermes_root):
    p = hermes_root / "secure-input" / "placements.json"
    p.parent.mkdir(parents=True)
    p.write_text("not json")
    assert placements.previous_stores(hermes_root, "api_key|X") == ()
