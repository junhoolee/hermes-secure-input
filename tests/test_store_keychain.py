"""Keychain store module (plan section 7.3, work 1; appendix A.1, A.4, A.8, A.10, A.11).

Every test plugs a fake ``security`` executable in through the ``security_path`` argument.
The real keychain is never touched here (only ``scripts/keychain_probe.py`` does that).
The fake keeps its items in a JSON state file whose path is written into the script itself,
so nothing reaches it through environment variables.
"""

from __future__ import annotations

import importlib
import inspect
import json
import os
import secrets
import stat
import sys
import time
from pathlib import Path

import pytest

from secure_input.stores import keychain

CANARY_PREFIX = "SECRET-" + "CANARY-"
DEFAULT_KC = "/Users/fake/Library/Keychains/login.keychain-db"
SVC = "hermes-secure-input.test-item"
ACCT = "hermes-secure-input"
REQ_ID = "0123456789abcdef0123456789abcdef"
TMP_SVC = "hermes-secure-input.tmp.0123456789ab"

FAKE = r'''#!{python}
import json, os, shlex, sys, time
STATE = {state!r}
LOG = {log!r}
TMP_PREFIX = "hermes-secure-input.tmp."

def load():
    with open(STATE) as f:
        return json.load(f)

def save(st):
    with open(STATE, "w") as f:
        json.dump(st, f)

def key(s, a):
    return s + "\u0000" + a

def opts(args):
    out, flags, i = {{}}, set(), 0
    while i < len(args):
        a = args[i]
        if a in ("-s", "-a", "-X", "-w_value"):
            out[a] = args[i + 1]; i += 2
        else:
            flags.add(a); i += 1
    return out, flags

def block(s, a, apps):
    lines = ['keychain: "%s"' % st["default_keychain"], "version: 512", 'class: "genp"', "attributes:",
             '    0x00000007 <blob>="%s"' % s, '    "acct"<blob>="%s"' % a, '    "svce"<blob>="%s"' % s,
             "access: 2 entries", "    entry 0:", "        authorizations (1): encrypt",
             "        don't-require-password", "        description: %s" % s, "        applications: <null>",
             "    entry 1:", "        authorizations (6): decrypt derive export_clear export_wrapped mac sign",
             "        don't-require-password", "        description: %s" % s]
    if apps is None:
        lines.append("        applications: <null>")
    else:
        lines.append("        applications (%d):" % len(apps))
        for n, p in enumerate(apps):
            lines.append("            %d: %s (OK)" % (n, p))
    return "\n".join(lines) + "\n"

argv = sys.argv[1:]
data = sys.stdin.read() if argv[:1] == ["-i"] else ""
with open(LOG, "a") as f:
    f.write(json.dumps({{"argv": argv, "stdin": data, "env": dict(os.environ), "pid": os.getpid()}}) + "\n")
st = load()
cmd = argv[0] if argv else ""
if cmd == "-i":
    first = data.splitlines()[0].split()[0] if data.strip() else ""
    slow = st.get("sleep", {{}}).get(first)
else:
    slow = st.get("sleep", {{}}).get(cmd)
if slow:
    time.sleep(slow)

if cmd == "default-keychain":
    if st.get("default_rc", 0):
        sys.exit(st["default_rc"])
    print('    "%s"' % st["default_keychain"])
    sys.exit(0)
if cmd == "find-generic-password":
    o, fl = opts(argv[1:])
    if st.get("find_rc") is not None:
        sys.exit(st["find_rc"])
    it = st["items"].get(key(o["-s"], o["-a"]))
    if it is None:
        sys.exit(44)
    if "-w" in fl:
        v = it["value"]
        if o["-s"].startswith(TMP_PREFIX) and st.get("tmp_readback") is not None:
            v = st["tmp_readback"]
        if not o["-s"].startswith(TMP_PREFIX) and st.get("main_readback") is not None:
            v = st["main_readback"]
        sys.stdout.write(v + "\n")
    sys.exit(0)
if cmd == "delete-generic-password":
    o, fl = opts(argv[1:])
    if st.get("delete_rc") is not None:
        sys.exit(st["delete_rc"])
    if st["items"].pop(key(o["-s"], o["-a"]), None) is None:
        sys.exit(44)
    save(st)
    sys.exit(0)
if cmd == "dump-keychain":
    if st.get("dump_rc", 0):
        sys.exit(st["dump_rc"])
    if st.get("dump_override") is not None:
        sys.stdout.write(st["dump_override"])
        sys.exit(0)
    out = []
    for k, it in st["items"].items():
        s, a = k.split("\u0000")
        out.append(block(s, a, it.get("apps", ["/usr/bin/security"])))
    sys.stdout.write("".join(out) + st.get("dump_extra", ""))
    sys.exit(0)
if cmd == "-i":
    rc = 0
    for line in data.splitlines():
        if not line.strip():
            continue
        parts = shlex.split(line)
        o, fl = opts(parts[1:])
        which = "tmp" if o["-s"].startswith(TMP_PREFIX) else "main"
        forced = st.get("write_rc", {{}}).get(which)
        if forced:
            rc = forced
            continue
        k = key(o["-s"], o["-a"])
        old = st["items"].get(k)
        apps = old.get("apps", ["/usr/bin/security"]) if old else ["/usr/bin/security"]
        st["items"][k] = {{"value": bytes.fromhex(o["-X"]).decode("utf-8"), "apps": apps}}
    save(st)
    sys.exit(rc)
sys.exit(2)
'''


class Fake:
    """A fake ``/usr/bin/security``: state file, call log, executable path."""

    def __init__(self, root: Path):
        self.root = root
        self.state_path = root / "state.json"
        self.log_path = root / "calls.jsonl"
        self.path = root / "security"
        self.state = {"default_keychain": DEFAULT_KC, "items": {}}
        self.write_state()
        self.path.write_text(FAKE.format(python=sys.executable, state=str(self.state_path),
                                         log=str(self.log_path)))
        self.path.chmod(self.path.stat().st_mode | stat.S_IXUSR)

    def write_state(self):
        self.state_path.write_text(json.dumps(self.state))

    def set(self, **kw):
        self.state.update(kw)
        self.write_state()

    def add_item(self, service, account, value, apps=("/usr/bin/security",)):
        self.state = json.loads(self.state_path.read_text())
        self.state["items"][service + "\u0000" + account] = {
            "value": value, "apps": list(apps) if apps is not None else None}
        self.write_state()

    def items(self):
        return json.loads(self.state_path.read_text())["items"]

    def value_of(self, service, account):
        it = self.items().get(service + "\u0000" + account)
        return None if it is None else it["value"]

    def calls(self):
        if not self.log_path.exists():
            return []
        return [json.loads(x) for x in self.log_path.read_text().splitlines() if x.strip()]

    def reset_log(self):
        if self.log_path.exists():
            self.log_path.unlink()

    def writes(self, which):
        """``-i`` calls whose line targets the temp item (``tmp``) or the main item (``main``)."""
        out = []
        for c in self.calls():
            if c["argv"][:1] == ["-i"]:
                is_tmp = keychain.TMP_PREFIX in c["stdin"]
                if (which == "tmp") == is_tmp:
                    out.append(c)
        return out


@pytest.fixture
def fake(tmp_path):
    return Fake(tmp_path)


def canary() -> str:
    return CANARY_PREFIX + secrets.token_hex(8)


def req(value=None, service=SVC, account=ACCT, listed=False):
    r = {"service": service, "account": account, "listed": listed, "request_id": REQ_ID}
    if value is not None:
        r["value"] = value
    return r


def run_save(fake, request):
    """Preflight then save, as the storage process does (same process, same module)."""
    pf = keychain.preflight(request, security_path=str(fake.path))
    assert pf["available"] is True, pf
    fake.reset_log()
    return keychain.save(request, security_path=str(fake.path))


RESULT_KEYS = {"saved", "replaced", "error", "service", "account", "listed", "new_item", "tmp_left",
               "main_touched", "main_created"}


# ---- constants (A.1) ---------------------------------------------------------------------------

def test_constants_match_appendix_a1():
    assert keychain.SECURITY_PATH == "/usr/bin/security"
    assert keychain.SERVICE_PREFIX == "hermes-secure-input."
    assert keychain.FIXED_ACCOUNT == "hermes-secure-input"
    assert keychain.TMP_PREFIX == "hermes-secure-input.tmp."
    assert keychain.TEST_PREFIX == "hermes-secure-input-test-"
    assert keychain.CALL_TIMEOUT_S == 5.0
    assert keychain.NAME_RE.pattern == r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$"
    assert keychain.MAX_LINE_BYTES == 2400
    assert keychain.MAX_VALUE_CHARS == 1024


# ---- save: new item ----------------------------------------------------------------------------

def test_save_new_item_makes_three_calls_and_stores_value(fake):
    v = canary()
    res = run_save(fake, req(v))
    assert set(res) == RESULT_KEYS
    assert res == {"saved": True, "replaced": False, "error": None, "service": SVC, "account": ACCT,
                   "listed": False, "new_item": True, "tmp_left": False, "main_touched": False, "main_created": True}
    assert len(fake.calls()) == 3
    assert fake.value_of(SVC, ACCT) == v
    assert fake.writes("tmp") == []


def test_save_existing_item_makes_seven_calls_and_replaces_value(fake):
    fake.add_item(SVC, ACCT, "old-value")
    v = canary()
    res = run_save(fake, req(v))
    assert res == {"saved": True, "replaced": True, "error": None, "service": SVC, "account": ACCT,
                   "listed": False, "new_item": False, "tmp_left": False, "main_touched": True, "main_created": False}
    calls = fake.calls()
    assert len(calls) == 7
    assert [c["argv"][0] for c in calls] == [
        "find-generic-password", "dump-keychain", "-i", "find-generic-password", "-i",
        "find-generic-password", "delete-generic-password"]
    assert calls[1]["argv"] == ["dump-keychain", "-a", DEFAULT_KC]
    assert fake.value_of(SVC, ACCT) == v
    assert fake.value_of(TMP_SVC, ACCT) is None


def test_listed_existing_item_is_never_new_item(fake):
    fake.add_item("example-like", "example-like", "old")
    res = run_save(fake, req(canary(), service="example-like", account="example-like", listed=True))
    assert res["saved"] is True and res["listed"] is True and res["new_item"] is False


def test_listed_missing_item_is_not_new_item(fake):
    res = run_save(fake, req(canary(), service="example-like", account="example-like", listed=True))
    assert res["saved"] is True and res["new_item"] is False


# ---- value never in argv or environment ----------------------------------------------------------

@pytest.mark.parametrize("existing", [False, True])
def test_value_and_hex_never_in_arguments_or_environment(fake, existing):
    if existing:
        fake.add_item(SVC, ACCT, "old-value")
    v = canary()
    forms = [v, v.encode().hex(), v.encode().hex().upper()]
    keychain.preflight(req(v), security_path=str(fake.path))
    run_save(fake, req(v))
    calls = fake.calls()
    assert calls
    for c in calls:
        joined = "\n".join(c["argv"])
        env = "\n".join(f"{k}={val}" for k, val in c["env"].items())
        for f in forms:
            assert f not in joined
            assert f not in env
    # the value does reach security, but only through stdin of ``-i`` as hex
    assert any(v.encode().hex() in c["stdin"] for c in calls if c["argv"] == ["-i"])
    assert all(v not in c["stdin"] for c in calls)


# ---- line length ---------------------------------------------------------------------------------

def _save_after_valueless_preflight(fake, request):
    """save() does not repeat value checks (A.11), so a too-long value reaches save() only when the
    caller skipped them; preflight without the value still primes the default keychain path."""
    pf = keychain.preflight({k: v for k, v in request.items() if k != "value"},
                            security_path=str(fake.path))
    assert pf["available"] is True, pf
    fake.reset_log()
    return keychain.save(request, security_path=str(fake.path))


def test_save_does_not_run_a_line_over_2400_bytes(fake):
    v = "a" * 1200        # 2400 hex chars: the line is over MAX_LINE_BYTES
    res = _save_after_valueless_preflight(fake, req(v))
    assert res["saved"] is False
    assert res["error"] == "keychain_line_too_long"
    assert res["main_touched"] is False
    assert [c for c in fake.calls() if c["argv"][:1] == ["-i"]] == []
    assert fake.value_of(SVC, ACCT) is None


def test_save_existing_item_long_line_runs_no_write_and_leaves_no_temp(fake):
    fake.add_item(SVC, ACCT, "old-value")
    res = _save_after_valueless_preflight(fake, req("b" * 1200))
    assert res["error"] == "keychain_line_too_long"
    assert res["saved"] is False and res["tmp_left"] is False and res["main_touched"] is False
    assert [c for c in fake.calls() if c["argv"][:1] == ["-i"]] == []
    assert fake.value_of(SVC, ACCT) == "old-value"


def test_line_bytes_of_longest_allowed_names_and_value_fit(fake):
    svc = "s" * 128
    acct = "a" * 128
    res = run_save(fake, req("x" * 1024, service=svc, account=acct))
    assert res["saved"] is True


# ---- value rules (3.1) ---------------------------------------------------------------------------

@pytest.mark.parametrize("value", [
    "비밀번호-값",               # Korean
    "a" * 1025,                 # 1,025 characters
    " leading-space",
    "trailing-space ",
    "two\nlines",
    "tab\tinside",
    "",
    "emoji-\U0001F600",
])
def test_preflight_with_value_rejects_unsupported_values(fake, value):
    res = keychain.preflight(req(value), security_path=str(fake.path))
    assert res["available"] is False
    assert res["reason"] == "keychain_value_unsupported"
    assert [c for c in fake.calls() if c["argv"][:1] == ["-i"]] == []


@pytest.mark.parametrize("value", ["a", "x" * 1024, "q'uo\"te\\back$slash", "in side space"])
def test_preflight_with_value_accepts_supported_values(fake, value):
    res = keychain.preflight(req(value), security_path=str(fake.path))
    assert res == {"available": True, "reason": None, "exists": False}


def test_preflight_without_value_does_not_check_value(fake):
    res = keychain.preflight(req(), security_path=str(fake.path))
    assert res == {"available": True, "reason": None, "exists": False}


# ---- preflight order (A.11 checks 1 to 6) --------------------------------------------------------

def test_preflight_missing_executable_is_unavailable(tmp_path):
    res = keychain.preflight(req(), security_path=str(tmp_path / "no-such-security"))
    assert res == {"available": False, "reason": "keychain_unavailable", "exists": None}


def test_preflight_default_keychain_failure_is_unavailable(fake):
    fake.set(default_rc=50)
    res = keychain.preflight(req(), security_path=str(fake.path))
    assert res == {"available": False, "reason": "keychain_unavailable", "exists": None}


@pytest.mark.parametrize("service,account", [
    (None, ACCT), (SVC, None), ("has space", ACCT), (SVC, 'quo"te'), ("-starts-with-dash", ACCT),
    (SVC + "\n", ACCT), ("s" * 129, ACCT), ("", ACCT),
])
def test_preflight_bad_names_are_name_invalid(fake, service, account):
    res = keychain.preflight(req(service=service, account=account), security_path=str(fake.path))
    assert res == {"available": False, "reason": "keychain_name_invalid", "exists": None}
    assert [c["argv"][0] for c in fake.calls()] == ["default-keychain"]


def test_preflight_existing_item_with_security_in_acl_is_available(fake):
    fake.add_item(SVC, ACCT, "old")
    res = keychain.preflight(req(), security_path=str(fake.path))
    assert res == {"available": True, "reason": None, "exists": True}
    assert [c["argv"] for c in fake.calls()][-1] == ["dump-keychain", "-a", DEFAULT_KC]


def test_preflight_find_other_exit_code_is_unavailable(fake):
    fake.set(find_rc=51)
    res = keychain.preflight(req(), security_path=str(fake.path))
    assert res == {"available": False, "reason": "keychain_unavailable", "exists": None}


def test_preflight_reads_no_value(fake):
    fake.add_item(SVC, ACCT, "old")
    keychain.preflight(req(canary()), security_path=str(fake.path))
    for c in fake.calls():
        assert "-w" not in c["argv"]
        assert c["argv"][:1] != ["-i"]


# ---- access list (5.2, A.11 check 6) -------------------------------------------------------------

def test_existing_item_without_security_in_acl_is_denied_and_never_written(fake):
    fake.add_item(SVC, ACCT, "old", apps=["/bin/cat"])
    pf = keychain.preflight(req(canary()), security_path=str(fake.path))
    assert pf == {"available": False, "reason": "keychain_acl_denied", "exists": True}
    fake.reset_log()
    res = keychain.save(req(canary()), security_path=str(fake.path))
    assert res["saved"] is False and res["error"] == "keychain_acl_denied"
    assert res["main_touched"] is False and res["tmp_left"] is False
    assert [c for c in fake.calls() if c["argv"][:1] == ["-i"] or "-w" in c["argv"]] == []
    assert len(fake.calls()) == 2
    assert fake.value_of(SVC, ACCT) == "old"


def test_acl_with_empty_application_list_is_denied(fake):
    fake.add_item(SVC, ACCT, "old", apps=[])
    res = keychain.preflight(req(), security_path=str(fake.path))
    assert res["reason"] == "keychain_acl_denied"


def test_acl_open_to_every_application_is_denied(fake):
    fake.add_item(SVC, ACCT, "old", apps=None)
    res = keychain.preflight(req(), security_path=str(fake.path))
    assert res == {"available": False, "reason": "keychain_acl_denied", "exists": True}


def test_acl_dump_failure_is_denied(fake):
    fake.add_item(SVC, ACCT, "old")
    fake.set(dump_rc=1)
    res = keychain.preflight(req(), security_path=str(fake.path))
    assert res["reason"] == "keychain_acl_denied"


def _block(cls, svce, acct, apps, label=None, desc=None):
    lines = [f'keychain: "{DEFAULT_KC}"', "version: 512", f'class: "{cls}"' if cls else "class: 0x00000010 ",
             "attributes:", f'    0x00000007 <blob>="{label or svce}"']
    if acct is not None:
        lines.append(f'    "acct"<blob>="{acct}"')
    if svce is not None:
        lines.append(f'    "svce"<blob>="{svce}"')
    lines += ["access: 1 entries", "    entry 0:",
              "        authorizations (6): decrypt derive export_clear export_wrapped mac sign",
              "        don't-require-password", f"        description: {desc or svce}"]
    if apps is None:
        lines.append("        applications: <null>")
    else:
        lines.append(f"        applications ({len(apps)}):")
        lines += [f"            {n}: {p} (OK)" for n, p in enumerate(apps)]
    return "\n".join(lines) + "\n"


def _dump_with_target(fake, blocks):
    fake.add_item(SVC, ACCT, "old")      # so that find-generic-password says "exists"
    fake.set(dump_override="".join(blocks))
    return keychain.preflight(req(), security_path=str(fake.path))


def test_acl_picks_only_the_exact_genp_block_among_lookalikes(fake):
    sec, cat = ["/usr/bin/security"], ["/bin/cat"]
    blocks = [
        _block("genp", SVC + "x", ACCT, sec),           # service plus a suffix
        _block("genp", SVC[:-1], ACCT, sec),            # service minus last char
        _block("genp", SVC, ACCT + "x", sec),           # same service, other account
        _block("inet", SVC, ACCT, sec),                 # other class
        _block("genp", "other", "other", cat, label=SVC, desc=SVC),   # name only in label/description
        _block("genp", SVC, ACCT, cat),                 # the real target: no security -> denied
    ]
    assert _dump_with_target(fake, blocks)["reason"] == "keychain_acl_denied"


def test_acl_lookalikes_with_security_do_not_rescue_a_denied_target(fake):
    blocks = [_block("genp", SVC.upper(), ACCT, ["/usr/bin/security"]),
              _block("genp", SVC, ACCT, ["/Applications/Other.app"])]
    assert _dump_with_target(fake, blocks)["reason"] == "keychain_acl_denied"


def test_acl_exact_block_with_security_passes_among_lookalikes(fake):
    blocks = [_block("genp", SVC + "x", ACCT, ["/bin/cat"]),
              _block("genp", "other", "other", ["/bin/cat"], label=SVC, desc=SVC),
              _block("genp", SVC, ACCT, ["/bin/cat", "/usr/bin/security"])]
    assert _dump_with_target(fake, blocks) == {"available": True, "reason": None, "exists": True}


def test_acl_no_matching_block_is_denied(fake):
    blocks = [_block("genp", SVC + "x", ACCT, ["/usr/bin/security"]),
              _block("genp", "other", "other", ["/usr/bin/security"], label=SVC, desc=SVC)]
    assert _dump_with_target(fake, blocks)["reason"] == "keychain_acl_denied"


def test_acl_two_matching_blocks_are_denied(fake):
    blocks = [_block("genp", SVC, ACCT, ["/usr/bin/security"]),
              _block("genp", SVC, ACCT, ["/usr/bin/security"])]
    assert _dump_with_target(fake, blocks)["reason"] == "keychain_acl_denied"


def test_acl_null_applications_in_exact_block_is_denied(fake):
    blocks = [_block("genp", SVC, ACCT, None)]
    assert _dump_with_target(fake, blocks)["reason"] == "keychain_acl_denied"


def test_acl_one_decrypt_entry_open_to_every_application_is_denied_even_if_another_lists_security(fake):
    text = "\n".join([
        f'keychain: "{DEFAULT_KC}"', "version: 512", 'class: "genp"', "attributes:",
        f'    "acct"<blob>="{ACCT}"', f'    "svce"<blob>="{SVC}"', "access: 2 entries",
        "    entry 0:", "        authorizations (1): decrypt", "        applications: <null>",
        "    entry 1:", "        authorizations (6): decrypt derive export_clear export_wrapped mac sign",
        "        applications (1):", "            0: /usr/bin/security (OK)"]) + "\n"
    assert _dump_with_target(fake, [text])["reason"] == "keychain_acl_denied"


def test_acl_security_only_in_non_decrypt_entry_is_denied(fake):
    text = "\n".join([
        f'keychain: "{DEFAULT_KC}"', "version: 512", 'class: "genp"', "attributes:",
        f'    "acct"<blob>="{ACCT}"', f'    "svce"<blob>="{SVC}"', "access: 2 entries",
        "    entry 0:", "        authorizations (1): encrypt", "        applications (1):",
        "            0: /usr/bin/security (OK)",
        "    entry 1:", "        authorizations (6): decrypt derive export_clear export_wrapped mac sign",
        "        applications (1):", "            0: /bin/cat (OK)"]) + "\n"
    assert _dump_with_target(fake, [text])["reason"] == "keychain_acl_denied"


def test_save_rechecks_acl_and_writes_nothing_when_denied(fake):
    fake.add_item(SVC, ACCT, "old")
    assert keychain.preflight(req(canary()), security_path=str(fake.path))["available"] is True
    fake.add_item(SVC, ACCT, "old", apps=["/bin/cat"])     # changed between preflight and save
    fake.reset_log()
    res = keychain.save(req(canary()), security_path=str(fake.path))
    assert res["error"] == "keychain_acl_denied" and res["saved"] is False
    assert [c for c in fake.calls() if c["argv"][:1] == ["-i"]] == []


# ---- temp item verification (A.11 (다)) ----------------------------------------------------------

def test_temp_readback_mismatch_never_runs_the_main_write(fake):
    fake.add_item(SVC, ACCT, "old-value")
    fake.set(tmp_readback="something-else")
    res = run_save(fake, req(canary()))
    assert res["saved"] is False
    assert res["error"] == "keychain_verify_failed"
    assert res["main_touched"] is False
    assert res["tmp_left"] is False
    assert len(fake.writes("tmp")) == 1
    assert fake.writes("main") == []
    assert fake.value_of(SVC, ACCT) == "old-value"
    assert fake.value_of(TMP_SVC, ACCT) is None
    assert fake.calls()[-1]["argv"] == ["delete-generic-password", "-s", TMP_SVC, "-a", ACCT]


def test_temp_write_failure_never_runs_the_main_write(fake):
    fake.add_item(SVC, ACCT, "old-value")
    fake.set(write_rc={"tmp": 1})
    res = run_save(fake, req(canary()))
    assert res["error"] == "keychain_write_failed" and res["saved"] is False
    assert res["main_touched"] is False
    assert fake.writes("main") == []
    assert fake.value_of(SVC, ACCT) == "old-value"
    assert fake.calls()[-1]["argv"][0] == "delete-generic-password"


# ---- main write and read back (A.11 (라), (마)) ----------------------------------------------------

def test_main_write_failure_with_mismatch_is_write_failed(fake):
    fake.set(write_rc={"main": 1})
    res = run_save(fake, req(canary()))
    assert res["saved"] is False and res["error"] == "keychain_write_failed"
    assert res["main_touched"] is False  # N-1: a new item had no earlier value


def test_main_readback_mismatch_after_rc0_is_verify_failed(fake):
    fake.add_item(SVC, ACCT, "old-value")
    fake.set(main_readback="garbled")
    res = run_save(fake, req(canary()))
    assert res["saved"] is False and res["error"] == "keychain_verify_failed"
    assert res["main_touched"] is True and res["tmp_left"] is False
    assert res["replaced"] is None


def test_main_write_rc_nonzero_but_readback_equal_is_saved(fake):
    v = canary()
    fake.set(write_rc={"main": 1})
    keychain.preflight(req(v), security_path=str(fake.path))
    fake.add_item(SVC, ACCT, v)          # the value is there although the exit code was not 0
    fake.reset_log()
    # (가) now sees the item, so this is the existing-item path: 7 calls, all succeed by read back
    res = keychain.save(req(v), security_path=str(fake.path))
    assert res["saved"] is True and res["error"] is None


# ---- timeout (A.11) ------------------------------------------------------------------------------

def test_call_over_the_limit_is_killed_and_keychain_timeout(fake, monkeypatch):
    # 2 s, not 0.5 s: the limit also covers the fake's Python start, and under a loaded full run the first call
    # (default-keychain, which does not sleep) took over 0.5 s, timed out first and left no call logged.
    monkeypatch.setattr(keychain, "CALL_TIMEOUT_S", 2.0)
    fake.set(sleep={"find-generic-password": 30})
    t = time.monotonic()
    res = keychain.preflight(req(), security_path=str(fake.path))
    took = time.monotonic() - t
    assert res == {"available": False, "reason": "keychain_timeout", "exists": None}
    assert took < 5
    pid = fake.calls()[-1]["pid"]
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


def test_timeout_before_main_write_is_saved_false(fake, monkeypatch):
    fake.add_item(SVC, ACCT, "old")
    keychain.preflight(req(canary()), security_path=str(fake.path))
    monkeypatch.setattr(keychain, "CALL_TIMEOUT_S", 0.5)
    fake.set(sleep={"dump-keychain": 30})
    res = keychain.save(req(canary()), security_path=str(fake.path))
    assert res["error"] == "keychain_timeout" and res["saved"] is False
    assert res["main_touched"] is False


def test_timeout_in_main_write_is_saved_null_and_temp_removed(fake, monkeypatch):
    fake.add_item(SVC, ACCT, "old")
    v = canary()
    keychain.preflight(req(v), security_path=str(fake.path))
    monkeypatch.setattr(keychain, "CALL_TIMEOUT_S", 1.0)
    # only the main write sleeps: the temp write goes first in the same "-i" path, so make the
    # temp step fast by letting the fake sleep only for lines that are not the temp item
    fake.set(sleep={})
    fake.reset_log()

    original = keychain._run

    def slow_main(security_path, argv, **kw):
        if argv == ["-i"] and keychain.TMP_PREFIX not in kw.get("stdin", b"").decode():
            fake.set(sleep={"add-generic-password": 30})
            try:
                return original(security_path, argv, **kw)
            finally:
                fake.set(sleep={})
        return original(security_path, argv, **kw)

    monkeypatch.setattr(keychain, "_run", slow_main)
    res = keychain.save(req(v), security_path=str(fake.path))
    assert res["error"] == "keychain_timeout"
    assert res["saved"] is None
    assert res["main_touched"] is True
    assert res["tmp_left"] is False
    assert fake.value_of(TMP_SVC, ACCT) is None


def test_security_runs_in_the_callers_process_group(fake):
    keychain.preflight(req(), security_path=str(fake.path))
    # the fake records nothing about groups; check the module never asks for a new session
    src = inspect.getsource(keychain)
    assert "start_new_session" not in src
    assert "setsid" not in src and "setpgrp" not in src and "process_group" not in src


# ---- temp item cleanup (A.11 (바)) ---------------------------------------------------------------

def test_temp_delete_failure_sets_tmp_left(fake):
    fake.add_item(SVC, ACCT, "old")
    fake.set(delete_rc=1)
    res = run_save(fake, req(canary()))
    assert res["saved"] is True
    assert res["tmp_left"] is True


def test_temp_delete_44_counts_as_removed(fake):
    fake.add_item(SVC, ACCT, "old")
    fake.set(delete_rc=44)
    res = run_save(fake, req(canary()))
    assert res["tmp_left"] is False


def test_temp_removed_after_verify_failure_even_when_delete_fails(fake):
    fake.add_item(SVC, ACCT, "old")
    fake.set(tmp_readback="different", delete_rc=1)
    res = run_save(fake, req(canary()))
    assert res["error"] == "keychain_verify_failed"
    assert res["tmp_left"] is True
    assert fake.calls()[-1]["argv"][0] == "delete-generic-password"


def test_temp_removed_after_temp_readback_timeout(fake, monkeypatch):
    fake.add_item(SVC, ACCT, "old")
    keychain.preflight(req(canary()), security_path=str(fake.path))
    original = keychain._run

    def slow_tmp_read(security_path, argv, **kw):
        if argv[:1] == ["find-generic-password"] and "-w" in argv and TMP_SVC in argv:
            return {"rc": None, "out": b"", "timeout": True}
        return original(security_path, argv, **kw)

    monkeypatch.setattr(keychain, "_run", slow_tmp_read)
    fake.reset_log()
    res = keychain.save(req(canary()), security_path=str(fake.path))
    assert res["error"] == "keychain_timeout" and res["saved"] is False
    assert res["main_touched"] is False and res["tmp_left"] is False
    assert fake.value_of(TMP_SVC, ACCT) is None


def test_new_item_never_makes_a_temp_item(fake):
    run_save(fake, req(canary()))
    assert fake.writes("tmp") == []
    assert all(c["argv"][0] != "delete-generic-password" for c in fake.calls())


# ---- save (가) failures --------------------------------------------------------------------------

def test_save_exists_check_other_code_is_unavailable_saved_false(fake):
    keychain.preflight(req(canary()), security_path=str(fake.path))
    fake.set(find_rc=51)
    fake.reset_log()
    res = keychain.save(req(canary()), security_path=str(fake.path))
    assert res["saved"] is False and res["error"] == "keychain_unavailable"
    assert res["new_item"] is False and res["replaced"] is None
    assert len(fake.calls()) == 1


def test_save_existing_item_without_known_keychain_path_writes_nothing(fake):
    keychain._DEFAULT_KEYCHAIN.clear()
    fake.add_item(SVC, ACCT, "old")
    res = keychain.save(req(canary()), security_path=str(fake.path))
    assert res["saved"] is False and res["error"] == "keychain_unavailable"
    assert [c for c in fake.calls() if c["argv"][:1] == ["-i"]] == []


# ---- no exceptions, no outside text in results ----------------------------------------------------

def test_save_never_raises(fake, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("boom " + "secret text")

    monkeypatch.setattr(keychain, "_run", boom)
    res = keychain.save(req(canary()), security_path=str(fake.path))
    assert set(res) == RESULT_KEYS
    assert res["saved"] is None and res["error"] == "internal_error"


def test_preflight_never_raises(fake, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("boom")

    monkeypatch.setattr(keychain, "_run", boom)
    res = keychain.preflight(req(), security_path=str(fake.path))
    assert res == {"available": False, "reason": "internal_error", "exists": None}


def test_results_contain_only_fixed_words(fake):
    fake.add_item(SVC, ACCT, "old")
    fake.set(tmp_readback="x")
    res = run_save(fake, req(canary()))
    allowed = {None, "keychain_unavailable", "keychain_timeout", "keychain_acl_denied",
               "keychain_name_invalid", "keychain_value_unsupported", "keychain_line_too_long",
               "keychain_write_failed", "keychain_verify_failed", "internal_error"}
    assert res["error"] in allowed
    dumped = json.dumps(res)
    assert CANARY_PREFIX not in dumped


def test_request_extra_keys_are_ignored(fake):
    r = req(canary())
    r["security_path"] = "/bin/false"
    r["stores"] = ["keychain"]
    res = run_save(fake, r)
    assert res["saved"] is True
    assert all(Path(c["argv"][0]).name != "false" for c in fake.calls())


# ---- default executable (A.10) -------------------------------------------------------------------

def test_default_executable_is_usr_bin_security_and_not_changed_by_environment(fake, monkeypatch):
    monkeypatch.setenv("SECURITY_PATH", str(fake.path))
    monkeypatch.setenv("HERMES_SECURE_INPUT_SECURITY_PATH", str(fake.path))
    monkeypatch.setenv("PATH", str(fake.root) + os.pathsep + os.environ.get("PATH", ""))
    mod = importlib.reload(keychain)
    try:
        assert mod.SECURITY_PATH == "/usr/bin/security"
        for fn in (mod.preflight, mod.save):
            assert inspect.signature(fn).parameters["security_path"].default == "/usr/bin/security"
            assert inspect.signature(fn).parameters["security_path"].kind is inspect.Parameter.KEYWORD_ONLY

        seen = []

        class Refuse:
            def __init__(self, argv, *a, **k):
                seen.append(argv[0])
                raise OSError("not starting anything in this test")

        monkeypatch.setattr(mod.subprocess, "Popen", Refuse)
        res = mod.preflight(req())
        assert seen == ["/usr/bin/security"]
        assert res["available"] is False
        assert fake.calls() == []
    finally:
        monkeypatch.undo()
        importlib.reload(keychain)


def test_module_reads_no_environment_variables():
    src = inspect.getsource(keychain)
    assert "os.environ" not in src and "getenv" not in src


def test_module_imports_only_the_standard_library():
    import ast
    tree = ast.parse(inspect.getsource(keychain))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0
            names.add((node.module or "").split(".")[0])
    assert names <= set(sys.stdlib_module_names) | {"__future__"}
    assert "keyring" not in names and "ctypes" not in names
