#!/usr/bin/env python3
"""Real round trips of protocol 2 (plan 7.3 "작업 5", integration card 4.4).

Every case starts ONE real request with ``start_request`` (real server child process, real storage grandchild,
real ``secure_input.stores.keychain`` module, real ``/usr/bin/security``) in a throwaway hermes_root under /tmp.
Tailscale is the fake binary of ``tests/helpers/fake_tailscale.py``; the page side is
``tests/helpers/browser_client.py`` talking to ``http://127.0.0.1:<port>/<token>/``.

The storage grandchild runs through a python wrapper that only times each ``security`` call (verb and seconds,
no arguments) and, for the Tailscale probe, can sleep before a save. It does not change what the module does.

Cases (card 4.4):
  1. api_key to .env and a new keychain item ``hermes-secure-input.test-<random>``
  2. login to the Hermes vault
  3. secret to an allow-listed item (service ``hermes-secure-input-test-<random>``) that already exists
  4. secret to a new item ``hermes-secure-input.test-<random>`` (not on the allow list)
  5. api_key to .env and the keychain where .env cannot be written: ``partial``
  6. secret to an allow-listed item whose access list lacks ``/usr/bin/security``: nothing written

Safety: values are fake (``SECRET-CANARY-<random>``), only compared, never printed or written to the result.
Only items whose service starts with ``hermes-secure-input-test-``, ``hermes-secure-input.test-`` or the
module's own ``hermes-secure-input.tmp.`` are made, and all of them are deleted in ``finally``. No value of any
other item is read. The item of case 6 is never read. The real ~/.hermes is not touched.

Run:  ~/.hermes/hermes-agent/.venv/bin/python -P scripts/real_roundtrip_v2.py [result.json]
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "tests"))
sys.dont_write_bytecode = True
import pwd  # noqa: E402

_HERMES_AGENT = os.environ.get("SECURE_INPUT_HERMES_AGENT_DIR") or str(
    Path(pwd.getpwuid(os.getuid()).pw_dir) / ".hermes" / "hermes-agent")
sys.path.append(_HERMES_AGENT)  # agent.vault_store for the read-back (appended: never shadows the repo)

from helpers.browser_client import BrowserClient  # noqa: E402
from helpers.fake_tailscale import FAKE_OWNER_LOGIN, FakeTailscale  # noqa: E402
from secure_input.launcher import start_request  # noqa: E402
from secure_input.serve import ServeManager  # noqa: E402
from secure_input.spec import RequestSpec, build_store_rows, resolve_keychain  # noqa: E402
from secure_input.stores import keychain as kcmod  # noqa: E402

SEC = "/usr/bin/security"
CANARY_PREFIX = "SECRET-" + "CANARY-"
NEW_TEST_PREFIX = kcmod.SERVICE_PREFIX + "test-"        # hermes-secure-input.test-
PREFIXES = (kcmod.TEST_PREFIX, NEW_TEST_PREFIX, kcmod.TMP_PREFIX)
OUT_DEFAULT = REPO / "docs" / "plans" / "storage-targets-impl-probes" / "real_roundtrip_v2.json"

BOOT = r"""
import io, json, sys, time
TIMING = {timing!r}
DELAY = {delay!r}
data = sys.stdin.read()
phase = json.loads(data).get("phase")
from secure_input.stores import keychain
_orig = keychain._run
def _timed(security_path, argv, **kw):
    t = time.monotonic()
    try:
        return _orig(security_path, argv, **kw)
    finally:
        with open(TIMING, "a") as f:
            f.write(json.dumps({{"phase": phase, "verb": argv[0] if argv else "",
                                "secs": round(time.monotonic() - t, 4)}}) + "\n")
keychain._run = _timed
if DELAY and phase == "save":
    time.sleep(DELAY)
sys.stdin = io.StringIO(data)
data = None
from secure_input import storage
sys.exit(storage.main())
"""


# --- keychain helpers (no value of another item is ever read) --------------------------------------------------

def sec(argv, stdin: bytes | None = None, capture=False, timeout=10.0):
    p = subprocess.run([SEC, *argv], input=stdin, stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=timeout)
    return p.returncode, (p.stdout if capture else b"")


def default_keychain() -> str:
    _rc, out = sec(["default-keychain"], capture=True)
    return out.decode("utf-8", "replace").strip().strip('"')


def our_items() -> list[dict]:
    """Items of the default keychain whose service starts with one of PREFIXES: service, account, mdat only."""
    _rc, out = sec(["dump-keychain", "-a", default_keychain()], capture=True, timeout=20.0)
    items, cur = [], None
    for line in out.decode("utf-8", "replace").splitlines():
        s = line.strip()
        if line.startswith("keychain: "):
            cur = {}
            items.append(cur)
        elif cur is not None:
            for key, tag in (("service", '"svce"<blob>="'), ("account", '"acct"<blob>="'),
                             ("mdat", '"mdat"<timedate>=')):
                if s.startswith(tag):
                    cur[key] = s[len(tag):].rstrip('"')
    out = b""
    return [i for i in items if any(i.get("service", "").startswith(p) for p in PREFIXES)]


def prefix_counts() -> dict:
    items = our_items()
    return {p: sum(1 for i in items if i.get("service", "").startswith(p)) for p in PREFIXES}


def kc_create(service: str, account: str, value: str, trusted: str) -> int:
    """Make a test item with ``security -i`` (value as hex on stdin) whose access list trusts ``trusted`` only."""
    assert service.startswith(PREFIXES[:2])
    line = f'add-generic-password -a "{account}" -s "{service}" -T "{trusted}" -X {value.encode().hex()}\n'
    rc, _ = sec(["-i"], stdin=line.encode())
    return rc


def kc_equal(service: str, account: str, expected: str) -> bool:
    """Read back an item this script or the plugin made (its access list has /usr/bin/security) and compare."""
    rc, out = sec(["find-generic-password", "-s", service, "-a", account, "-w"], capture=True)
    got = out[:-1] if out.endswith(b"\n") else out
    ok = rc == 0 and got == expected.encode()
    got = out = b""
    return ok


def kc_delete(service: str, account: str) -> int:
    assert service.startswith(PREFIXES)
    return sec(["delete-generic-password", "-s", service, "-a", account])[0]


def security_agents() -> int:
    p = subprocess.run(["/usr/bin/pgrep", "-x", "SecurityAgent"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    return len(p.stdout.split())


# --- one request --------------------------------------------------------------------------------------------------

def canary() -> str:
    return CANARY_PREFIX + secrets.token_hex(8)


def storage_python(folder: Path, timing: Path, delay: float = 0.0) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    boot = folder / "boot.py"
    boot.write_text(BOOT.format(timing=str(timing), delay=delay))
    wrapper = folder / "python-wrapper"
    wrapper.write_text("#!/bin/sh\n"
                       "case \"$*\" in\n"
                       f"  *secure_input.storage*) exec '{sys.executable}' -P '{boot}' ;;\n"
                       "esac\n"
                       f"exec '{sys.executable}' \"$@\"\n")
    wrapper.chmod(wrapper.stat().st_mode | stat.S_IXUSR)
    return wrapper


def scan(root: Path, needles: list[str]) -> int:
    """Occurrences of any needle in every file under root except .env files and vault data files."""
    hits = 0
    for p in root.rglob("*"):
        if not p.is_file() or p.name == ".env" or "vault" in p.relative_to(root).parts:
            continue
        data = p.read_bytes()
        hits += sum(data.count(n.encode()) for n in needles if n)
    return hits


def audit_events(root: Path, request_id: str) -> list[str]:
    p = root / "logs" / "secure-input.jsonl"
    lines = [json.loads(x) for x in p.read_text().splitlines() if x.strip()] if p.exists() else []
    return [x["event"] for x in lines if x.get("request_id") == request_id]


def timings(path: Path) -> dict:
    rows = [json.loads(x) for x in path.read_text().splitlines()] if path.exists() else []
    out = {}
    for phase in ("preflight", "save"):
        rs = [r for r in rows if r["phase"] == phase]
        out[phase] = {"calls": [[r["verb"], r["secs"]] for r in rs], "count": len(rs),
                      "total_secs": round(sum(r["secs"] for r in rs), 3),
                      "max_secs": round(max((r["secs"] for r in rs), default=0.0), 3)}
    return out


def strip_values(body):
    """The submit answer without anything that could carry a value (it carries none; this is a guard)."""
    return json.loads(json.dumps(body))


class Case:
    def __init__(self, name: str, base: Path):
        self.name = name
        self.tmp = Path(tempfile.mkdtemp(prefix=f"si-rt2-{name}-", dir="/tmp"))
        self.root = self.tmp / "hermes"
        for p in ("worker", "sage"):
            (self.root / "profiles" / p).mkdir(parents=True)
        self.timing = self.tmp / "timing.jsonl"
        self.handle = None

    def start(self, spec_kwargs: dict, delay: float = 0.0, serve: ServeManager | None = None):
        python = storage_python(self.tmp / "py", self.timing, delay)
        serve = serve or ServeManager(bin=str(FakeTailscale(self.tmp / "fake-ts",
                                                             dns_name="fake-host.example-tailnet.ts.net").bin))
        spec = RequestSpec(requester={"type": "agent", "profile": "default", "platform": "slack",
                                      "session_key": "rt2-session", "user_id": "U-RT2"},
                           hermes_root=str(self.root), **spec_kwargs)
        self.spec = spec
        self.handle = start_request(spec, serve=serve, python=str(python))
        return self.handle

    def client(self, base_url: str | None = None, identity: str | None = FAKE_OWNER_LOGIN) -> BrowserClient:
        return BrowserClient(base_url or self.handle.local_url, identity=identity, timeout=90.0)

    def finish(self, needles: list[str]) -> dict:
        outcome = self.handle.wait(timeout=120)
        stderr = self.handle.stderr_text
        res = {"parent_status": outcome.status,
               "parent_partial": outcome.meta.get("partial"),
               "parent_reason": outcome.meta.get("reason"),
               "parent_stores": outcome.meta.get("stores"),
               "audit_events": audit_events(self.root, self.handle.request_id),
               "security_calls": timings(self.timing),
               "no_canary_in_logs_and_files": scan(self.root, needles) == 0 and not any(n in stderr for n in needles)}
        return res

    def cleanup(self):
        if self.handle is not None and self.handle.returncode is None:
            self.handle.cancel(grace=1.0)
        for p in self.root.rglob("*"):
            if p.is_dir():
                p.chmod(0o755)
        shutil.rmtree(self.tmp, ignore_errors=True)


def submit_once(c: BrowserClient, plaintext: dict) -> tuple[int, dict, float]:
    t = time.monotonic()
    r = c.submit(plaintext, auto_stores=False)
    secs = round(time.monotonic() - t, 3)
    try:
        body = r.json()
    except ValueError:
        body = {}
    return r.status_code, strip_values(body), secs


def env_value_equal(home: Path, name: str, value: str) -> bool:
    p = home / ".env"
    return p.exists() and p.read_text().splitlines().count(f"{name}={value}") == 1


def vault_equal(home: Path, item_id, identifier: str, password: str) -> dict:
    old = os.environ.get("HERMES_HOME")
    os.environ["HERMES_HOME"] = str(home)
    try:
        from agent.vault_store import VaultStore
        store = VaultStore(base_dir=home / "vault")
        secret = store.resolve_secret(item_id) if item_id else {}
        meta = store.get_meta(item_id) if item_id else None
        out = {"password_matches": secret.get("password") == password,
               "identifier_matches": getattr(meta, "identifier", None) == identifier}
        secret.clear()
        return out
    finally:
        if old is None:
            os.environ.pop("HERMES_HOME", None)
        else:
            os.environ["HERMES_HOME"] = old


API = dict(purpose="통합 시험: 검색 도구 키", label="시험용 API 키", env_var="EXA_API_KEY")
LOGIN = dict(purpose="통합 시험: 관리자 페이지 로그인", label="시험용 관리자", origin="https://admin.example.com")
SECRET = dict(purpose="통합 시험: 키체인에서 읽을 비밀번호", label="시험용 비밀번호")


def api_spec(item: str, profile="default") -> dict:
    stores = build_store_rows("api_key", [{"store": "env"}, {"store": "keychain"}])
    return dict(kind="api_key", target_profile=profile, profile_editable=True, stores=stores,
                keychain=resolve_keychain("api_key", item, env_var=API["env_var"], keychain_chosen=True), **API)


def secret_spec(item: str, allow=()) -> dict:
    return dict(kind="secret", target_profile="default", profile_editable=False,
                keychain=resolve_keychain("secret", item, allow=list(allow)), **SECRET)


def allow_item(service: str) -> dict:
    return {"id": "rt2-test-item", "service": service, "account": service, "label": "시험용 허용 항목",
            "used_by": "통합 시험 스크립트"}


def case_api_two_stores(made: list) -> dict:
    case = Case("api", Path("/tmp"))
    try:
        item = "test-" + secrets.token_hex(5)
        service = kcmod.SERVICE_PREFIX + item
        made.append((service, kcmod.FIXED_ACCOUNT))
        case.start(api_spec(item))
        c = case.client()
        opened = c.open().json()
        v = canary()
        code, body, secs = submit_once(c, {"kind": "api_key", "target_profile": "default", "value": v,
                                           "stores": ["env", "keychain"]})
        res = case.finish([v])
        res.update(http_status=code, submit_status=(body.get("result") or {}).get("status"),
                   submit_stores=(body.get("result") or {}).get("stores"), submit_secs=secs,
                   open_stores=[{k: r[k] for k in ("store", "available", "unavailable_reason", "exists")}
                                for r in opened["target"]["stores"]],
                   keychain_service=service,
                   readback={"env_equal": env_value_equal(case.root, "EXA_API_KEY", v),
                             "keychain_equal": kc_equal(service, kcmod.FIXED_ACCOUNT, v)})
        v = ""
        return res
    finally:
        case.cleanup()


def case_login_vault(made: list) -> dict:
    case = Case("login", Path("/tmp"))
    try:
        case.start(dict(kind="login", target_profile="default", profile_editable=True, **LOGIN))
        c = case.client()
        c.open()
        ident, pw = canary().lower() + "@example.com", canary()
        code, body, secs = submit_once(c, {"kind": "login", "target_profile": "default", "identifier_type": "email",
                                           "identifier": ident, "password": pw, "otp_secret": "",
                                           "stores": ["hermes_vault"]})
        res = case.finish([ident, pw])
        rows = res["parent_stores"] or []
        item_id = rows[0].get("item_id") if rows else None
        res.update(http_status=code, submit_status=(body.get("result") or {}).get("status"),
                   submit_stores=(body.get("result") or {}).get("stores"), submit_secs=secs,
                   readback=vault_equal(case.root, item_id, ident, pw))
        ident = pw = ""
        return res
    finally:
        case.cleanup()


def case_secret_listed_existing(made: list) -> dict:
    case = Case("secret-listed", Path("/tmp"))
    try:
        service = kcmod.TEST_PREFIX + secrets.token_hex(6)
        made.append((service, service))
        before_rc = kc_create(service, service, "fake-old-" + secrets.token_hex(6), SEC)
        case.start(secret_spec("rt2-test-item", allow=[allow_item(service)]))
        c = case.client()
        opened = c.open().json()
        v = canary()
        code, body, secs = submit_once(c, {"kind": "secret", "target_profile": "default", "value": v,
                                           "stores": ["keychain"]})
        res = case.finish([v])
        res.update(http_status=code, submit_status=(body.get("result") or {}).get("status"),
                   submit_stores=(body.get("result") or {}).get("stores"), submit_secs=secs,
                   prepared_item_rc=before_rc, keychain_service=service,
                   open_stores=[{k: r[k] for k in ("store", "available", "unavailable_reason", "exists")}
                                for r in opened["target"]["stores"]],
                   open_keychain={k: opened["target"]["keychain"][k] for k in ("listed", "new_item")},
                   readback={"keychain_equal": kc_equal(service, service, v)})
        v = ""
        return res
    finally:
        case.cleanup()


def case_secret_new(made: list) -> dict:
    case = Case("secret-new", Path("/tmp"))
    try:
        item = "test-" + secrets.token_hex(5)
        service = kcmod.SERVICE_PREFIX + item
        made.append((service, kcmod.FIXED_ACCOUNT))
        case.start(secret_spec(item))
        c = case.client()
        opened = c.open().json()
        v = canary()
        code, body, secs = submit_once(c, {"kind": "secret", "target_profile": "default", "value": v,
                                           "stores": ["keychain"]})
        res = case.finish([v])
        res.update(http_status=code, submit_status=(body.get("result") or {}).get("status"),
                   submit_stores=(body.get("result") or {}).get("stores"), submit_secs=secs,
                   keychain_service=service,
                   open_keychain={k: opened["target"]["keychain"][k] for k in ("listed", "new_item")},
                   readback={"keychain_equal": kc_equal(service, kcmod.FIXED_ACCOUNT, v)})
        v = ""
        return res
    finally:
        case.cleanup()


def case_partial(made: list) -> dict:
    case = Case("partial", Path("/tmp"))
    try:
        item = "test-" + secrets.token_hex(5)
        service = kcmod.SERVICE_PREFIX + item
        made.append((service, kcmod.FIXED_ACCOUNT))
        worker = case.root / "profiles" / "worker"
        case.start(api_spec(item, profile="worker"))
        c = case.client()
        c.open()
        # After the create-time check: a folder where Hermes' writer wants its lock file (<home>/.env.lock), so
        # opening the lock fails and the .env write fails. (A read-only profile folder does not work: Hermes'
        # ensure_hermes_home() makes the folder writable again.) The pre-write check does not take the lock.
        (worker / ".env.lock").mkdir()
        v = canary()
        code, body, secs = submit_once(c, {"kind": "api_key", "target_profile": "worker", "value": v,
                                           "stores": ["env", "keychain"]})
        res = case.finish([v])
        res["audit_events"] = audit_events(worker, case.handle.request_id)
        res.update(http_status=code, submit_status=(body.get("result") or {}).get("status"),
                   submit_partial=(body.get("result") or {}).get("partial"),
                   submit_stores=(body.get("result") or {}).get("stores"), submit_secs=secs,
                   keychain_service=service,
                   readback={"env_file_exists": (worker / ".env").exists(),
                             "keychain_equal": kc_equal(service, kcmod.FIXED_ACCOUNT, v)})
        v = ""
        return res
    finally:
        case.cleanup()


def case_acl_denied(made: list) -> dict:
    case = Case("acl", Path("/tmp"))
    try:
        service = kcmod.TEST_PREFIX + secrets.token_hex(6)
        made.append((service, service))
        before_rc = kc_create(service, service, "fake-old-" + secrets.token_hex(6), "/bin/cat")
        mdat_before = next((i.get("mdat") for i in our_items() if i.get("service") == service), None)
        case.start(secret_spec("rt2-test-item", allow=[allow_item(service)]))
        c = case.client()
        opened = c.open().json()
        v = canary()
        answers = []
        for _ in range(6):  # more than MAX_SUBMIT_ATTEMPTS (5): a counted failure would end the request on the 5th
            code, body, secs = submit_once(c, {"kind": "secret", "target_profile": "default", "value": v,
                                               "stores": ["keychain"]})
            answers.append({"http_status": code, "error_code": body.get("error_code"), "stores": body.get("stores"),
                            "secs": secs})
        cancel = c.cancel()
        res = case.finish([v])
        v = ""
        items = our_items()
        res.update(prepared_item_rc=before_rc, keychain_service=service,
                   open_stores=[{k: r[k] for k in ("store", "available", "unavailable_reason", "exists")}
                                for r in opened["target"]["stores"]],
                   submits=answers, cancel_http_status=cancel.status_code,
                   item_mdat_unchanged=mdat_before is not None and mdat_before == next(
                       (i.get("mdat") for i in items if i.get("service") == service), None),
                   tmp_items_now=sum(1 for i in items if i.get("service", "").startswith(kcmod.TMP_PREFIX)))
        return res
    finally:
        case.cleanup()


def main() -> int:
    out_path = Path(sys.argv[1]) if len(sys.argv) > 1 else OUT_DEFAULT
    result: dict = {"when": time.strftime("%F %T %Z"), "security": SEC, "tailscale": "fake (tests/helpers)",
                    "securityagent_before": security_agents(), "prefix_counts_before": prefix_counts(), "cases": {}}
    made: list = []
    cases = [("1_api_key_env_and_keychain_new", case_api_two_stores),
             ("2_login_vault", case_login_vault),
             ("3_secret_listed_existing", case_secret_listed_existing),
             ("4_secret_new_unlisted", case_secret_new),
             ("5_api_key_partial_env_fails", case_partial),
             ("6_secret_acl_denied", case_acl_denied)]
    try:
        for name, fn in cases:
            try:
                result["cases"][name] = fn(made)
            except Exception as exc:  # keep going; the error type only (never a value)
                result["cases"][name] = {"error": type(exc).__name__}
            print(name, "done", flush=True)
    finally:
        deleted = {}
        for service, account in made:
            deleted[service] = kc_delete(service, account)
        for item in our_items():  # anything of ours left (e.g. a temp item)
            deleted[item["service"]] = kc_delete(item["service"], item["account"])
        result["cleanup_delete_rc"] = deleted
        result["prefix_counts_after"] = prefix_counts()
        result["securityagent_after"] = security_agents()
    c = result["cases"]

    def g(name, *keys):
        x = c.get(name, {})
        for k in keys:
            x = x.get(k) if isinstance(x, dict) else None
        return x

    def rows(name):
        return {r["store"]: r for r in (g(name, "parent_stores") or [])}

    result["checks"] = {
        "1_saved": g("1_api_key_env_and_keychain_new", "parent_status") == "saved"
        and g("1_api_key_env_and_keychain_new", "parent_partial") is False,
        "1_readback": g("1_api_key_env_and_keychain_new", "readback") == {"env_equal": True, "keychain_equal": True},
        "1_keychain_new_item": rows("1_api_key_env_and_keychain_new").get("keychain", {}).get("new_item") is True,
        "1_save_calls_3": g("1_api_key_env_and_keychain_new", "security_calls", "save", "count") == 2 + 3,
        "2_saved": g("2_login_vault", "parent_status") == "saved",
        "2_readback": g("2_login_vault", "readback") == {"password_matches": True, "identifier_matches": True},
        "3_saved_replaced": g("3_secret_listed_existing", "parent_status") == "saved"
        and rows("3_secret_listed_existing").get("keychain", {}).get("replaced") is True,
        "3_save_calls_3_plus_7": g("3_secret_listed_existing", "security_calls", "save", "count") == 3 + 7,
        "3_readback": g("3_secret_listed_existing", "readback") == {"keychain_equal": True},
        "4_saved_new_item": g("4_secret_new_unlisted", "parent_status") == "saved"
        and rows("4_secret_new_unlisted").get("keychain", {}).get("new_item") is True,
        "4_readback": g("4_secret_new_unlisted", "readback") == {"keychain_equal": True},
        "5_partial": g("5_api_key_partial_env_fails", "parent_status") == "saved"
        and g("5_api_key_partial_env_fails", "parent_partial") is True
        and g("5_api_key_partial_env_fails", "submit_status") == "saved"
        and g("5_api_key_partial_env_fails", "submit_partial") is True,
        "5_env_failed_keychain_saved": rows("5_api_key_partial_env_fails").get("env", {}).get("saved") is False
        and rows("5_api_key_partial_env_fails").get("keychain", {}).get("saved") is True,
        "5_readback": g("5_api_key_partial_env_fails", "readback") == {"env_file_exists": False,
                                                                        "keychain_equal": True},
        "6_all_store_unavailable": [s.get("error_code") for s in (g("6_secret_acl_denied", "submits") or [])]
        == ["store_unavailable"] * 6,
        "6_reason_acl_denied": all(s.get("stores") == [{"store": "keychain", "reason": "keychain_acl_denied"}]
                                   for s in (g("6_secret_acl_denied", "submits") or [{}])),
        "6_not_counted_still_opened": g("6_secret_acl_denied", "cancel_http_status") == 200
        and g("6_secret_acl_denied", "parent_status") == "cancelled",
        "6_nothing_written": g("6_secret_acl_denied", "item_mdat_unchanged") is True
        and g("6_secret_acl_denied", "tmp_items_now") == 0
        and "-i" not in [v for v, _s in (g("6_secret_acl_denied", "security_calls", "save", "calls") or [])],
        "no_canary_in_logs_every_case": all(x.get("no_canary_in_logs_and_files") is True for x in c.values()),
        "prefix_items_after_all_0": all(v == 0 for v in result["prefix_counts_after"].values()),
        "no_new_securityagent": result["securityagent_after"] <= result["securityagent_before"],
    }
    text = json.dumps(result, ensure_ascii=False, indent=1)
    assert CANARY_PREFIX not in text
    out_path.write_text(text + "\n")
    print(json.dumps({"checks": result["checks"], "prefix_counts_after": result["prefix_counts_after"]}, indent=1))
    return 0 if all(result["checks"].values()) else 1


if __name__ == "__main__":
    sys.exit(main())
