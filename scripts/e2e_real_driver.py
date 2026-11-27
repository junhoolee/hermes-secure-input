#!/usr/bin/env python3
"""Real-server driver for ``ui/e2e/real-server.spec.ts`` (card criterion 3 and 5).

Starts ONE real request (``start_request``: real server process, real storage grandchild, built UI
from ``secure_input/static``) in a throwaway hermes_root, with a fake ``tailscale`` binary so the page
is reached on ``http://127.0.0.1:<port>/<token>/``. Protocol on stdio, one JSON object per line:

    stdout  {"event": "ready", "local_url": ..., "request_id": ...}
    stdin   {"expect": {...}}      # the canary values the browser typed (never argv/env)
    stdout  {"event": "result", "status": ..., "target_profile": ..., "checks": {name: bool}}

Values are only compared, never printed. The temp folder is deleted at the end.

Protocol 2 (plan appendix A): the page sends ``"v": 2`` and the chosen ``stores`` inside the encrypted content.
``--kind secret`` asks for a password that goes to the Mac keychain only, through an allow-list item whose service
starts with ``hermes-secure-input-test-`` (plan 7.3 task 5). The driver reads the item back with ``security
find-generic-password -w``, compares it, and deletes it. ``--security`` and ``--python`` exist for the repository's
tests (a fake ``security`` and a python wrapper that puts a fake keychain module into the storage process).
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "tests"))
sys.dont_write_bytecode = True
import pwd  # noqa: E402

_HERMES_AGENT = os.environ.get("SECURE_INPUT_HERMES_AGENT_DIR") or str(
    Path(pwd.getpwuid(os.getuid()).pw_dir) / ".hermes" / "hermes-agent")
sys.path.append(_HERMES_AGENT)  # agent.vault_store for the read-back check (appended: never shadows the repo)

from helpers.fake_tailscale import FakeTailscale  # noqa: E402
from secure_input.launcher import start_request  # noqa: E402
from secure_input.profiles import resolve_profile_home  # noqa: E402
from secure_input.serve import ServeManager  # noqa: E402
from secure_input.spec import RequestSpec, resolve_keychain  # noqa: E402

SECRET_TEST_PREFIX = "hermes-secure-input-test-"  # appendix A.1 TEST_PREFIX

SPECS = {
    "api_key": dict(purpose="Exa 웹 검색 도구를 쓰려면 API 키가 필요합니다", label="Exa API 키", env_var="EXA_API_KEY"),
    "login": dict(purpose="쇼핑몰 관리자 페이지를 점검하려면 로그인 정보가 필요합니다", label="예시 쇼핑몰 관리자",
                  origin="https://admin.example.com"),
    "otp_code": dict(purpose="accounts.example.com 로그인 도중 사이트가 일회용 코드를 요구했습니다",
                     label="accounts.example.com 일회용 코드", site="accounts.example.com"),
    "secret": dict(purpose="시험 스크립트가 Mac 키체인에서 읽을 비밀번호가 필요합니다", label="시험용 비밀번호"),
}


def secret_keychain() -> dict:
    """An allow-list item made for this run only (service and account ``hermes-secure-input-test-<random>``)."""
    name = SECRET_TEST_PREFIX + secrets.token_hex(6)
    allow = [{"id": "e2e-test-password", "service": name, "account": name, "label": "시험용 비밀번호",
              "used_by": "e2e 시험 드라이버"}]
    return resolve_keychain("secret", "e2e-test-password", allow=allow)


def keychain_read(security: str, service: str, account: str) -> tuple[int, str]:
    """``security find-generic-password -s -a -w``: (exit code, value). The value is only compared."""
    p = subprocess.run([security, "find-generic-password", "-s", service, "-a", account, "-w"],
                       capture_output=True, text=True, timeout=10)
    return p.returncode, p.stdout.rstrip("\n")


def keychain_delete(security: str, service: str, account: str) -> int:
    return subprocess.run([security, "delete-generic-password", "-s", service, "-a", account],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10).returncode
AUDIT_REQUIRED = {"ts", "event", "request_id", "path_fp", "requester", "purpose", "kind", "label", "target_profile",
                  "storage", "detail"}


def emit(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def audit_lines(home: Path) -> list[dict]:
    p = home / "logs" / "secure-input.jsonl"
    return [json.loads(x) for x in p.read_text().splitlines() if x.strip()] if p.exists() else []


def scan(root: Path, needles: list[str]) -> int:
    """Occurrences of any needle in every file under root except .env files and vault data files."""
    hits = 0
    for p in root.rglob("*"):
        if not p.is_file() or p.name == ".env" or "vault" in p.relative_to(root).parts:
            continue
        data = p.read_bytes()
        hits += sum(data.count(n.encode()) for n in needles if n)
    return hits


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--kind", choices=sorted(SPECS), required=True)
    ap.add_argument("--requested", default="default")
    ap.add_argument("--real-tailscale", action="store_true",
                    help="use the real Tailscale Serve (public tailnet URL) instead of the fake binary")
    ap.add_argument("--python", default=sys.executable, help="interpreter for the server and storage processes")
    ap.add_argument("--security", default="/usr/bin/security", help="keychain CLI used to read back and delete")
    args = ap.parse_args()

    tmp = Path(tempfile.mkdtemp(prefix="si-e2e-"))
    try:
        root = tmp / "hermes"
        for name in ("worker", "sage"):
            (root / "profiles" / name).mkdir(parents=True)
        if args.real_tailscale:
            serve = ServeManager()
            if serve.status_text() != "No serve config":
                emit({"event": "error", "error": "tailscale serve already has config; refusing to touch it"})
                return 2
        else:
            serve = ServeManager(bin=str(FakeTailscale(tmp / "fake-ts", dns_name="fake-host.example-tailnet.ts.net").bin))
        kind = args.kind
        extra = {"keychain": secret_keychain()} if kind == "secret" else {}
        spec = RequestSpec(kind=kind, requester={"type": "agent", "profile": "default", "platform": "slack",
                                                 "session_key": "e2e-session", "user_id": "U-E2E"},
                           target_profile=args.requested, profile_editable=kind not in ("otp_code", "secret"),
                           hermes_root=str(root), **SPECS[kind], **extra)
        handle = start_request(spec, serve=serve, python=args.python)
        emit({"event": "ready", "local_url": handle.local_url, "request_id": handle.request_id,
              **({"public_url": handle.url} if args.real_tailscale else {})})
        line = sys.stdin.readline()
        expect = (json.loads(line) if line.strip() else {}).get("expect", {})
        line = ""
        outcome = handle.wait(timeout=120)
        actual = outcome.meta.get("target_profile") or args.requested
        home = resolve_profile_home(actual, root)
        checks: dict[str, bool] = {}

        if kind == "api_key":
            env_lines = (home / ".env").read_text().splitlines() if (home / ".env").exists() else []
            checks["env_line_matches"] = env_lines.count(f"EXA_API_KEY={expect.get('value')}") == 1
            others = [resolve_profile_home(p, root) for p in ("default", "worker", "sage") if p != actual]
            checks["other_profiles_untouched"] = not any((h / ".env").exists() for h in others)
        elif kind == "login":
            os.environ["HERMES_HOME"] = str(home)
            from agent.vault_store import VaultStore
            store = VaultStore(base_dir=home / "vault")
            item_id = (outcome.meta.get("storage") or {}).get("item_id")
            secret = store.resolve_secret(item_id) if item_id else {}
            checks["password_matches"] = secret.get("password") == expect.get("password")
            meta = store.get_meta(item_id) if item_id else None  # Hermes keeps the login id in item metadata
            checks["identifier_matches"] = getattr(meta, "identifier", None) == expect.get("identifier")
            want_otp = bool(expect.get("otp_secret"))
            checks["otp_secret_presence_matches"] = bool(secret.get("otp_secret")) == want_otp
            if want_otp:
                checks["otp_secret_matches"] = (str(secret.get("otp_secret") or "").replace(" ", "").upper()
                                                == expect["otp_secret"].replace(" ", "").upper())
            checks["has_otp_meta_matches"] = bool((outcome.meta.get("storage") or {}).get("has_otp")) == want_otp
            secret.clear()
            others = [resolve_profile_home(p, root) for p in ("default", "worker", "sage") if p != actual]
            checks["other_profiles_untouched"] = not any((h / "vault").exists() for h in others)
        elif kind == "secret":
            kc = spec.keychain
            rows = outcome.meta.get("stores") or []
            checks["keychain_row_saved"] = (len(rows) == 1 and rows[0].get("store") == "keychain"
                                            and rows[0].get("saved") is True and rows[0].get("service") == kc["service"])
            code, value = keychain_read(args.security, kc["service"], kc["account"])
            checks["keychain_value_matches"] = code == 0 and value == expect.get("value")
            value = ""
            keychain_delete(args.security, kc["service"], kc["account"])
            checks["keychain_item_removed"] = keychain_read(args.security, kc["service"], kc["account"])[0] == 44
            checks["no_env_file"] = not any((resolve_profile_home(p, root) / ".env").exists()
                                            for p in ("default", "worker", "sage"))
        else:
            checks["code_matches"] = outcome.code == expect.get("code")
            outcome.code = None

        lines = audit_lines(resolve_profile_home("default", root))
        events = [x["event"] for x in lines if x.get("request_id") == handle.request_id]
        final = "delivered" if kind == "otp_code" else "saved"
        checks["audit_events"] = all(e in events for e in ("created", "opened", "submitted", final))
        checks["audit_fields"] = bool(lines) and all(AUDIT_REQUIRED <= set(x) for x in lines)
        checks["audit_context"] = bool(lines) and all(
            x["requester"].get("type") == "agent" and x["requester"].get("profile") == "default"
            and x["purpose"] == spec.purpose and x["kind"] == kind and x["label"] == spec.label for x in lines)
        if actual != "default":
            chosen = audit_lines(home)
            checks["audit_in_chosen_profile"] = any(x["event"] == "saved" and x["target_profile"] == actual
                                                    for x in chosen)
        needles = [str(v) for v in expect.values() if v]
        checks["no_canary_outside_env_and_vault"] = scan(root, needles) == 0
        handle_stderr = handle.stderr_text
        checks["no_canary_in_child_stderr"] = not any(n in handle_stderr for n in needles)
        expect.clear()
        extra: dict = {}
        if args.real_tailscale:
            import httpx
            import time as _time
            _time.sleep(1.0)
            try:
                code = httpx.get(handle.url, timeout=10).status_code
                extra["ended_url"] = str(code)
            except httpx.HTTPError as exc:
                code = None
                extra["ended_url"] = type(exc).__name__
            checks["ended_url_404_or_refused"] = code == 404 or code is None
            extra["serve_status"] = serve.status_text()
            checks["serve_status_clean"] = extra["serve_status"] == "No serve config"
        emit({"event": "result", "status": outcome.status, "target_profile": actual, "checks": checks, **extra})
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
