#!/usr/bin/env python3
"""Real-server driver for ``ui/e2e/screenshots.spec.ts`` (final captures).

Starts ONE real secure-input request (``start_request``: real server process, real storage grandchild,
built page from ``secure_input/static``) in a throwaway hermes_root with profiles default, worker and sage,
and a fake ``tailscale`` binary, so the page is reached on ``http://127.0.0.1:<port>/<token>/``.
Only the fake owner account may use the link: the browser sends ``Tailscale-User-Login`` itself
(``extraHTTPHeaders`` in the specs), as Tailscale Serve would.
The request uses the fixed scenarios A, B, C of the UI review card.

    --scenario A|B|C        which request to make
    --mode form             normal request (the browser fills and submits it)
    --mode opened           the driver itself calls api/open first, so the browser lands on "already opened"
    --mode timeout          the submit window is shortened to a few seconds (test-only TTL)

Protocol on stdio, one JSON object per line:

    stdout  {"event": "ready", "local_url": ..., "submit_deadline_s": ...}
    stdin   {"finish": true}     # the browser is done; wait briefly, then cancel if still open
    stdout  {"event": "result", "status": ...}

No value is ever printed. The temp folder is deleted at the end.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "tests"))
sys.dont_write_bytecode = True
# Like the gateway: RequestSpec checks env names with hermes_cli.config (appended: never shadows the repo).
sys.path.append(os.environ.get("SECURE_INPUT_HERMES_AGENT_DIR") or str(Path.home() / ".hermes" / "hermes-agent"))

from helpers.fake_tailscale import OWNER_HEADER, FakeTailscale  # noqa: E402
from secure_input.launcher import start_request  # noqa: E402
from secure_input.serve import ServeManager  # noqa: E402
from secure_input.spec import RequestSpec  # noqa: E402

SCENARIOS = {
    "A": dict(kind="api_key", purpose="Exa 웹 검색 도구를 쓰려면 API 키가 필요합니다", label="Exa API 키",
              requester_profile="default", target_profile="default", profile_editable=True, env_var="EXA_API_KEY"),
    "B": dict(kind="login", purpose="쇼핑몰 관리자 페이지를 점검하려면 로그인 정보가 필요합니다", label="예시 쇼핑몰 관리자",
              requester_profile="worker", target_profile="worker", profile_editable=True,
              origin="https://admin.example.com"),
    "C": dict(kind="otp_code", purpose="accounts.example.com 로그인 도중 사이트가 일회용 코드를 요구했습니다",
              label="accounts.example.com 일회용 코드", requester_profile="default", target_profile="default",
              profile_editable=False, site="accounts.example.com"),
}
TIMEOUT_SUBMIT_S = 4


def emit(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", choices=sorted(SCENARIOS), required=True)
    ap.add_argument("--mode", choices=("form", "opened", "timeout"), default="form")
    args = ap.parse_args()

    tmp = Path(tempfile.mkdtemp(prefix="si-capture-"))
    try:
        root = tmp / "hermes"
        root.mkdir()
        for name in ("worker", "sage"):
            (root / "profiles" / name).mkdir(parents=True)
        serve = ServeManager(bin=str(FakeTailscale(tmp / "fake-ts", dns_name="fake-host.example-tailnet.ts.net").bin))
        s = dict(SCENARIOS[args.scenario])
        requester_profile = s.pop("requester_profile")
        spec = RequestSpec(requester={"type": "agent", "profile": requester_profile, "platform": "slack",
                                      "session_key": "capture-session", "user_id": "U-CAPTURE"},
                           hermes_root=str(root), **s)
        ttls = {"submit": TIMEOUT_SUBMIT_S} if args.mode == "timeout" else None
        handle = start_request(spec, serve=serve, _test_ttls=ttls)
        deadline = None
        if args.mode == "opened":
            # Someone (here: the driver) already opened the link once.
            req = urllib.request.Request(handle.local_url + "api/open", data=b"{}", method="POST",
                                         headers={"Content-Type": "application/json", **OWNER_HEADER})
            with urllib.request.urlopen(req, timeout=10) as r:
                deadline = json.loads(r.read().decode("utf-8")).get("submit_deadline_s")
        emit({"event": "ready", "local_url": handle.local_url, "mode": args.mode, "opened_by_driver": deadline is not None})
        sys.stdin.readline()
        try:
            # "opened" never gets a submit, so it is cancelled after a short wait.
            outcome = handle.wait(timeout=2 if args.mode == "opened" else 15)
        except TimeoutError:
            outcome = handle.cancel()
        emit({"event": "result", "status": outcome.status, "reason": outcome.meta.get("reason")})
        outcome.code = None
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
