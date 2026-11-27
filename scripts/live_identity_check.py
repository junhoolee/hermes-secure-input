#!/usr/bin/env python3
"""Live check of "who opened the link" (security review S-4) through the REAL Tailscale Serve.

Run from the repository root on the Mac that runs Hermes:

    ~/.hermes/hermes-agent/.venv/bin/python -P scripts/live_identity_check.py \
        > docs/security-review/results-after-fix/live_identity.json

It adds test paths to the real Serve config for a few seconds and removes them again; it does nothing
when Serve already has other config. The Hermes home is a temp folder and no credential value is
submitted. Output: JSON with booleans, counts and HTTP statuses only. No tailnet host name, no account
name, no path token is printed.

1. allow list = the owner account (``start_request`` without a list): ``POST api/open`` via Serve -> 200.
2. new request whose allow list is ``someone-else@example.com`` only: ``POST api/open`` via Serve -> 403
   ``identity_not_allowed``; the link is still unused afterwards.
3. same as 2, but the client itself sends ``Tailscale-User-Login: someone-else@example.com`` through Serve:
   status, plus (test hook on an in-process server built by the same ``create_app``) how many
   ``Tailscale-User-Login`` headers reached the server and whether the value equals the client's.
4. ``tailscale serve status`` = "No serve config" at the end.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.dont_write_bytecode = True
# Like the gateway: RequestSpec checks env names with hermes_cli.config (appended: never shadows the repo).
sys.path.append(os.environ.get("SECURE_INPUT_HERMES_AGENT_DIR") or str(Path.home() / ".hermes" / "hermes-agent"))

import httpx  # noqa: E402

from secure_input.launcher import new_token, start_request  # noqa: E402
from secure_input.serve import ServeManager  # noqa: E402
from secure_input.server import IDENTITY_HEADER, ServerContext, create_app  # noqa: E402
from secure_input.spec import RequestSpec  # noqa: E402

FOREIGN = "someone-else@example.com"
ENV_VAR = "IDENTITY_CHECK_UNUSED_KEY"  # nothing is ever submitted; SECURE_INPUT_* names are refused by design
JSON = {"Content-Type": "application/json"}


def spec_for(root: Path) -> RequestSpec:
    return RequestSpec(kind="api_key", purpose="secure-input 계정 확인 실측", label="identity check",
                       requester={"type": "user", "profile": "default", "platform": "cli",
                                  "session_key": "identity-check", "user_id": "local"},
                       target_profile="default", profile_editable=True, hermes_root=str(root),
                       env_var=ENV_VAR)


def post_open(http: httpx.Client, base: str, headers: dict | None = None) -> httpx.Response:
    return http.post(base + "api/open", content="{}", headers={**JSON, **(headers or {})})


def wait_200(http: httpx.Client, url: str, attempts: int = 30) -> int:
    status = 0
    for _ in range(attempts):
        try:
            status = http.get(url).status_code
        except httpx.HTTPError:
            status = 0
        if status == 200:
            return status
        time.sleep(0.3)
    return status


def via_launcher(http: httpx.Client, root: Path, serve: ServeManager, out: dict) -> None:
    # 1. owner only (start_request reads it from `tailscale status --json`)
    h = start_request(spec_for(root), serve=serve)
    try:
        page = wait_200(http, h.url)
        r = post_open(http, h.url)
        out["1_owner_allowed"] = {"page_get_status": page, "open_status": r.status_code}
    finally:
        h.cancel()

    # 2. list given directly to the start function: only someone else
    h = start_request(spec_for(root), serve=serve, allowed_logins=[FOREIGN])
    try:
        page = wait_200(http, h.url)
        r = post_open(http, h.url)
        # Not consumed: a call that carries the listed account opens it (loopback, header set by this script).
        again = post_open(http, h.local_url, {"Tailscale-User-Login": FOREIGN})
        out["2_owner_not_on_list"] = {"page_get_status": page, "open_status": r.status_code,
                                      "error_code": r.json().get("error_code"),
                                      "link_still_unused_open_status": again.status_code}
    finally:
        h.cancel()

    # 3a. same list, the client sends a forged identity header through Serve
    h = start_request(spec_for(root), serve=serve, allowed_logins=[FOREIGN])
    try:
        wait_200(http, h.url)
        r = post_open(http, h.url, {"Tailscale-User-Login": FOREIGN})
        out["3_forged_header_via_serve"] = {"open_status": r.status_code, "error_code": r.json().get("error_code")}
    finally:
        h.cancel()


def hooked_server(root: Path, serve: ServeManager, http: httpx.Client, host: str, owner: str, out: dict) -> None:
    """3b. Same app code in this process, with a hook that records what reached it (counts and booleans)."""
    import uvicorn

    token = new_token()
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(16)
    port = sock.getsockname()[1]
    ctx = ServerContext(spec_for(root), token=token, request_id=os.urandom(16).hex(), static_dir=REPO / "secure_input" / "static",
                        public_host=host, port=port, allowed_logins=[FOREIGN], store=lambda home, req: {})
    seen: list[dict] = []
    app = create_app(ctx)

    async def hook(scope, receive, send):
        if scope["type"] == "http" and scope["path"].endswith("/api/open"):
            values = [v.decode("latin-1") for k, v in scope["headers"] if k.decode("latin-1").lower() == IDENTITY_HEADER]
            names = sorted({k.decode("latin-1").title() for k, _v in scope["headers"]})
            seen.append({"identity_header_count": len(values),
                         "equals_client_value": any(v.strip().lower() == FOREIGN for v in values),
                         "equals_owner_login": any(v.strip().lower() == owner.strip().lower() for v in values),
                         "header_names": names})
        await app(scope, receive, send)

    server = uvicorn.Server(uvicorn.Config(hook, log_level="warning", access_log=False, lifespan="off", ws="none"))
    t = threading.Thread(target=lambda: server.run(sockets=[sock]), daemon=True)
    t.start()
    try:
        serve.add(token, port)
        url = f"https://{host}/{token}/"
        wait_200(http, url)
        r = post_open(http, url, {"Tailscale-User-Login": FOREIGN})
        rec = seen[-1] if seen else {}
        out["3_forged_header_hook"] = {"open_status": r.status_code, "error_code": r.json().get("error_code"),
                                       "identity_header_count": rec.get("identity_header_count"),
                                       "equals_client_value": rec.get("equals_client_value"),
                                       "equals_owner_login": rec.get("equals_owner_login"),
                                       "lifecycle_state_after": ctx.lc.state}
        out["header_names_reaching_backend"] = rec.get("header_names")
    finally:
        out["3_hook_serve_removed"] = serve.remove(token)
        server.should_exit = True
        t.join(5)


def main() -> int:
    serve = ServeManager()
    out: dict = {"serve_status_before_is_empty": serve.status_text() == "No serve config"}
    if not out["serve_status_before_is_empty"]:
        out["error"] = "tailscale serve already has config; refusing to touch it"
        print(json.dumps(out, indent=2))
        return 2
    host = serve.dns_name()
    owner = serve.owner_login()
    out["owner_login_read"] = bool(owner)
    tmp = Path(tempfile.mkdtemp(prefix="si-identity-"))
    root = tmp / "hermes"
    root.mkdir()
    try:
        with httpx.Client(timeout=15) as http:
            via_launcher(http, root, serve, out)
            hooked_server(root, serve, http, host, owner, out)
        env = root / ".env"
        out["no_value_stored"] = not env.exists() or ENV_VAR not in env.read_text()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        time.sleep(0.5)
        out["serve_status_after_is_empty"] = serve.status_text() == "No serve config"
    o1, o2 = out.get("1_owner_allowed", {}), out.get("2_owner_not_on_list", {})
    o3, o3h = out.get("3_forged_header_via_serve", {}), out.get("3_forged_header_hook", {})
    out["summary"] = {
        "case1_open_status": o1.get("open_status"),
        "case2_open_status": o2.get("open_status"),
        "case2_link_still_unused": o2.get("link_still_unused_open_status") == 200,
        "case3_open_status": o3.get("open_status"),
        "case3_serve_replaced_client_header": (o3h.get("identity_header_count") == 1
                                               and o3h.get("equals_client_value") is False
                                               and o3h.get("equals_owner_login") is True),
        "expected": {"case1": 200, "case2": 403, "case3": 403},
    }
    out["ok"] = (o1.get("open_status") == 200 and o2.get("open_status") == 403
                 and out["summary"]["case2_link_still_unused"] and o3.get("open_status") == 403
                 and o3h.get("open_status") == 403 and out["summary"]["case3_serve_replaced_client_header"]
                 and out["serve_status_after_is_empty"])
    text = json.dumps(out, indent=2, ensure_ascii=False)
    for secret_ish in (host, host.split(".")[0], owner):
        if secret_ish and secret_ish.lower() in text.lower():  # never print the host or the account
            text = json.dumps({"error": "refused to print: output contained a host or account name"})
    print(text)
    return 0 if out["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
