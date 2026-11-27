#!/usr/bin/env python3
"""One real round trip through Tailscale Serve (card criterion 9).

Creates a throwaway hermes_root, starts an ``api_key`` request with a canary value, then from
this Mac: GETs ``https://<tailnet host>/<token>/`` (prints HTTP code and TLS version), runs
open + submit like the browser, waits for the outcome, checks the same URL is 404 afterwards,
and prints ``tailscale serve status``. Tokens and the canary value are never printed.

Run with the Hermes venv python:
    ~/.hermes/hermes-agent/.venv/bin/python scripts/tailscale_roundtrip.py
"""

from __future__ import annotations

import hashlib
import http.client
import os
import shutil
import ssl
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import urlsplit

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "tests"))
# Since fix 1 RequestSpec checks env names with Hermes' hermes_cli.config (appended, like the gateway), and
# SECURE_INPUT_* names are refused, so the test variables are called ROUNDTRIP_CHECK_*.
sys.path.append(os.environ.get("SECURE_INPUT_HERMES_AGENT_DIR") or str(Path.home() / ".hermes" / "hermes-agent"))
sys.dont_write_bytecode = True

from helpers.browser_client import BrowserClient  # noqa: E402
from secure_input.launcher import start_request  # noqa: E402
from secure_input.serve import ServeManager  # noqa: E402
from secure_input.spec import RequestSpec  # noqa: E402

failures: list[str] = []


def check(ok: bool, what: str) -> None:
    print(f"  [{'OK' if ok else 'FAIL'}] {what}")
    if not ok:
        failures.append(what)


def https_get(url: str, attempts: int = 10):
    parts = urlsplit(url)
    last = None
    for _ in range(attempts):
        conn = http.client.HTTPSConnection(parts.hostname, parts.port or 443, timeout=15,
                                           context=ssl.create_default_context())
        try:
            conn.request("GET", parts.path)
            resp = conn.getresponse()
            body = resp.read()
            return resp.status, conn.sock.version() if conn.sock else None, resp.getheaders(), body
        except OSError as exc:
            last = exc
            time.sleep(0.5)
        finally:
            conn.close()
    raise RuntimeError(f"HTTPS GET failed: {type(last).__name__}")


def api_key_spec(root: Path, env_var: str) -> RequestSpec:
    return RequestSpec.from_dict({
        "kind": "api_key", "purpose": "secure-input Tailscale round trip test", "label": "roundtrip test",
        "requester": {"type": "user", "profile": "default", "platform": "cli", "session_key": "roundtrip",
                      "user_id": "local"},
        "target_profile": "default", "profile_editable": True, "env_var": env_var,
        "origin": None, "site": None, "hermes_root": str(root)})


def stage_two_concurrent(root: Path, static: Path, serve: ServeManager, canary: str) -> None:
    """Stage 2: two live requests; ending A must leave B's Serve path alone (contract 5.7)."""
    print("--- stage 2: two concurrent requests A and B ---")
    a = b = None
    try:
        a = start_request(api_key_spec(root, "ROUNDTRIP_CHECK_A"), static_dir=static, serve=serve)
        b = start_request(api_key_spec(root, "ROUNDTRIP_CHECK_B"), static_dir=static, serve=serve)
        status_a, _, _, _ = https_get(a.url)
        status_b, _, _, _ = https_get(b.url)
        print(f"before: GET A -> HTTP {status_a}, GET B -> HTTP {status_b}")
        check(status_a == 200 and status_b == 200, "both A and B served")

        ca = BrowserClient(a.url)
        ca.open()
        r = ca.submit({"kind": "api_key", "target_profile": "default", "value": canary + "-A"})
        out_a = a.wait(timeout=15)
        print(f"A submit -> HTTP {r.status_code}, outcome {out_a.status}")
        check(out_a.status == "saved", "A saved")
        time.sleep(0.5)

        status_b2, _, _, _ = https_get(b.url)
        print(f"after A ended: GET B -> HTTP {status_b2}")
        check(status_b2 == 200, "B still served after A's path was removed")
        try:
            status_a2, _, _, _ = https_get(a.url, attempts=1)
            print(f"after A ended: GET A -> HTTP {status_a2}")
        except RuntimeError as exc:
            status_a2 = "refused"
            print(f"after A ended: GET A -> connection refused ({exc})")
        check(status_a2 == 404, "A is 404 while B keeps :443 open")
        tokens = [x.url.rstrip("/").rsplit("/", 1)[1] for x in (a, b)]
        mid = serve.status_text()
        for t, name in zip(tokens, ("<token A>", "<token B>")):
            mid = mid.replace(t, name)
        print(f"serve status with only B left: {mid!r}")
        check("<token A>" not in mid and "<token B>" in mid, "status lists B only")

        cb = BrowserClient(b.url)
        cb.open()
        r = cb.submit({"kind": "api_key", "target_profile": "default", "value": canary + "-B"})
        out_b = b.wait(timeout=15)
        print(f"B submit -> HTTP {r.status_code}, outcome {out_b.status}")
        check(out_b.status == "saved", "B saved")
        time.sleep(0.5)
        after = serve.status_text()
        print(f"serve status after A and B: {after!r}")
        check(after == "No serve config", "serve status back to 'No serve config' after stage 2")
    finally:
        for h in (a, b):
            if h is not None and not h.done:
                h.cancel()


def main() -> int:
    work = Path(tempfile.mkdtemp(prefix="secure-input-roundtrip-"))
    root = work / "hermes"
    (root / "profiles" / "worker").mkdir(parents=True)
    static = work / "static"
    (static / "assets").mkdir(parents=True)
    (static / "index.html").write_text("<!doctype html><title>roundtrip</title>\n")
    (static / "assets" / "app.js").write_text("console.log('roundtrip');\n")
    canary = "SECRET-CANARY-" + os.urandom(12).hex()
    serve = ServeManager()
    print(f"tailscale CLI: {serve.bin}")
    print(f"serve status before: {serve.status_text()!r}")
    spec = RequestSpec.from_dict({
        "kind": "api_key", "purpose": "secure-input Tailscale round trip test", "label": "roundtrip test",
        "requester": {"type": "user", "profile": "default", "platform": "cli", "session_key": "roundtrip",
                      "user_id": "local"},
        "target_profile": "default", "profile_editable": True, "env_var": "ROUNDTRIP_CHECK_TEST",
        "origin": None, "site": None, "hermes_root": str(root)})
    handle = None
    try:
        handle = start_request(spec, static_dir=static, serve=serve)
        token = handle.url.rstrip("/").rsplit("/", 1)[1]
        host = urlsplit(handle.url).hostname
        print(f"request: host={host} path_fp={hashlib.sha256(token.encode()).hexdigest()[:8]} "
              f"token_len={len(token)} local_port={handle.port}")
        print(f"serve status during: {serve.status_text().replace(token, '<token>')!r}")

        status, tls, headers, body = https_get(handle.url)
        print(f"GET https://{host}/<token>/ -> HTTP {status}, TLS {tls}")
        check(status == 200 and b"roundtrip" in body, "page served through Tailscale Serve (backend got /<token>/)")
        check(tls in ("TLSv1.2", "TLSv1.3"), "TLS 1.2 or newer")
        hdrs = {k.lower(): v for k, v in headers}
        check(hdrs.get("cache-control") == "no-store" and "frame-ancestors 'none'" in hdrs.get(
            "content-security-policy", ""), "security headers present through Serve")
        a_status, _, _, _ = https_get(handle.url + "assets/app.js")
        print(f"GET https://{host}/<token>/assets/app.js -> HTTP {a_status}")
        check(a_status == 200, "nested static path keeps the token prefix")

        client = BrowserClient(handle.url)
        r = client.open()
        print(f"POST open -> HTTP {r.status_code}")
        check(r.status_code == 200, "open")
        r = client.submit({"kind": "api_key", "target_profile": "default", "value": canary})
        print(f"POST submit -> HTTP {r.status_code} status={r.json().get('result', {}).get('status')}")
        check(r.status_code == 200, "submit")
        out = handle.wait(timeout=15)
        print(f"outcome: {out.status} storage={out.meta.get('storage')}")
        check(out.status == "saved", "outcome saved")
        env = (root / ".env").read_text()
        check(env == f"ROUNDTRIP_CHECK_TEST={canary}\n", ".env holds exactly the submitted value (compared, not printed)")
        check(canary.encode() not in r.content, "canary not in submit response")

        time.sleep(0.5)
        # With no other Serve config left, tailscaled stops listening on :443, so the ended URL
        # refuses the connection; if another Serve config keeps :443 open it answers 404.
        try:
            status2, _, _, _ = https_get(handle.url, attempts=1)
            print(f"GET same URL after end -> HTTP {status2}")
        except RuntimeError as exc:
            status2 = "refused"
            print(f"GET same URL after end -> connection refused ({exc})")
        check(status2 in (404, "refused"), "ended URL is 404 or the connection is refused (no listener)")
        after = serve.status_text()
        print(f"serve status after: {after!r}")
        check(after == "No serve config", "serve status back to 'No serve config'")
        stage_two_concurrent(root, static, serve, canary)
    finally:
        if handle is not None and not handle.done:
            handle.cancel()
        shutil.rmtree(work, ignore_errors=True)
    print("RESULT: " + ("PASS" if not failures else f"FAIL ({len(failures)}): " + "; ".join(failures)))
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
