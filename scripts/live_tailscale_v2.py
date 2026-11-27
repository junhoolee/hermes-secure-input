#!/usr/bin/env python3
"""Protocol 2 through the real Tailscale Serve (plan 5.7, 7.3 "작업 5", integration card 4.5).

Three measurements, written to docs/plans/storage-targets-impl-probes/live_tailscale_v2.json:

1. one ``api_key`` submit with two stores (.env and a new keychain item ``hermes-secure-input.test-<random>``)
   through ``https://<this Mac's tailnet name>/<token>/``: the answer arrives whole and says ``saved``;
2. the same with the storage process held back about 25 s before it saves (python wrapper, phase ``save``
   only): the answer of close to 30 s still arrives through Serve; its time is recorded;
3. ``tailscale serve --https=443 --set-path /<token> off`` timed 5 times (a test path pointing at an unused
   local port is added before each run; only that path is removed). All 5 must be under 4 s (plan 5.7).

The real server, storage process, keychain module and ``/usr/bin/security`` are used (helpers of
``scripts/real_roundtrip_v2.py``). The page side is ``tests/helpers/browser_client.py`` on the public URL; the
``Tailscale-User-Login`` header comes from Serve itself. Refuses to start unless ``tailscale serve status`` is
``No serve config``, and checks it again at the end. Values are fake and never printed or written.

Run:  ~/.hermes/hermes-agent/.venv/bin/python -P scripts/live_tailscale_v2.py [result.json]
"""

from __future__ import annotations

import json
import secrets
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.dont_write_bytecode = True

import httpx  # noqa: E402

import real_roundtrip_v2 as rt  # noqa: E402
from secure_input.serve import ServeManager  # noqa: E402

OUT_DEFAULT = rt.REPO / "docs" / "plans" / "storage-targets-impl-probes" / "live_tailscale_v2.json"
NO_CONFIG = "No serve config"
OFF_LIMIT_S = 4.0
DELAY_S = 25.0


def submit_through_serve(made: list, delay: float) -> dict:
    case = rt.Case("ts-delay" if delay else "ts", Path("/tmp"))
    try:
        item = "test-" + secrets.token_hex(5)
        service = rt.kcmod.SERVICE_PREFIX + item
        made.append((service, rt.kcmod.FIXED_ACCOUNT))
        handle = case.start(rt.api_spec(item), delay=delay, serve=ServeManager())
        status_during = ServeManager().status_text()
        c = case.client(base_url=handle.url, identity=None)  # through Serve: Serve adds the identity header
        r = c.open()
        open_status = r.status_code
        v = rt.canary()
        err = None
        try:
            code, body, secs = rt.submit_once(c, {"kind": "api_key", "target_profile": "default", "value": v,
                                                  "stores": ["env", "keychain"]})
        except httpx.HTTPError as exc:  # the answer did not arrive whole
            code, body, secs, err = None, {}, None, type(exc).__name__
        res = case.finish([v])
        result = body.get("result") or {}
        res.update(delay_s=delay, open_http_status=open_status, submit_http_status=code, submit_error=err,
                   submit_answer_ok=body.get("ok"), submit_status=result.get("status"),
                   submit_partial=result.get("partial"), submit_stores=result.get("stores"),
                   submit_secs=secs, serve_path_added=status_during != NO_CONFIG,
                   keychain_service=service,
                   readback={"env_equal": rt.env_value_equal(case.root, "EXA_API_KEY", v),
                             "keychain_equal": rt.kc_equal(service, rt.kcmod.FIXED_ACCOUNT, v)})
        v = ""
        time.sleep(1.0)
        try:
            res["ended_url_http_status"] = httpx.get(handle.url, timeout=15).status_code
        except httpx.HTTPError as exc:
            res["ended_url_http_status"] = type(exc).__name__
        res["serve_status_after"] = ServeManager().status_text()
        return res
    finally:
        case.cleanup()


def time_serve_off(n: int = 5) -> dict:
    serve = ServeManager()
    secs, rcs, after = [], [], []
    for _ in range(n):
        token = "rt2test" + secrets.token_urlsafe(18)
        serve.add(token, 9)  # an unused local port: only the Serve path is measured
        t = time.monotonic()
        ok = serve.remove(token)
        secs.append(round(time.monotonic() - t, 3))
        rcs.append(ok)
        after.append(serve.status_text())
    return {"command": "tailscale serve --https=443 --set-path /<token> off", "secs": secs, "removed": rcs,
            "status_after_each": after, "max_secs": max(secs), "all_under_4s": all(s < OFF_LIMIT_S for s in secs)}


def main() -> int:
    out_path = Path(sys.argv[1]) if len(sys.argv) > 1 else OUT_DEFAULT
    serve = ServeManager()
    start_status = serve.status_text()
    if start_status != NO_CONFIG:
        print(json.dumps({"error": "tailscale serve already has config; not touched"}))
        return 2
    result: dict = {"when": time.strftime("%F %T %Z"), "tailscale_bin": serve.bin,
                    "tailscale_version": serve._run("version").stdout.splitlines()[0],
                    "serve_status_start": start_status, "securityagent_before": rt.security_agents(),
                    "prefix_counts_before": rt.prefix_counts()}
    made: list = []
    try:
        for name, delay in (("1_two_stores_through_serve", 0.0), ("2_slow_save_through_serve", DELAY_S)):
            try:
                result[name] = submit_through_serve(made, delay)
            except Exception as exc:  # the error type only
                result[name] = {"error": type(exc).__name__}
            print(name, "done", flush=True)
        result["3_serve_off_timing"] = time_serve_off()
    finally:
        result["cleanup_delete_rc"] = {s: rt.kc_delete(s, a) for s, a in made}
        for item in rt.our_items():
            result["cleanup_delete_rc"][item["service"]] = rt.kc_delete(item["service"], item["account"])
        result["prefix_counts_after"] = rt.prefix_counts()
        result["securityagent_after"] = rt.security_agents()
        result["serve_status_end"] = ServeManager().status_text()
    one, slow, off = result["1_two_stores_through_serve"], result["2_slow_save_through_serve"], result[
        "3_serve_off_timing"]
    result["checks"] = {
        "1_saved_through_serve": one.get("submit_http_status") == 200 and one.get("submit_status") == "saved"
        and one.get("submit_partial") is False and one.get("parent_status") == "saved",
        "1_readback": one.get("readback") == {"env_equal": True, "keychain_equal": True},
        "2_slow_answer_arrived": slow.get("submit_http_status") == 200 and slow.get("submit_error") is None
        and slow.get("submit_status") == "saved",
        "2_answer_took_25_to_30s": isinstance(slow.get("submit_secs"), float) and 25.0 <= slow["submit_secs"] < 30.0,
        "2_readback": slow.get("readback") == {"env_equal": True, "keychain_equal": True},
        "3_serve_off_all_under_4s": off.get("all_under_4s") is True and len(off.get("secs", [])) == 5,
        # with no Serve path left the HTTPS listener is gone: refused (ConnectError) or 404, never the page
        "ended_urls_404_or_refused": all(x.get("ended_url_http_status") in (404, "ConnectError") for x in (one, slow)),
        "no_canary_in_logs": one.get("no_canary_in_logs_and_files") is True
        and slow.get("no_canary_in_logs_and_files") is True,
        "prefix_items_after_all_0": all(v == 0 for v in result["prefix_counts_after"].values()),
        "serve_status_end_clean": result["serve_status_end"] == NO_CONFIG,
        "no_new_securityagent": result["securityagent_after"] <= result["securityagent_before"],
    }
    text = json.dumps(result, ensure_ascii=False, indent=1)
    assert rt.CANARY_PREFIX not in text
    out_path.write_text(text + "\n")
    print(json.dumps({"checks": result["checks"], "slow_submit_secs": slow.get("submit_secs"),
                      "serve_off_secs": off.get("secs"), "serve_status_end": result["serve_status_end"]}, indent=1))
    return 0 if all(result["checks"].values()) else 1


if __name__ == "__main__":
    sys.exit(main())
