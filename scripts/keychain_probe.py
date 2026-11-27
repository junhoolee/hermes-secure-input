#!/usr/bin/env python3
"""Real-keychain probe for the keychain store module (plan 7.3 work 1, 5.2, A.11).

What it does, on the login (default) keychain of this Mac:

1. counts items whose service starts with ``hermes-secure-input-test-`` or
   ``hermes-secure-input.tmp.`` (both must be 0 before and after);
2. ``preflight()`` then ``save()`` of a NEW fake item (expects 3 ``security`` calls);
3. ``preflight()`` then ``save()`` that REPLACES the same item (expects 7 calls, temp item first);
4. times ``security dump-keychain -a <default keychain path>`` 5 times while the fake item exists;
5. deletes the fake item (and any temp item of this run) and counts both prefixes again.

Safety rules kept:
- only ``/usr/bin/security`` touches the keychain (through ``secure_input.stores.keychain``);
- the only items made have a service starting with ``hermes-secure-input-test-`` (fake item) or
  ``hermes-secure-input.tmp.`` (the module's own temp item);
- values are fake, random, generated here, never printed and never written to the result file;
- ``dump-keychain`` output stays in memory; only prefix counts and timings leave this process;
- no value of any item not made here is read (no ``-w`` on other items), the keychain is not
  locked, ``example-unlock-item`` is not touched.

Run:  python3 scripts/keychain_probe.py [result.json]
"""

from __future__ import annotations

import json
import secrets
import subprocess
import sys
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from secure_input.stores import keychain  # noqa: E402

SEC = keychain.SECURITY_PATH
CANARY_PREFIX = "SECRET-" + "CANARY-"
OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "scripts" / "keychain_probe_result.json"

calls = {"n": 0}
_orig_run = keychain._run


def _counting_run(security_path, argv, **kw):
    calls["n"] += 1
    return _orig_run(security_path, argv, **kw)


keychain._run = _counting_run


def security_agent_processes() -> int:
    p = subprocess.run(["/usr/bin/pgrep", "-x", "SecurityAgent"], stdout=subprocess.PIPE,
                       stderr=subprocess.DEVNULL)
    return len(p.stdout.split())


def default_keychain() -> str:
    r = _orig_run(SEC, ["default-keychain"], capture=True)
    return r["out"].decode("utf-8", "replace").strip().strip('"')


def timed_dump(path: str) -> tuple[float, int | None, str]:
    t = time.monotonic()
    r = _orig_run(SEC, ["dump-keychain", "-a", path], capture=True)
    secs = round(time.monotonic() - t, 3)
    text = r["out"].decode("utf-8", "replace")
    return secs, (None if r["timeout"] else r["rc"]), text


def prefix_counts(text: str) -> dict:
    counts = {keychain.TEST_PREFIX: 0, keychain.TMP_PREFIX: 0}
    for line in text.splitlines():
        s = line.strip()
        if s.startswith('"svce"<blob>="'):
            name = s[len('"svce"<blob>="'):]
            for p in counts:
                if name.startswith(p):
                    counts[p] += 1
    return counts


def delete(service: str, account: str) -> int | None:
    r = _orig_run(SEC, ["delete-generic-password", "-s", service, "-a", account])
    return None if r["timeout"] else r["rc"]


def step(request: dict) -> dict:
    calls["n"] = 0
    t = time.monotonic()
    pf = keychain.preflight(request)
    pf_calls, pf_secs = calls["n"], round(time.monotonic() - t, 3)
    calls["n"] = 0
    t = time.monotonic()
    row = keychain.save(request) if pf["available"] else None
    return {"preflight": pf, "preflight_calls": pf_calls, "preflight_secs": pf_secs,
            "save": row, "save_calls": calls["n"], "save_secs": round(time.monotonic() - t, 3)}


def main() -> int:
    run = secrets.token_hex(4)
    service = keychain.TEST_PREFIX + run
    account = keychain.FIXED_ACCOUNT
    request_id = uuid.uuid4().hex
    tmp_service = keychain.TMP_PREFIX + request_id[:12]
    res: dict = {"when": time.strftime("%F %T %Z"), "security": SEC, "run": run,
                 "item_service_prefix": keychain.TEST_PREFIX, "tmp_service_prefix": keychain.TMP_PREFIX,
                 "securityagent_processes_before": security_agent_processes()}

    kc = default_keychain()
    res["default_keychain_is_login"] = kc.endswith("/login.keychain-db")
    secs, rc, text = timed_dump(kc)
    res["before"] = {"dump_rc": rc, "counts": prefix_counts(text)}
    text = ""

    try:
        v1 = CANARY_PREFIX + secrets.token_hex(16)
        res["new_item"] = step({"service": service, "account": account, "listed": False,
                                "request_id": request_id, "value": v1})
        v2 = CANARY_PREFIX + secrets.token_hex(16)
        res["replace_existing"] = step({"service": service, "account": account, "listed": False,
                                        "request_id": request_id, "value": v2})
        v1 = v2 = ""

        timings, rcs = [], []
        for _ in range(5):
            secs, rc, text = timed_dump(kc)
            timings.append(secs)
            rcs.append(rc)
        res["acl_read_with_path"] = {"command": "security dump-keychain -a <default keychain path>",
                                     "secs": timings, "rc": rcs, "max_secs": max(timings),
                                     "over_2_5s": max(timings) > 2.5,
                                     "fake_item_present": prefix_counts(text)[keychain.TEST_PREFIX] == 1}
        text = ""
    finally:
        res["cleanup"] = {"delete_item_rc": delete(service, account),
                          "delete_tmp_rc": delete(tmp_service, account)}
        secs, rc, text = timed_dump(kc)
        res["after"] = {"dump_rc": rc, "counts": prefix_counts(text)}
        text = ""
        res["securityagent_processes_after"] = security_agent_processes()

    ok_new = res["new_item"]["save"] == {
        "saved": True, "replaced": False, "error": None, "service": service, "account": account,
        "listed": False, "new_item": True, "tmp_left": False, "main_touched": True}
    ok_rep = res["replace_existing"]["save"] == {
        "saved": True, "replaced": True, "error": None, "service": service, "account": account,
        "listed": False, "new_item": False, "tmp_left": False, "main_touched": True}
    res["checks"] = {
        "new_item_saved": ok_new,
        "new_item_save_calls_is_3": res["new_item"]["save_calls"] == 3,
        "existing_preflight_available": res["replace_existing"]["preflight"] == {
            "available": True, "reason": None, "exists": True},
        "existing_saved": ok_rep,
        "existing_save_calls_is_7": res["replace_existing"]["save_calls"] == 7,
        "acl_read_max_under_2_5s": not res["acl_read_with_path"]["over_2_5s"],
        "test_prefix_items_after_is_0": res["after"]["counts"][keychain.TEST_PREFIX] == 0,
        "tmp_prefix_items_after_is_0": res["after"]["counts"][keychain.TMP_PREFIX] == 0,
        "no_new_securityagent": res["securityagent_processes_after"] <= res["securityagent_processes_before"],
    }
    out = json.dumps(res, ensure_ascii=False, indent=1)
    assert CANARY_PREFIX not in out
    OUT.write_text(out + "\n")
    print(json.dumps({"checks": res["checks"], "acl_read_secs": res["acl_read_with_path"]["secs"],
                      "after_counts": res["after"]["counts"]}, indent=1))
    return 0 if all(res["checks"].values()) else 1


if __name__ == "__main__":
    sys.exit(main())
