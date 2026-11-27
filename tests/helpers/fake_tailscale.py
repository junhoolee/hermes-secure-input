"""A fake ``tailscale`` CLI for tests: an executable script that records argv.

``status --json`` reports ``Self.DNSName`` and the owner account (``Self.UserID`` ->
``User[<id>].LoginName`` = :data:`FAKE_OWNER_LOGIN`), like the real CLI. ``status_mode`` makes
``status --json`` misbehave: ``no_user`` (no User map), ``exit_1``, ``not_json``.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

FAKE_OWNER_LOGIN = "owner@example.test"
FAKE_OWNER_ID = 4242
# The header the real Serve adds for the owner; tests send it to the loopback server themselves.
OWNER_HEADER = {"Tailscale-User-Login": FAKE_OWNER_LOGIN}

_SCRIPT = """#!{python}
import json, sys
argv = sys.argv[1:]
with open({log!r}, "a") as f:
    f.write(json.dumps(argv) + "\\n")
if argv[:2] == ["status", "--json"]:
    mode = {mode!r}
    if mode == "exit_1":
        sys.exit(1)
    if mode == "not_json":
        print("not json")
        sys.exit(0)
    status = {{"Self": {{"DNSName": {dns!r} + ".", "UserID": {uid!r}}}, "BackendState": "Running"}}
    if mode != "no_user":
        status["User"] = {{str({uid!r}): {{"ID": {uid!r}, "LoginName": {login!r}, "DisplayName": "Owner"}},
                           "7": {{"ID": 7, "LoginName": "someone-else@example.com"}}}}
    print(json.dumps(status))
elif argv[:2] == ["serve", "status"]:
    print("No serve config")
sys.exit(0)
"""


class FakeTailscale:
    def __init__(self, folder: Path, dns_name: str, owner_login: str = FAKE_OWNER_LOGIN, status_mode: str = "ok"):
        folder.mkdir(parents=True, exist_ok=True)
        self.dns_name = dns_name
        self.owner_login = owner_login
        self.log = folder / "calls.jsonl"
        self.bin = folder / "tailscale"
        self.bin.write_text(_SCRIPT.format(python=sys.executable, log=str(self.log), dns=dns_name, uid=FAKE_OWNER_ID,
                                           login=owner_login, mode=status_mode))
        os.chmod(self.bin, 0o755)

    def calls(self) -> list[list[str]]:
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text().splitlines() if line.strip()]

    def off_calls(self, token: str) -> list[list[str]]:
        return [c for c in self.calls() if c and c[0] == "serve" and c[-1] == "off" and f"/{token}" in c]

    def add_calls(self, token: str) -> list[list[str]]:
        return [c for c in self.calls() if c and c[0] == "serve" and "--set-path" in c and c[-1] != "off"
                and f"/{token}" in c]
