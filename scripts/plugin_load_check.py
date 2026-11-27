#!/usr/bin/env python3
"""Load this repository as a Hermes plugin in a throwaway HERMES_HOME and list what it registered.

    ~/.hermes/hermes-agent/.venv/bin/python scripts/plugin_load_check.py

Creates ``<tmp>/hermes`` with ``config.yaml`` (``plugins.enabled: [secure-input]``) and a symlink
``plugins/secure-input -> <repo>``, then runs Hermes' own plugin loader in a child process with
``HOME`` and ``HERMES_HOME`` pointed at the temp folder (the real ``~/.hermes`` is never read for
config and never written). Prints one JSON line and exits non-zero if anything is missing.
"""

from __future__ import annotations

import json
import os
import pwd
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
_REAL_HOME = Path(pwd.getpwuid(os.getuid()).pw_dir)  # not $HOME: tests point HOME at a temp folder
HERMES_AGENT = Path(os.environ.get("SECURE_INPUT_HERMES_AGENT_DIR") or _REAL_HOME / ".hermes" / "hermes-agent")

CHILD = r"""
import json, sys
from hermes_cli.plugins import discover_plugins, get_plugin_manager, get_plugin_command_handler
discover_plugins(force=True)
mgr = get_plugin_manager()
from tools.registry import registry
tools = {}
for name in ("secure_input_request", "secure_input_enter_code"):
    entry = registry.get_entry(name, scope=mgr.scope_key)
    tools[name] = None if entry is None else entry.toolset
loaded = {k: bool(v.enabled) for k, v in mgr._plugins.items() if k == "secure-input"}
errors = {k: str(getattr(v, "error", "") or "") for k, v in mgr._plugins.items()
          if k == "secure-input" and getattr(v, "error", None)}
hooks = sorted(h for h, cbs in getattr(mgr, "_hooks", {}).items() if any("secure_input" in getattr(cb, "__module__", "") or "secure_input" in getattr(getattr(cb, "__self__", None), "__module__", "") for cb in cbs))
# Hermes' own pre_tool_call directive path (what the tool executor consults before dispatch).
from hermes_cli.plugins import _get_pre_tool_call_directive_details as directive
def d(args):
    r = directive("browser_vault", args)
    return None if r is None or getattr(r, "action", None) is None else [r.action, (r.message or "")[:60]]
directives = {"enter_code": d({"action": "enter_code"}), "enter_code_handle": d({"action": "enter_code", "handle": "v1"}),
              "save_login": d({"action": "save_login"}), "fill": d({"action": "fill", "handle": "v1"})}
print(json.dumps({"plugins": loaded, "errors": errors, "tools": tools,
                  "command_secure_input": get_plugin_command_handler("secure-input") is not None,
                  "hooks": hooks,
                  "slack_actions": [repr(a) for a, _cb, plugin in getattr(mgr, "_slack_action_handlers", []) if plugin == "secure-input"],
                  "directives": directives}, ensure_ascii=False))
"""

CONFIG_ON = "plugins:\n  enabled:\n    - secure-input\n"
CONFIG_OFF = CONFIG_ON + ("  entries:\n    secure-input:\n      settings:\n        intercept_core_code_prompt: false\n"
                          "        intercept_core_save_login: false\n")


def run(config_text: str) -> dict | None:
    with tempfile.TemporaryDirectory(prefix="si-load-") as tmp:
        home = Path(tmp)
        hermes = home / ".hermes"
        (hermes / "plugins").mkdir(parents=True)
        (hermes / "plugins" / "secure-input").symlink_to(REPO, target_is_directory=True)
        (hermes / "config.yaml").write_text(config_text)
        env = {k: v for k, v in os.environ.items() if not k.startswith(("HERMES_", "SECURE_INPUT_"))}
        env.update(HOME=str(home), HERMES_HOME=str(hermes), PYTHONDONTWRITEBYTECODE="1",
                   PYTHONPATH=str(HERMES_AGENT), SECURE_INPUT_TAILSCALE_BIN="/usr/bin/false")
        proc = subprocess.run([sys.executable, "-c", CHILD], cwd=str(HERMES_AGENT), env=env, capture_output=True,
                              text=True, timeout=180)
        line = (proc.stdout.strip().splitlines() or [""])[-1]
        print(line)
        if proc.returncode != 0:
            print(proc.stderr[-4000:], file=sys.stderr)
            return None
        return json.loads(line)


def main() -> int:
    on = run(CONFIG_ON)
    off = run(CONFIG_OFF)
    if on is None or off is None:
        print("RESULT: FAIL")
        return 1
    dir_on, dir_off = on["directives"], off["directives"]
    ok = (on["plugins"].get("secure-input") is True
          and on["tools"] == {"secure_input_request": "secure_input", "secure_input_enter_code": "secure_input"}
          and on["command_secure_input"] and "pre_tool_call" in on["hooks"]
          and dir_on["enter_code"] and dir_on["enter_code"][0] == "block"
          and dir_on["save_login"] and dir_on["save_login"][0] == "block"
          and dir_on["enter_code_handle"] and dir_on["enter_code_handle"][0] == "block" and dir_on["fill"] is None
          and all(v is None for v in dir_off.values()))
    print("RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
