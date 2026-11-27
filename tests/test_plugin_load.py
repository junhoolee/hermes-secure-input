"""Criterion 2 (and the real hook path of criteria 6/12): Hermes' own plugin loader registers the
tools, the command, the hook and the Slack ack, and Hermes' own ``pre_tool_call`` directive path
blocks every ``enter_code`` (with or without a handle) and ``save_login`` only while the settings are on."""

import json
import subprocess
import sys

from conftest import REPO_ROOT


def test_hermes_loader_registers_tools_command_and_hook():
    proc = subprocess.run([sys.executable, str(REPO_ROOT / "scripts" / "plugin_load_check.py")],
                          capture_output=True, text=True, timeout=400)
    assert proc.returncode == 0, proc.stdout + proc.stderr[-2000:]
    on, off = (json.loads(line) for line in proc.stdout.splitlines()[:2])
    assert on["plugins"] == {"secure-input": True} and on["errors"] == {}
    assert on["tools"] == {"secure_input_request": "secure_input", "secure_input_enter_code": "secure_input"}
    assert on["command_secure_input"] is True and on["hooks"] == ["pre_tool_call"]
    assert on["slack_actions"] == ["'secure_input_open'"]
    d = on["directives"]
    assert d["enter_code"][0] == "block" and d["enter_code"][1].startswith("secure-input: browser_vault enter_code is")
    assert d["enter_code_handle"] == d["enter_code"]  # a handle does not get past the hook
    assert d["save_login"][0] == "block"
    assert d["fill"] is None
    assert off["directives"] == {"enter_code": None, "enter_code_handle": None, "save_login": None, "fill": None}
    assert proc.stdout.strip().endswith("RESULT: PASS")
