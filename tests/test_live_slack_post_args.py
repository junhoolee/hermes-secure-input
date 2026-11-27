"""scripts/live_slack_post.py takes the Slack channel and thread from args or env, never from the repo (S-14)."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys

from conftest import REPO_ROOT

SCRIPT = REPO_ROOT / "scripts" / "live_slack_post.py"


def load():
    spec = importlib.util.spec_from_file_location("live_slack_post", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_without_channel_and_thread_prints_usage_and_fails():
    env = {k: v for k, v in os.environ.items() if not k.startswith("SECURE_INPUT_TEST_SLACK_")}
    proc = subprocess.run([sys.executable, str(SCRIPT)], capture_output=True, text=True, env=env, timeout=60)
    assert proc.returncode != 0
    msg = proc.stdout + proc.stderr
    assert "SECURE_INPUT_TEST_SLACK_CHANNEL" in msg and "SECURE_INPUT_TEST_SLACK_THREAD_TS" in msg


def test_channel_and_thread_come_from_env():
    mod = load()
    args = mod.parse_args([], {"SECURE_INPUT_TEST_SLACK_CHANNEL": "CTEST", "SECURE_INPUT_TEST_SLACK_THREAD_TS": "1.2"})
    assert (args.channel, args.thread) == ("CTEST", "1.2")


def test_args_win_over_env():
    mod = load()
    args = mod.parse_args(["--channel", "CARG", "--thread", "3.4"],
                          {"SECURE_INPUT_TEST_SLACK_CHANNEL": "CTEST", "SECURE_INPUT_TEST_SLACK_THREAD_TS": "1.2"})
    assert (args.channel, args.thread) == ("CARG", "3.4")
