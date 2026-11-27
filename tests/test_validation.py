"""Shared input checks (secure_input/validation.py): one-line values and writable env names."""

from __future__ import annotations

import pytest

from secure_input.validation import check_env_var_name, is_clean_single_line

# security-review S-2: str.splitlines() breaks on these, and a later .env read would split the value.
LINE_BREAKERS = ["\u2028", "\u2029", "\u0085", "\u000b", "\u000c", "\u001c", "\u001d", "\u001e"]

# security-review S-1: names the core writer refuses, plus names the plugin itself reads.
REFUSED_NAMES = ["HERMES_YOLO_MODE", "HERMES_REDACT_SECRETS", "DYLD_INSERT_LIBRARIES", "PATH", "PYTHONPATH",
                 "NODE_OPTIONS", "GIT_SSH_COMMAND", "BASH_ENV", "HERMES_HOME", "SECURE_INPUT_TAILSCALE_BIN",
                 "SECURE_INPUT_HERMES_AGENT_DIR"]


@pytest.mark.parametrize("ch", LINE_BREAKERS + ["\n", "\r", "\x00", "\t", "\x7f"])
def test_clean_single_line_rejects_line_breaks_and_control_chars(ch):
    assert not is_clean_single_line(f"앞{ch}INJECTED_VAR=x")


def test_clean_single_line_rejects_empty():
    assert not is_clean_single_line("")


@pytest.mark.parametrize("v", ["SECRET-CANARY-abc", "Exa 검색 도구 키 등록", "a # b", '"quoted', "  spaced  "])
def test_clean_single_line_accepts_ordinary_text(v):
    assert is_clean_single_line(v)


@pytest.mark.parametrize("name", REFUSED_NAMES)
def test_check_env_var_name_refuses_denied_names(name):
    with pytest.raises(ValueError) as exc:
        check_env_var_name(name)
    assert name not in str(exc.value)


@pytest.mark.parametrize("name", ["", "exa_api_key", "1ABC", "A-B", "A B", "ÄPI_KEY"])
def test_check_env_var_name_refuses_bad_shape(name):
    with pytest.raises(ValueError):
        check_env_var_name(name)


def test_check_env_var_name_accepts_ordinary_key():
    check_env_var_name("EXA_API_KEY")


def test_check_env_var_name_refuses_when_core_check_cannot_be_imported(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def no_core(name, *a, **kw):
        if name == "hermes_cli.config" or name.startswith("hermes_cli"):
            raise ImportError("blocked for test")
        return real_import(name, *a, **kw)

    monkeypatch.setattr(builtins, "__import__", no_core)
    with pytest.raises(ValueError):
        check_env_var_name("EXA_API_KEY")
