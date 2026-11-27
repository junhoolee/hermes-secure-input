"""docs/protocol.md (2판) stays in step with the code (integration card 4.6).

1. Every constant in the doc's tables 1.1 and 1.2 has the value the code has, and every constant of
   ``secure_input/config.py`` and of ``secure_input/stores/keychain.py`` is in those tables.
2. The store failure reason words of section 10 are exactly the words the code can put in a store's
   ``error`` / ``reason`` (``store_unavailable`` is the HTTP word of section 3.4, not a store reason).
3. Every HTTP error word the server answers with is in section 3.4 with its status and message.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from secure_input import config, server
from secure_input.lifecycle import HTTP_STATUS
from secure_input.stores import keychain

REPO = Path(__file__).resolve().parent.parent
DOC = (REPO / "docs" / "protocol.md").read_text()


def section(title_prefix: str) -> str:
    lines = DOC.splitlines()
    start = next(i for i, ln in enumerate(lines) if ln.startswith(title_prefix))
    level = len(title_prefix) - len(title_prefix.lstrip("#"))
    end = next((i for i in range(start + 1, len(lines))
                if lines[i].startswith("#") and len(lines[i]) - len(lines[i].lstrip("#")) <= level), len(lines))
    return "\n".join(lines[start:end])


def table_rows(text: str) -> list[list[str]]:
    rows = []
    for ln in text.splitlines():
        if ln.startswith("| ") and not ln.startswith("|---"):
            rows.append([c.strip() for c in ln.strip().strip("|").split("|")])
    return rows[1:] if rows else rows  # drop the header


def doc_constants(title: str) -> dict:
    out = {}
    for row in table_rows(section(title)):
        name = row[0].strip("`")
        if re.fullmatch(r"[A-Z_][A-Z0-9_]*", name):
            out[name] = row[1].strip("`")
    return out


def code_value(obj):
    return obj.pattern if isinstance(obj, re.Pattern) else obj


def public_constants(module) -> dict:
    return {k: code_value(v) for k, v in vars(module).items()
            if re.fullmatch(r"[A-Z][A-Z0-9_]*", k) and not isinstance(v, type(re)) and not callable(v)}


def same(doc_text: str, value) -> bool:
    if isinstance(value, str) and not doc_text.startswith(('"', "'", "b'", 'b"')):
        return doc_text == value  # a regex pattern written bare
    try:
        return ast.literal_eval(doc_text) == value
    except (ValueError, SyntaxError):
        return False


def test_config_constants_match_table_1_1():
    doc = doc_constants("### 1.1")
    code = {k: v for k, v in public_constants(config).items() if k != "SECURITY_HEADERS"}
    assert sorted(set(code) - set(doc)) == []  # SECURITY_HEADERS is section 5's header block
    assert sorted(set(doc) - set(code)) == []
    assert {k: doc[k] for k in doc if not same(doc[k], code[k])} == {}


def test_keychain_constants_match_table_1_2():
    doc = doc_constants("### 1.2")
    code = public_constants(keychain)
    assert sorted(set(code) - set(doc)) == []
    assert sorted(set(doc) - set(code)) == []
    assert {k: doc[k] for k in doc if not same(doc[k], code[k])} == {}


def test_security_headers_block_matches_config():
    for name, value in config.SECURITY_HEADERS.items():
        assert f"{name}: {value}" in section("## 5.")


REASON_PATTERNS = [r'StoreError\("([a-z_]+)"', r'_Stop\("([a-z_]+)"', r'preflight_result\(False, "([a-z_]+)"',
                   r'"(?:error|reason)": "([a-z_]+)"', r'\berror="([a-z_]+)"', r'\breason = "([a-z_]+)"',
                   r'\bmissing = "([a-z_]+)"', r'_NO_RESULT, "([a-z_]+)"', r'else "(no_result)"',
                   r'"(store_timeout)" if']


def code_reason_words() -> set:
    files = [REPO / "secure_input" / "storage.py", REPO / "secure_input" / "server.py",
             *sorted((REPO / "secure_input" / "stores").glob("*.py"))]
    words = set()
    for f in files:
        text = f.read_text()
        if f.name == "server.py":  # only the create-time check of the server fills store reasons
            text = text[text.index("def run_create_preflight"):text.index("def open_stores")]
        for pat in REASON_PATTERNS:
            words.update(re.findall(pat, text))
    return words - {"store_unavailable"}


def doc_reason_words() -> set:
    return {row[0].strip("`") for row in table_rows(section("## 10."))}


def test_every_reason_word_in_code_is_in_section_10():
    assert sorted(code_reason_words() - doc_reason_words()) == []


def test_every_reason_word_in_section_10_is_in_code():
    assert sorted(doc_reason_words() - code_reason_words()) == []


def test_http_error_words_with_status_and_message_are_in_section_3_4():
    rows = {r[0].strip("`"): r for r in table_rows(section("### 3.4"))}
    statuses = dict(HTTP_STATUS, **server.EXTRA_STATUS)
    assert sorted(set(statuses) - set(rows)) == []
    assert sorted(set(rows) - set(statuses)) == []
    assert {k: rows[k][1] for k in rows if rows[k][1] != str(statuses[k])} == {}
    assert {k: rows[k][3] for k in rows if rows[k][3] != server.MESSAGES[k]} == {}
