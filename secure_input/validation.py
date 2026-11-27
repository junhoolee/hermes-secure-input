"""Shared input checks (security review S-1, S-2, S-6).

Neither function puts the checked value or name into an exception message.
"""

from __future__ import annotations

import re
import unicodedata

ENV_VAR_RE = re.compile(r"^[A-Z_][A-Z0-9_]*$")
_PLUGIN_PREFIX = "SECURE_INPUT_"
_BAD_CATEGORIES = frozenset({"Cc", "Zl", "Zp"})


def is_clean_single_line(v: str) -> bool:
    """True only for a non-empty string that ``str.splitlines()`` keeps as one line and that has no
    control (Cc), line separator (Zl) or paragraph separator (Zp) character."""
    if not isinstance(v, str) or len(v.splitlines()) != 1:
        return False
    return not any(unicodedata.category(c) in _BAD_CATEGORIES for c in v)


REASON_MAX_CHARS = 120
KEYCHAIN_VALUE_MAX_CHARS = 1024


def has_format_char(v: str) -> bool:
    """True when ``v`` holds an invisible format character (Unicode Cf: U+200B zero-width space, U+202E
    right-to-left override, U+200D zero-width joiner and the like; reviews T-4, N-2)."""
    return any(unicodedata.category(c) == "Cf" for c in v)


def is_reason_text(v) -> bool:
    """An agent-written reason, an allow-list ``label`` or ``used_by`` (plan 2.2, 3.2 rule 1): one clean line of
    1-120 characters, not blank, and no invisible format character (Unicode Cf, e.g. U+200B, U+202E; review T-4)."""
    if not isinstance(v, str) or not v.strip() or len(v) > REASON_MAX_CHARS or not is_clean_single_line(v):
        return False
    return not has_format_char(v)


def is_keychain_value(v) -> bool:
    """The value rule for anything written to the Mac keychain (plan 3.1): 1-1024 characters, printable ASCII
    0x20-0x7E only (so one line), and neither the first nor the last character is a space."""
    if not isinstance(v, str) or not 1 <= len(v) <= KEYCHAIN_VALUE_MAX_CHARS:
        return False
    return all(0x20 <= ord(c) <= 0x7E for c in v) and v[0] != " " and v[-1] != " "


def check_env_var_name(name: str) -> None:
    """Raise ``ValueError`` unless ``name`` may be written to a profile ``.env``.

    Refused: names outside ``^[A-Z_][A-Z0-9_]*$``, names starting with ``SECURE_INPUT_`` (the plugin
    reads those itself), and names Hermes' own env writer refuses. When the Hermes check cannot be
    imported the name is refused: no check, no write.
    """
    if not isinstance(name, str) or not ENV_VAR_RE.fullmatch(name):
        raise ValueError("invalid environment variable name")
    if name.startswith(_PLUGIN_PREFIX):
        raise ValueError("environment variable name is reserved for secure-input")
    try:
        from hermes_cli.config import validate_env_var_name_for_write
    except Exception:  # health: allow BLE001 - any import failure means the name cannot be checked
        raise ValueError("environment variable name check unavailable") from None
    try:
        validate_env_var_name_for_write(name)
    except ValueError:
        raise ValueError("environment variable name is refused by the Hermes env writer") from None
