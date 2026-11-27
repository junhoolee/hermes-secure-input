"""Profile home resolution. ``hermes_root`` (the default profile home) is the only basis;
this module never looks at ``~/.hermes`` or ``HERMES_HOME`` on its own."""

from __future__ import annotations

import os
import re
from pathlib import Path

PROFILE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


class ProfileError(ValueError):
    """Raised with a reason only (no paths outside the root are echoed)."""


def _root(hermes_root: str | os.PathLike) -> Path:
    root = Path(hermes_root)
    if not root.is_absolute():
        raise ProfileError("hermes_root must be an absolute path")
    if not root.is_dir():
        raise ProfileError("hermes_root does not exist")
    return root


def resolve_profile_home(name: str, hermes_root: str | os.PathLike) -> Path:
    root = _root(hermes_root)
    if name == "default":
        return root
    if not isinstance(name, str) or not PROFILE_NAME_RE.fullmatch(name):
        raise ProfileError("invalid profile name")
    home = root / "profiles" / name
    if not home.is_dir():
        raise ProfileError("profile does not exist")
    return home


def list_profiles(hermes_root: str | os.PathLike) -> list[str]:
    root = _root(hermes_root)
    names = ["default"]
    prof = root / "profiles"
    if prof.is_dir():
        names += sorted(p.name for p in prof.iterdir() if p.is_dir() and PROFILE_NAME_RE.fullmatch(p.name))
    return names


def all_profile_homes(hermes_root: str | os.PathLike) -> list[Path]:
    return [resolve_profile_home(n, hermes_root) for n in list_profiles(hermes_root)]
