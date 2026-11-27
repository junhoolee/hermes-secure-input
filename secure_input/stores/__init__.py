"""Store modules (plan appendix A.10): ``env``, ``hermes_vault`` and ``keychain``.

``keychain`` (``secure_input.stores.keychain``, card 1) is imported by name only when a request uses it, so
the other stores work without it. Tests put an A.10-shaped stand-in into ``sys.modules`` under that name.
"""

from __future__ import annotations

import importlib
from types import ModuleType

from ..config import STORE_NAMES


def load(name: str) -> ModuleType:
    """The module of store ``name`` (one of ``STORE_NAMES``)."""
    if name not in STORE_NAMES:
        raise KeyError(name)
    return importlib.import_module(f"{__name__}.{name}")
