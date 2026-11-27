"""secure-input: one-time credential entry links for Hermes (server core).

The parent-side API lives in :mod:`secure_input.launcher`; the wire contract is
documented in ``docs/protocol.md``.
"""

from .config import PROTOCOL_VERSION

__all__ = ["PROTOCOL_VERSION"]
