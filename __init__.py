"""Hermes plugin entry point for secure-input. The code lives in ``secure_input/plugin.py``."""

try:
    from .secure_input.plugin import register  # noqa: F401
except ImportError:
    # Hermes always imports this file as a package, so a failure there is real and re-raised.
    # pytest imports it as a plain top-level module when the checkout folder's name is not a
    # Python identifier (for example ``hermes-secure-input``); the tests import the package
    # themselves, so nothing is needed from this file in that case.
    if __package__:
        raise
