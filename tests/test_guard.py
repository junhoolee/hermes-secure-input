import os

import pytest

from conftest import REAL_HERMES, RealHermesWrite


def test_guard_blocks_writes_under_real_hermes():
    # The parent folder does not exist, so even an unguarded open could not create anything.
    probe = REAL_HERMES / "secure-input-guard-probe-does-not-exist" / "x.txt"
    assert not probe.parent.exists()
    with pytest.raises(RealHermesWrite):
        open(probe, "w")
    with pytest.raises(RealHermesWrite):
        os.open(probe, os.O_WRONLY | os.O_CREAT)


def test_home_and_hermes_home_are_temp():
    assert not os.environ["HOME"].startswith(str(REAL_HERMES.parent) + "/.hermes")
    assert os.path.realpath(os.environ["HOME"]) != str(REAL_HERMES.parent)
