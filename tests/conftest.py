"""Shared fixtures.

Safety guard (card section 6): every test runs with HOME and HERMES_HOME pointed at a temp
folder, and two independent checks fail the run if anything touches the real ``~/.hermes``:

1. an in-process audit hook that raises on any write/rename/remove/mkdir under the real
   ``~/.hermes`` (except bytecode caches, which ``sys.dont_write_bytecode`` already disables);
2. a session-level snapshot of the real secret/log files (``.env``, ``vault/``, ``logs/``,
   ``secure-input/``) of every profile, compared after the session, which also catches
   writes made by child processes the audit hook cannot see.
"""

from __future__ import annotations

import json
import os
import pwd
import stat
import sys
import textwrap
from pathlib import Path

import pytest

sys.dont_write_bytecode = True

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
TESTS_DIR = Path(__file__).resolve().parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

def _hermes_agent_dir() -> Path | None:
    """Hermes' source folder (plugin tests import ``tools``, ``agent``, ``gateway``, ``hermes_cli``).
    Appended, never prepended, so it cannot shadow this repo's modules."""
    env = os.environ.get("SECURE_INPUT_HERMES_AGENT_DIR", "").strip()
    if env:
        return Path(env)
    import importlib.util
    try:
        spec = importlib.util.find_spec("agent")
    except (ImportError, ValueError):
        spec = None
    for loc in (spec.submodule_search_locations or []) if spec else []:
        if (Path(loc).parent / "hermes_constants.py").exists():
            return Path(loc).parent
    return None


HERMES_AGENT_DIR = _hermes_agent_dir()
if HERMES_AGENT_DIR is not None and str(HERMES_AGENT_DIR) not in sys.path:
    sys.path.append(str(HERMES_AGENT_DIR))

REAL_HOME = Path(pwd.getpwuid(os.getuid()).pw_dir)
REAL_HERMES = (REAL_HOME / ".hermes").resolve()

_WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC


def _under_real_hermes(path) -> bool:
    try:
        if isinstance(path, int):
            return False
        p = os.fsdecode(path)
    except TypeError:
        return False
    try:
        resolved = Path(os.path.abspath(p))
    except Exception:
        return False
    try:
        resolved.relative_to(REAL_HERMES)
    except ValueError:
        return False
    return True


def _is_write_mode(mode, flags) -> bool:
    if isinstance(mode, str) and any(c in mode for c in "wax+"):
        return True
    if isinstance(flags, int) and flags & _WRITE_FLAGS:
        return True
    return False


class RealHermesWrite(AssertionError):
    pass


def _audit_hook(event: str, args) -> None:
    if event == "open":
        path, mode, flags = (list(args) + [None, None, None])[:3]
        if path is not None and _is_write_mode(mode, flags) and _under_real_hermes(path):
            raise RealHermesWrite(f"test tried to write under real ~/.hermes: {path}")
    elif event in ("os.rename", "os.replace"):
        for p in args[:2]:
            if _under_real_hermes(p):
                raise RealHermesWrite(f"test tried to rename under real ~/.hermes: {p}")
    elif event in ("os.remove", "os.rmdir", "os.mkdir", "os.chmod", "os.truncate", "shutil.rmtree"):
        if args and _under_real_hermes(args[0]):
            raise RealHermesWrite(f"test tried {event} under real ~/.hermes: {args[0]}")


sys.addaudithook(_audit_hook)


def _sensitive_paths() -> list[Path]:
    homes = [REAL_HERMES]
    prof = REAL_HERMES / "profiles"
    if prof.is_dir():
        homes += [p for p in prof.iterdir() if p.is_dir()]
    out: list[Path] = []
    for h in homes:
        out.append(h / ".env")
        for sub in ("vault", "logs", "secure-input"):
            d = h / sub
            out.append(d)
            if d.is_dir():
                for root, _dirs, files in os.walk(d):
                    for f in files:
                        if sub == "logs" and f != "secure-input.jsonl":
                            continue  # other logs change constantly (live gateway)
                        out.append(Path(root) / f)
    return out


def _snapshot() -> dict[str, tuple]:
    snap = {}
    for p in _sensitive_paths():
        try:
            st = p.stat()
        except FileNotFoundError:
            snap[str(p)] = None
            continue
        if stat.S_ISDIR(st.st_mode):
            if p.name == "logs":
                continue
            snap[str(p)] = ("dir", sorted(os.listdir(p)))
        else:
            snap[str(p)] = (st.st_size, st.st_mtime_ns)
    return snap


@pytest.fixture(scope="session", autouse=True)
def _real_hermes_untouched():
    before = _snapshot()
    yield
    after = _snapshot()
    changed = {k for k in set(before) | set(after) if before.get(k, "absent") != after.get(k, "absent")
               and not (k not in before and after.get(k) is None)}
    assert not changed, f"real ~/.hermes secret/log paths changed during tests: {sorted(changed)}"


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path_factory, monkeypatch):
    home = tmp_path_factory.mktemp("home")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("HERMES_HOME", str(home / ".hermes-not-used"))
    monkeypatch.setenv("PYTHONDONTWRITEBYTECODE", "1")
    monkeypatch.delenv("SECURE_INPUT_TAILSCALE_BIN", raising=False)
    yield home


@pytest.fixture
def hermes_root(tmp_path) -> Path:
    """A temp default-profile home with one extra profile ``worker``."""
    root = tmp_path / "hermes"
    (root / "profiles" / "worker").mkdir(parents=True)
    return root


@pytest.fixture
def static_dir(tmp_path) -> Path:
    d = tmp_path / "static"
    (d / "assets").mkdir(parents=True)
    (d / "index.html").write_text("<!doctype html><title>dummy</title><script src=\"assets/app.js\"></script>\n")
    (d / "assets" / "app.js").write_text("console.log('dummy');\n")
    return d


@pytest.fixture
def canary() -> str:
    return "SECRET-CANARY-" + os.urandom(12).hex()


FAKE_DNS = "fake-host.example-tailnet.ts.net"


@pytest.fixture
def fake_tailscale(tmp_path):
    """A fake ``tailscale`` executable that logs argv as JSON lines."""
    from helpers.fake_tailscale import FakeTailscale

    return FakeTailscale(tmp_path / "fake-ts", dns_name=FAKE_DNS)


def make_spec_dict(root: Path, **over) -> dict:
    kind = over.pop("kind", "api_key")
    d = {
        "kind": kind,
        "purpose": "Exa 검색 도구 키 등록",
        "label": "Exa API key",
        "requester": {"type": "agent", "profile": "default", "platform": "slack",
                      "session_key": "sess-1", "user_id": "U123"},
        "target_profile": "default",
        "profile_editable": kind != "otp_code",
        "env_var": "EXA_API_KEY" if kind == "api_key" else None,
        "origin": "https://example.com" if kind == "login" else None,
        "site": "example.com" if kind == "otp_code" else None,
        "hermes_root": str(root),
    }
    d.update(over)
    return d


@pytest.fixture
def spec_dict(hermes_root):
    return lambda **over: make_spec_dict(hermes_root, **over)
