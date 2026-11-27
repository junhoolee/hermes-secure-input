"""Tailscale Serve path management (docs/protocol.md 7).

Adds ``/<token>`` on the tailnet HTTPS listener and removes exactly that path again. Other
Serve configuration is never touched. Measured on Tailscale 1.102.3: Serve strips the
``--set-path`` prefix before proxying, so the proxy target carries the token path again
(``http://127.0.0.1:<port>/<token>``) and the backend always receives ``/<token>/...``.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from typing import Callable, Optional, Sequence

MACOS_APP_BIN = "/Applications/Tailscale.app/Contents/MacOS/Tailscale"
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{8,128}$")

Runner = Callable[[Sequence[str]], "subprocess.CompletedProcess[str]"]


class ServeError(RuntimeError):
    pass


def find_tailscale_bin() -> Optional[str]:
    env = os.environ.get("SECURE_INPUT_TAILSCALE_BIN", "").strip()
    if env:
        return env
    if os.path.isfile(MACOS_APP_BIN) and os.access(MACOS_APP_BIN, os.X_OK):
        return MACOS_APP_BIN
    return shutil.which("tailscale")


def _default_runner(argv: Sequence[str]) -> "subprocess.CompletedProcess[str]":
    return subprocess.run(list(argv), capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)


class ServeManager:
    def __init__(self, bin: Optional[str] = None, runner: Optional[Runner] = None):
        self.bin = bin or find_tailscale_bin()
        self._runner = runner or _default_runner

    def _run(self, *args: str) -> "subprocess.CompletedProcess[str]":
        if not self.bin:
            raise ServeError("tailscale CLI not found (set SECURE_INPUT_TAILSCALE_BIN)")
        try:
            return self._runner([self.bin, *args])
        except (OSError, subprocess.SubprocessError) as exc:
            raise ServeError(f"tailscale CLI failed to run: {type(exc).__name__}") from None

    @staticmethod
    def _check_token(token: str) -> None:
        if not isinstance(token, str) or not _TOKEN_RE.fullmatch(token):
            raise ServeError("invalid path token")

    def dns_name(self) -> str:
        proc = self._run("status", "--json")
        if proc.returncode != 0:
            raise ServeError("tailscale status failed")
        try:
            name = json.loads(proc.stdout)["Self"]["DNSName"]
        except (ValueError, KeyError, TypeError):
            raise ServeError("tailscale status has no Self.DNSName") from None
        name = str(name).rstrip(".")
        if not name:
            raise ServeError("tailscale DNS name is empty (MagicDNS off?)")
        return name

    def owner_login(self) -> str:
        """Login name of the account this Mac's Tailscale runs as (``User[Self.UserID].LoginName``)."""
        proc = self._run("status", "--json")
        if proc.returncode != 0:
            raise ServeError("tailscale status failed")
        try:
            status = json.loads(proc.stdout)
            login = status["User"][str(status["Self"]["UserID"])]["LoginName"]
        except (ValueError, KeyError, TypeError):
            raise ServeError("tailscale status has no owner login") from None
        login = str(login).strip() if isinstance(login, str) else ""
        if not login:
            raise ServeError("tailscale owner login is empty")
        return login

    def add(self, token: str, port: int) -> None:
        self._check_token(token)
        proc = self._run("serve", "--bg", "--https=443", "--set-path", f"/{token}",
                         f"http://127.0.0.1:{int(port)}/{token}")
        if proc.returncode != 0:
            raise ServeError(f"tailscale serve add failed (exit {proc.returncode})")

    def remove(self, token: str) -> bool:
        self._check_token(token)
        try:
            proc = self._run("serve", "--https=443", "--set-path", f"/{token}", "off")
        except ServeError:
            return False
        return proc.returncode == 0

    def status_text(self) -> str:
        proc = self._run("serve", "status")
        return (proc.stdout or "").strip()
