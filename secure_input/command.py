"""Argument parsing for the ``/secure-input`` command (Slack: ``!secure-input``).

    /secure-input key <ENV_VAR> [--profile <프로필>] [--purpose "<문구>"] [--label "<이름표>"]
    /secure-input login <https://사이트> [--label "<이름표>"] [--profile <프로필>] [--purpose "<문구>"]
    /secure-input secret <keychain_item> [--label "<이름표>"] [--profile <프로필>] [--purpose "<문구>"]
    /secure-input help

Only names travel through here (variable names, a site address, a keychain item name, a profile name). No value
is ever typed on the command line: the value goes into the one-time page. There is no option that picks stores:
the page preselects the kind's default and the user turns stores on or off there. The ``<keychain_item>`` name goes
through the plugin's plan 3.2 rules 3-8, the same as the tool argument.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlsplit

from .profiles import PROFILE_NAME_RE
from .spec import ENV_VAR_RE, SpecError, normalize_origin

USAGE = """사용법:
  /secure-input key <ENV_VAR> [--profile <프로필>] [--purpose "<문구>"] [--label "<이름표>"]
  /secure-input login <https://사이트> [--label "<이름표>"] [--profile <프로필>] [--purpose "<문구>"]
  /secure-input secret <keychain_item> [--label "<이름표>"] [--profile <프로필>] [--purpose "<문구>"]
  /secure-input help
Slack에서는 / 대신 ! 를 씁니다(!secure-input key EXA_API_KEY).
값은 명령에 적지 않습니다. 명령은 일회용 입력 페이지 링크를 보내고, 값은 그 페이지에만 입력합니다.
--profile 을 생략하면 이 대화의 프로필에 저장합니다.
secret 은 Mac 키체인에 저장할 비밀번호입니다. <keychain_item> 에는 허용 목록의 id 나 새 이름(영문 소문자, 숫자, -)을 적습니다.
저장 위치는 입력 페이지에서 고릅니다."""

_OPTIONS = ("--profile", "--purpose", "--label")


class CommandError(ValueError):
    """A bad command line. ``str()`` is a Korean reason followed by the usage text."""

    def __init__(self, reason: str):
        super().__init__(f"{reason}\n\n{USAGE}")
        self.reason = reason

    def usage_text(self) -> str:
        return str(self)


@dataclass(frozen=True)
class ParsedCommand:
    action: str  # "key" | "login" | "secret" | "help"
    kind: Optional[str] = None
    env_var: Optional[str] = None
    origin: Optional[str] = None
    keychain_item: Optional[str] = None
    profile: Optional[str] = None  # None: the session's profile
    purpose: str = ""
    label: str = ""


def https_origin(value: str) -> Optional[str]:
    """``https://host[:port]`` for an https URL (path, query and fragment dropped; a non-ASCII host in
    its ``xn--`` punycode form), else None."""
    if not isinstance(value, str) or not value.startswith("https://"):
        return None
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError:
        return None
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password:
        return None
    host = parts.hostname
    if "." not in host and host != "localhost":
        return None
    try:
        return normalize_origin(f"https://{host}" + (f":{port}" if port and port != 443 else ""))
    except SpecError:  # host has no ASCII (punycode) form
        return None


def parse_command(raw: str) -> ParsedCommand:
    try:
        words = shlex.split(raw or "")
    except ValueError:
        raise CommandError("따옴표가 닫히지 않았습니다.") from None
    if not words or words[0] in ("help", "-h", "--help", "도움말"):
        if len(words) > 1:
            raise CommandError("help 뒤에는 인자를 붙이지 않습니다.")
        return ParsedCommand(action="help")
    action, rest = words[0], words[1:]
    if action not in ("key", "login", "secret"):
        raise CommandError("알 수 없는 하위 명령입니다. key, login, secret, help 중 하나를 쓰세요.")
    positional: list[str] = []
    opts: dict[str, str] = {}
    i = 0
    while i < len(rest):
        w = rest[i]
        if w.startswith("--"):
            if w not in _OPTIONS:
                raise CommandError("알 수 없는 옵션이 있습니다. --profile, --purpose, --label 만 쓸 수 있습니다.")
            if i + 1 >= len(rest):
                raise CommandError(f"{w} 뒤에 값이 없습니다.")
            opts[w[2:]] = rest[i + 1]
            i += 2
            continue
        positional.append(w)
        i += 1
    if len(positional) != 1:
        what = {"key": "변수 이름", "login": "사이트 주소", "secret": "키체인 항목 이름"}[action]
        raise CommandError(f"{action} 뒤에는 {what} 하나만 적습니다.")
    target = positional[0]

    profile = opts.get("profile")
    if profile is not None and profile != "default" and not PROFILE_NAME_RE.fullmatch(profile):
        raise CommandError("프로필 이름 형식이 맞지 않습니다(영문 소문자, 숫자, -, _).")

    keychain_item = None
    if action == "key":
        if not ENV_VAR_RE.fullmatch(target):
            raise CommandError("변수 이름은 영문 대문자, 숫자, _ 로만 쓰고 숫자로 시작하지 않습니다(예: EXA_API_KEY).")
        kind, env_var, origin = "api_key", target, None
        default_purpose, default_label = f"{target} 값을 직접 등록합니다", target
    elif action == "secret":
        kind, env_var, origin, keychain_item = "secret", None, None, target
        default_purpose, default_label = f"Mac 키체인 항목 {target} 의 값을 직접 등록합니다", target[:80]
    else:
        origin = https_origin(target)
        if origin is None:
            raise CommandError("사이트 주소는 https:// 로 시작하는 주소여야 합니다(예: https://admin.example.com).")
        kind, env_var = "login", None
        default_purpose, default_label = f"{origin} 로그인 정보를 직접 등록합니다", str(urlsplit(origin).hostname)

    purpose = opts.get("purpose", default_purpose)
    label = opts.get("label", default_label)
    if not purpose.strip() or len(purpose) > 200:
        raise CommandError("--purpose 는 1-200자로 적습니다.")
    if not label.strip() or len(label) > 80:
        raise CommandError("--label 은 1-80자로 적습니다.")
    return ParsedCommand(action=action, kind=kind, env_var=env_var, origin=origin, keychain_item=keychain_item,
                         profile=profile, purpose=purpose, label=label)
