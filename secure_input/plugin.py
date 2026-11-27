"""Hermes registration for secure-input: agent tools, the ``/secure-input`` command, the Slack
button ack and the ``pre_tool_call`` guard. ``register(ctx)`` is the plugin entry point
(re-exported by the repository root ``__init__.py``).

Nothing here ever sees a value except the one-time code inside ``secure_input_enter_code``, which
goes straight from ``Outcome.code`` into Hermes' own ``browser_vault enter_code`` page write.
"""

from __future__ import annotations

import contextlib
import json
import logging
import threading
import time
from typing import Any, Callable, Optional

from .command import USAGE, CommandError, https_origin, parse_command
from .config import KIND_STORES, OPEN_TTL_S, STORE_NAMES, STORE_TIMEOUT_S, SUBMIT_TTL_S, WAIT_MARGIN_S
from .launcher import Outcome, StartError, TooManyActive, start_request, sweep_stale
from .notify import (ACTION_ID, MAIN_CREATED_TEXT, MAIN_TOUCHED_TEXT, RESULT_UNKNOWN_TEXT, STORE_ERROR_WORDS,
                     STORE_KO, LinkCard, NotifyError, error_word, failure_word_text, keychain_left_of,
                     keychain_notes, notifier_for_session, result_text, result_unknown, tmp_left_said)
from .profiles import ProfileError, resolve_profile_home
from .serve import ServeError, ServeManager
from .spec import (ENV_VAR_RE, KeychainItemError, RequestSpec, SpecError, build_store_rows, normalize_hostname,
                   parse_keychain_items, resolve_keychain)
from .stores import placements

log = logging.getLogger(__name__)

TOOLSET = "secure_input"


def parent_wait_s(kind: str) -> float:
    """How long the parent waits for a request's result (plan 5.7 6, appendix A.1): the open and submit windows, the
    margin and the timeouts of every store the kind can use (api_key 400, login 400, secret 390, otp_code 370 s)."""
    return float(OPEN_TTL_S + SUBMIT_TTL_S + WAIT_MARGIN_S + sum(STORE_TIMEOUT_S[s] for s in KIND_STORES[kind]))
SETTING_CODE = "intercept_core_code_prompt"
SETTING_SAVE_LOGIN = "intercept_core_save_login"
SETTING_ALLOWED_LOGINS = "allowed_tailscale_logins"
SETTING_ALLOW_NO_IDENTITY = "allow_no_identity_header"
NO_IDENTITY_NOTE = "Tailscale 계정을 확인하지 못해 입력 페이지를 띄우지 못했습니다. 요청을 만들지 않았습니다."
ENV_VAR_REFUSED_NOTE = ("이 변수 이름으로는 저장할 수 없습니다. Hermes가 프로그램 실행이나 보안 설정에 쓰는 이름"
                        "(예: PATH, PYTHONPATH, HERMES_HOME, HERMES_YOLO_MODE)과 SECURE_INPUT_ 로 시작하는 이름은 "
                        "이 기능으로 저장하지 않습니다. 요청을 만들지 않았습니다.")

REQUEST_DESCRIPTION = (
    "Ask the user to enter a credential on a one-time secure page instead of in chat. "
    "사용자에게 채팅으로 비밀번호, API 키, 인증 코드를 물어보지 말고 이 도구를 쓴다. "
    "SSH 안내(`hermes vault add`, set_secret.sh)나 채팅 질문 대신 이 도구를 쓴다. "
    "Use it whenever work is blocked by a missing credential: "
    "(1) a site login page but no saved login for that origin (browser_vault list has none, or save_login "
    "returned prompt_unavailable) -> kind='login', origin=<page origin>, then browser_vault fill "
    "handle=<storage.item_id>; for sites that also offer one-time-number or QR login, use the ID/password login; "
    "(2) the site asks for a one-time code during login -> use secure_input_enter_code instead; "
    "(3) an API key or token is missing (env var unset, 401) -> kind='api_key', env_var=<NAME>; "
    "(4) a password a script on this Mac reads from the Mac keychain -> kind='secret' with keychain_item "
    "(pick an id of the allow list in the keychain_item description first). "
    "Stores: api_key -> env (default) and keychain, login -> hermes_vault only, secret -> keychain only. "
    "If a script on this Mac must read an API key too, add keychain to stores; keep env on as well, Hermes reads "
    "API keys from .env. In each stores reason write who reads the value from where. The user can still turn "
    "stores on or off on the page. "
    "Sends the user a link button in this conversation and waits up to about 400 s for the result. "
    "결과에는 값이 없다: the result carries only status and where it was stored "
    "(never the value, the login id or the link)."
)

NO_ALLOWED_ITEMS = "허용된 기존 항목 없음"  # appendix A.12
KEYCHAIN_ITEM_DESCRIPTION = (
    "api_key and secret only (secret: required). Names the Mac keychain item. An id of the allow list below writes "
    "that existing item (kind 'secret' only). Any other name ^[a-z0-9][a-z0-9-]{0,39}$ becomes this plugin's own "
    "new item (service hermes-secure-input.<name>, account hermes-secure-input), which no other program reads "
    "yet. api_key default: env_var lower-cased with _ -> -. Allowed existing items (id: label, 쓰는 곳):"
)

ENTER_CODE_DESCRIPTION = (
    "Enter the one-time code (2FA/SMS/email/OTP) the CURRENT browser page asks for during login. The user "
    "types it on a one-time secure page (link button in this conversation), never in chat; Hermes writes it "
    "into the page and the code is not stored. Use this instead of browser_vault enter_code, with or without a "
    "handle: pass the saved login's handle here when you have one (with an authenticator key the code is "
    "generated and nobody is asked). "
    "사용자에게 채팅으로 인증 코드를 물어보지 말고 이 도구를 쓴다. 결과에는 값이 없다."
)

def keychain_item_description(allow) -> str:
    """The ``keychain_item`` argument's description (plan 3.2 rule 2): one line per allow-list item with its id,
    label and used_by, never its service or account; an empty list says so."""
    lines = [f"- `{i['id']}`: {i['label']} (쓰는 곳: {i['used_by']})" for i in allow] or [f"- {NO_ALLOWED_ITEMS}"]
    return "\n".join([KEYCHAIN_ITEM_DESCRIPTION] + lines)


def build_request_schema(allow=()) -> dict:
    """The ``secure_input_request`` schema; built when the plugin registers, from the ``keychain_items`` setting."""
    return {
        "name": "secure_input_request",
        "description": REQUEST_DESCRIPTION,
        "parameters": {
            "type": "object",
            "properties": {
                "kind": {"type": "string", "enum": ["api_key", "login", "secret"]},
                "purpose": {"type": "string",
                            "description": "Why it is needed, one Korean sentence for the user (1-200 chars). "
                                           "No invisible characters and no emoji made by joining characters."},
                "label": {"type": "string",
                          "description": "Short name shown to the user (1-80 chars), e.g. 'Exa API 키'. "
                                         "No invisible characters and no emoji made by joining characters."},
                "env_var": {"type": "string", "description": "api_key only: variable name, ^[A-Z_][A-Z0-9_]*$."},
                "origin": {"type": "string", "description": "login only: https:// origin of the login page."},
                "target_profile": {"type": "string",
                                   "description": "Profile to store into (default: this session's profile). "
                                                  "The user can still change it on the page."},
                "stores": {"type": "array",
                           "description": "Stores to preselect on the page (omit: the kind's default). The user can "
                                          "turn them on or off; you cannot lock them.",
                           "items": {"type": "object",
                                     "properties": {
                                         "store": {"type": "string", "enum": list(STORE_NAMES)},
                                         "reason": {"type": "string",
                                                    "description": "One Korean sentence (1-120 chars, one line): "
                                                                   "who reads the value from this store."},
                                         "needed": {"type": "boolean",
                                                    "description": "true: the task reads the value from this "
                                                                   "store (the page warns if the user turns it off)."}},
                                     "required": ["store"]}},
                "keychain_item": {"type": "string", "description": keychain_item_description(list(allow))},
            },
            "required": ["kind", "purpose", "label"],
        },
    }


REQUEST_SCHEMA = build_request_schema()

ENTER_CODE_SCHEMA = {
    "name": "secure_input_enter_code",
    "description": ENTER_CODE_DESCRIPTION,
    "parameters": {
        "type": "object",
        "properties": {
            "handle": {"type": "string",
                       "description": "Optional saved-login handle; with an authenticator key the code is generated "
                                      "and nobody is asked."},
            "target": {"type": "string", "enum": ["browser", "preview"],
                       "description": "Same as browser_vault target (default browser)."},
        },
        "required": [],
    },
}

BLOCK_CODE_MESSAGE = (
    "secure-input: browser_vault enter_code is blocked here (with or without a handle) because its chat prompt "
    "would send the code through the chat service. Call secure_input_enter_code instead and pass the same "
    "handle if you had one (same page; a saved authenticator key still generates the code, otherwise the user "
    "types it on a one-time secure page). Do not ask the user for the code in chat."
)
BLOCK_SAVE_LOGIN_MESSAGE = (
    "secure-input: browser_vault save_login is replaced here. Call secure_input_request with kind='login', "
    "origin=<this login page's https origin>, a Korean purpose and a label; when it returns status 'saved', "
    "follow the note in the result: it says whether to call browser_vault fill with handle=<storage.item_id>. "
    "Do not ask the user for the id or password in chat and do not suggest `hermes vault add` over SSH."
)

ENV_NOTE = ("값은 {profile} 프로필의 .env 에 저장했습니다. 실행 중인 Hermes는 게이트웨이를 다시 시작한 뒤에 이 값을 읽습니다. "
            "이 값이 필요한 일은 지금 이어서 하지 말고, 사용자에게 게이트웨이를 다시 시작한 뒤(Slack에서는 !restart) "
            "같은 일을 다시 요청해 달라고 알리세요.")
VAULT_NOTE = "로그인은 {profile} 프로필 vault 에 새 항목으로 저장했습니다. browser_vault fill handle=<storage.item_id> 로 입력하세요."
# A session reads only its own profile's vault and .env (hermes-agent agent/vault_store.py, agent/vault_backends/
# local.py), so a value saved in another profile cannot be used by the session that asked.
VAULT_OTHER_PROFILE_NOTE = ("로그인은 {profile} 프로필 vault 에 새 항목으로 저장했습니다. 이 세션은 {session} 프로필이라 "
                            "이 항목을 쓸 수 없습니다. browser_vault fill 을 시도하지 말고 사용자에게 이 사실을 알리세요.")
ENV_OTHER_PROFILE_SUFFIX = " 이 세션은 {session} 프로필이라 이 값을 쓰지 못합니다."
SETTING_KEYCHAIN_ITEMS = "keychain_items"

# Appendix A.12: the tool's fixed sentences, word for word.
NEW_ITEM_NOTE = "새 항목입니다. 이 항목을 읽는 프로그램은 아직 없습니다. 값을 쓸 프로그램이 이 항목 이름과 키체인 계정 이름으로 읽게 되어 있는지는 사용자가 그 프로그램의 설정에서 확인해야 합니다. 사용자에게 두 이름을 알려 주고, 키체인 항목의 값은 읽지 마세요."
RESULT_UNKNOWN_NOTE = RESULT_UNKNOWN_TEXT  # "저장 여부를 확인하지 못했습니다."
SECRETS_COMMAND_NOTE = "Hermes가 이 값을 쓰려면 본체 설정 `secrets.command`가 필요합니다."
LISTED_NAME_NOTE = "`{name}`은 허용 목록의 항목 `{id}`가 쓰는 이름입니다. keychain_item에 `{id}`를 넘기세요."
PASS_KEYCHAIN_ITEM_NOTE = "keychain_item을 직접 넘기세요."
LISTED_SECRET_ONLY_NOTE = "허용 목록의 항목 `{id}`는 kind `secret`으로만 쓸 수 있습니다."
MAIN_TOUCHED_NOTE = MAIN_TOUCHED_TEXT  # "키체인 항목 `{service}`의 기존 값이 바뀌었을 수 있습니다."
MAIN_CREATED_NOTE = MAIN_CREATED_TEXT  # RC-1: "키체인에 `{service}` 항목이 새로 만들어졌고 ... 있을 수 있습니다."
TMP_LEFT_NOTE = ("임시 키체인 항목에 이번에 넣은 값이 남아 있을 수 있습니다. "
                 "사용자에게 README의 '남은 임시 키체인 항목' 절의 명령으로 확인해 지우라고 알리세요.")
EXPIRED_NOTES = {  # by end reason; any other reason of an expired request is the open window
    "open_window_passed": "사용자가 60초 안에 링크를 열지 않았습니다.",
    "submit_window_passed": "사용자가 연 뒤 5분 안에 제출하지 않았습니다.",
    "window_passed_while_saving": "사용자는 시간 안에 제출했지만 저장하는 동안 제출 시간이 지났고 저장은 실패했습니다.",
    "window_passed_after_failed_save": "사용자가 값을 보냈지만 저장하지 못했고, 다시 보내지 않은 채 제출 시간이 지났습니다.",
}
# Per-store sentences of the tool result (plan 5.3; written by this card).
KEYCHAIN_SAVED_NOTE = "값은 Mac 키체인 항목(service `{service}`, account `{account}`)에 저장했습니다."
# Security review 3 R3-5: an allow-list item's account (often a login id) never goes to the model; its id does.
KEYCHAIN_LISTED_SAVED_NOTE = "값은 Mac 키체인 항목(service `{service}`, 허용 목록 항목 `{id}`)에 저장했습니다."
STORE_FAILED_NOTE = "{store} 에는 저장하지 못했습니다{why}."
STORE_UNKNOWN_NOTE = "{store} 에 저장됐는지 확인하지 못했습니다{why}."
PARTIAL_NOTE = "일부 저장소에만 저장했습니다. 실패한 저장소만 다시 요청하세요."
# Appendix A.8 store result row: the keys the tool result keeps (never a value, its length or a login id).
TOOL_ROW_KEYS = ("store", "saved", "replaced", "error", "env_var", "profile", "origin", "item_id", "has_otp",
                 "removed_count", "replace_error", "service", "account", "listed", "new_item", "tmp_left",
                 "main_touched", "main_created")


def _tool_row(row: dict) -> dict:
    out = {k: row[k] for k in TOOL_ROW_KEYS if k in row}
    if row.get("store") == "keychain" and row.get("listed") is True:
        out.pop("account", None)  # R3-5: an allow-list item's account stays on the page
    if "error" in out:
        out["error"] = error_word(row)
    return out
NOT_CREATED = " 요청을 만들지 않았습니다."
KEYCHAIN_NAME_RULE_NOTE = ("keychain_item 은 영문 소문자, 숫자, - 로 된 1-40자 이름이어야 합니다(^[a-z0-9][a-z0-9-]{0,39}$). "
                           "kind 'secret' 에서는 꼭 넘깁니다.")


def keychain_refusal(exc: KeychainItemError, name: Any) -> str:
    """The tool's (and the command's) answer to a ``keychain_item`` refused by plan 3.2 rules 3, 4, 7, 8."""
    if exc.rule == 3:
        text = LISTED_SECRET_ONLY_NOTE.format(id=exc.listed_id)
    elif exc.rule == 4:
        text = LISTED_NAME_NOTE.format(name=name, id=exc.listed_id)
    elif exc.rule == 7:
        text = PASS_KEYCHAIN_ITEM_NOTE
    else:
        text = KEYCHAIN_NAME_RULE_NOTE
    return text + NOT_CREATED


NO_CODE_FIELD_NOTE = "Hermes가 이 페이지의 코드 입력칸을 인식하지 못했습니다. 일회용 코드를 채팅으로 묻지 마세요. 사용자에게는 이 사이트의 코드 칸은 자동 입력이 되지 않는다는 사실만 알리세요. 일회용 코드가 필요 없는 다른 로그인 방법이 있으면 그것을 쓰고, 없으면 이 로그인을 멈추세요."


class IdentityUnavailable(StartError):
    """Nobody to allow on the link: owner account unreadable and ``allowed_tailscale_logins`` empty."""


def _session_env(name: str) -> str:
    try:
        from gateway.session_context import get_session_env
        return get_session_env(name, "") or ""
    except Exception:  # health: allow BLE001 - outside a Hermes install
        import os
        return os.environ.get(name, "")


def _default_hermes_root() -> str:
    from hermes_constants import get_default_hermes_root
    return str(get_default_hermes_root())


def _default_interrupted() -> bool:
    try:
        from tools.interrupt import is_interrupted
        return bool(is_interrupted())
    except Exception:  # health: allow BLE001
        return False


@contextlib.contextmanager
def _human_wait(session_key: str):
    try:
        from tools.approval_human_wait import activity_heartbeat, human_wait_window
    except Exception:  # health: allow BLE001
        yield lambda: None
        return
    with human_wait_window(session_key or None):
        yield activity_heartbeat("waiting for the user on a secure-input page")


class SecureInput:
    """State and behaviour behind the registrations (injectable for tests)."""

    def __init__(self, ctx: Any, *, start: Callable[..., Any] = start_request,
                 notifier_factory: Callable[[Any], Any] = notifier_for_session,
                 hermes_root: Optional[Callable[[], str]] = None, start_kwargs: Optional[dict] = None,
                 wait_budget_s: Optional[float] = None, interrupted: Callable[[], bool] = _default_interrupted,
                 settings: Optional[Callable[[str, Any], Any]] = None, title_prefix: str = ""):
        self.ctx = ctx
        self._start = start
        self._notifier_factory = notifier_factory
        self._root = hermes_root or _default_hermes_root
        self._start_kwargs = dict(start_kwargs or {})
        self._budget = wait_budget_s
        self._interrupted = interrupted
        self._settings = settings
        self.title_prefix = title_prefix
        self._live: dict[str, Any] = {}
        self._lock = threading.Lock()
        self.last_code_request: Optional[str] = None

    # -- helpers ---------------------------------------------------------------------------------------
    def setting(self, key: str, default: Any) -> Any:
        if self._settings is not None:
            return self._settings(key, default)
        value = None
        try:
            value = self.ctx.get_config(key, None)
        except Exception:  # health: allow BLE001
            value = None
        if value is None:
            try:
                from hermes_cli.config import load_config_readonly
                from hermes_cli.plugins_state import _plugin_settings_entry
                entry = _plugin_settings_entry(load_config_readonly() or {}, self.ctx.plugin_id) or {}
                value = entry.get(key)
            except Exception:  # health: allow BLE001
                value = None
        return default if value is None else value

    def hermes_root(self) -> str:
        return self._root()

    def session_profile(self) -> str:
        return str(self.ctx.profile_name)

    def requester(self, rtype: str, *, platform: str = "", session_key: str = "", user_id: str = "") -> dict:
        return {"type": rtype, "profile": self.session_profile(),
                "platform": platform or _session_env("HERMES_SESSION_PLATFORM"),
                "session_key": session_key or _session_env("HERMES_SESSION_KEY"),
                "user_id": user_id or _session_env("HERMES_SESSION_USER_ID")}

    def allow_list(self) -> list[dict]:
        """The setting ``keychain_items`` (plan 3.2 rule 1), parsed. Left-out items are logged by number and field
        name only, never by their text."""
        items, warnings = parse_keychain_items(self.setting(SETTING_KEYCHAIN_ITEMS, None))
        for w in warnings:
            log.warning("secure-input: keychain_items item %s left out (field %s)", w["index"], w["field"])
        return items

    def request_schema(self) -> dict:
        return build_request_schema(self.allow_list())

    def build_spec(self, *, kind: str, purpose: str, label: str, requester: dict, target_profile: Optional[str],
                   env_var: Optional[str] = None, origin: Optional[str] = None, site: Optional[str] = None,
                   profile_editable: bool = True, stores: Optional[list] = None,
                   keychain_item: Optional[str] = None) -> RequestSpec:
        """``stores`` is the agent's ``stores`` argument (``None``: the kind's defaults) and ``keychain_item`` its
        ``keychain_item``; both go through plan 2.3 and 3.2 (``SpecError``, ``KeychainItemError``)."""
        root = self.hermes_root()
        profile = target_profile or requester["profile"]
        resolve_profile_home(requester["profile"], root)  # ProfileError: session profile unknown
        resolve_profile_home(profile, root)  # ProfileError: target profile missing
        rows = keychain = None
        if kind in ("api_key", "login", "secret"):
            chosen = isinstance(stores, (list, tuple)) and any(
                isinstance(s, dict) and s.get("store") == "keychain" for s in stores)
            keychain = resolve_keychain(kind, keychain_item, env_var=env_var, allow=self.allow_list(),
                                        keychain_chosen=chosen)
            key = placements.key_for(kind, env_var=env_var, origin=origin,
                                     keychain_item=(keychain or {}).get("id"))
            rows = build_store_rows(kind, stores, history=placements.previous_stores(root, key))
        return RequestSpec(kind=kind, purpose=purpose, label=label, requester=requester, target_profile=profile,
                           profile_editable=profile_editable, hermes_root=root, env_var=env_var, origin=origin,
                           site=site, stores=rows, keychain=keychain)

    def _card(self, spec: RequestSpec, url: str) -> LinkCard:
        return LinkCard(kind=spec.kind, label=spec.label, purpose=spec.purpose, target_profile=spec.target_profile,
                        url=url, env_var=spec.env_var, origin=spec.origin, site=spec.site,
                        profile_editable=spec.profile_editable, title_prefix=self.title_prefix,
                        stores=tuple(spec.stores or ()), keychain=spec.keychain)

    def identity_kwargs(self) -> dict:
        """Who may use the next link (security review S-4), computed for every request.

        The allow list is this Mac's Tailscale owner account plus ``allowed_tailscale_logins``. When the
        owner cannot be read and the setting is empty there is nobody to allow: :class:`IdentityUnavailable`.
        ``allow_no_identity_header`` is honoured only as a real ``true`` from the plugin settings.
        """
        raw = self.setting(SETTING_ALLOWED_LOGINS, [])
        extra = [x.strip() for x in ([raw] if isinstance(raw, str) else raw if isinstance(raw, (list, tuple)) else [])
                 if isinstance(x, str) and x.strip()]
        serve = self._start_kwargs.get("serve") or ServeManager()
        try:
            owner: list[str] = [serve.owner_login()]
        except ServeError:
            owner = []
        if not owner and not extra:
            raise IdentityUnavailable(NO_IDENTITY_NOTE)
        return {"allowed_logins": owner + extra,
                "allow_no_identity_header": self.setting(SETTING_ALLOW_NO_IDENTITY, False) is True}

    def launch(self, spec: RequestSpec):
        """Start the request and show the link. Returns ``(handle, notifier, ref, card)``."""
        handle = self._start(spec, **{**self.identity_kwargs(), **self._start_kwargs})
        with self._lock:
            self._live[handle.request_id] = handle
        card = self._card(spec, handle.url)
        try:
            notifier = self._notifier_factory(self.ctx)
            ref = notifier.post_link(card)
        except Exception:
            handle.cancel()
            self._forget(handle)
            raise
        return handle, notifier, ref, card

    def _forget(self, handle) -> None:
        with self._lock:
            self._live.pop(handle.request_id, None)

    def budget(self, kind: str) -> float:
        """The parent's wait for ``kind`` (:func:`parent_wait_s`); ``wait_budget_s`` overrides it (tests)."""
        return self._budget if self._budget is not None else parent_wait_s(kind)

    def wait(self, handle, *, session_key: str = "") -> Outcome:
        """Wait for the result; past the kind's budget or on an interrupted turn, cancel. ``handle.cancel()`` gets
        no ``grace``: the handle then waits the kind's cancel wait so a save in progress ends and is reported."""
        deadline = time.monotonic() + self.budget(handle.spec.kind)
        with _human_wait(session_key) as heartbeat:
            while True:
                try:
                    return handle.wait(timeout=1.0)
                except TimeoutError:
                    pass
                if self._interrupted():
                    log.info("secure-input request %s cancelled: turn interrupted", handle.request_id)
                    return handle.cancel()
                if time.monotonic() >= deadline:
                    return handle.cancel()
                heartbeat()

    def finish(self, handle, notifier, ref, card: LinkCard, outcome: Outcome) -> None:
        try:
            notifier.update(ref, result_text(card, outcome.status, outcome.meta))
        finally:
            self._forget(handle)

    def cancel_all(self) -> None:
        with self._lock:
            handles = list(self._live.values())
        for h in handles:
            try:
                h.cancel()  # the kind's cancel wait (appendix A.1)
            except Exception:  # health: allow BLE001
                log.warning("secure-input: cancel on unload failed", exc_info=True)

    # -- results ---------------------------------------------------------------------------------------
    @staticmethod
    def _storage(kind: str, env_var: Optional[str], origin: Optional[str], meta: Optional[dict],
                 keychain: Optional[dict] = None) -> dict:
        got = (meta or {}).get("storage") or {}
        if got.get("type") == "keychain" or (kind == "secret" and not got):
            kc = keychain or {}
            if kc.get("listed") is True:  # R3-5: the allow-list id and label instead of the account
                return {"type": "keychain", "service": got.get("service") or kc.get("service"), "listed": True,
                        "allow_list_id": kc.get("id"), "label": kc.get("label")}
            return {"type": "keychain", "service": got.get("service") or kc.get("service"),
                    "account": got.get("account") or kc.get("account")}
        if kind == "api_key":
            return {"type": got.get("type") or "env", "env_var": got.get("env_var") or env_var,
                    "item_id": got.get("item_id")}
        return {"type": got.get("type") or "vault", "origin": got.get("origin") or origin,
                "item_id": got.get("item_id"), "replaced": got.get("replaced") is True}

    def _saved_note(self, kind: str, rows: list, actual: str, other: bool, partial: bool,
                    keychain: Optional[dict] = None) -> str:
        """One sentence per store row (plan 5.3), then the keychain-only ``api_key`` sentence (4.3 (나)).
        ``keychain``: the request's ``RequestSpec.keychain`` (an allow-list item is named by its id, R3-5)."""
        session = self.session_profile()
        parts = []
        for r in rows:
            store, ok = r.get("store"), r.get("saved")
            if ok is True and store == "env":
                parts.append(ENV_NOTE.format(profile=actual)
                             + (ENV_OTHER_PROFILE_SUFFIX.format(session=session) if other else ""))
            elif ok is True and store == "hermes_vault":
                parts.append(VAULT_OTHER_PROFILE_NOTE.format(profile=actual, session=session) if other
                             else VAULT_NOTE.format(profile=actual))
            elif ok is True and store == "keychain" and r.get("listed") is True:
                parts.append(KEYCHAIN_LISTED_SAVED_NOTE.format(service=r.get("service"),
                                                               id=(keychain or {}).get("id")))
            elif ok is True and store == "keychain":
                parts.append(KEYCHAIN_SAVED_NOTE.format(service=r.get("service"), account=r.get("account")))
                if r.get("new_item") is True:
                    parts.append(NEW_ITEM_NOTE)
            elif store in STORE_KO:
                word = r.get("error") if r.get("error") in STORE_ERROR_WORDS else None
                why = f"(사유 {failure_word_text(word)})" if word else ""
                parts.append((STORE_FAILED_NOTE if ok is False else STORE_UNKNOWN_NOTE).format(store=STORE_KO[store],
                                                                                              why=why))
        kc = next((r for r in rows if r.get("store") == "keychain" and r.get("saved") is True), None)
        if kind == "api_key" and kc is not None and not any(
                r.get("store") == "env" and r.get("saved") is True for r in rows):
            parts.append(f"{SECRETS_COMMAND_NOTE} service `{kc.get('service')}`, account `{kc.get('account')}`.")
        if partial:
            parts.append(PARTIAL_NOTE)
        return " ".join(parts)

    def result(self, *, kind: str, label: str, target_profile: Optional[str], env_var=None, origin=None,
               outcome: Optional[Outcome] = None, request_id: Optional[str] = None, note: str = "",
               spec: Optional[RequestSpec] = None) -> str:
        status = outcome.status if outcome is not None else "failed"
        meta = outcome.meta if outcome is not None else {}
        rows = [_tool_row(r) for r in meta.get("stores") or [] if isinstance(r, dict) and r.get("store") in STORE_KO]
        partial = meta.get("partial") is True
        saved = status == "saved"
        actual = meta.get("target_profile") or target_profile
        session = self.session_profile()
        other = saved and bool(actual) and actual != session  # saved where this session cannot read it
        if not note:
            if saved and rows:
                note = self._saved_note(kind, rows, actual, other, partial, spec.keychain if spec else None)
            elif saved and kind == "api_key":
                note = ENV_NOTE.format(profile=actual)
                if other:
                    note += ENV_OTHER_PROFILE_SUFFIX.format(session=session)
            elif saved:
                note = (VAULT_OTHER_PROFILE_NOTE.format(profile=actual, session=session) if other
                        else VAULT_NOTE.format(profile=actual))
            elif status == "expired":
                note = EXPIRED_NOTES.get(str(meta.get("reason")), EXPIRED_NOTES["open_window_passed"])
                note += " 다시 필요하면 사용자에게 알리고 새 요청을 만드세요."
            elif status == "cancelled":
                note = "요청이 취소되었습니다. 같은 턴에 다시 요청하지 마세요."
            elif result_unknown(kind, status, meta):
                note = RESULT_UNKNOWN_NOTE
            else:
                note = f"저장하지 못했습니다(사유 {meta.get('reason') or 'unknown'})."
        # A.13, RC-1: a keychain item may have changed, or been made, although the row says not saved; RC2-1: also
        # what an earlier attempt of the request left there (keychain_left), each sentence once.
        left = keychain_left_of(meta)
        for sentence in keychain_notes(rows, left, MAIN_TOUCHED_NOTE, MAIN_CREATED_NOTE):
            note += " " + sentence
        if tmp_left_said(rows, left):  # R3-3
            note += " " + TMP_LEFT_NOTE
        if saved and rows and spec is not None and spec.stores:
            before = {s["store"] for s in spec.stores if s["selected"]}
            after = {r["store"] for r in rows}
            for store in STORE_NAMES:
                if store in before - after:
                    note += f" 사용자가 페이지에서 {STORE_KO[store]} 저장을 껐습니다."
                elif store in after - before:
                    note += f" 사용자가 페이지에서 {STORE_KO[store]} 저장을 켰습니다."
        if saved and target_profile and actual != target_profile:
            note += f" 사용자가 페이지에서 프로필을 {target_profile} 에서 {actual} 로 바꿨습니다."
        return json.dumps({"success": saved and not partial, "status": "partial" if saved and partial else status,
                           "request_id": request_id or meta.get("request_id"), "kind": kind, "label": label,
                           "target_profile": actual,
                           "storage": self._storage(kind, env_var, origin, meta, spec.keychain if spec else None),
                           "stores": rows, "partial": partial, "keychain_left": left, "note": note.strip()},
                          ensure_ascii=False)

    # -- agent tool: secure_input_request ----------------------------------------------------------------
    def tool_request(self, args: dict, **_kw) -> str:
        kind = str(args.get("kind") or "")
        purpose = args.get("purpose")
        label = args.get("label")
        env_var = args.get("env_var") or None
        origin = args.get("origin") or None
        target = args.get("target_profile") or None
        keychain_item = args.get("keychain_item")
        stores_arg = args.get("stores")

        def fail(note: str) -> str:
            return self.result(kind=kind, label=str(label or ""), target_profile=target or self.session_profile(),
                               env_var=env_var, origin=origin, note=note)

        if kind not in ("api_key", "login", "secret"):
            return fail("kind 는 api_key, login, secret 가운데 하나여야 합니다. "
                        "일회용 코드는 secure_input_enter_code 를 쓰세요.")
        if kind == "api_key":
            origin = None
            if not isinstance(env_var, str) or not ENV_VAR_RE.fullmatch(env_var):
                return fail("api_key 요청에는 env_var(^[A-Z_][A-Z0-9_]*$)가 필요합니다.")
        elif kind == "login":
            env_var = None
            norm = https_origin(origin) if isinstance(origin, str) else None
            if norm is None:
                return fail("login 요청에는 https:// origin 이 필요합니다.")
            origin = norm
        else:
            env_var = origin = None
        try:
            spec = self.build_spec(kind=kind, purpose=purpose, label=label, target_profile=target,
                                   requester=self.requester("agent"), env_var=env_var, origin=origin,
                                   stores=stores_arg, keychain_item=keychain_item)
        except ProfileError as exc:
            return fail(f"프로필을 찾지 못해 요청을 만들지 않았습니다({exc}).")
        except KeychainItemError as exc:
            return fail(keychain_refusal(exc, keychain_item))
        except SpecError as exc:
            if exc.field == "env_var":
                return fail(ENV_VAR_REFUSED_NOTE)
            return fail(f"요청 인자가 맞지 않아 요청을 만들지 않았습니다({exc.field}: {exc.reason}).")
        return self._run_blocking(spec)

    def _run_blocking(self, spec: RequestSpec) -> str:
        common: dict[str, Any] = dict(kind=spec.kind, label=spec.label, target_profile=spec.target_profile,
                                      env_var=spec.env_var, origin=spec.origin, spec=spec)
        try:
            handle, notifier, ref, card = self.launch(spec)
        except TooManyActive:
            return self.result(**common, note="이미 열린 요청이 3개라 새 요청을 만들지 않았습니다. 기존 요청이 끝난 뒤 다시 시도하세요.")
        except IdentityUnavailable:
            return self.result(**common, note=NO_IDENTITY_NOTE)
        except (StartError, ProfileError) as exc:
            return self.result(**common, note=f"입력 페이지를 띄우지 못했습니다({exc}).")
        except NotifyError:
            return self.result(**common, note="이 대화에 링크를 보낼 수 없어 요청을 취소했습니다.")
        outcome = self.wait(handle, session_key=spec.requester.get("session_key", ""))
        self.finish(handle, notifier, ref, card, outcome)
        return self.result(**common, outcome=outcome, request_id=handle.request_id)

    # -- one-time code prompt (used by otp_flow) ---------------------------------------------------------
    def code_prompt(self, site: str, hint: str = "") -> str:
        """``(site, hint) -> code`` for Hermes' vault code slot; ``""`` when expired/cancelled/failed."""
        host = str(site or "").split("/")[0].split(":")[0]  # core passes "<host>[:port]"
        try:
            host = normalize_hostname(host)  # look-alike non-ASCII host -> xn-- form (S-6)
            spec = self.build_spec(kind="otp_code", purpose=f"{host} 로그인 도중 사이트가 일회용 코드를 요구했습니다",
                                   label=f"{host} 일회용 코드"[:80], target_profile=None,
                                   requester=self.requester("agent"), site=host, profile_editable=False)
            handle, notifier, ref, card = self.launch(spec)
        except Exception as exc:  # health: allow BLE001 - the core reports code_declined
            log.warning("secure-input: code request could not start (%s)", type(exc).__name__)
            self.last_code_request = None
            return ""
        self.last_code_request = handle.request_id
        outcome = self.wait(handle, session_key=spec.requester.get("session_key", ""))
        self.finish(handle, notifier, ref, card, outcome)
        code = outcome.code if outcome.status == "delivered" else None
        outcome.code = None
        return code or ""

    # -- user command ----------------------------------------------------------------------------------
    def command(self, raw_args: str, source: Any = None, session_key: str = "", platform: str = "", **_kw) -> str:
        try:
            cmd = parse_command(raw_args or "")
        except CommandError as exc:
            return exc.usage_text()
        if cmd.action == "help":
            return USAGE
        requester = self.requester("user", platform=platform, session_key=session_key,
                                   user_id=str(getattr(source, "user_id", "") or ""))
        try:
            spec = self.build_spec(kind=cmd.kind, purpose=cmd.purpose, label=cmd.label, requester=requester,
                                   target_profile=cmd.profile, env_var=cmd.env_var, origin=cmd.origin,
                                   keychain_item=cmd.keychain_item)
        except ProfileError:
            return f"프로필을 찾지 못해 요청을 만들지 않았습니다.\n\n{USAGE}"
        except KeychainItemError as exc:
            return keychain_refusal(exc, cmd.keychain_item)
        except SpecError as exc:
            if exc.field == "env_var":
                return ENV_VAR_REFUSED_NOTE
            return f"요청 인자가 맞지 않습니다({exc.field}: {exc.reason}).\n\n{USAGE}"
        try:
            handle, notifier, ref, card = self.launch(spec)
        except TooManyActive:
            return "이미 열린 요청이 3개라 새 요청을 만들지 않았습니다."
        except IdentityUnavailable:
            return NO_IDENTITY_NOTE
        except (StartError, ProfileError) as exc:
            return f"입력 페이지를 띄우지 못했습니다({exc})."
        except NotifyError:
            return "이 대화에 링크를 보낼 수 없어 요청을 취소했습니다."

        def _bg() -> None:
            try:
                outcome = handle.wait(timeout=self.budget(spec.kind))
            except TimeoutError:
                outcome = handle.cancel()
            self.finish(handle, notifier, ref, card, outcome)

        threading.Thread(target=_bg, name=f"secure-input-{handle.request_id[:8]}", daemon=True).start()
        target = {"api_key": f"변수 {spec.env_var}", "login": f"사이트 {spec.origin}",
                  "secret": f"Mac 키체인 항목 {(spec.keychain or {}).get('service')}"}[spec.kind]
        return (f"입력 링크를 보냈습니다({target}, 프로필 {spec.target_profile}). 결과는 링크 메시지에 표시됩니다.")

    # -- hook ------------------------------------------------------------------------------------------
    def pre_tool_call(self, tool_name: str = "", args: Optional[dict] = None, **_kw):
        if tool_name != "browser_vault" or not isinstance(args, dict):
            return None
        action = str(args.get("action") or "")
        # Every core enter_code: with a handle but no authenticator key Hermes falls back to the same chat
        # prompt as without one. secure_input_enter_code reaches Hermes through ctx.dispatch_tool, which
        # does not run pre_tool_call, so it is not blocked here.
        if action == "enter_code":
            if self.setting(SETTING_CODE, True) is not False:
                return {"action": "block", "message": BLOCK_CODE_MESSAGE}
        if action == "save_login" and self.setting(SETTING_SAVE_LOGIN, True) is not False:
            return {"action": "block", "message": BLOCK_SAVE_LOGIN_MESSAGE}
        return None


async def _ack_open_click(ack, body=None, action=None, **_kw) -> None:
    """The button only opens the URL in the user's browser; Slack still posts the click: ack it."""
    await ack()


def register(ctx: Any) -> SecureInput:
    from . import otp_flow

    svc = SecureInput(ctx)
    try:
        sweep_stale(svc.hermes_root())
    except Exception:  # health: allow BLE001 - a sweep failure must not block loading
        log.warning("secure-input: sweep_stale at load failed", exc_info=True)
    ctx.register_tool(name="secure_input_request", toolset=TOOLSET, schema=svc.request_schema(),
                      handler=lambda args, **kw: svc.tool_request(args, **kw),
                      description="자격증명을 일회용 보안 페이지로 받기", emoji="🔑")
    ctx.register_tool(name="secure_input_enter_code", toolset=TOOLSET, schema=ENTER_CODE_SCHEMA,
                      handler=lambda args, task_id=None, **kw: otp_flow.enter_code(svc, args, task_id=task_id),
                      description="로그인 일회용 코드를 일회용 보안 페이지로 받아 입력", emoji="🔢")
    ctx.register_command("secure-input", svc.command, description="자격증명을 일회용 보안 페이지로 등록",
                         args_hint="key <ENV_VAR> | login <https://사이트> | secret <keychain_item> | help")
    ctx.register_hook("pre_tool_call", svc.pre_tool_call)
    try:
        ctx.register_slack_action_handler(ACTION_ID, _ack_open_click)
    except Exception:  # health: allow BLE001 - older cores without Slack action hooks
        log.warning("secure-input: Slack action handler not registered", exc_info=True)
    ctx.on_unload(svc.cancel_all)
    return svc
