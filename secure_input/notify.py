"""Link notifications (card 5.3).

One interface, two implementations:

* ``SlackNotifier``: a normal message in the current Slack conversation/thread with a description
  section and one URL button (``action_id`` ``secure_input_open``); when the request ends the same
  message is replaced via ``chat.update`` with the result text and no button, so an expired link
  never stays clickable in Slack.
* ``TextNotifier``: ``ctx.post_message`` text (CLI, Desktop, other chats, and the fallback when the
  Slack route cannot be used); the result replaces it through the handle's ``edit``.

What leaves the machine: the link, purpose, kind, label, target profile, the variable name or site
address, and the result status. Never a value or an identifier (login id).

The Slack route uses the gateway's own adapter client so the bot identity and the thread match the
conversation. That needs private gateway attributes (``docs/integration-notes.md`` lists them); when
any of them is missing the notifier falls back to the text message.
"""

from __future__ import annotations

import asyncio
import logging
import unicodedata
from dataclasses import dataclass
from typing import Any, Callable, Optional

log = logging.getLogger(__name__)

KIND_KO = {"api_key": "API 키", "login": "사이트 로그인", "otp_code": "일회용 코드", "secret": "비밀번호"}
STORE_KO = {"env": ".env", "hermes_vault": "Hermes vault", "keychain": "Mac 키체인"}
# Appendix A.4: the only failure words a store row may carry. Anything else (another program's text) is never
# shown, only "사유" is dropped.
STORE_ERROR_WORDS = frozenset((
    "store_timeout", "keychain_unavailable", "keychain_timeout", "keychain_acl_denied", "keychain_name_invalid",
    "keychain_value_unsupported", "keychain_line_too_long", "keychain_write_failed", "keychain_verify_failed",
    "invalid_env_var", "invalid_value", "env_write_failed", "bad_home", "env_not_writable", "masked_value",
    "verify_failed", "invalid_identifier_type", "vault_rejected", "unsupported_kind", "internal_error", "no_result"))
RESULT_UNKNOWN_TEXT = "저장 여부를 확인하지 못했습니다."  # appendix A.12
MAIN_TOUCHED_TEXT = "키체인 항목 `{service}`의 기존 값이 바뀌었을 수 있습니다."  # appendix A.12
# RC-1: the main write ran on an item that was not there before (``main_created``) and the save failed.
MAIN_CREATED_TEXT = "키체인에 `{service}` 항목이 새로 만들어졌고 이번에 넣은 값이 들어 있을 수 있습니다."
# Reason ``window_passed_while_saving``: submitted in time, the window passed while saving, nothing saved.
WINDOW_PASSED_WHILE_SAVING_TEXT = "만료: 저장하는 동안 제출 시간이 지났고 저장하지 못했습니다"
# Reason ``window_passed_after_failed_save`` (RC-2): a save failed and could be retried, no other submit came.
WINDOW_PASSED_AFTER_FAILED_SAVE_TEXT = "만료: 보낸 값은 저장하지 못했고, 다시 보내지 않은 채 제출 시간이 지났습니다"
# R3-3: the first sentence is the same, letter for letter, on the page (ui/src/lib/copy.ts).
TMP_LEFT_TEXT = ("임시 키체인 항목에 이번에 넣은 값이 남아 있을 수 있습니다. "
                 "Hermes가 도는 컴퓨터에서 README의 '남은 임시 키체인 항목' 절의 명령으로 확인해 지우세요.")


def result_unknown(kind: str, status: str, meta: Optional[dict]) -> bool:
    """Nobody knows whether the value was written (appendix A.2 last rows): the request failed with a store result
    nobody saw (``store_timeout``, ``no_result``), or the server ended without its ``done`` line (``child_exited``)
    for a kind that saves."""
    reason = (meta or {}).get("reason")
    return status == "failed" and (reason in ("store_timeout", "no_result")
                                   or (reason == "child_exited" and kind != "otp_code"))


def error_word(row: dict) -> Optional[str]:
    word = row.get("error")
    return word if word in STORE_ERROR_WORDS else None
LIFETIME_TEXT = "60초 안에 열어야 하고 한 번만 열 수 있습니다. 연 뒤 5분 안에 제출하세요."
BUTTON_TEXT = "입력 페이지 열기"
ACTION_ID = "secure_input_open"
CALL_TIMEOUT_S = 30.0
SECTION_MAX_CHARS = 3000  # Slack: a section block's text object


class NotifyError(RuntimeError):
    """The link could not be shown anywhere."""


@dataclass(frozen=True)
class LinkCard:
    kind: str
    label: str
    purpose: str
    target_profile: str
    url: str
    env_var: Optional[str] = None
    origin: Optional[str] = None
    site: Optional[str] = None
    profile_editable: bool = True
    title_prefix: str = ""
    stores: tuple = ()  # RequestSpec.stores rows (appendix A.5)
    keychain: Optional[dict] = None  # RequestSpec.keychain (appendix A.5)


def _esc(text: str) -> str:
    """Write ``&``, ``<``, ``>`` as Slack's entities, the escaping Slack asks for in every text field (review R3-7)."""
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _plain(text: str) -> dict:
    """A Block Kit ``plain_text`` object: Slack shows it as typed (no bold, code, links, mentions or emoji images;
    review R3-7). Agent-written text only ever goes into these."""
    return {"type": "plain_text", "text": _esc(text), "emoji": False}


def _quoted(text: str) -> str:
    """An agent-written reason inside the plugin's double quotes; a ``"`` in it becomes ``'`` so the reason cannot
    close the quote and go on as if the plugin said it (review R3-7)."""
    return '"' + _flat(text).replace('"', "'") + '"'


def _flat(text: str) -> str:
    """Requester-written text on one line: every control, line or paragraph separator becomes a space
    (S-6; specs refuse these already, this keeps a raw card from adding a fake line)."""
    return "".join(" " if unicodedata.category(c) in ("Cc", "Zl", "Zp") else c for c in str(text))


def _target_line(card: LinkCard) -> Optional[str]:
    if card.kind == "api_key":
        return f"변수: {card.env_var}"
    if card.kind == "login":
        return f"사이트: {card.origin}"
    if card.kind == "secret":
        return None  # the keychain line names what is written
    return f"사이트: {card.site}"


def _profile_line(card: LinkCard) -> str:
    if card.kind == "otp_code":
        return "저장: 하지 않음(코드는 로그인 페이지에 바로 입력됩니다)"
    if card.kind == "secret":
        return f"로그를 남길 프로필: {card.target_profile} (Mac 키체인은 프로필과 무관합니다)"
    suffix = " (페이지에서 바꿀 수 있음)" if card.profile_editable else ""
    return f"저장될 프로필: {card.target_profile}{suffix}"


def _store_lines(card: LinkCard) -> list[str]:
    """Where the value goes (plan 5.3, 6.3 R-1): the preselected stores, the keychain item's names (the plugin's
    own text) and each reason the agent wrote (quoted, so it never reads as the plugin's word).

    An allow-list item is named by its service, id, label and used_by; its account is never sent, since an existing
    item's account is often a login id or an email address (review R3-5). The plugin's own items show their fixed
    account."""
    rows = [r for r in card.stores if isinstance(r, dict) and r.get("store") in STORE_KO]
    if not rows:
        return []
    chosen = ", ".join(STORE_KO[r["store"]] for r in rows if r.get("selected")) or "없음"
    fixed = all(r.get("fixed") for r in rows)
    lines = [f"저장 위치: {chosen}" + ("" if fixed else " (페이지에서 켜고 끌 수 있음)")]
    kc_row = next((r for r in rows if r["store"] == "keychain"), None)
    kc = card.keychain or {}
    if kc_row is not None:
        head = "키체인 항목" if kc_row.get("selected") else "키체인 항목(켜면 저장)"
        if kc.get("service") and kc.get("listed"):
            lines.append(f"{head}: {_flat(kc['service'])} (허용 목록 항목 {kc.get('id')}: {_flat(kc.get('label') or '')}, "
                         f"쓰는 곳: {_flat(kc.get('used_by') or '')})")
        elif kc.get("service"):
            lines.append(f"{head}: {kc['service']} (계정 {kc.get('account')}, 이 플러그인 전용 이름)")
        else:
            lines.append(f"{head}: 쓸 수 없음(변수 이름으로 키체인 이름을 만들 수 없습니다)")
    for r in rows:
        if r.get("reason"):
            lines.append(f"Hermes가 적은 이유({STORE_KO[r['store']]}): {_quoted(r['reason'])}")
    return lines


def _title(card: LinkCard) -> str:
    return f"자격증명 입력 요청: {KIND_KO.get(card.kind, card.kind)}"


def _lines(card: LinkCard) -> list[str]:
    """The link message as lines; the first is the title, the rest hold agent-written text unescaped."""
    title = f"{card.title_prefix} {_title(card)}" if card.title_prefix else _title(card)
    target = _target_line(card)
    return ([title, f"이름표: {_flat(card.label)}", f"목적: {_flat(card.purpose)}"]
            + ([_flat(target)] if target else []) + _store_lines(card) + [_profile_line(card), LIFETIME_TEXT])


def build_blocks(card: LinkCard) -> list[dict]:
    """Title in a ``mrkdwn`` section (the plugin's own words, bold); every other line, all agent-written text among
    them, in one ``plain_text`` section, so Slack shows it as typed (review R3-7)."""
    head = (f"{_esc(card.title_prefix)} " if card.title_prefix else "") + f"*{_title(card)}*"
    return ([{"type": "section", "text": {"type": "mrkdwn", "text": head}}]
            + [{"type": "section", "text": _plain(chunk)} for chunk in _chunks(_lines(card)[1:])]
            + [{"type": "actions", "elements": [{"type": "button",
                                                 "text": {"type": "plain_text", "text": BUTTON_TEXT},
                                                 "url": card.url, "action_id": ACTION_ID}]}])


def _chunks(lines: list[str]) -> list[str]:
    """Lines joined into as few texts as fit Slack's 3,000-character section limit once escaped (usually one; the
    longest allowed purpose, label and reasons written with ``&`` need two)."""
    out: list[str] = []
    for line in lines:
        if out and len(_esc(out[-1] + "\n" + line)) <= SECTION_MAX_CHARS:
            out[-1] += "\n" + line
        else:
            out.append(line)
    return out


def fallback_text(card: LinkCard) -> str:
    return "\n".join(_lines(card) + [f"{BUTTON_TEXT}: {card.url}"])


def _row_place(row: dict, card: LinkCard, profile: str) -> str:
    if row["store"] == "env":
        return f"{row.get('env_var') or card.env_var}, 프로필 {row.get('profile') or profile}"
    if row["store"] == "hermes_vault":
        return f"{row.get('origin') or card.origin} 로그인, 프로필 {row.get('profile') or profile}"
    return f"Mac 키체인 {row.get('service') or (card.keychain or {}).get('service')}"


# Security review 3 N-3: a short gloss after a failure word, in the Slack result and the tool note. Only this word.
ERROR_WORD_GLOSS = {"keychain_acl_denied": "접근 허용 목록에 /usr/bin/security 없음"}


def failure_word_text(word: str) -> str:
    """``word`` or ``word: gloss`` (``ERROR_WORD_GLOSS``), the text after ``사유 ``."""
    gloss = ERROR_WORD_GLOSS.get(word)
    return f"{word}: {gloss}" if gloss else word


def _row_failure(row: dict, card: LinkCard, profile: str) -> str:
    if row.get("saved") is None:
        return f"{_row_place(row, card, profile)}(결과 확인 못 함)"
    word = error_word(row)
    return _row_place(row, card, profile) + (f"(사유 {failure_word_text(word)})" if word else "")


def keychain_failure_notes(rows: list, touched: str = MAIN_TOUCHED_TEXT, created: str = MAIN_CREATED_TEXT) -> list:
    """The sentences of keychain lines that did not save but whose main write ran: an earlier value may have
    changed (``main_touched``, A.13), or the item was made and may hold the value sent (``main_created``, RC-1)."""
    out = []
    for r in rows:
        if not (isinstance(r, dict) and r.get("store") == "keychain" and r.get("saved") is False):
            continue
        if r.get("main_touched") is True:
            out.append(touched.format(service=r.get("service")))
        if r.get("main_created") is True:
            out.append(created.format(service=r.get("service")))
    return out


def keychain_left_of(meta: Optional[dict]) -> Optional[dict]:
    """The end report's ``keychain_left`` (RC2-1, secure_input/server.py): what any attempt of the request left in
    its keychain item. Only its service, ``listed`` and the three facts; ``None`` when it is not there."""
    left = (meta or {}).get("keychain_left")
    if not isinstance(left, dict):
        return None
    return {"service": left.get("service"), "listed": left.get("listed") is True,
            **{k: left.get(k) is True for k in ("main_touched", "main_created", "tmp_left")}}


def keychain_notes(rows: list, left: Optional[dict], touched: str = MAIN_TOUCHED_TEXT,
                   created: str = MAIN_CREATED_TEXT) -> list:
    """The keychain sentences of an end report: those of its store lines (:func:`keychain_failure_notes`) and those
    of ``keychain_left`` (RC2-1), each once, earlier value first."""
    failed = [r for r in rows if isinstance(r, dict) and r.get("store") == "keychain" and r.get("saved") is False]
    out: list = []
    for template, key in ((touched, "main_touched"), (created, "main_created")):
        services = [r.get("service") for r in failed if r.get(key) is True]
        if left and left.get(key) is True:
            services.append(left.get("service"))
        out.extend(s for s in (template.format(service=v) for v in services) if s not in out)
    return out


def _touched(rows: list, left: Optional[dict] = None) -> str:
    return "".join(" " + s for s in keychain_notes(rows, left))


def tmp_may_be_left(rows: list) -> bool:
    """A temporary keychain item may still hold the new value (R3-3): the keychain module said ``tmp_left``, or
    the keychain row was made without an answer of the storage process (``store_timeout``, ``no_result``), whose
    end skipped the module's own delete of the temporary item."""
    return any(isinstance(r, dict) and r.get("store") == "keychain"
               and (r.get("tmp_left") is True or r.get("error") in ("store_timeout", "no_result")) for r in rows)


def tmp_left_said(rows: list, left: Optional[dict]) -> bool:
    """The end report says a temporary item may be left: a store line says so, or an earlier attempt did (RC2-1)."""
    return tmp_may_be_left(rows) or bool(left and left.get("tmp_left") is True)


def result_text(card: LinkCard, status: str, meta: Optional[dict]) -> str:
    text = _result_text(card, status, meta)
    if tmp_left_said((meta or {}).get("stores") or [], keychain_left_of(meta)):
        text += " " + TMP_LEFT_TEXT
    return text


def _result_text(card: LinkCard, status: str, meta: Optional[dict]) -> str:
    meta = meta or {}
    head = f"{card.title_prefix} " if card.title_prefix else ""
    name = f"{KIND_KO.get(card.kind, card.kind)} '{card.label}'"
    reason = meta.get("reason") or ""
    rows = [r for r in meta.get("stores") or [] if isinstance(r, dict) and r.get("store") in STORE_KO]
    profile = meta.get("target_profile") or card.target_profile
    # RC2-1: what earlier attempts of this request left in the keychain item, merged with the store lines.
    touched = _touched(rows, keychain_left_of(meta))
    if status == "saved" and rows:
        done = "; ".join(_row_place(r, card, profile) for r in rows if r.get("saved") is True)
        if meta.get("partial") is True:
            failed = "; ".join(_row_failure(r, card, profile) for r in rows if r.get("saved") is not True)
            return f"{head}일부만 저장: {done}; 실패: {failed} ({name}){touched}"
        return f"{head}저장 완료: {done}{touched}"
    if result_unknown(card.kind, status, meta):
        tail = f" 저장소: {'; '.join(_row_failure(r, card, profile) for r in rows)}." if rows else ""
        return f"{head}{RESULT_UNKNOWN_TEXT} ({name}){tail}{touched}"
    if status in ("expired", "cancelled", "failed", "saved") and touched:
        rest = {k: v for k, v in meta.items() if k not in ("stores", "keychain_left")}
        return _result_text(card, status, rest) + touched
    if status == "saved":
        storage = meta.get("storage") or {}
        profile = meta.get("target_profile") or card.target_profile
        stype = storage.get("type") or ("env" if card.kind == "api_key" else "vault")
        if stype == "env":
            where = storage.get("env_var") or card.env_var
        else:
            where = f"{storage.get('origin') or card.origin} 로그인"
        return f"{head}저장 완료: {where}, 프로필 {profile}"
    if status == "delivered":
        return f"{head}전달 완료: {card.site or ''} 일회용 코드를 로그인 페이지로 넘겼습니다".replace("  ", " ")
    if status == "expired":
        if reason == "window_passed_while_saving":
            return f"{head}{WINDOW_PASSED_WHILE_SAVING_TEXT} ({name})"
        if reason == "window_passed_after_failed_save":
            return f"{head}{WINDOW_PASSED_AFTER_FAILED_SAVE_TEXT} ({name})"
        if reason == "submit_window_passed":
            return f"{head}만료: 연 뒤 5분 안에 제출되지 않았습니다 ({name})"
        return f"{head}만료: 60초 안에 열리지 않았습니다 ({name})"
    if status == "cancelled":
        why = {"user_cancelled": "사용자가 입력 페이지에서 취소했습니다",
               "parent_gone": "Hermes 쪽에서 요청을 거두었습니다",
               "terminated": "Hermes 쪽에서 요청을 거두었습니다"}.get(reason, "요청이 취소되었습니다")
        return f"{head}취소: {why} ({name})"
    code = f", 사유 {reason}" if reason else ""
    if card.kind == "otp_code":
        return f"{head}실패: 코드를 로그인 페이지로 넘기지 못했습니다 ({name}{code})"
    return f"{head}실패: 저장하지 못했습니다 ({name}{code})"


def result_blocks(text: str) -> list[dict]:
    """The result message: the whole sentence (it carries the label) as ``plain_text`` (review R3-7)."""
    return [{"type": "section", "text": _plain(text)}]


# -- implementations ----------------------------------------------------------------------------------


class TextNotifier:
    """``ctx.post_message`` text; ``update`` edits it in place (or posts anew where edits are unsupported)."""

    def __init__(self, post: Callable[[str], Any]):
        self._post = post

    def post_link(self, card: LinkCard) -> Any:
        handle = self._post(fallback_text(card))
        if not getattr(handle, "ok", False):
            raise NotifyError(f"link message refused: {getattr(handle, 'error', None) or 'unknown'}")
        return handle

    def update(self, ref: Any, text: str) -> None:
        try:
            ref.edit(text)
        except Exception:  # health: allow BLE001 - a failed result edit must not fail the request
            log.warning("secure-input: result edit failed", exc_info=True)


@dataclass(frozen=True)
class SlackTarget:
    channel: str
    thread_ts: Optional[str]
    call: Callable[[str, dict], Any]  # (Web API method name, kwargs) -> response mapping


@dataclass(frozen=True)
class SlackRef:
    channel: str
    ts: str


class SlackNotifier:
    def __init__(self, target: SlackTarget, fallback: Optional[TextNotifier]):
        self._t = target
        self._fallback = fallback

    def post_link(self, card: LinkCard) -> Any:
        # The top-level text is only the notification preview; mrkdwn false and parse none keep Slack from
        # formatting it or turning addresses into links (review R3-7).
        kwargs: dict[str, Any] = {"channel": self._t.channel, "text": _esc(fallback_text(card)),
                                  "blocks": build_blocks(card), "mrkdwn": False, "parse": "none",
                                  "unfurl_links": False, "unfurl_media": False}
        if self._t.thread_ts:
            kwargs["thread_ts"] = self._t.thread_ts
        try:
            resp = self._t.call("chat_postMessage", kwargs)
            if resp is None or not resp.get("ts"):
                raise NotifyError("chat.postMessage returned no ts")
            return SlackRef(channel=str(resp.get("channel") or self._t.channel), ts=str(resp.get("ts")))
        except Exception as exc:  # health: allow BLE001 - fall back to text
            log.warning("secure-input: Slack block post failed (%s); falling back to text", type(exc).__name__)
            if self._fallback is None:
                raise NotifyError("Slack post failed") from None
            return self._fallback.post_link(card)

    def update(self, ref: Any, text: str) -> None:
        if not isinstance(ref, SlackRef):
            if self._fallback is not None:
                self._fallback.update(ref, text)
            return
        try:
            self._t.call("chat_update", {"channel": ref.channel, "ts": ref.ts, "text": _esc(text),
                                         "blocks": result_blocks(text), "parse": "none"})
        except Exception as exc:  # health: allow BLE001
            log.warning("secure-input: Slack chat.update failed (%s)", type(exc).__name__)


# -- routing ---------------------------------------------------------------------------------------


def resolve_slack_target(ctx: Any) -> Optional[SlackTarget]:
    """The Slack conversation the calling session answers in, through the gateway's adapter client.

    Private gateway names used (any missing one raises and the caller falls back to text):
    ``hermes_cli.plugin_messages._gateway_loop``, ``ctx._manager.home_path``,
    ``SlackAdapter._client_for``, ``SlackAdapter._resolve_thread_ts``.
    Must be called from a worker thread (tool handler, sync command handler), never the gateway loop.
    """
    from gateway.plugin_messages import bound_route, resolve
    from gateway.session_context import bound_session_key
    from hermes_cli.plugin_messages import _gateway_loop

    session_key = bound_session_key()
    if not session_key:
        return None
    runner, loop = _gateway_loop()
    if runner is None or loop is None:
        return None
    route = bound_route()
    plugin_home, plugin_id = ctx._manager.home_path, ctx.plugin_id

    async def _resolve():
        target, _err = await asyncio.to_thread(resolve, runner, session_key=session_key, route=route,
                                               plugin_home=plugin_home, plugin_id=plugin_id)
        if target is None or target.platform != "slack" or target.adapter is None:
            return None
        adapter = target.adapter
        client = adapter._client_for(target.chat_id, target.metadata)
        thread_ts = adapter._resolve_thread_ts(None, target.metadata)
        return client, str(target.chat_id), (str(thread_ts) if thread_ts else None)

    resolved = asyncio.run_coroutine_threadsafe(_resolve(), loop).result(CALL_TIMEOUT_S)
    if resolved is None:
        return None
    client, channel, thread_ts = resolved

    def call(method: str, kwargs: dict) -> Any:
        coro = getattr(client, method)(**kwargs)
        return asyncio.run_coroutine_threadsafe(coro, loop).result(CALL_TIMEOUT_S)

    return SlackTarget(channel=channel, thread_ts=thread_ts, call=call)


def notifier_for_session(ctx: Any, resolver: Callable[[Any], Optional[SlackTarget]] = resolve_slack_target):
    text = TextNotifier(ctx.post_message)
    try:
        target = resolver(ctx)
    except Exception as exc:  # health: allow BLE001 - private gateway attrs moved: use text
        log.warning("secure-input: Slack route unavailable (%s: %s); using text messages",
                    type(exc).__name__, str(exc)[:200])
        target = None
    return SlackNotifier(target, text) if target is not None else text
