"""``secure_input_enter_code``: the site's one-time code during login, through the one-time page.

Mechanism (docs/otp-code-feasibility.md): Hermes' ``browser_vault enter_code`` asks the per-thread
code-prompt slot (``agent.vault_backends.unlock.get_code_prompt_callback``) for the code when no
authenticator key is saved. In a Slack turn the gateway puts a Slack-modal prompt in that slot, which
would carry the code through Slack. This tool runs on the agent's tool thread, swaps the slot for
``SecureInput.code_prompt`` (our page, ``otp_code`` kind), dispatches Hermes' own ``browser_vault``
handler on the SAME thread through ``ctx.dispatch_tool`` (so the slot swap is what it reads, and the
Bot Desktop fence and origin checks stay Hermes'), and restores the previous callback in ``finally``.

The code exists only inside the callback's return value and Hermes' page write; it is never logged,
put in the result, or kept.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Optional

log = logging.getLogger(__name__)


def enter_code(svc: Any, args: dict, *, task_id: Optional[str] = None) -> str:
    from agent.vault_backends import unlock

    handle = str((args or {}).get("handle") or "")
    call_args: dict[str, Any] = {"action": "enter_code"}
    if handle:
        call_args["handle"] = handle
    if (args or {}).get("target"):
        call_args["target"] = str(args["target"])

    svc.last_code_request = None
    previous = unlock.get_code_prompt_callback()
    unlock.set_code_prompt_callback(svc.code_prompt)
    try:
        raw = svc.ctx.dispatch_tool("browser_vault", call_args, task_id=task_id)
    finally:
        unlock.set_code_prompt_callback(previous)

    try:
        result = json.loads(raw) if isinstance(raw, str) else dict(raw)
    except (TypeError, ValueError):
        result = {"success": False, "error": "browser_vault returned an unreadable result"}
    if not isinstance(result, dict):
        result = {"success": False, "error": "browser_vault returned an unreadable result"}
    if result.get("error_type") == "no_code_field":
        from .plugin import NO_CODE_FIELD_NOTE
        result["note"] = NO_CODE_FIELD_NOTE
    result["secure_input"] = {"request_id": svc.last_code_request}
    return json.dumps(result, ensure_ascii=False)
