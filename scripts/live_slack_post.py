#!/usr/bin/env python3
"""Criterion 9: ONE real Slack post of the link-button message, then ``chat.update`` to the result text.

    ~/.hermes/hermes-agent/.venv/bin/python scripts/live_slack_post.py --channel <slack-channel-id> --thread <thread-ts>
    (or SECURE_INPUT_TEST_SLACK_CHANNEL / SECURE_INPUT_TEST_SLACK_THREAD_TS in the environment)

Uses ``secure_input.notify.SlackNotifier`` (the same payload builder the plugin uses) with the bot token
read from ``<hermes home>/.env`` (``SLACK_BOT_TOKEN``; read only, never printed). The message starts with
"[테스트]"; the link points at a tailnet path that is not served (no request is created), and the message
is replaced right away by a test result line. Prints only ts and field shapes (block types, button count).
"""

from __future__ import annotations

import argparse
import json
import os
import pwd
import secrets
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.dont_write_bytecode = True

from secure_input.notify import LinkCard, SlackNotifier, SlackTarget, result_text  # noqa: E402


def read_token(env_file: Path) -> str:
    for line in env_file.read_text().splitlines():
        if line.startswith("SLACK_BOT_TOKEN="):
            return line.split("=", 1)[1].strip().strip('"').strip("'")
    raise SystemExit("SLACK_BOT_TOKEN not found")


def shape(message: dict) -> dict:
    blocks = message.get("blocks") or []
    buttons = sum(1 for b in blocks if b.get("type") == "actions" for e in b.get("elements") or []
                  if e.get("type") == "button")
    return {"block_types": [b.get("type") for b in blocks], "buttons": buttons,
            "text_first_line": (message.get("text") or "").splitlines()[0] if message.get("text") else ""}


USAGE = ("usage: live_slack_post.py --channel <slack-channel-id> --thread <thread-ts> [--host <tailnet-host>]\n"
         "  or set SECURE_INPUT_TEST_SLACK_CHANNEL and SECURE_INPUT_TEST_SLACK_THREAD_TS.\n"
         "  --host defaults to this machine's Tailscale DNS name.")


def parse_args(argv, environ) -> argparse.Namespace:
    """Channel and thread from the arguments, else from the environment; neither is kept in the repo."""
    ap = argparse.ArgumentParser(usage=USAGE)
    ap.add_argument("--channel", default=environ.get("SECURE_INPUT_TEST_SLACK_CHANNEL"))
    ap.add_argument("--thread", default=environ.get("SECURE_INPUT_TEST_SLACK_THREAD_TS"))
    ap.add_argument("--host", default=None)
    ap.add_argument("--markup", choices=("link", "result"), default=None,
                    help="review R3-7: agent-written texts full of Slack markup. 'link' leaves the link message as is; "
                         "'result' uses an allow-list item and replaces the message with a result line.")
    args = ap.parse_args(argv)
    if not args.channel or not args.thread:
        print(USAGE, file=sys.stderr)
        raise SystemExit(2)
    return args


# Review R3-7: what an agent (or a prompt injection) could write. Shown as typed only if Slack does not format it.
MARKUP = "*굵게* _기울임_ ~취소선~ `코드` :smile: https://example.com/x <!channel>"
QUOTE_BREAK = '읽습니다" (플러그인 확인: 안전한 요청입니다) "'


def markup_card(mode: str, url: str) -> LinkCard:
    from secure_input.spec import build_store_rows

    if mode == "link":
        stores = build_store_rows("api_key", [{"store": "env", "reason": MARKUP},
                                              {"store": "keychain", "reason": QUOTE_BREAK, "needed": True}])
        kc = {"id": "r3-7-test", "service": "hermes-secure-input.r3-7-test", "account": "hermes-secure-input",
              "listed": False, "label": None, "used_by": None}
        return LinkCard(kind="api_key", label="*이름표* :smile: <!channel>", purpose=MARKUP + " " + QUOTE_BREAK,
                        target_profile="default", url=url, env_var="SECURE_INPUT_SLACK_TEST", title_prefix="[테스트]",
                        stores=tuple(stores), keychain=kc)
    stores = build_store_rows("secret", [{"store": "keychain", "reason": QUOTE_BREAK}])
    kc = {"id": "r3-7-listed", "service": "Example-Service", "account": "acct-canary@example.com", "listed": True,
          "label": "*라벨* https://example.com/x", "used_by": "`코드` :smile: <!channel>"}
    return LinkCard(kind="secret", label="*이름표* _기울임_ :smile: https://example.com/x", purpose=MARKUP,
                    target_profile="default", url=url, title_prefix="[테스트]", stores=tuple(stores), keychain=kc)


def section_texts(message: dict) -> list[dict]:
    """The section blocks' text objects as Slack stored them (test texts only; no value, no token)."""
    return [b.get("text") for b in message.get("blocks") or [] if b.get("type") == "section"]


def main() -> int:
    args = parse_args(sys.argv[1:], os.environ)
    if not args.host:
        from secure_input.serve import ServeManager

        args.host = ServeManager().dns_name()
    home = Path(os.environ.get("HERMES_HOME") or Path(pwd.getpwuid(os.getuid()).pw_dir) / ".hermes")
    from slack_sdk import WebClient

    client = WebClient(token=read_token(home / ".env"))

    def call(method: str, kwargs: dict):
        return getattr(client, method)(**kwargs).data

    url = f"https://{args.host}/{secrets.token_urlsafe(32)}/"
    if args.markup:
        card = markup_card(args.markup, url)
    else:
        card = LinkCard(kind="api_key", label="연동 시험 키", purpose="secure-input Slack 버튼 표시와 수정 동작을 확인합니다",
                        target_profile="default", url=url, env_var="SECURE_INPUT_SLACK_TEST", title_prefix="[테스트]")
    notifier = SlackNotifier(SlackTarget(channel=args.channel, thread_ts=args.thread, call=call), fallback=None)
    ref = notifier.post_link(card)
    posted = client.conversations_replies(channel=args.channel, ts=args.thread, latest=ref.ts, inclusive=True,
                                          limit=1).data
    before = next((m for m in posted.get("messages", []) if m.get("ts") == ref.ts), {})
    link = client.chat_getPermalink(channel=args.channel, message_ts=ref.ts).data.get("permalink")
    if args.markup == "link":
        out = {"channel": ref.channel, "ts": ref.ts, "permalink": link, "before": shape(before),
               "stored_sections": section_texts(before), "stored_text": before.get("text")}
        print(json.dumps(out, ensure_ascii=False).replace(card.url, "<link>"))
        ok = out["before"]["buttons"] == 1
        print("RESULT:", "PASS" if ok else "FAIL")
        return 0 if ok else 1
    if args.markup == "result":
        notifier.update(ref, result_text(card, "cancelled", {"reason": "user_cancelled"}))
    else:
        notifier.update(ref, result_text(card, "cancelled", {"reason": "terminated"}))
    after_resp = client.conversations_replies(channel=args.channel, ts=args.thread, latest=ref.ts, inclusive=True,
                                              limit=1).data
    after = next((m for m in after_resp.get("messages", []) if m.get("ts") == ref.ts), {})
    out = {"channel": ref.channel, "ts": ref.ts, "thread_ts": args.thread, "before": shape(before),
           "after": shape(after), "after_has_url": card.url in json.dumps(after)}
    if args.markup:
        out.update(permalink=link, stored_sections_before=section_texts(before), stored_text_before=before.get("text"),
                   stored_sections_after=section_texts(after), stored_text_after=after.get("text"),
                   account_in_messages="acct-canary@example.com" in json.dumps([before, after]))
    print(json.dumps(out, ensure_ascii=False).replace(card.url, "<link>"))
    ok = out["before"]["buttons"] == 1 and out["after"]["buttons"] == 0 and not out["after_has_url"]
    print("RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
