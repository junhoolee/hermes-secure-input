"""Link notifications (card 5.3): Slack Block Kit button + plain-text fallback."""

import json

import pytest

from secure_input.notify import (LIFETIME_TEXT, LinkCard, NotifyError, SlackNotifier, SlackTarget, TextNotifier,
                                 build_blocks, fallback_text, notifier_for_session, result_text)

URL = "https://fake-host.example-tailnet.ts.net/TOKEN_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG/"


def card(**over):
    d = dict(kind="api_key", label="Exa <키>", purpose="검색 & 요약에 필요합니다", target_profile="default", url=URL,
             env_var="EXA_API_KEY")
    d.update(over)
    return LinkCard(**d)


class FakeSlack:
    """Records every Web API call (the whole payload) like a Slack client would receive it."""

    def __init__(self, fail_post=False):
        self.calls: list[tuple[str, dict]] = []
        self.fail_post = fail_post

    def __call__(self, method, kwargs):
        self.calls.append((method, json.loads(json.dumps(kwargs))))
        if method == "chat_postMessage" and self.fail_post:
            raise RuntimeError("invalid_blocks")
        return {"ok": True, "ts": "1795000000.000100", "channel": kwargs["channel"]}


class FakeHandle:
    def __init__(self, ok=True, error=None):
        self.ok, self.error, self.edits = ok, error, []

    def edit(self, text):
        self.edits.append(text)
        return {"ok": True}


class FakePost:
    def __init__(self, ok=True):
        self.posts, self.handles, self.ok = [], [], ok

    def __call__(self, text):
        self.posts.append(text)
        h = FakeHandle(ok=self.ok, error=None if self.ok else "no_conversation")
        self.handles.append(h)
        return h


def shown(blocks):
    """Every section's text, in order (title in mrkdwn, the rest in plain_text; review R3-7)."""
    return "\n".join(b["text"]["text"] for b in blocks if b["type"] == "section")


def test_blocks_have_section_and_one_url_button():
    blocks = build_blocks(card())
    assert [b["type"] for b in blocks] == ["section", "section", "actions"]
    section = shown(blocks)
    for part in ("API 키", "EXA_API_KEY", "default", LIFETIME_TEXT):
        assert part in section
    assert "&lt;키&gt;" in section and "&amp;" in section  # user text escaped for mrkdwn
    (button,) = blocks[-1]["elements"]
    assert button == {"type": "button", "text": {"type": "plain_text", "text": "입력 페이지 열기"}, "url": URL,
                      "action_id": "secure_input_open"}


def test_title_prefix_starts_the_block_text_outside_bold():
    text = build_blocks(card(title_prefix="[테스트]"))[0]["text"]["text"]
    assert text == "[테스트] *자격증명 입력 요청: API 키*"


def test_fallback_text_contains_link_and_context():
    text = fallback_text(card(title_prefix="[테스트]"))
    assert text.startswith("[테스트]")
    assert URL in text and "EXA_API_KEY" in text and LIFETIME_TEXT in text


def test_login_and_otp_cards_name_site():
    assert "https://admin.example.com" in shown(build_blocks(card(kind="login", env_var=None,
                                                                  origin="https://admin.example.com")))
    otp = shown(build_blocks(card(kind="otp_code", env_var=None, site="accounts.example.com", profile_editable=False)))
    assert "accounts.example.com" in otp and "일회용 코드" in otp


@pytest.mark.parametrize("status,meta,expect", [
    ("saved", {"target_profile": "worker", "storage": {"type": "env", "env_var": "EXA_API_KEY"}},
     "저장 완료: EXA_API_KEY, 프로필 worker"),
    ("saved", {"target_profile": "default", "storage": {"type": "vault", "origin": "https://a.example.com"}},
     "저장 완료: https://a.example.com 로그인, 프로필 default"),
    ("delivered", {"target_profile": "default"}, "전달 완료"),
    ("expired", {"reason": "open_window_passed"}, "만료: 60초 안에 열리지 않았습니다"),
    ("expired", {"reason": "submit_window_passed"}, "만료: 연 뒤 5분 안에 제출되지 않았습니다"),
    ("cancelled", {"reason": "user_cancelled"}, "취소"),
    ("failed", {"reason": "too_many_attempts"}, "실패"),
])
def test_result_text(status, meta, expect):
    assert expect in result_text(card(), status, meta)


def test_failed_otp_code_says_not_handed_over_not_not_saved():
    otp = card(kind="otp_code", label="로그인 코드", env_var=None, site="accounts.example.com", profile_editable=False)
    text = result_text(otp, "failed", {"reason": "too_many_attempts"})
    assert "실패: 코드를 로그인 페이지로 넘기지 못했습니다 (" in text
    assert "저장하지 못했습니다" not in text
    assert "사유 too_many_attempts" in text
    assert "실패: 저장하지 못했습니다 (" in result_text(card(), "failed", {"reason": "too_many_attempts"})


def test_slack_notifier_posts_blocks_in_thread_then_update_removes_button():
    fake = FakeSlack()
    n = SlackNotifier(SlackTarget(channel="C1", thread_ts="1795.1", call=fake), fallback=None)
    ref = n.post_link(card())
    n.update(ref, "저장 완료: EXA_API_KEY, 프로필 default")
    (m1, post), (m2, upd) = fake.calls
    assert m1 == "chat_postMessage" and post["channel"] == "C1" and post["thread_ts"] == "1795.1"
    assert post["blocks"][-1]["elements"][0]["url"] == URL and URL in post["text"]
    assert m2 == "chat_update" and upd["ts"] == "1795000000.000100" and upd["channel"] == "C1"
    assert all(b["type"] != "actions" for b in upd["blocks"]) and URL not in json.dumps(upd)
    assert "저장 완료" in upd["text"]


def test_slack_post_failure_falls_back_to_text_message():
    fake, post = FakeSlack(fail_post=True), FakePost()
    n = SlackNotifier(SlackTarget(channel="C1", thread_ts=None, call=fake), fallback=TextNotifier(post))
    ref = n.post_link(card())
    assert len(post.posts) == 1 and URL in post.posts[0]
    n.update(ref, "만료: 60초 안에 열리지 않았습니다")
    assert post.handles[0].edits == ["만료: 60초 안에 열리지 않았습니다"]


def test_text_notifier_refusal_raises():
    with pytest.raises(NotifyError):
        TextNotifier(FakePost(ok=False)).post_link(card())


class Ctx:
    def __init__(self):
        self.post_message = FakePost()


def test_notifier_for_session_falls_back_when_private_slack_attrs_break():
    def broken_resolver(ctx):
        raise AttributeError("'SlackAdapter' object has no attribute '_client_for'")

    ctx = Ctx()
    n = notifier_for_session(ctx, resolver=broken_resolver)
    assert isinstance(n, TextNotifier)
    n.post_link(card())
    assert URL in ctx.post_message.posts[0]


def test_notifier_for_session_uses_slack_when_resolved():
    fake = FakeSlack()
    n = notifier_for_session(Ctx(), resolver=lambda ctx: SlackTarget(channel="C9", thread_ts="1.2", call=fake))
    assert isinstance(n, SlackNotifier)
    n.post_link(card())
    assert fake.calls[0][1]["channel"] == "C9"
