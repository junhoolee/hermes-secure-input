# 로그인 도중 일회용 코드: 가능 여부와 방식

결론: **본체 수정 없이 가능하다. `otp_code_implemented: true`.** 도구 `secure_input_enter_code`(`secure_input/otp_flow.py`)로 구현했다.

기준: Hermes 본체 `~/.hermes/hermes-agent` v0.23.3 (HEAD `caafe5389a`), 2026-11-23.

## 1. 본체가 코드를 받는 경로

- `browser_vault` 도구의 `enter_code`(`tools/browser_vault_tool.py:400` `browser_vault_enter_code`)는 핸들이 없거나
  저장된 로그인에 인증 앱 키가 없으면 `unlock.get_code_prompt_callback()`으로 받은 콜백에 `(site, "")`를 주고 코드를
  받는다(`:457-462`). 받은 코드는 공백과 `-`를 지운 뒤 `_eval_js_secret`로 페이지에 쓴다(`:437-455`).
- 콜백 슬롯은 스레드별이다(`agent/vault_backends/unlock.py:31` `_callback_tls`, `:52-58`).
- Slack 같은 메시징 턴에서 게이트웨이는 이 슬롯에 Slack 코드 카드(모달) 콜백을 넣는다(`gateway/session_vault_prompt.py:43-47`
  → `gateway/session_vault_code_card.py:77-128` `code_card_scope`, `:119` `unlock.set_code_prompt_callback(code_prompt)`).
  이 콜백은 `adapter.send_vault_code_prompt`로 Slack에 입력 모달을 띄우므로 코드가 Slack 서버를 평문으로 지난다.

## 2. 우리 방식

1. `secure_input_enter_code` 핸들러는 에이전트의 도구 스레드에서 돈다. 이 스레드에서 이전 콜백을 기억하고
   `unlock.set_code_prompt_callback(svc.code_prompt)`로 바꾼다.
2. 본체 `browser_vault` 핸들러를 **같은 스레드에서** 부른다: `ctx.dispatch_tool("browser_vault", {"action": "enter_code", ["handle"], ["target"]}, task_id=<도구가 받은 task_id>)`.
   `ctx.dispatch_tool`(`hermes_cli/plugins_context.py:485`)은 공개 플러그인 API이고 `registry.dispatch`를 바로 부른다.
   그래서 본체의 Bot Desktop 잠금 확인(`_fenced_page_op`), origin 확인, 페이지 쓰기는 본체 것이 그대로 돈다. `pre_tool_call` 훅은
   이 경로에서 돌지 않으므로 우리 차단 훅에 걸리지 않는다.
3. 본체가 슬롯의 콜백을 부르면 `svc.code_prompt(site, hint)`가 `kind="otp_code"`, `site=<호스트>`, `profile_editable=False`,
   목적 "`<site>` 로그인 도중 사이트가 일회용 코드를 요구했습니다", 이름표 "`<site>` 일회용 코드"로 요청을 만들고, 링크 버튼을
   보내고, 기다린 뒤 `Outcome.code`를 돌려준다. 만료, 취소, 실패면 `""`를 돌려주고 본체는 `code_declined`로 처리한다.
   코드는 변수에 오래 두지 않고(`outcome.code = None`) 로그나 결과에 넣지 않는다.
4. `finally`에서 이전 콜백을 되돌린다.

확인한 사실:

- 도구 핸들러는 `task_id`를 키워드로 받는다. 본체 `registry.dispatch`가 핸들러 시그니처에 있는 문맥 인자를 넘긴다
  (`tools/registry.py:1091-1099`).
- `can_prompt_here(prompt)`(`agent/vault_backends/unlock.py:248-255`)는 cron, 단발 질의, 무인 플랫폼에서만 거짓이다
  (`tools/approval_context.py:229-233`). Slack 턴에서는 참이고, 콜백이 우리 것이므로 본체는 우리 콜백을 부른다.
- 콜백은 다른 스레드에서 불리지 않는다. 본체 `enter_code`는 슬롯을 읽은 그 스레드에서 바로 콜백을 부른다(`:457-462`).
- 핸들을 주면(저장된 로그인) 본체가 먼저 인증 앱 키로 코드를 만들고, 키가 없을 때만 우리 콜백을 부른다.

## 3. 본체 Slack 모달로 새지 않게 하는 장치

`pre_tool_call` 훅(`secure_input/plugin.py` `SecureInput.pre_tool_call`)이 본체 `browser_vault`의 `enter_code`를
**핸들이 있든 없든** `{"action": "block", "message": ...}`로 막는다. 메시지는 `secure_input_enter_code`를 쓰고 핸들이 있었다면
같은 핸들을 넘기라고 알린다. `fill`, `list` 같은 다른 action과 다른 도구는 막지 않는다.
설정 `plugins.entries.secure-input.settings.intercept_core_code_prompt: false`이면 핸들 유무와 상관없이 막지 않는다(기본값은 막기).
훅은 기다리지 않는다(훅 30초 제한, `website/docs/user-guide/features/hooks.md:396`).

핸들 있는 호출도 막는 이유: 그 로그인에 인증 앱 키가 없으면 본체 `write_backend_code`가 `None`을 돌려주고
(`tools/browser_vault_context.py:51-71`), 본체는 핸들 없는 호출과 똑같이 스레드 슬롯의 콜백을 부른다
(`tools/browser_vault_tool.py:457-466`). Slack 턴에서 그 콜백은 게이트웨이의 Slack 모달이므로 코드가 Slack 서버를 지나간다.

막아도 기능은 줄지 않는다. `secure_input_enter_code`는 `handle`을 받아 본체 `browser_vault`에 그대로 넘기고, 이 호출은
`ctx.dispatch_tool` → `registry.dispatch` 경로라 `pre_tool_call` 훅을 거치지 않는다(`hermes_cli/plugins_context.py:485-493`).
인증 앱 키가 있는 로그인이면 본체가 키로 코드를 만들어 넣고 입력 페이지 요청은 생기지 않는다. 키가 없으면 본체가 우리 콜백을
불러 입력 페이지로 코드를 받는다.

## 4. 한계: 한국어 라벨의 코드 칸

본체 `classify_otp_controls`(`agent/vault_login_classifier.py:138`)는 `autocomplete=one-time-code`이거나 영어 이름/라벨
(otp, 2fa, verification code 등)인 칸만 코드 칸으로 본다. 네이버 일회용 번호 칸(`#OnetimeCode`, 라벨 "일회용 번호")은
인식되지 않는다(2026-11-23 실측). 이때 본체는 `no_code_field`를 돌려주고, 우리 도구는 요청을 만들지 않고 그 결과에
`note`: "Hermes가 이 페이지의 코드 입력칸을 인식하지 못했습니다. 일회용 코드를 채팅으로 묻지 마세요. 사용자에게는 이 사이트의 코드 칸은 자동 입력이 되지 않는다는 사실만 알리세요. 일회용 코드가 필요 없는 다른 로그인 방법이 있으면 그것을 쓰고, 없으면 이 로그인을 멈추세요."를 붙여 돌려준다.
v1에서는 이 한계를 우회하지 않기로 정했다. 네이버처럼 일회용 번호/QR 로그인이 함께 있는 사이트는 아이디/비밀번호 로그인을
기본으로 쓰라고 `secure_input_request` 설명에 적었다.

## 5. 테스트

`tests/test_otp_flow.py` (본체의 진짜 `browser_vault` 핸들러, 페이지는 `_eval_js`/`_eval_js_secret`만 가짜):

- `test_code_goes_through_our_page_into_the_page_write`: 가짜 Slack 코드 카드(`send_vault_code_prompt`) 호출 0건, 우리 페이지
  요청 1건(`otp_code`, `profile_editable=False`), 가짜 `_eval_js_secret`에 코드 1건 전달, 이전 콜백 복원, Slack payload와 결과에 코드 0건.
- `test_expired_code_request_returns_code_declined`: 만료면 본체가 `code_declined`, 페이지 쓰기 0건.
- `test_no_code_field_is_passed_through_with_korean_note`: 한국어 라벨 칸은 `no_code_field`와 안내 문구, 요청 0건.

- `test_handle_without_authenticator_key_goes_through_our_page`: 실제 vault(임시 HERMES_HOME)에 인증 앱 키 없이 저장한 로그인의
  핸들을 넘기면 입력 페이지 요청 1건, 가짜 `send_vault_code_prompt` 0건, 코드가 가짜 `_eval_js_secret`에 1건 전달된다.
- `test_handle_with_authenticator_key_needs_no_page`: 인증 앱 키가 있는 로그인의 핸들이면 입력 페이지 요청 0건, Slack 게시 0건,
  본체가 만든 코드가 페이지에 1건 쓰인다.

`tests/test_plugin.py::test_hook_blocks_every_core_enter_code_and_save_login_only`, `::test_hook_settings_turn_interception_off`,
`tests/test_plugin_load.py`(본체 `_get_pre_tool_call_directive_details` 경로)에서 차단 범위와 설정 끄기를 확인한다.
실제 브라우저에서 코드를 넣어 `Outcome.code`가 일치하는지는 `ui/e2e/real-server.spec.ts`의 `otp_code` 테스트가 확인한다.
