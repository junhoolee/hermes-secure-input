# Hermes 통합 조사 결과 (플러그인을 Hermes 본체에 연결하는 방법의 조사, 2026-11-23)

기준: Hermes 본체 `~/.hermes/hermes-agent` (v0.23.3, HEAD `caafe5389a`). 아래 파일:줄은 이 시점 기준이다. 본체는 고치지 않았다.

## 1. 도구 대기 방식: 동기 대기(도구 1건이 끝까지 기다림)

`secure_input_request`는 링크를 보낸 뒤 결과가 날 때까지 같은 도구 호출 안에서 기다린다. 최대 대기는
60초(열기) + 300초(제출) + 10초(여유) = 370초다(`secure_input/plugin.py` `WAIT_BUDGET_S`).
두 번째 도구(`secure_input_status`)를 쓰는 대체 방식은 필요하지 않아 만들지 않았다.

근거:

- 도구 호출 마감의 기본값은 420초다. `agent/tool_executor.py:136` `_DEFAULT_CONCURRENT_TOOL_TIMEOUT_S = 420.0`.
  순차 호출도 같은 값을 쓴다(`agent/tool_executor.py:854-861` `_resolve_sequential_tool_timeout`, 설정
  `timeouts.tools.sequential_call`이 없으면 `timeouts.tools.concurrent_batch`, 그것도 없으면 420초).
  370초는 420초보다 짧다.
- 대기는 `tools/approval_human_wait.py`의 `human_wait_window(session_key)` 안에서 한다. 이 창에 든 시간은
  도구 마감에서 빠진다(`agent/tool_executor.py:891` `remaining = deadline + authorization_gate.excluded_seconds() - ...`,
  `:544` `excluded_seconds`). 한 창이 빼 주는 시간의 상한은 `approvals.timeout`(기본 300초) + 60초다
  (`tools/approval_human_wait.py` `human_wait_ceiling`). 그래서 사용자가 `timeouts.tools.*`를 370초보다 짧게
  줄여도 사람 대기 시간만큼 마감이 늘어난다.
- 게이트웨이의 무응답 감시(`agent.inactivity_timeout`, 실제 설정 120초, `~/.hermes/config.yaml:72`)는
  `activity_heartbeat("waiting for the user on a secure-input page")`를 약 1초마다 불러 막는다(본체 쪽에서 10초 간격으로
  묶어 기록). 사용 예와 같은 방식이다(`gateway/session_vault_code_card.py:114-118`).
- 턴 중단(`/stop`): 대기 루프가 1초마다 `tools.interrupt.is_interrupted()`를 보고, 참이면 `handle.cancel()`로 요청을
  끝낸다. 결과는 `cancelled`다(테스트 `tests/test_plugin.py::test_interrupt_cancels_request`).
- 사용자 명령(`/secure-input`)은 기다리지 않는다. 링크를 보낸 뒤 바로 답하고, 결과는 백그라운드 스레드가 기다렸다가
  링크 메시지를 고친다.

## 2. Slack 전송 경로: (1) 게이트웨이 Slack 어댑터의 클라이언트

`secure_input/notify.py` `resolve_slack_target`이 경로를 정한다.

1. 호출 문맥의 세션 키(`gateway.session_context.bound_session_key()`)와 라이브 소스(`gateway.plugin_messages.bound_route()`)를 읽는다.
   `ctx.post_message`가 쓰는 것과 같은 값이다(`hermes_cli/plugin_messages.py` `post()`).
2. 게이트웨이 루프에서 `gateway.plugin_messages.resolve(...)`(`gateway/plugin_messages.py:86`)로 대화의
   `PostTarget(platform, chat_id, adapter, metadata)`를 얻는다. 다른 프로필의 세션이면 본체가 거절한다.
3. `platform == "slack"`이면 어댑터의 `_client_for(chat_id, metadata)`(`plugins/platforms/slack/adapter.py:1950`)로
   워크스페이스에 맞는 WebClient를 얻고, `_resolve_thread_ts(None, metadata)`(`:2871`)로 스레드를 정한다.
4. 그 클라이언트로 `chat_postMessage(channel, thread_ts, text, blocks)`, 결과가 나오면 `chat_update(channel, ts, text, blocks)`.
   봇 정체와 스레드가 대화와 같다.

의존하는 본체 비공개 이름: `hermes_cli.plugin_messages._gateway_loop`, `ctx._manager.home_path`,
`SlackAdapter._client_for`, `SlackAdapter._resolve_thread_ts`.

깨졌을 때의 대체 동작: 위 단계에서 예외가 나거나(속성 없음 등) Slack 대화가 아니면 `ctx.post_message`로 같은 내용을
글자 메시지(링크 포함)로 보내고, 결과는 그 핸들의 `edit`로 고친다. `chat.postMessage`가 실패해도 같은 대체로 간다.
테스트: `tests/test_notify.py::test_notifier_for_session_falls_back_when_private_slack_attrs_break`,
`::test_slack_post_failure_falls_back_to_text_message`. 글자 메시지도 보낼 수 없으면(대화 없음) 요청을 취소하고
`failed`와 "이 대화에 링크를 보낼 수 없어 요청을 취소했습니다"를 돌려준다(`tests/test_plugin.py::test_no_conversation_cancels_and_reports`).

(2) 프로필 봇 토큰으로 직접 보내는 경로는 쓰지 않는다. 실제 Slack 게시 확인 스크립트(`scripts/live_slack_post.py`)만
같은 payload 생성기(`SlackNotifier`)에 봇 토큰 WebClient를 붙여 쓴다.

버튼 클릭: `ctx.register_slack_action_handler("secure_input_open", ...)`로 받은 클릭은 `await ack()`만 한다. 본체는
연결 시 이 처리기를 `self._app.action(action_id)`에 붙인다(`plugins/platforms/slack/adapter.py:1708`).

Slack으로 나가는 내용: 링크, 목적 문구, 종류, 이름표, 대상 프로필, 변수 이름 또는 사이트 주소, 결과 상태. 값과 로그인
아이디는 넣지 않는다(`tests/test_plugin.py`의 `everything_sent` 검사, 성공/만료/취소/실패 네 경우).

실제 게시 1회(2026-11-23): 채널 `<slack-channel-id>`, 스레드 `<thread-ts>`, 메시지 ts `<message-ts>`.
게시 직후 블록은 `section`, `actions`(버튼 1개), `chat.update` 뒤 블록은 `section`(버튼 0개), 링크 문자열 없음.

## 3. 에이전트에게 toolset이 보이는지

- 새 플러그인 toolset은 플랫폼 목록에 이름이 없어도 기본으로 켜진다. 예외는 기본 끔 목록(`_DEFAULT_OFF_TOOLSETS`)과
  `known_plugin_toolsets.<platform>`에 이미 기록된(=사용자가 한 번 본 뒤 끈) 이름이다(`hermes_cli/tools_config.py:521-528`
  `_enabled_plugin_toolsets`).
- 실제 `~/.hermes/config.yaml`의 `known_plugin_toolsets.slack`은 `a2a`, `spotify`뿐이라 `secure_input`은 Slack에서 켜진다.
- 필요한 설정(실제 파일은 고치지 않았다):
  1. 플러그인 설치: `~/.hermes/plugins/secure-input` (이 저장소를 두거나 심볼릭 링크).
  2. `hermes plugins enable secure-input` (= `plugins.enabled`에 `secure-input` 추가). 사용자 플러그인은 켜야 로드된다.
  3. 게이트웨이 재시작. 게이트웨이는 시작할 때 플러그인을 읽는다. kanban worker의 toolset 고정도 게이트웨이의 플러그인
     목록을 따른다(`~/.hermes/plugins/kanban-bgwait/__init__.py:108-112` 주석).
  4. 다른 프로필(예: worker)에서도 쓰려면 그 프로필 설정에서도 2를 한다.
- 선택 설정(기본 true): `plugins.entries.secure-input.settings.intercept_core_code_prompt`,
  `plugins.entries.secure-input.settings.intercept_core_save_login`. `ctx.get_config`가 `settings` 아래를 읽고
  (`hermes_cli/plugins_context.py:75`), 같은 이름을 `plugins.entries.secure-input.<key>`에 직접 써도 읽는다.

로드 확인: `scripts/plugin_load_check.py`(임시 HOME/HERMES_HOME, 본체 로더 `discover_plugins`)가 도구 2개, 명령,
훅, Slack 액션 등록과, 본체 `_get_pre_tool_call_directive_details`(`hermes_cli/plugins.py:1132`)의 차단 결과를 출력한다.

## 4. 자격증명 때문에 막혔을 때 이 도구로 오게 하는 장치 (5.6): (b)를 택함

- (a) 본체 `save_login`의 콜백 슬롯을 바꾸는 방식은 택하지 않았다. 이유 두 가지:
  1. 본체 `browser_vault_save_login`은 콜백이 돌려준 아이디/비밀번호를 받아 직접 vault에 저장한다
     (`tools/browser_vault_tool.py:354-372`, `get_vault_store().add_item(...)`). 우리 서버는 `login`을 받으면 항상
     vault에 새 항목으로 저장한다(계약 8절). 둘을 이으면 같은 로그인이 두 번 저장된다. 저장하지 않고 넘기려면 계약 1-9절에
     없는 "로그인 전달" 모드가 필요하다(계약 변경은 새 프로토콜 버전).
  2. 슬롯은 스레드별이다(`agent/vault_backends/unlock.py:31, 52-66`). 본체 도구는 에이전트의 도구 스레드에서 돌고,
     `pre_tool_call` 훅은 시간 제한 작업 스레드로 옮겨져 돈다(`website/docs/user-guide/features/hooks.md:396`).
     훅에서 슬롯을 바꿔도 본체 도구 스레드에는 보이지 않는다.
- (b) `pre_tool_call` 훅이 `browser_vault`의 `save_login`을 막고, `secure_input_request(kind='login', origin=<페이지 origin>)`
  뒤 결과의 메모를 따르라는 메시지를 돌려준다. 메모가 `browser_vault fill handle=<storage.item_id>`를 쓸지 알려 준다(`secure_input/plugin.py`
  `BLOCK_SAVE_LOGIN_MESSAGE`). 같은 훅이 본체 `enter_code`를 핸들이 있든 없든 막고 `secure_input_enter_code`(같은 핸들을 넘김)로 보낸다.
  핸들이 있어도 인증 앱 키가 없으면 본체가 Slack 모달로 코드를 묻기 때문이다(`docs/otp-code-feasibility.md` 3절).
  `secure_input_enter_code`는 `ctx.dispatch_tool`로 본체를 부르므로 훅에 걸리지 않는다.
  훅은 기다리지 않는다(훅 제한 30초, `hooks.md:396`).
- 차단은 플랫폼과 무관하게 설정이 켜져 있으면 늘 한다. Desktop/CLI에서도 우리 페이지가 같은 일을 하기 때문이다.
- (c) `secure_input_request` 설명에 세 경우(로그인 없음, 일회용 코드, API 키 없음)와 "채팅 질문이나 SSH 안내 대신 이 도구"를
  적었다(`tests/test_plugin.py::test_request_description_names_three_blocked_cases_and_no_chat`).
- 테스트: `tests/test_blocked_path.py`(Slack 턴 조건에서 본체 `save_login`은 `prompt_unavailable`과 `hermes vault add`
  안내를 돌려주고, 우리 훅은 막고 안내하며, 설정을 끄면 개입하지 않는다), `tests/test_plugin_load.py`(본체 지시 경로).

## 5. 그 밖의 결정

- `hermes_root`: `hermes_constants.get_default_hermes_root()`. 프로필 존재 확인과 목록은 서버 코어의
  `secure_input.profiles`(같은 루트 기준, 계약 8절)로 한다. 요청 세션 프로필은 `ctx.profile_name`
  (`hermes_cli/plugins_context.py:210`)이다. 이름이 `custom`이면 프로필을 찾지 못해 요청을 만들지 않는다.
- 요청자 정보: `get_session_env("HERMES_SESSION_PLATFORM" | "HERMES_SESSION_KEY" | "HERMES_SESSION_USER_ID")`.
  명령은 디스패처가 주는 `platform`, `session_key`, `source.user_id`를 쓴다(`gateway/run_inbound_hooks.py:302-310`).
- 로드할 때 `sweep_stale(hermes_root)`를 부르고, 요청마다 `start_request`가 다시 부른다. `on_unload`는 살아 있는 요청을 모두 취소한다.
- `api_key` 저장 뒤 `note`: 실행 중인 Hermes는 게이트웨이를 다시 시작한 뒤에 새 값을 읽는다고 알린다. 그리고 에이전트에게
  이 값이 필요한 일을 지금 이어서 하지 말고, 사용자에게 게이트웨이를 다시 시작한 뒤(Slack에서는 `!restart`) 같은 일을 다시
  요청해 달라고 알리게 한다(`secure_input/plugin.py` `ENV_NOTE`). 근거: 다중 프로필 게이트웨이는 다음 턴에 프로필 `.env`를
  다시 읽을 수 있지만(`website/docs/developer-guide/multiplexing-gateway.md:199-201`), 이미 만들어진 에이전트는 자격증명
  묶음을 유지한다(`gateway/session_tui_ops.py:147-148`). 그래서 모든 경우에 충분한 절차는 게이트웨이 재시작 뒤 다시 요청하는
  것이다. CLI `/reload`(`hermes_cli/cli_loops_mixin.py:277-279`)는 안내하지 않는다.
- 로그인 아이디: Hermes vault는 아이디를 암호화 본문이 아닌 항목 메타데이터에 둔다(`agent/vault_store.py:547-605`).
  우리 도구 결과에는 그래도 넣지 않는다.
