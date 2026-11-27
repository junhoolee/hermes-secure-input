# secure-input 규약 (2판)

이 문서는 서버(`secure_input/*.py`), 입력 화면(`ui/`, 빌드 결과는 `secure_input/static/`), Hermes 연결(도구, Slack)이 함께 지키는 약속이다. 2판은 저장 위치에 Mac 키체인을 더하고, 한 번 입력한 값을 고른 저장 위치 여러 곳에 저장하게 한 판이다.

- 이 문서는 지금 코드가 하는 대로 적었다. 계획서(`docs/plans/storage-targets-plan.md`) 부록 A와 다른 곳은 마지막 절 "계획서 부록 A와 다른 점"에 모았다.
- 1절부터 13절을 바꾸려면 규약 버전(`PROTOCOL_VERSION`)을 올린다. 화면과 서버는 한 저장소에서 함께 나가므로, 버전이 다른 화면과 서버가 섞이지 않는다.
- 이 문서의 "값"은 사용자가 입력한 비밀값(API 키, 비밀번호, 인증 앱 설정 키, 일회용 코드)이다. 어느 출력, 로그, 오류에도 값과 값의 길이는 들어가지 않는다. 로그인 아이디도 결과와 로그에 넣지 않는다.
- "저장소"는 값을 넣는 곳이다. 이름은 셋이다. `env`는 프로필의 `.env` 파일이다. `hermes_vault`는 Hermes 암호화 저장소(vault)다. `keychain`은 이 Mac의 기본(login) 키체인이다. Example Vault는 저장소가 아니다.

## 1. 상수

### 1.1 `secure_input/config.py`

| 이름 | 값 | 뜻 |
|---|---|---|
| `OPEN_TTL_S` | `60` | 링크를 열 수 있는 시간(초). 요청을 만들 때의 점검이 끝난 때부터 센다(6.1절). |
| `SUBMIT_TTL_S` | `300` | 연 뒤 제출할 수 있는 시간(초). 처음 연 시각부터 센다. 저장 중에 흐른 시간도 든다. |
| `MAX_SUBMIT_ATTEMPTS` | `5` | 요청 하나에서 실패로 세는 제출의 한도. 5번째 실패로 요청이 끝난다. |
| `MAX_ACTIVE_REQUESTS` | `3` | 동시에 살아 있는 요청의 한도(모든 프로필을 합친 수). |
| `PROTOCOL_VERSION` | `2` | 여는 응답과 제출 본문의 `v`. |
| `HKDF_INFO` | `b"hermes-secure-input/v1/submit"` | 암호 키를 만드는 HKDF의 info. 2판에서도 바꾸지 않았다. 제출 본문의 `v`가 2가 아니면 복호화 전에 거절하기 때문이다. |
| `MAX_BODY_BYTES` | `65536` | POST 본문 한도(64 KB). |
| `SHUTDOWN_GRACE_S` | `2.0` | 끝 상태가 된 서버가 응답을 보내고 내려가기까지의 여유(초). |
| `READY_TIMEOUT_S` | `20.0` | 부모가 서버의 `ready` 줄을 기다리는 시간(초). 요청을 만들 때의 점검 10초가 이 안에 든다. |
| `KINDS` | `("api_key", "login", "otp_code", "secret")` | 요청 종류. |
| `LOGIN_IDENTIFIER_TYPES` | `("email", "phone", "username")` | 로그인 아이디의 종류. |
| `STORE_NAMES` | `("env", "hermes_vault", "keychain")` | 저장소 이름. 이 순서가 화면의 줄 순서이고 쓰는 순서다. |
| `KIND_STORES` | `{"api_key": ("env", "keychain"), "login": ("hermes_vault",), "secret": ("keychain",), "otp_code": ()}` | 종류마다 고를 수 있는 저장소. |
| `KIND_DEFAULT_STORES` | `{"api_key": ("env",), "login": ("hermes_vault",), "secret": ("keychain",), "otp_code": ()}` | 에이전트가 `stores`를 넘기지 않았을 때 미리 켜지는 저장소. |
| `STORE_TIMEOUT_S` | `{"env": 10.0, "hermes_vault": 30.0, "keychain": 20.0}` | 저장소마다의 시한(초). 저장 프로세스 전체 시한을 셈하는 데만 쓴다(8.1절). |
| `PREFLIGHT_AT_CREATE_TIMEOUT_S` | `10.0` | 요청을 만들 때의 점검 전체의 시한(초). |
| `WAIT_MARGIN_S` | `10.0` | 부모 대기 시간의 여유(초). |
| `CANCEL_MARGIN_S` | `5.0` | 취소 뒤 기다리는 시간의 여유(초). |
| `KEYCHAIN_ID_RE` | `^[a-z0-9][a-z0-9-]{0,39}$` | 도구 인자 `keychain_item`의 모양. |
| `KEYCHAIN_NAME_RE` | `^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$` | 키체인 service와 account의 모양. |
| `MAX_KEYCHAIN_ITEMS` | `20` | 허용 목록 `keychain_items`에서 쓰는 항목 수의 상한(2.2절 1번). |

정규식은 모두 `re.fullmatch`로 검사한다. `re.match`와 `$`는 끝에 줄바꿈 하나가 붙은 이름을 통과시키기 때문이다.

셈으로 정해지는 시간은 다음과 같다.

| 이름 | 셈 | 종류마다의 값 |
|---|---|---|
| 부모의 대기 시간 (`plugin.parent_wait_s`) | `OPEN_TTL_S + SUBMIT_TTL_S + WAIT_MARGIN_S + sum(STORE_TIMEOUT_S[s] for s in KIND_STORES[kind])` | `api_key` 400초, `login` 400초, `secret` 390초, `otp_code` 370초 |
| 취소 뒤 기다리는 시간 (`launcher.cancel_grace_s`) | `sum(STORE_TIMEOUT_S[s] for s in KIND_STORES[kind]) + CANCEL_MARGIN_S` | `api_key` 35초, `login` 35초, `secret` 25초, `otp_code` 5초 |
| 저장 프로세스의 시한 (`storage.save_timeout`) | 사용자가 켠 저장소의 `STORE_TIMEOUT_S` 합 | 예: `api_key`의 `.env`와 키체인이면 30초 |

취소 뒤 기다리는 시간은 부모가 서버의 표준 입력을 닫은 뒤 SIGTERM을 보내기 전까지 기다리는 시간이다. `RequestHandle.cancel()`의 `grace`가 `None`(기본값)이면 이 값을 쓴다. 게이트웨이가 플러그인을 내릴 때(`cancel_all`)도 같은 값을 쓴다. 저장 중인 요청이 끝까지 저장하고 결과를 알릴 시간을 주려는 것이다.

### 1.2 `secure_input/stores/keychain.py`

이 파일은 플러그인의 다른 모듈을 import하지 않는다. 그래서 `config.py`와 같은 값도 따로 둔다.

| 이름 | 값 | 뜻 |
|---|---|---|
| `SECURITY_PATH` | `"/usr/bin/security"` | 키체인을 다루는 유일한 실행 파일. |
| `SERVICE_PREFIX` | `"hermes-secure-input."` | 플러그인이 새로 만드는 항목의 service 앞머리. |
| `FIXED_ACCOUNT` | `"hermes-secure-input"` | 새 항목과 임시 항목의 account. |
| `TMP_PREFIX` | `"hermes-secure-input.tmp."` | 임시 항목의 service 앞머리. 뒤에 요청 번호의 앞 12자가 붙는다. |
| `TEST_PREFIX` | `"hermes-secure-input-test-"` | 실측과 시험이 만드는 가짜 항목의 service 앞머리. |
| `CALL_TIMEOUT_S` | `5.0` | `security` 호출 하나의 시한(초). |
| `NAME_RE` | `^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$` | `KEYCHAIN_NAME_RE`와 같은 값. |
| `MAX_LINE_BYTES` | `2400` | `security -i`에 주는 한 줄의 바이트 한도. |
| `MAX_VALUE_CHARS` | `1024` | 키체인에 넣는 값의 글자 수 한도. |

요청 번호는 `uuid.uuid4().hex`(영문 소문자와 숫자 32자)다. 그래서 임시 항목의 service는 `KEYCHAIN_NAME_RE`에 맞는다. 키체인 모듈은 요청 번호의 앞 12자를 다시 검사하지 않고 임시 항목 이름에 쓴다.

### 1.3 그 밖의 한도 (`secure_input/server.py`, `secure_input/validation.py`)

| 칸 | 한도 |
|---|---|
| `api_key`의 `value` | 1자에서 8,192자, 한 줄, ASCII |
| `secret`의 `value` | 1자에서 1,024자, 0x20에서 0x7E의 글자만, 첫 글자와 끝 글자는 공백이 아님 (`validation.is_keychain_value`) |
| `login`의 `identifier` | 앞뒤 공백을 뗀 뒤 1자에서 512자 |
| `login`의 `password` | 1자에서 4,096자 |
| `login`의 `otp_secret` | 0자에서 1,024자, 빠져도 된다 |
| `otp_code`의 `code` | 앞뒤 공백을 뗀 뒤 1자에서 64자, 제어 문자 없음 |
| 이유 문장(`stores[].reason`), 허용 목록의 `label`과 `used_by` | 한 줄, 1자에서 120자 |

"한 줄"은 `validation.is_clean_single_line`을 통과한다는 뜻이다. `str.splitlines()`가 자르는 줄바꿈(LF, CR, U+2028, U+2029, U+0085, U+000B, U+000C, U+001C~U+001E), 탭과 그 밖의 제어 문자, 줄과 문단 구분 문자가 없어야 한다.

## 2. 요청 명세 `RequestSpec` (`secure_input/spec.py`)

| 칸 | 규칙 |
|---|---|
| `kind` | `api_key`, `login`, `otp_code`, `secret` |
| `purpose` | 필수, 1자에서 200자, 한 줄, 유니코드 Cf 글자 없음(`validation.has_format_char`. 이유 문장과 같은 규칙) |
| `label` | 필수, 1자에서 80자, 한 줄, 유니코드 Cf 글자 없음 |
| `requester` | `{"type": "agent" 또는 "user", "profile", "platform", "session_key", "user_id"}` |
| `target_profile` | 프로필 이름 |
| `profile_editable` | 참이나 거짓. `otp_code`는 항상 거짓이다. `secret`은 이 값과 관계없이 요청한 프로필로만 받는다(4절). |
| `env_var` | `api_key`에서만. `^[A-Z_][A-Z0-9_]*$` 전체 일치, `SECURE_INPUT_`로 시작하지 않음, Hermes의 `hermes_cli.config.validate_env_var_name_for_write`가 받아들임(그 검사를 불러오지 못하면 거절). |
| `origin` | `login`에서만. 경로 없는 `https://` 주소. `spec.normalize_origin(origin)`과 같아야 한다(호스트는 `xn--` punycode 소문자, 443 포트는 뺀다). |
| `site` | `otp_code`에서만. ASCII 호스트 이름(`spec.normalize_hostname`으로 먼저 바꾼다). |
| `hermes_root` | 기본 프로필 폴더의 절대 경로. 모든 프로필 폴더의 기준이다. |
| `stores` | 아래 2.1절 |
| `keychain` | 아래 2.2절 |

검사에 걸리면 `SpecError(field, reason)`이다. 걸린 값은 오류에 넣지 않는다.

### 2.1 `stores`

- `otp_code`이면 빈 목록이다. 그 밖에는 `KIND_STORES[kind]`의 저장소가 모두 `STORE_NAMES`의 순서로 들어간다.
- 항목은 `{"store", "selected", "fixed", "by", "reason", "needed"}`다.
  - `selected`는 미리 켜졌는지다.
  - `fixed`는 `len(KIND_STORES[kind]) == 1`이다. `fixed`가 참이면 `selected`도 참이다.
  - `by`는 미리 켜진 까닭이다. `agent`(에이전트가 `stores`에 넣음), `history`(그 값이 전에 저장된 곳, `api_key`에서만), `default`(종류의 기본값), `null`(미리 켜지지 않음) 가운데 하나다. 둘 이상에 해당하면 `agent`, `history`, `default` 순으로 앞의 것을 쓴다. `selected`가 거짓이면 `null`이다.
  - `reason`은 `null`이거나 한 줄 1자에서 120자다. `needed`는 참이나 거짓이다. 에이전트가 넘기지 않은 저장소는 `reason`이 `null`, `needed`가 거짓이다.
- 에이전트가 넘긴 `stores`가 목록이 아니거나, 비었거나, 겹치거나, 모르는 이름이거나, 그 종류가 고를 수 없는 저장소이거나, 모르는 칸이 있거나, `needed`가 참·거짓이 아니거나, `reason`이 규칙에 맞지 않으면 요청을 만들지 않는다(`SpecError("stores", ...)`).
- "전에 저장된 곳"은 `<hermes_root>/secure-input/placements.json`(0600)에 남는다. 열쇠는 `api_key|<변수 이름>`, `login|<사이트 주소>`, `secret|<keychain_item>`이고, 저장소마다 저장된 곳(프로필과 변수 이름, 프로필과 사이트 주소와 항목 번호, service와 account)과 시각만 적는다. 값과 아이디는 적지 않는다. 미리 켜기에 쓰는 것은 `api_key`뿐이다.

### 2.2 `keychain`

`KIND_STORES[kind]`에 `keychain`이 있을 때(`api_key`, `secret`)만 있다. 모양은 `{"id", "service", "account", "listed", "label", "used_by"}`다. `spec.resolve_keychain(kind, keychain_item, env_var=..., allow=..., keychain_chosen=...)`이 다음 규칙으로 만든다.

1. 허용 목록은 플러그인 설정 `keychain_items`이고, 항목마다 `{"id", "service", "account", "label", "used_by"}`다. service가 `hermes-secure-input.`로 시작하는 항목은 허용 목록에서 빠진다. 규칙에 맞는 항목 가운데 앞의 20개(`MAX_KEYCHAIN_ITEMS`)만 쓴다. 넘는 항목은 빠지고 경고가 로그에 남는다. 빠진 항목마다 `secure-input: keychain_items item <index> left out (field <칸>)` 경고가 한 줄이고, 개수를 넘어 빠진 항목들은 처음으로 빠진 항목의 `index`와 칸 `limit`으로 한 줄만 남는다(`spec.parse_keychain_items`의 경고 `{"index", "field"}`). 경고에 칸의 글자는 넣지 않는다.
2. 도구 설명에는 허용 목록의 `id`, `label`, `used_by`만 한 줄씩 나온다. service와 account는 나오지 않는다. 목록이 비면 "허용된 기존 항목 없음"이 나온다.
3. 허용 목록의 `id`는 `secret`에서만 쓸 수 있다. `api_key`가 그 `id`를 넘기면 요청을 만들지 않는다.
4. 넘긴 이름이 허용 목록 항목의 service나 account와 같으면(대소문자 무시) 요청을 만들지 않는다.
5. `secret`은 `keychain_item`이 필수다. 허용 목록의 `id`이면 그 항목을 쓰고 `listed`가 참이다.
6. 허용 목록 밖의 이름은 `KEYCHAIN_ID_RE`에 맞아야 하고, 항목은 service `hermes-secure-input.<이름>`, account `hermes-secure-input`인 새 항목이다. `listed`는 거짓, `label`과 `used_by`는 `null`이다.
7. `api_key`에서 `keychain_item`을 넘기지 않으면 기본 이름은 변수 이름을 소문자로 바꾸고 `_`를 `-`로 바꾼 것이다(`EXA_API_KEY`이면 `exa-api-key`). 기본 이름을 쓸 수 없고(모양이 맞지 않거나 허용 목록과 겹침) 에이전트가 `stores`에 `keychain`을 넣었으면 요청을 만들지 않는다. 넣지 않았으면 요청은 만들어지고 `id`, `service`, `account`, `label`, `used_by`는 `null`, `listed`는 거짓이다. 그 키체인 줄은 요청을 만들 때의 점검에서 `keychain_name_invalid`로 쓸 수 없게 된다.
8. 그 밖의 모양이 틀린 이름은 요청을 만들지 않는다.

로그인은 키체인에 넣지 않는다. `login`과 `otp_code`가 `keychain_item`을 넘기면 요청을 만들지 않는다.

## 3. 주소와 API

- 경로 토큰은 `secrets.token_urlsafe(32)`(43자)다. 요청 번호는 `uuid4().hex`이고 토큰과 관계가 없다.
- 공개 주소는 `https://<tailnet 호스트>/<토큰>/`(끝에 `/`)다. `/<토큰>/`로 시작하지 않는 경로는 모두 404다(`/<토큰>`처럼 끝의 `/`가 없는 것도 404).
- `GET /<토큰>/`과 정적 파일은 상태가 `created`(여는 시한 안), `opened`(제출 시한 안), `saving`일 때만 200이다. 그 밖에는 410(`gone`, 본문은 일반 텍스트)이다. 정적 파일에는 비밀과 요청 내용이 없다.
- `/<토큰>/api/` 아래의 모든 호출은 허용된 Tailscale 계정이어야 한다(5.1절). 아니면 403이고 아무것도 소모하지 않는다.
- base64url은 항상 `=` 없이 쓴다.

### 3.1 여는 요청 `POST /<토큰>/api/open`

본문은 `{}`다. 요청 하나에 한 번, 여는 시한 안에서만 200이다. 두 번째 호출과 `saving` 중의 호출은 410 `already_opened`다. 시한이 지난 뒤에는 410 `expired`다.

200 본문:

```json
{"v": 2, "request_id": "...", "kind": "secret",
 "purpose": "...", "label": "...",
 "requester": {"type": "agent", "profile": "default"},
 "target": {"profile": "default", "profiles": ["default", "worker"], "profile_editable": false,
            "env_var": null, "origin": null, "site": null,
            "stores": [
              {"store": "keychain", "selected": true, "fixed": true, "by": "agent", "reason": "...", "needed": true,
               "scope": "mac", "ident": "example-unlock-item", "available": true, "unavailable_reason": null,
               "exists": true}],
            "keychain": {"id": "example-vault-password", "service": "example-unlock-item", "account": "example-unlock-item",
                         "listed": true, "new_item": false, "label": "...", "used_by": "..."}},
 "server_public_key": "<base64url, P-256 비압축 점 65바이트>",
 "sid": "<base64url, 32바이트>",
 "submit_deadline_s": 300, "opened_at": "<ISO 8601>"}
```

- `target.stores`의 줄은 요청 명세의 `stores`(2.1절)에 다음 칸을 더한 것이다. 순서는 `env`, `hermes_vault`, `keychain`이다. `otp_code`이면 빈 목록이다.
  - `scope`는 `profile`(`env`, `hermes_vault`) 또는 `mac`(`keychain`)이다.
  - `ident`는 `env`이면 변수 이름, `hermes_vault`이면 사이트 주소, `keychain`이면 키체인 service다. 이름이 없는 키체인(2.2절 7번)이면 `null`이다.
  - `available`과 `unavailable_reason`은 요청을 만들 때의 점검(6.1절) 결과다. `unavailable_reason`은 10절의 낱말 가운데 하나이거나 `null`이다.
  - `exists`는 값을 읽지 않고 알 수 있을 때만 참이나 거짓이다. `env`(변수 줄이 이미 있는지)와 이름이 있는 `keychain`(항목이 이미 있는지)만 해당한다. `hermes_vault`는 항상 `null`이다. 점검이 끝나지 않았으면 `null`이다.
- `target.keychain`은 `stores`에 `keychain`이 있을 때만 있다. `new_item`은 `listed`가 거짓이고 그 줄의 `exists`가 거짓일 때만 참이다. 이름이 없는 키체인이면 `id`, `service`, `account`, `label`, `used_by`는 `null`, `listed`와 `new_item`은 거짓이다. 화면은 service와 account를 보여 주기만 하고 서버로 돌려보내지 않는다.

### 3.2 제출 `POST /<토큰>/api/submit`

본문:

```json
{"v": 2, "sid": "...", "client_public_key": "<base64url 65바이트>", "iv": "<base64url 12바이트>",
 "ciphertext": "<base64url, 암호문 뒤에 GCM 태그 16바이트>"}
```

답:

- 성공(저장): 200 `{"ok": true, "result": {"status": "saved", "partial": false, "stores": [<저장소 결과 줄>], "storage": {...}, "label": "..."}}`. `stores`에는 그 제출에서 켜진 저장소만 `STORE_NAMES`의 순서로 들어간다. 저장이 확인된 곳이 1곳 이상이고 나머지가 실패했거나 결과를 모르면 `partial`이 참이다.
- 성공(`otp_code` 전달): 200 `{"ok": true, "result": {"status": "delivered", "storage": {...}, "label": "..."}}`.
- `storage`는 처음으로 저장된 저장소(순서 `env`, `hermes_vault`, `keychain`)를 가리킨다. 칸은 `type`, `profile`, `origin`, `env_var`, `item_id`이고 해당하지 않는 칸은 `null`이다. `type`은 `env`, `vault`, `keychain`, `browser_page` 넷이다. `keychain`이면 `service`와 `account`가 더 있다. `otp_code`는 `{"type": "browser_page", "profile": <요청한 프로필>, 나머지 null}`이다.
- 쓸 수 없는 저장소가 있음: 422 `{"ok": false, "error_code": "store_unavailable", "message": "...", "stores": [{"store": "keychain", "reason": "keychain_acl_denied"}]}`. `stores`에는 쓸 수 없는 저장소만 든다. 아무 데도 쓰지 않았다. 실패로 세지 않고 요청은 `opened`로 돌아간다.
- 하나도 저장하지 못함: 422 `{"ok": false, "error_code": "storage_failed", "message": "...", "result_unknown": false, "stores": [<저장소 결과 줄>]}`. 실패로 센다. 프로필 폴더를 찾지 못한 경우도 이 모양이고 `stores`는 빈 목록이다.
- 결과를 모름: 422 `{"ok": false, "error_code": "storage_failed", "message": "...", "result_unknown": true, "stores": [<저장소 결과 줄>]}`. 요청은 이미 `failed`로 끝났다. 화면은 다시 보내기를 보여 주지 않는다.
- 저장 중: 409 `{"ok": false, "error_code": "saving_in_progress", "message": "..."}`. 첫 제출의 잠금을 기다리지 않고 바로 답한다.
- 저장하는 동안 제출 시한이 지났거나 부모나 종료 신호가 요청을 끝내기로 했고, 아무것도 쓰지 않았거나 하나도 저장하지 못한 경우: 410 `deadline_passed`. 저장하는 종류(`api_key`, `login`, `secret`)의 제출이 이 답을 받으면 화면은 시간 초과 화면 대신 "저장했는지 알 수 없습니다" 끝 화면(`result_unknown`)을 보인다. 값은 이미 서버로 갔고 키체인 본 항목이 바뀌었을 수 있기 때문이다(`main_touched`).
- 그 밖의 실패: 4xx `{"ok": false, "error_code": "...", "message": "<한국어, 값 없음>"}`.

**저장소 결과 줄** (제출 응답, 부모에게 가는 결과, 저장 프로세스의 출력에서 같은 모양)

| 칸 | 저장소 | 뜻 |
|---|---|---|
| `store` | 모두 | 저장소 이름 |
| `saved` | 모두 | `true`(저장 확인), `false`(저장하지 못함을 앎), `null`(모름) |
| `replaced` | 모두 | `saved`가 `true`일 때만 참이나 거짓, 그 밖에는 `null`. `env`는 같은 변수 줄이 이미 있었는지, `hermes_vault`는 예전 항목을 1개 이상 지웠는지, `keychain`은 같은 항목이 이미 있었는지다. |
| `error` | 모두 | 10절의 낱말 또는 `null` |
| `env_var`, `profile` | `env` | 변수 이름과 프로필 |
| `origin`, `item_id`, `profile` | `hermes_vault` | 사이트 주소, Hermes가 준 항목 번호, 프로필 |
| `has_otp`, `removed_count`, `replace_error` | `hermes_vault` | 부모에게 가는 결과에만 있다. 제출 응답에는 넣지 않는다. |
| `service`, `account`, `listed` | `keychain` | 항목 이름과 허용 목록에서 왔는지 |
| `new_item` | `keychain` | 저장할 때 쓰기 순서 (가)에서 항목이 없었고 `listed`가 거짓이면 참. 여는 응답의 `keychain.new_item`과 다를 수 있다. |
| `tmp_left` | `keychain` | 임시 항목이 남았으면 참, 아니면 거짓, 결과 줄이 오지 않았으면 `null` |
| `main_touched` | `keychain` | 쓰기 전에 있던 본 항목에 쓰기 (라)를 시작했으면 참(예전 값이 바뀌었을 수 있다). 없던 항목을 새로 만드는 쓰기에서는 거짓(`false`)이다. (라)에 닿지 않았으면 거짓, 결과 줄이 오지 않았으면 `null` |
| `main_created` | `keychain` | 쓰기 전에는 없던 본 항목에 쓰기 (라)를 실행했고, 그 쓰기가 실패했다고 확인되지 않았으면 참(그 이름의 항목이 새로 생겼고 이번 값이 들어 있을 수 있다). 곧 (라)의 끝 코드가 0이거나 (라)가 시한을 넘겼으면 참이고, (라)의 끝 코드가 0이 아니고 되읽기가 같지 않으면(`keychain_write_failed`) 거짓이다. `main_touched`와 같은 자리에서 정하고 둘이 함께 참인 일은 없다. (라)에 닿지 않았으면 거짓, 결과 줄이 오지 않았으면 `null`. 같은 요청 안에서 앞선 저장이 `main_created: true`로 실패한 항목에 뒤 저장이 또 실패하면, 서버는 그 줄을 `main_touched: false`, `main_created: true`로 고쳐 보낸다(그 항목에는 이 요청 전의 값이 없었다). 같은 요청 안에서 앞선 저장이 `main_created: true`로 실패한 항목에 뒤 저장이 성공하면, 서버는 그 줄을 `replaced: false`로, 허용 목록 밖 항목이면 `new_item: true`로 고쳐 보낸다(그 항목에는 이 요청 전의 값이 없었다). 이 기억은 그 요청의 서버 프로세스 메모리에만 있다. |

### 3.3 취소 `POST /<토큰>/api/cancel`

본문은 `{"sid": "..."}`다. 성공하면 200 `{"ok": true, "result": {"status": "cancelled"}}`이고 요청은 `cancelled`(detail `user_cancelled`)로 끝난다. sid가 틀렸거나 없거나 아직 열지 않은 요청이면 403 `bad_sid`, 이미 끝났으면 410 `deadline_passed`, 저장 중이면 409 `saving_in_progress`다. 저장 중의 취소 거절은 실패로 세지 않고, 끝낼 사유로 기록하지 않으며, 로그 줄도 쓰지 않는다.

### 3.4 HTTP 오류 낱말

본문은 모두 `{"ok": false, "error_code": <낱말>, "message": <아래 문장>}`이다(`gone`만 일반 텍스트).

| 낱말 | HTTP | 실패로 세나 | 문장 |
|---|---|---|---|
| `already_opened` | 410 | 아니요 | 이 링크는 이미 열렸습니다. 새 링크를 요청하세요. |
| `expired` | 410 | 아니요 | 링크가 만료되었습니다. 새 링크를 요청하세요. |
| `bad_sid` | 403 | 예 (제출만) | 세션이 맞지 않습니다. 페이지를 새로 열어 주세요. |
| `decrypt_failed` | 400 | 예 | 암호화된 값을 풀지 못했습니다. 다시 제출해 주세요. |
| `invalid_payload` | 400 | 예 | 입력 형식이 올바르지 않습니다. 입력값을 확인해 주세요. |
| `storage_failed` | 422 | 예 (`result_unknown`이 참이면 해당 없음) | 값을 저장하지 못했습니다. 다시 시도해 주세요. |
| `masked_value` | 422 | 예 | 가려진 값처럼 보여 저장하지 않았습니다. 원래 키 전체를 붙여 넣어 주세요. |
| `replayed` | 409 | 예 | 이미 받은 제출입니다. 다시 제출해 주세요. |
| `deadline_passed` | 410 | 아니요 | 제출 시간이 지났습니다. 새 링크를 요청하세요. |
| `too_many_attempts` | 429 | (5번째 실패의 답) | 실패가 너무 많아 이 요청을 끝냈습니다. 새 링크를 요청하세요. |
| `already_submitted` | 409 | 아니요 | 이미 제출이 끝난 요청입니다. |
| `saving_in_progress` | 409 | 아니요 | 저장 중입니다. 저장이 끝날 때까지 기다려 주세요. |
| `store_unavailable` | 422 | 아니요 | 지금 쓸 수 없는 저장 위치가 있어 아무 데도 저장하지 않았습니다. |
| `not_found` | 404 | 아니요 | 찾을 수 없습니다. |
| `gone` | 410 | 아니요 | 이 링크는 더 이상 쓸 수 없습니다. |
| `bad_origin` | 403 | 아니요 | 허용되지 않은 출처의 요청입니다. |
| `unsupported_media_type` | 415 | 아니요 | JSON 요청만 받습니다. |
| `payload_too_large` | 413 | 아니요 | 요청이 너무 큽니다. |
| `method_not_allowed` | 405 | 아니요 | 허용되지 않은 요청 방식입니다. |
| `internal_error` | 500 | 아니요 | 서버 오류가 났습니다. 다시 시도해 주세요. |
| `identity_required` | 403 | 아니요 | Tailscale 계정을 확인할 수 없는 접속입니다. Tailscale에 로그인한 기기에서 링크를 여세요. |
| `identity_not_allowed` | 403 | 아니요 | 이 Tailscale 계정으로는 이 링크를 쓸 수 없습니다. 요청한 사람의 계정으로 로그인한 기기에서 여세요. |

- 5번째 실패는 그 실패의 낱말이 아니라 429 `too_many_attempts`로 답한다. 서버가 바로 내려가 6번째 제출은 닿지 못하기 때문이다.
- 끝난 요청에 온 제출은 `already_submitted`(저장됨, 전달됨), `too_many_attempts`(실패), `deadline_passed`(만료, 취소)다. 실제로는 서버가 2초 안에 내려간다.
- 열기 전에 온 제출은 403 `bad_sid`다.

## 4. 암호화와 제출 내용

- 서버는 요청마다 새 P-256 키 쌍을 만든다. 개인 키는 메모리에만 있다.
- 브라우저: 새 ECDH P-256 키 쌍 → 공유 비밀(x 좌표 32바이트) → HKDF-SHA256(salt = `sid`의 원래 32바이트, info = `hermes-secure-input/v1/submit`, 길이 32) → AES-256-GCM 키. iv는 무작위 12바이트다. AAD는 `request_id`의 UTF-8 바이트다.
- 평문은 UTF-8 JSON이다.
  - `{"kind": "api_key", "target_profile": "...", "value": "...", "stores": ["env", "keychain"]}`
  - `{"kind": "login", "target_profile": "...", "identifier_type": "...", "identifier": "...", "password": "...", "otp_secret": "", "stores": ["hermes_vault"]}`
  - `{"kind": "secret", "target_profile": "...", "value": "...", "stores": ["keychain"]}`
  - `{"kind": "otp_code", "code": "..."}` (`stores` 칸이 없다)
- 다음 가운데 하나라도 어기면 `invalid_payload`다.
  - 평문의 `kind`가 요청의 `kind`와 같다. 모르는 칸이 없다(`login`의 `otp_secret`만 빠져도 된다).
  - `target_profile`은 여는 응답의 `profiles` 안에 있다. `profile_editable`이 거짓이거나 `secret`이면 요청한 프로필과 같다. 화면은 `secret`에서 프로필 고르기를 보여 주지 않고 요청한 프로필을 그대로 보낸다. `secret`의 `target_profile`은 로그를 남길 프로필이다.
  - `stores`는 필수이고, 1개 이상이고, 겹치지 않고, 여는 응답의 저장소 이름의 부분집합이고, `fixed`인 저장소를 모두 포함한다.
  - 1.3절의 한도와 한 줄 규칙. `api_key`의 `value`는 ASCII다. `secret`의 `value`는 키체인 값 규칙을 지킨다(두 번 입력의 비교는 화면이 한다).
- 여는 응답에서 `available`이 거짓이었던 저장소를 켜서 보내도 `invalid_payload`가 아니다. 쓰기 전 점검으로 간다. 그 사이에 쓸 수 있게 됐을 수 있기 때문이다. 여전히 쓸 수 없으면 `store_unavailable`이다.
- 다시 보내기: 한 번 본 (`client_public_key`, `iv`) 쌍이 다시 오면 처음 결과와 관계없이 `replayed`다.
- 성공은 많아야 한 번이다.

## 5. 응답 헤더와 요청 검사

모든 응답에 다음 헤더가 붙는다(`Server` 헤더는 없다).

```
Cache-Control: no-store
Referrer-Policy: no-referrer
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'
```

POST는 `Content-Type: application/json`만 받는다(`; charset=utf-8` 같은 뒷부분은 된다). `Origin` 헤더가 있으면 `https://<tailnet 호스트>` 또는 서버 자신의 `http://127.0.0.1:<port>`여야 한다. 본문은 64 KB까지다.

### 5.1 링크를 연 계정 확인

Tailscale Serve는 접속한 tailnet 사용자의 계정을 `Tailscale-User-Login` 헤더로 서버에 넘긴다. 서버는 이 헤더로 링크를 쓰는 사람을 확인한다.

허용 목록:
- 허용 목록은 이 Mac의 Tailscale 소유 계정 1개와 플러그인 설정 `allowed_tailscale_logins`의 계정을 합친 것이다.
- 소유 계정은 `ServeManager.owner_login()`이 `tailscale status --json`에서 `User[str(Self.UserID)].LoginName`을 읽어 얻는다. 코드와 설정 파일에는 계정 이름을 적지 않는다.
- 플러그인은 요청을 만들 때마다 허용 목록을 새로 계산한다. 비교는 앞뒤 공백을 지우고 소문자로 바꾼 값으로 한다.
- 소유 계정을 읽지 못하고 `allowed_tailscale_logins`도 비어 있으면 플러그인은 요청을 만들지 않고 입력 서버도 시작하지 않는다. 요청한 쪽은 "Tailscale 계정을 확인하지 못해 입력 페이지를 띄우지 못했습니다. 요청을 만들지 않았습니다."를 받는다. 설정 목록이 있으면 그 목록만으로 진행한다.
- 허용 목록과 시험용 설정 `allow_no_identity_header`는 입력 서버의 표준 입력 설정 JSON(`allowed_logins`, `allow_no_identity_header`)으로만 간다. 인자나 환경변수로는 넘기지 않는다. `allow_no_identity_header`는 기본값이 거짓이고, 플러그인 설정에 불린 `true`가 있을 때만 켜진다.

서버 검사:
- 검사 대상은 `/<토큰>/api/` 아래의 모든 요청이다(`open`, `submit`, `cancel`, 그 밖의 이름, POST가 아닌 방식 포함). 다른 모든 검사(방식, Content-Type, Origin, 크기)보다 먼저 한다.
- 페이지 파일을 받는 GET은 검사하지 않는다. 거절 화면을 보여 주려면 페이지가 열려야 하기 때문이다.
- 헤더가 없으면 `allow_no_identity_header`가 참일 때만 통과하고, 아니면 403 `identity_required`다. 헤더가 2개 이상이거나 값이 허용 목록에 없으면 403 `identity_not_allowed`다.
- 거절은 링크를 소모하지 않고(`open`의 한 번을 쓰지 않는다) 실패로도 세지 않는다. 그래서 허용되지 않은 계정이 먼저 눌러도 허용된 계정은 여는 시한 안에 정상으로 열 수 있다.
- 로그에는 거절마다 `open_denied` 줄을 쓴다. `detail`은 `{"reason": "identity_required" 또는 "identity_not_allowed"}`뿐이고 계정 이름은 쓰지 않는다. 한 요청에 5줄까지만 쓴다.

실제 Serve로 잰 사실(2026-11-24, `scripts/live_identity_check.py`, 결과 `docs/security-review/results-after-fix/live_identity.json`):
- 클라이언트가 `Tailscale-User-Login`을 직접 붙여 Serve로 보내도 서버에 닿는 계정 헤더는 1개이고 그 값은 실제 접속 계정이다. Serve가 클라이언트의 헤더를 버리고 실제 계정을 넣는다. 그래서 tailnet의 다른 기기는 계정을 지어낼 수 없다.
- 이 Mac 안에서 `127.0.0.1:<port>`로 직접 접속하는 프로세스는 Serve를 거치지 않으므로 헤더를 지어낼 수 있다. 이것은 막지 않는다. 같은 Mac의 프로세스는 이미 Hermes와 같은 권한을 가진다.

"입력 시작" 버튼은 넣지 않았다. 페이지가 열리자마자 `open`을 부른다. 페이지 파일을 GET으로 받는 것만으로는 링크가 소모되지 않고, 허용되지 않은 계정의 `open`은 403이며 링크를 소모하지 않는다. Slack 게시는 `unfurl_links: False`이고, Slack 서버는 tailnet 밖이라 주소에 닿지 못한다. 남는 경우는 허용된 계정의 기기에 페이지 스크립트를 실행하는 미리보기 기능이 있는 경우다. 그때는 미리보기만으로 링크가 소모된다.

## 6. 요청 상태

상태는 `created`, `opened`, `saving`, `saved`, `delivered`, `expired`, `cancelled`, `failed`다. 끝 상태는 `saved`, `delivered`, `expired`, `cancelled`, `failed`다. `saving`은 끝 상태가 아니다. 시계는 바꿔 끼울 수 있다(`Lifecycle(clock)`).

### 6.1 요청을 만들 때의 점검

서버는 시작할 때 Serve 경로를 더한 뒤, 저장 프로세스를 `phase: "preflight"`로 한 번 띄워 그 종류의 저장소를 모두 점검한다. 점검은 요청의 `target_profile`로 하고, 전체 시한은 `PREFLIGHT_AT_CREATE_TIMEOUT_S`(10초)다. 점검이 끝나면 서버는 `ready` 줄을 내고, 여는 시한 60초의 시계는 그때부터 센다. 시한 안에 점검 줄이 오지 않은 저장소는 `available: false`, `unavailable_reason: "store_timeout"`이다. 프로필 폴더를 찾지 못하면 모든 저장소가 `bad_home`이다. 사용자가 화면에서 프로필을 바꾸면 제출 뒤의 쓰기 전 점검이 새 프로필로 다시 본다.

### 6.2 들어가고 나가는 길

| 지금 상태 | 일어난 일 | 다음 상태 |
|---|---|---|
| `created` | 여는 요청 | `opened` |
| `created` | 여는 시한이 지남 | `expired`, detail `open_window_passed` |
| `opened` | 제출이 복호화, 형식 검사, 가려진 값 검사, 저장소 목록 검사를 모두 통과함 (`otp_code` 밖) | `saving` |
| `opened` | `otp_code`의 제출이 검사를 통과함 | `delivered` (`saving`을 거치지 않는다) |
| `opened` | 제출이 검사에서 걸림 | `opened`, 그 오류 응답, 실패로 셈 (5번째이면 `failed`, detail `too_many_attempts`) |
| `opened` | 제출 시한이 지남 | `expired`, detail `submit_window_passed`. 보낸 값을 저장하지 못한 적이 있으면 detail `window_passed_after_failed_save`(6.3절). "저장하지 못한 적"은 저장이 실패해 `saving`에서 `opened`로 돌아온 경우와, 서버가 저장 전에 제출을 `masked_value`나 `storage_failed`(프로필 오류)로 거절하고 요청이 `opened`로 남은 경우다 |
| `opened` | 화면 취소 | `cancelled`, detail `user_cancelled` |
| `created`, `opened` | 부모의 표준 입력이 닫히거나 부모 프로세스가 사라짐 | `cancelled`, detail `parent_gone` |
| `created`, `opened` | SIGTERM | `cancelled`, detail `terminated` |
| `saving` | 제출 시한이 지남 | `saving` 그대로. 보류된 끝 사유가 없으면 `expired`(detail `submit_window_passed`)를 기록한다. 저장이 하나도 되지 않아 이 사유로 끝나면 끝 사유는 `window_passed_while_saving`이다(6.3절). |
| `saving` | 부모가 사라짐 | `saving` 그대로. 보류된 끝 사유가 없으면 `cancelled`(detail `parent_gone`)를 기록한다. |
| `saving` | SIGTERM | `saving` 그대로. 보류된 끝 사유가 없으면 `cancelled`(detail `terminated`)를 기록한다. |
| `saving` | 화면 취소 | `saving` 그대로. 409 `saving_in_progress`. 실패로 세지 않고, 끝 사유로 기록하지 않고, 로그 줄을 쓰지 않는다. |
| `saving` | 두 번째 제출 | `saving` 그대로. 409 `saving_in_progress`. 실패로 세지 않는다. 로그에 `failed` 줄(`error_code` `saving_in_progress`, `final` false)을 쓴다. |
| `saving` | 여는 요청 | 410 `already_opened` |
| `saving` | 페이지 다시 읽기 | 정적 페이지는 내준다. 페이지의 여는 요청은 410 `already_opened`다. |
| `saving` | 저장 프로세스가 끝남 | 6.3절 |
| `saving` | 서버 프로세스가 `done` 줄 없이 끝남(SIGKILL 등) | 서버는 기록하지 못한다. 저장 프로세스는 따로 살아 있어 끝까지 쓸 수 있다. 부모가 `failed`(reason `child_exited`)로 끝낸다. 도구 결과와 Slack 결과 메시지는 "저장 여부를 확인하지 못했습니다."다. |

보류된 끝 사유는 처음 기록된 하나만 남는다.

**SIGTERM과 SIGINT.** 서버는 uvicorn의 신호 가로채기를 끄고(`uvicorn.Server.capture_signals`를 아무 일도 하지 않게 덮어쓴다) SIGTERM 처리기를 직접 건다. 처리기는 표시만 세우고, 감시 스레드가 그 표시를 보고 위 표대로 한다. SIGINT는 파이썬 기본 동작(KeyboardInterrupt)으로 서버 실행을 끝내고, `main()`이 그것을 잡아 정리한다. 어느 경우든 `main()`은 저장 스레드가 끝나기를 기다린 뒤, 끝 상태가 아니면 `cancelled`(detail `terminated`)로 끝내고, Serve 경로를 지우고, `done` 줄을 낸 뒤 종료 코드 0으로 끝난다.

**결과를 반영하는 곳.** 저장 결과를 요청 상태, 로그, 부모에게 갈 결과에 반영하는 일은 제출을 처리하는 코루틴이 아니라 저장 스레드가 한다. 응답을 보낼 연결이 끊겨도 반영된다. 끝난 요청의 결과 보고(`report_terminal`)는 한 번만 하고, 저장 스레드의 반영, 시한 감시(`tick`), 강제 종료(`abort`), 그리고 페이지 호출이 끝난 요청을 보고하는 `report_end()`가 모두 같은 잠금(`_end_lock`, RLock) 아래에서 한다. 그래서 저장이 막 끝난 순간의 새로 고침이나 두 번째 제출이, 일부만 저장된 요청을 저장소 줄 없이 먼저 보고하는 일이 없다.

### 6.3 저장 프로세스가 끝났을 때의 갈림

"시한 안"은 보류된 끝 사유가 없고 저장 프로세스가 제출 시한 안에 끝났다는 뜻이다. "시한 밖"은 보류된 끝 사유가 있거나 제출 시한이 지났다는 뜻이다. 시한 밖에서 끝낼 때 보류된 끝 사유가 `cancelled`(`parent_gone`, `terminated`)이면 그 사유를 쓴다. 그 밖에는(보류된 사유가 없거나 보류된 사유가 제출 시한이면) `expired`(detail `window_passed_while_saving`)를 쓴다. 사용자는 시한 안에 제출했고, 저장하는 동안 시한이 지났고, 하나도 저장되지 않았다는 뜻이다. `submit_window_passed`는 요청이 저장 중이 아닌 `opened`일 때 제출 시한이 지나야 끝 사유가 된다. 저장이 실패해 아래 표의 "시한 안" 갈래로 `opened`로 돌아간 적이 있는 요청은, 다시 보내지 않은 채(또는 시한이 지난 뒤에 보내) 시한이 지나면 `expired`(detail `window_passed_after_failed_save`)로 끝난다. 서버가 저장 전에 제출을 422 `masked_value`(서버 안의 가려진 값 검사)나 422 `storage_failed`(프로필 오류, `stores: []`)로 거절하고 요청이 `opened`로 남은 경우도 같다(`Lifecycle.note_failed_save`). 400 `invalid_payload`, `decrypt_failed`, `bad_sid`, `replayed`는 쓸 수 있는 값이 서버에 닿지 않은 제출이라 이 표시를 켜지 않는다. 화면은 같은 오류 코드(422 `store_unavailable`, `masked_value`, `result_unknown`이 참이 아닌 `storage_failed`)로 같은 경우를 가린다. 사용자가 값을 한 번 보냈으므로 "연 뒤 5분 안에 제출하지 않았다"는 문장이 사실과 다르기 때문이다(재확인 RC-2). 화면이 받는 답은 그대로 410 `deadline_passed`다. 마지막으로 쓰기 단계에 들어간 저장의 `stores`가 이 끝 결과에도 실린다. 그보다 앞선 저장이 키체인에 남긴 것은 `keychain_left`로 실린다(아래 목록).

| 끝 사유 | 뜻 | Slack 결과 메시지 | 도구 결과 문장 |
|---|---|---|---|
| `submit_window_passed` | 연 뒤 제출 시한 안에 저장까지 간 제출이 없었다 | 만료: 연 뒤 5분 안에 제출되지 않았습니다 | 사용자가 연 뒤 5분 안에 제출하지 않았습니다. |
| `window_passed_while_saving` | 시한 안에 제출했고, 저장하는 동안 시한이 지났고, 하나도 저장하지 못했다 | 만료: 저장하는 동안 제출 시간이 지났고 저장하지 못했습니다 | 사용자는 시간 안에 제출했지만 저장하는 동안 제출 시간이 지났고 저장은 실패했습니다. |
| `window_passed_after_failed_save` | 시한 안에 제출한 값을 저장하지 못했고(저장 실패로 `opened`로 돌아감, 또는 저장 전 `masked_value`나 프로필 오류 `storage_failed`), 다시 저장까지 간 제출 없이 시한이 지났다 | 만료: 보낸 값은 저장하지 못했고, 다시 보내지 않은 채 제출 시간이 지났습니다 | 사용자가 값을 보냈지만 저장하지 못했고, 다시 보내지 않은 채 제출 시간이 지났습니다. |

Slack 문장 뒤에는 다른 만료 문장처럼 ` (<종류> '<이름표>')`가 붙고, 키체인 줄과 `keychain_left`에 따라 13절의 키체인 문장과 임시 항목 문장이 이어진다.

| 저장 결과 (`storage.save_outcome`의 `category`) | 시한 안 | 시한 밖 |
|---|---|---|
| 쓰기 전 점검에서 쓸 수 없는 저장소가 있음 (`unavailable`) | `opened`로 돌아감. 422 `store_unavailable`. 실패로 세지 않음. | 보류된 취소 사유, 없으면 `expired`(`window_passed_while_saving`). 410 `deadline_passed`. |
| 저장 프로세스가 가려진 값을 찾음 (`masked`) | `opened`로 돌아감. 422 `masked_value`. 실패로 셈. | 보류된 취소 사유, 없으면 `expired`(`window_passed_while_saving`). 410 `deadline_passed`. |
| 켠 저장소가 모두 저장됨 (`saved`) | `saved` | `saved`. 로그 `detail`에 `deferred` |
| 일부만 저장됨 (`saved`, `partial: true`) | `saved`, `partial: true` | `saved`, `partial: true`. 로그 `detail`에 `deferred` |
| 하나도 저장되지 않았고 모두 `saved: false` (`none_saved`) | `opened`로 돌아감. 422 `storage_failed`(`result_unknown: false`). 실패로 셈. | 보류된 취소 사유, 없으면 `expired`(`window_passed_while_saving`). 410 `deadline_passed`. |
| 저장이 확인된 곳이 0곳이고 결과를 모르는 곳이 있음 (`unknown`) | `failed`. detail `store_timeout`(시한으로 끝냄) 또는 `no_result`. 422 `storage_failed`(`result_unknown: true`). | 왼쪽과 같다. 로그 `detail`에 `deferred` |

- "쓰기 전 점검에서 쓸 수 없는 저장소가 있음"은 저장 프로세스가 `available: false` 점검 줄을 하나라도 냈고 `store` 줄을 하나도 내지 않은 경우다. 저장 프로세스가 그 뒤에 `done` 줄 없이 끝나도(시한으로 끝낸 경우 포함) 같다. 저장 프로세스는 점검 줄에 하나라도 거짓이 있으면 쓰기 단계에 들어가지 않기 때문이다.
- 쓰기 단계에 들어간 뒤(점검 줄이 모두 `available: true`였던 뒤) `expired`나 `cancelled`로 끝나거나 `opened`로 돌아가면, 그 로그 줄의 `detail`과 부모에게 가는 결과에도 `stores`를 넣는다. 예전 값이 바뀌었을 수 있는 키체인 줄(`main_touched: true`)을 남기려는 것이다.
- 끝 보고(부모에게 가는 결과, 그래서 Slack 결과 메시지와 도구 결과, 그리고 로그의 끝 줄)는 그 요청의 모든 시도가 키체인에 남긴 것을 말한다(2차 재확인 RC2-1). 서버는 저장이 끝날 때마다 그 저장의 키체인 줄로 세 사실을 고쳐 요청 동안 기억한다(`ServerContext.kc_left`, 서버 프로세스 메모리에만 있다). 저장됐다고 확인되지 않은 줄(저장하지 못한 줄과 저장 여부를 모르는 줄)의 `main_touched`나 `main_created`가 참이면 그 칸을 참으로 둔다. 임시 항목이 남았을 수 있는 줄(`tmp_left`가 참이거나 `error`가 `store_timeout`, `no_result`)이면 저장에 성공한 줄이어도 `tmp_left`를 참으로 둔다. 키체인에 저장된 줄(`saved: true`)이 오면 `main_touched`와 `main_created`를 거짓으로 되돌린다. 그 항목에는 이제 저장됐다고 보고되는 값이 들어 있기 때문이다. `tmp_left`는 되돌리지 않는다.
- 셋 가운데 하나라도 참이면 끝 결과의 meta와 끝 줄의 `detail`에 `keychain_left`를 싣는다. 모양은 `{"service": <키체인 service>, "listed": <bool>, "main_touched": <bool>, "main_created": <bool>, "tmp_left": <bool>}`이다. 계정 이름(`account`)은 싣지 않는다. 허용 목록 항목의 계정 이름은 흔히 로그인 아이디라 Slack과 도구 결과로 보내지 않기 때문이다. 한 요청의 키체인 항목은 하나이므로 `keychain_left`도 하나다.
- Slack 결과 메시지와 도구 결과는 `stores` 줄에서 나온 키체인 문장과 `keychain_left`에서 나온 문장을 합쳐 문장 끝에 붙인다. 같은 문장은 한 번만 붙인다. 일부만이 아닌 "저장 완료"에도 붙인다. 예를 들어 키체인에만 보낸 값이 새 항목을 만들고 실패한 뒤 키체인을 끄고 `.env`에만 저장하면, Slack 결과 메시지는 "저장 완료: <변수 이름>, 프로필 <프로필>" 뒤에 새 항목 문장을 붙인다.
- 결과를 모를 때 마지막 상태를 `expired`나 `cancelled`로 적지 않는다. 썼는지 모르는 채로 "만료"나 "취소"로 적으면 틀린 기록이 되기 때문이다.
- `opened`로 돌아가도 제출 시한은 처음 연 시각 기준 그대로다.

### 6.4 정리

- 끝 상태가 되면 서버는 응답을 보내고, Serve 경로를 지우고, 2초 안에 내려간다.
- 부모가 사라지면(표준 입력 EOF 또는 부모 pid가 없음) 서버는 Serve 경로를 지우고 내려간다. 저장 중이면 저장이 끝난 뒤에 내려간다.
- 부모(`launcher`)는 서버가 어떻게 끝났든 그 토큰의 `serve ... off`를 한 번 더 한다. 열린 요청은 `<요청한 프로필 폴더>/secure-input/active/<request_id>.json`(0600: `request_id`, `token`, `pid`, `port`, `created_at`)에 기록되고 정리할 때 지운다. `sweep_stale()`은 pid가 죽은 기록의 Serve 경로를 지운다.
- 살아 있는 요청은 3개까지다. 넘으면 `start_request`가 `TooManyActive`를 낸다.

## 7. Tailscale Serve (`secure_input/serve.py`)

- CLI 찾기: `SECURE_INPUT_TAILSCALE_BIN` → `/Applications/Tailscale.app/Contents/MacOS/Tailscale` → `PATH`의 `tailscale`. tailnet 호스트는 `tailscale status --json`의 `Self.DNSName`(끝의 점을 뗀다)이고 코드에 적지 않는다.
- 더하기: `serve --bg --https=443 --set-path /<토큰> http://127.0.0.1:<port>/<토큰>`.
- 지우기: `serve --https=443 --set-path /<토큰> off`. 다른 Serve 설정은 건드리지 않는다(`serve reset`을 쓰지 않는다). funnel은 쓰지 않는다.

## 8. 저장 프로세스 (`python -m secure_input.storage`)

서버는 저장 프로세스를 `-P`, `cwd=<플러그인 폴더>`, `HERMES_HOME=<대상 프로필 폴더>`로 띄운다. 요청은 표준 입력으로만 준다(인자와 환경변수에 넣지 않는다). 서버와 저장 프로세스는 Hermes 소스 폴더를 `PYTHONPATH`에 받는다(`storage.hermes_agent_dir()`, 또는 `SECURE_INPUT_HERMES_AGENT_DIR`). 이름 검사가 `hermes_cli.config`를, vault 저장이 `agent/vault_store.py`를 불러오기 때문이다.

프로필 폴더는 `secure_input.profiles.resolve_profile_home(name, hermes_root)`로만 정한다. `default`는 `hermes_root`이고, 그 밖에는 `hermes_root/profiles/<이름>`이다(이름은 `^[a-z0-9][a-z0-9_-]{0,63}$`, 폴더가 있어야 한다). 프로필 목록도 `hermes_root`에서 읽는다.

### 8.1 띄우기와 시한

- 새 프로세스 그룹으로 띄운다(`start_new_session=True`). 시한이 지나면 그룹 전체에 SIGTERM을 보내고, 1초 뒤에도 남아 있으면 SIGKILL을 보낸다. 저장 프로세스가 띄우는 `security`는 새 그룹을 만들지 않고 이 그룹 안에 있으므로 함께 끝난다.
- 시한은 `phase: "save"`이면 켜진 저장소의 `STORE_TIMEOUT_S` 합이고, `phase: "preflight"`이면 `PREFLIGHT_AT_CREATE_TIMEOUT_S`다.
- 저장 프로세스는 저장소 하나를 쓰기 직전에 `os.getppid()`가 시작할 때의 값과 같은지 본다. 다르면 서버가 죽은 것이므로 그 저장소부터 쓰지 않는다.
- 서버는 표준 출력을 줄마다 읽는다. 시한으로 끝냈든 스스로 끝났든 받은 줄로 저장소마다의 결과를 정한다.

### 8.2 입력 (표준 입력의 JSON 한 개. 서버는 쓰고 나서 표준 입력을 닫는다)

| 칸 | 언제 | 뜻 |
|---|---|---|
| `phase` | 항상 | `preflight`(요청을 만들 때, 값 없음) 또는 `save`(제출 뒤) |
| `kind` | 항상 | `api_key`, `login`, `secret` |
| `stores` | 항상 | `preflight`이면 `KIND_STORES[kind]` 전체, `save`이면 사용자가 켠 저장소 |
| `request_id` | 항상 | 요청 번호. 키체인 임시 항목 이름에 쓴다. |
| `env_var` | `env`가 있을 때 | 변수 이름 |
| `label`, `origin` | `hermes_vault`가 있을 때 | 항목 이름과 사이트 주소 |
| `keychain` | `keychain`이 있을 때 | `{"service", "account", "listed"}`. 이름이 없는 키체인이면 `null`. |
| `value` | `save`이고 `api_key`나 `secret` | 값 |
| `masked_check` | `save`이고 `api_key` | 서버가 가려진 값 검사를 이미 했으면 참, Hermes 함수를 불러오지 못해 하지 못했으면 거짓 |
| `identifier_type`, `identifier`, `password`, `otp_secret` | `save`이고 `login` | 로그인 내용 |

### 8.3 출력 (표준 출력. 한 줄에 JSON 한 개. 값, 값의 길이, 아이디는 넣지 않는다)

1. 형식이 틀린 입력(모르는 `phase`, 빈 `stores`, 모르거나 겹친 저장소)은 `{"event": "done", "ok": false, "error": "internal_error"}`, 종료 코드 3이다.
2. `kind`가 저장 종류가 아니거나 그 종류가 고를 수 없는 저장소가 있으면, 저장소마다 `{"event": "preflight", "store", "available": false, "reason": "unsupported_kind", "exists": null}`을 내고 `{"event": "done", "ok": false, "error": "store_unavailable"}`, 종료 코드 2로 끝난다.
3. `phase`가 `save`이고 `api_key`이며 `masked_check`가 참이 아니면, 저장소 점검보다 먼저 Hermes의 `refuse_redacted_env_value`로 가려진 값 검사를 한다. 걸리면 점검 줄 없이 `{"event": "done", "ok": false, "error": "masked_value"}`, 종료 코드 2로 끝난다. 그 함수를 불러오지 못하면 건너뛴다.
4. 저장소마다 점검 줄 한 줄: `{"event": "preflight", "store": "keychain", "available": true, "reason": null, "exists": true}`. 저장소 모듈을 불러오지 못하거나 점검이 예외를 내면 `available: false`, `reason: "internal_error"`다.
5. `phase`가 `preflight`이면 `{"event": "done", "ok": true}`, 종료 코드 0으로 끝난다.
6. `phase`가 `save`이고 점검 줄에 하나라도 `available: false`가 있으면 아무 데도 쓰지 않고 `{"event": "done", "ok": false, "error": "store_unavailable"}`, 종료 코드 2로 끝난다.
7. 모두 쓸 수 있으면 `STORE_NAMES`의 순서로 쓴다. 저장소 하나가 끝날 때마다 `{"event": "store", <저장소 결과 줄에서 profile을 뺀 칸>}` 한 줄을 내고 바로 비운다(flush). 저장소 모듈의 `save()`가 예외를 내면 그 줄은 `saved: null`, `error: "internal_error"`다.
8. 모두 끝나면 `{"event": "done", "ok": true}`, 종료 코드 0이다. 저장소가 실패해도 `ok`는 참이다. 실패는 저장소 줄에 있다.
9. 그 밖의 예상하지 못한 예외는 `{"event": "done", "ok": false, "error": "internal_error"}`, 종료 코드 3이다.

서버는 `save`에서 `store` 줄이 오지 않은 저장소를 채운다. 시한으로 끝냈으면 `{"saved": null, "error": "store_timeout"}`, 시한 전에 끝났으면 `{"saved": null, "error": "no_result"}`다(6.3절의 쓸 수 없는 저장소 경우는 빼고).

## 9. 저장소 모듈 (`secure_input/stores/`)

`env.py`, `hermes_vault.py`, `keychain.py`는 같은 두 함수를 낸다.

- `preflight(request) -> {"available", "reason", "exists"}`. 값을 쓰지 않는다. `request`에 값이 있으면(`phase: "save"`) 값 규칙 검사도 한다.
- `save(request) -> <저장소 결과 줄에서 store를 뺀 칸>`. 예외를 밖으로 내지 않는다. 실패는 `error` 칸의 낱말로 돌려준다.
- 저장 프로세스는 표준 입력 JSON을 그대로 넘기지 않고 저장소마다 필요한 칸만 넘긴다. `env`는 `{"env_var", "value"?}`, `hermes_vault`는 `{"label", "origin", 로그인 칸?}`, `keychain`은 `{"service", "account", "listed", "request_id", "value"?}` 다섯 열쇠다. `value`와 로그인 칸은 `phase: "save"`일 때만 넣는다. `keychain` 칸이 `null`이면 `service`와 `account`를 `None`으로 넘긴다.
- 저장소 모듈은 저장소 전체 시한을 세지 않는다. 키체인 모듈이 지키는 시한은 `security` 호출 하나의 `CALL_TIMEOUT_S`(5초)뿐이다.

### 9.1 `env` (`.env`)

`<프로필 폴더>/.env`에 Hermes 자신의 쓰기 함수로만 쓴다. 점검과 `save()`가 같은 순서로 본다.

1. 변수 이름 검사(2절 `env_var`의 규칙). 걸리면 `invalid_env_var`.
2. 값이 있으면 한 줄이고 ASCII인지. 아니면 `invalid_value`.
3. Hermes(`hermes_cli.config`, `agent.secret_scope`)를 불러오지 못하면 `env_write_failed`.
4. Hermes의 `get_env_path()`가 `<프로필 폴더>/.env`인지. 아니면 `bad_home`. `HERMES_HOME`이 절대 경로의 폴더가 아니어도 `bad_home`.
5. `require_env_writable(name, "set")`. 걸리면 `env_not_writable`.
6. 점검의 `exists`는 그 변수 줄이 이미 있는지다(줄 내용은 메모리에서만 본다).

`save()`는 Hermes의 `.env.lock` 아래에서 파일의 바이트와 권한을 먼저 잡아 두고, 같은 변수 줄이 2개 이상이면 먼저 모두 지우고, `save_env_value(name, value)`(Hermes의 따옴표 규칙. 한 줄이 있으면 그 자리에서 바꾸고, 없으면 끝에 더한다)로 쓰고, Hermes의 읽기 함수 `agent.secret_scope.load_env_file`로 되읽어 비교하고(`verify_failed`), 권한을 0600으로 맞춘다. 잠금 아래의 어느 단계가 실패하면 같은 잠금 안에서 파일을 원래 바이트와 권한으로 되돌린 뒤(없던 파일이면 지운다) `env_write_failed`나 `verify_failed`를 돌려준다. 다른 줄은 그대로 둔다. Hermes가 출력하는 것은 표준 오류로 보낸다. 가려진 값 검사는 이 모듈이 하지 않는다. 서버가 저장 전에 하고, 서버가 못 했으면 저장 프로세스가 저장소 점검보다 먼저 한다(8.3절 3번).

### 9.2 `hermes_vault`

- 점검: 프로필 폴더(`bad_home`), 아이디 종류(`invalid_identifier_type`), Hermes의 `VaultStore`를 불러오고 이미 있는 vault가 열리는지(`vault_rejected`). vault가 없어도 된다(첫 저장이 만든다). 점검은 아무것도 만들지 않는다.
- 저장: `VaultStore().add_item(kind="login", label=..., secret={identifier_type, identifier, password, otp_secret?}, origin=...)`로 늘 새 항목을 만든다. 저장이 성공한 뒤에만, `kind == "login"`이고 정규화한 `origin`이 같고 아이디(`(identifier or "").strip()`, 대소문자 구분, `identifier_type`은 비교하지 않음)가 같은 예전 항목을 `remove_item`으로 통째로 지운다(예전 인증 앱 설정 키도 함께 지워진다). "예전"은 `(created_at, id)`가 새 항목보다 작은 것이다(`created_at`이 없거나 시간대가 있는 ISO 시각이 아닌 항목은 남긴다). 더하기, 목록, 지우기는 `<프로필 폴더>/secure-input/login.lock`(flock, 0600) 아래에서 한다. 새 저장이 실패하면 아무것도 지우지 않는다(`vault_rejected`). 목록이나 지우기가 실패하면 새 항목은 남고 저장은 성공이다(`replace_error: true`).
- 결과 줄: `item_id`, `origin`, `replaced`(예전 항목을 1개 이상 지움), 부모에게만 가는 `has_otp`, `removed_count`, `replace_error`.

### 9.3 `keychain`

모든 `security` 호출은 다음을 지킨다.

- 실행 파일은 `security_path` 인자(기본값 `/usr/bin/security`)다. 이 인자는 시험만 가짜 실행 파일을 끼울 때 쓴다. 환경변수, 설정, 요청 칸으로는 바꿀 수 없다.
- 값은 명령 인자와 환경변수에 넣지 않는다. 값이 드는 명령은 `security -i`의 표준 입력으로만 주고, 값은 UTF-8 바이트의 16진수(`-X`)로 쓴다. 한 줄은 `add-generic-password -a "<account>" -s "<service>" -U -X <16진수>`다.
- 한 줄이 `MAX_LINE_BYTES`(2,400바이트)를 넘으면 실행하지 않고 `keychain_line_too_long`이다.
- 표준 출력과 오류 출력은 버린다. `-w` 되읽기 출력과 접근 허용 목록(`dump-keychain`) 출력만 메모리에서 비교하거나 걸러 낸 뒤 버린다.
- 호출 하나의 시한은 5초다. 넘기면 그 `security` 프로세스에 SIGKILL을 보내고 `keychain_timeout`이다. `security`는 저장 프로세스와 같은 프로세스 그룹에 둔다.
- 파이썬 `keyring`과 Security framework 직접 호출은 쓰지 않는다.

**점검 (`preflight`)**

1. `security_path`의 실행 파일이 있는지. 없으면 `keychain_unavailable`.
2. `security default-keychain`의 종료 코드가 0인지. 아니면 `keychain_unavailable`. 출력에서 앞뒤 공백과 큰따옴표를 뗀 값이 기본 키체인 경로다. 모듈은 이 경로를 `security_path`마다 모듈 안에 기억한다(`save()`가 쓴다).
3. `service`나 `account`가 없거나 `NAME_RE`에 맞지 않으면 `keychain_name_invalid`.
4. 값이 있으면 키체인 값 규칙(1.3절)을 본다. 맞지 않으면 `keychain_value_unsupported`. 맞으면 본 항목 쓰기 줄과 임시 항목 쓰기 줄의 바이트 수를 미리 세어, 하나라도 2,400바이트를 넘으면 `keychain_line_too_long`.
5. `security find-generic-password -s <service> -a <account>`로 있는지 본다. 값은 읽지 않는다. 0이면 `exists: true`, 44이면 `exists: false`, 그 밖은 `keychain_unavailable`.
6. 있으면 `security dump-keychain -a <기본 키체인 경로>`로 접근 허용 목록을 읽는다. `class: "genp"`이고 `"svce"`와 `"acct"`가 정확히 같은 항목이 하나여야 하고, 그 항목의 `decrypt` 권한 묶음이 모든 프로그램에 열려 있지 않고(`applications: <null>`이 아님) 목록에 `/usr/bin/security`가 있어야 한다. 아니면 `keychain_acl_denied`. 그 항목 밖의 줄은 메모리에서 버린다.

**쓰기 순서 (`save`)**

`save()`는 점검 1번부터 4번을 다시 하지 않는다. 이름 규칙도 다시 보지 않는다. 다시 하는 것은 (가)=점검 5번과 (나)=점검 6번뿐이다. (나)에 쓰는 기본 키체인 경로는 같은 프로세스에서 같은 `security_path`로 먼저 돈 `preflight()`가 기억해 둔 값이다. 기억된 경로가 없으면 쓰지 않고 `keychain_unavailable`(`saved: false`)로 끝난다. 저장 프로세스는 같은 프로세스, 같은 모듈 객체로 `preflight()`를 먼저 부르고, 모든 저장소가 쓸 수 있을 때만 `save()`를 부른다.

- (가) 있는지 확인한다.
- (나) 이미 있으면 접근 허용 목록을 확인한다.
- (다) 이미 있는 항목을 바꿀 때만: 임시 항목(service `hermes-secure-input.tmp.<요청 번호 앞 12자>`, account `hermes-secure-input`)에 같은 값을 쓰고, `security find-generic-password -s <service> -a <account> -w`로 되읽어 비교한다. 쓰기의 종료 코드가 0이 아니면 `keychain_write_failed`, 되읽은 값이 다르면 `keychain_verify_failed`로 끝낸다. 두 경우 모두 본 항목은 건드리지 않는다.
- (라) 본 항목에 쓴다.
- (마) 본 항목을 `-w`로 되읽어 비교한다. (라)의 종료 코드가 0이 아니고 되읽은 값도 다르면 `keychain_write_failed`, (라)의 종료 코드가 0인데 되읽은 값이 다르면 `keychain_verify_failed`, 같으면 `saved: true`다. (라)나 (마)가 시한을 넘기면 `keychain_timeout`이고 `saved`는 `null`이다.
- (바) (다)에서 임시 항목을 만들었으면 어느 단계에서 끝나든 `security delete-generic-password -s <임시 service> -a hermes-secure-input`으로 지운다. 종료 코드가 0이나 44가 아니면 `tmp_left: true`다.

`save()` 한 번의 `security` 호출 수는 새 항목이면 3번(있는지 확인, 쓰기, 되읽기)이고, 이미 있는 항목이면 7번(있는지 확인, 접근 목록, 임시 쓰기, 임시 되읽기, 본 쓰기, 본 되읽기, 임시 지우기)이다. 중간에 끝나면 이보다 적다. 결과 줄의 `new_item`은 `listed`가 거짓이고 (가)에서 항목이 없었을 때만 참이다. `replaced`는 `saved`가 참이고 (가)에서 항목이 있었을 때 참이다.

## 10. 저장소 실패 사유 낱말 전체 목록

이 표에 없는 사유 낱말은 쓰지 않는다. "단계"의 점검은 쓰기 전 점검이고 쓰기는 값을 쓰는 단계다. 점검 낱말이 `save()` 안의 재확인(키체인 쓰기 순서 (가)와 (나))에서 나오면 그 저장소 줄은 `saved: false`와 그 낱말이고, 요청은 6.3절의 갈림을 따른다(`store_unavailable`이 아니다). 그때는 앞 순서의 저장소(`env`)가 이미 쓰였을 수 있기 때문이다.

| 낱말 | 저장소 | 뜻 | 단계 | `saved` |
|---|---|---|---|---|
| `store_timeout` | 모두 | 저장 프로세스를 시한으로 끝냈고 이 저장소의 결과 줄이 오지 않았다. 요청을 만들 때의 점검에서는 그 시한 안에 이 저장소의 점검 줄이 오지 않았다. | 점검 또는 쓰기 | `null` |
| `no_result` | 모두 | 저장 프로세스가 시한 전에 끝났는데 이 저장소의 결과 줄이 없다. | 쓰기 | `null` |
| `internal_error` | 모두 | 예상하지 못한 예외. 저장소 모듈을 불러오지 못한 경우를 포함한다. 쓰기 단계에서 나면 쓰기가 시작됐는지 모른다. | 점검 또는 쓰기 | 점검이면 쓰지 않음, 쓰기이면 `null` |
| `unsupported_kind` | 모두 | 저장 프로세스가 모르는 종류이거나 그 종류가 고를 수 없는 저장소다. 방어용이다. | 점검 | 쓰지 않음 |
| `bad_home` | `env`, `hermes_vault` | 프로필 폴더가 Hermes가 계산한 폴더와 다르거나 절대 경로의 폴더가 아니다. 요청을 만들 때 프로필을 찾지 못한 경우도 이 낱말이다. | 점검 | 쓰지 않음 |
| `invalid_env_var` | `env` | 변수 이름이 Hermes의 이름 규칙에 맞지 않는다. 요청을 만들 때 이미 걸러지므로 방어용이다. | 점검 | 쓰지 않음 |
| `invalid_value` | `env` | 값이 한 줄 ASCII가 아니다. 서버의 형식 검사가 먼저 거르므로 방어용이다. | 점검 | 쓰지 않음 |
| `env_not_writable` | `env` | Hermes가 이 변수를 이 기능으로 쓰지 못하게 한다. | 점검 | 쓰지 않음 |
| `env_write_failed` | `env` | Hermes의 쓰기 함수를 불러오지 못했거나(점검), 쓰는 도중에 실패했다(쓰기. 파일은 저장 전 바이트로 되돌렸다). | 점검 또는 쓰기 | 점검이면 쓰지 않음, 쓰기이면 `false` |
| `verify_failed` | `env` | 쓴 뒤 되읽은 값이 다르다. 파일은 저장 전 바이트로 되돌렸다. | 쓰기 | `false` |
| `masked_value` | 저장 프로세스 (`api_key`) | 값이 가려진 모양이다. 저장소 줄의 낱말이 아니라 `done` 줄의 `error`이고, 제출 응답은 422 `masked_value`다. | 점검 (저장소 점검보다 먼저) | 쓰지 않음 |
| `invalid_identifier_type` | `hermes_vault` | 아이디 종류가 `email`, `phone`, `username` 가운데 하나가 아니다. 방어용이다. | 점검 | 쓰지 않음 |
| `vault_rejected` | `hermes_vault` | Hermes vault를 불러오거나 열지 못했거나(점검), 항목을 받지 않았다(쓰기). | 점검 또는 쓰기 | 점검이면 쓰지 않음, 쓰기이면 `false` |
| `keychain_unavailable` | `keychain` | `/usr/bin/security`가 없거나, 기본 키체인이 조회되지 않거나, 있는지 확인이 0이나 44가 아닌 종료 코드를 냈다. `save()`에서 기억된 기본 키체인 경로가 없을 때도 이 낱말이다. | 점검. `save()`의 (가)와 (나) | 점검이면 쓰지 않음, `save()`이면 `false` |
| `keychain_timeout` | `keychain` | `security` 호출 하나가 5초를 넘겨 그 프로세스를 끝냈다. (라) 전이면 본 항목은 그대로다. (라)나 (마)이면 본 항목이 바뀌었는지 모른다. | 점검 또는 쓰기 | 점검이면 쓰지 않음, (라) 전이면 `false`, (라)나 (마)이면 `null` |
| `keychain_acl_denied` | `keychain` | 이미 있는 항목의 접근 허용 목록에 `/usr/bin/security`가 없다(9.3절 점검 6번). | 점검 또는 `save()`의 (나) | 점검이면 쓰지 않음, `save()`이면 `false` |
| `keychain_name_invalid` | `keychain` | 키체인 이름이 규칙에 맞지 않는다. `api_key`의 기본 이름을 쓸 수 없을 때(2.2절 7번)만 요청이 만들어진 채 보인다. | 점검 | 쓰지 않음 |
| `keychain_value_unsupported` | `keychain` | 값이 키체인 값 규칙에 맞지 않는다. `api_key`에서만 나온다. `secret`은 서버가 `invalid_payload`로 먼저 거절한다. | 점검 | 쓰지 않음 |
| `keychain_line_too_long` | `keychain` | `security -i`에 줄 한 줄이 2,400바이트를 넘는다. 값 규칙을 지키면 나오지 않는 방어용이다. | 점검. `save()` 안이면 쓰기 | 점검이면 쓰지 않음, `save()`이면 `false` |
| `keychain_write_failed` | `keychain` | 임시 항목 쓰기 (다) 또는 본 항목 쓰기 (라)의 종료 코드가 0이 아니었다. (다)이면 본 항목은 그대로다. | 쓰기 | `false` |
| `keychain_verify_failed` | `keychain` | 되읽은 값이 넣은 값과 다르다. (다)이면 본 항목은 그대로다. (마)이면 본 항목에 이미 새 값을 썼다. 쓰기 전에 있던 항목이면 예전 값이 바뀌었고 `main_touched`가 참이다. 없던 항목이면 `main_touched`는 거짓이다. | 쓰기 | `false` |

"다시 보낼 수 있나"는 6.3절의 갈림을 따른다. 점검 단계의 낱말은 모두 `store_unavailable`로 답하고 요청은 `opened`로 돌아가므로 같은 페이지에서 다시 보낼 수 있다(그 저장소를 끄거나 값을 고쳐서). `store_timeout`과 `no_result`로 결과를 모르게 된 요청은 `failed`로 끝나 다시 보낼 수 없다.

1판의 저장 실패 낱말 `timeout`(저장 프로세스 시한)과 `failed`(사유 없는 실패의 기본값)는 2판에서 쓰지 않는다. `timeout`은 `store_timeout`으로 바뀌었고, `failed`는 결과 줄마다 사유가 있어 필요 없어졌다.

## 11. 부모 API와 결과 (`secure_input/launcher.py`)

```python
handle = start_request(spec: RequestSpec, *, static_dir=None, serve=None, python=sys.executable,
                       allowed_logins: list[str] | None = None,     # None: serve.owner_login()만
                       allow_no_identity_header: bool = False) -> RequestHandle
handle.url          # 공개 주소
handle.request_id
handle.wait(timeout: float | None = None, heartbeat: Callable[[], None] | None = None) -> Outcome
handle.cancel(grace: float | None = None)   # None: 종류의 취소 뒤 기다리는 시간(1.1절)
# Outcome: status ("saved"|"delivered"|"expired"|"cancelled"|"failed"), meta (dict, 값 없음),
#          code (str | None, otp_code만)
sweep_stale(hermes_root) -> int
```

- 서버의 표준 출력은 줄마다 JSON이다. `{"event": "ready", "url", "request_id", "port"}` 한 줄과, 끝에 `{"event": "done", "status", "meta"}` 한 줄(전달된 `otp_code`이면 `"code"`도)이다. 요청 명세는 서버의 표준 입력으로 간다. uvicorn 접근 로그는 끈다(경로 토큰이 들어가기 때문이다). 서버의 표준 오류에는 값, 토큰, sid, 키가 없다.
- `Outcome.meta`: `request_id`, `kind`, `label`, `target_profile`(실제로 쓴 프로필), `storage`(3.2절의 모양. vault이면 `has_otp`, `replaced`, `replace_error`가 더 있다), 저장이면 `partial`과 `stores`(저장소 결과 줄), 성공이 아니면 `reason`(`open_window_passed`, `submit_window_passed`, `window_passed_while_saving`, `window_passed_after_failed_save`, `too_many_attempts`, `user_cancelled`, `parent_gone`, `terminated`, `serve_add_failed`, `child_exited`, `store_timeout`, `no_result`). 쓰기 단계에 들어간 뒤 `expired`나 `cancelled`로 끝나도 `stores`가 있다. 그 요청의 저장이 키체인에 무언가 남겼을 수 있으면 `keychain_left`(6.3절)가 있다. `saving`은 부모에게 가지 않는다.
- `wait(timeout)`은 시간이 지나도 요청이 열려 있으면 `TimeoutError`를 낸다(요청은 계속 돈다). `heartbeat`는 기다리는 동안 5초쯤마다 불린다.
- `cancel()`은 서버의 표준 입력을 닫고(서버는 `parent_gone`을 기록하거나, 저장 중이면 보류한다), `grace`가 지나도 살아 있으면 SIGTERM, 그다음 SIGKILL을 보낸다. `Outcome`을 돌려준다.
- 그 밖의 속성: `port`, `local_url`(`http://127.0.0.1:<port>/<토큰>/`), `pid`, `returncode`, `done`, `events`(`code`를 뺀 서버 줄), `stderr_text`(마지막 64 KB). 오류: `TooManyActive`, `StartError`(`index.html` 없음, Tailscale을 쓸 수 없음, 서버 시작 실패), `ProfileError`(요청한 프로필이나 대상 프로필이 없음).
- 살아 있는 요청은 `hermes_root` 아래의 모든 프로필을 합쳐 센다. `sweep_stale`은 pid가 살아 있어도 60 + 300 + 120초보다 오래된 기록을 지운다(pid 재사용 대비). 그 pid를 죽이지는 않는다.
- `_test_ttls`(비공개 키워드)는 시험에서만 시한을 줄인다. 계약보다 늘릴 수는 없다.
- 에이전트 도구 `secure_input_request`의 결과(JSON 문자열)는 `success`, `status`(`saved`, `partial`, `expired`, `cancelled`, `failed`), `request_id`, `kind`, `label`, `target_profile`, `storage`, `stores`, `partial`, `keychain_left`, `note`다. `plugin.SecureInput.result`가 `Outcome`에서 만든다.
  - `keychain_left`는 6.3절의 모양(`service`, `listed`, `main_touched`, `main_created`, `tmp_left`, `account`는 없다)이고, 끝 결과에 없으면 `null`이다. `note`의 키체인 문장은 `stores`의 키체인 줄과 `keychain_left`를 합쳐 한 번씩 붙인다.
  - `storage`가 키체인이면 이 플러그인 전용 항목은 `{"type": "keychain", "service", "account"}`이고, 허용 목록 항목은 `{"type": "keychain", "service", "listed": true, "allow_list_id", "label"}`이다. 허용 목록 항목의 `account`는 넣지 않는다. 그 이름은 흔히 로그인 아이디나 이메일이라 입력 페이지(여는 응답의 `target.keychain`)에만 보인다. 이 규칙은 저장됨, 일부만 저장, 실패, 결과 모름, 만료, 취소 어느 끝에서도 같다.
  - `stores`는 저장소 결과 줄(3.2절의 표)에서 `store`, `saved`, `replaced`, `error`, `env_var`, `profile`, `origin`, `item_id`, `has_otp`, `removed_count`, `replace_error`, `service`, `account`, `listed`, `new_item`, `tmp_left`, `main_touched`, `main_created` 가운데 있는 칸만 남긴 것이다(`plugin.TOOL_ROW_KEYS`). 키체인 줄의 `listed`가 참이면 `account`를 뺀다.
  - `note`의 키체인 저장 문장은 전용 항목이면 "값은 Mac 키체인 항목(service \`<service>\`, account \`<account>\`)에 저장했습니다."(`KEYCHAIN_SAVED_NOTE`), 허용 목록 항목이면 "값은 Mac 키체인 항목(service \`<service>\`, 허용 목록 항목 \`<id>\`)에 저장했습니다."(`KEYCHAIN_LISTED_SAVED_NOTE`)이다. 실패 낱말 `keychain_acl_denied`는 `note`와 Slack 결과 메시지에서 `keychain_acl_denied: 접근 허용 목록에 /usr/bin/security 없음`으로 쓴다(`notify.ERROR_WORD_GLOSS`). 다른 낱말에는 풀이를 붙이지 않는다.
- `static_dir`의 기본값은 `secure_input/static/`이다. `index.html`이 없으면 `StartError`다. `/<토큰>/`은 `index.html`을 내주고, 다른 경로는 `static_dir` 아래 파일에 대응한다(`..`와 점으로 시작하는 이름은 안 된다). 그래서 화면은 자산을 상대 주소(`assets/app.js`처럼)로 가리킨다.

## 12. 로그 (`<대상 프로필 폴더>/logs/secure-input.jsonl`, 0600)

모든 줄의 칸: `ts`(시간대 있는 ISO 8601), `event`, `request_id`, `path_fp`(토큰 sha256의 앞 16진수 8자), `requester`(다섯 칸 모두), `purpose`, `kind`, `label`, `target_profile`, `storage`(`{"type": "env", "env_var"}`, `{"type": "vault", "origin"}`, `{"type": "keychain", "service", "account"}`, `{"type": "browser_page", "site"}` 가운데 하나), `stores`(요청 명세의 저장소 줄마다 `store`, `selected`, `by`, `reason`, `needed`와 이름 칸: 변수 이름, 사이트 주소, 또는 service와 account), `detail`.

| 줄 | `detail` |
|---|---|
| `created` | `port` |
| `opened` | 없음 |
| `open_denied` | `reason`(`identity_required` 또는 `identity_not_allowed`). 한 요청에 5줄까지. 계정 이름은 쓰지 않는다. |
| `submitted` | `attempt` |
| `saving` | `stores`(켠 저장소 이름) |
| `saved` | `stores`(저장소마다 `store`, `saved`, `replaced`, `error`, 키체인이면 `main_touched`, `main_created`, `tmp_left`), `partial`, 보류된 끝 사유가 있었으면 `deferred`(`"expired"` 또는 `"cancelled"`). 아이디, 값, 지운 항목 번호는 쓰지 않는다. |
| `delivered` | 없음 |
| `failed` | 실패한 제출이면 `error_code`, `attempt`, `final`(그리고 저장 실패이면 `stores`). `store_unavailable`이면 `stores`가 쓸 수 없는 저장소와 사유다. 저장 중 두 번째 제출이면 `error_code` `saving_in_progress`, `final` false. 결과를 몰라 끝났으면 `reason`(`store_timeout` 또는 `no_result`)과 `stores`, `partial`. 부모가 쓰면 `reason: child_exited`. |
| `expired` | `reason`. 쓰기 단계에 들어간 뒤이면 `stores`. |
| `cancelled` | `reason`(`user_cancelled`, `parent_gone`, `terminated`). 쓰기 단계에 들어간 뒤이면 `stores`. |
| `cleanup` | `by`(`server` 또는 `launcher`), `serve_removed` |

요청을 끝내는 줄(`saved`, 요청을 끝낸 `failed`, `expired`, `cancelled`)의 `detail`에는, 그 요청의 저장이 키체인에 무언가 남겼을 수 있으면 6.3절의 `keychain_left`가 더 있다.

사용자가 화면에서 프로필을 바꾸면 저장에 관한 줄(`saving`, `saved`, 저장 실패의 `failed`)은 고른 프로필의 로그에도 간다. 그 줄의 `target_profile`은 고른 프로필이고 `detail.requested_profile`은 원래 프로필이다.

## 13. 고정 문장

여러 곳이 글자 그대로 써야 하는 문장이다. 그 밖의 문장은 화면(`ui/src/lib/copy.ts`)과 도구(`secure_input/plugin.py`)가 정한다.

| 쓰는 곳 | 문장 |
|---|---|
| 화면: 키체인 새 항목 안내 (`new_item: true`. 여는 응답의 `keychain.new_item`으로 판단한다) | 새 항목입니다. 값을 쓸 프로그램이 이 항목 이름과 키체인 계정 이름으로 읽게 되어 있는지는 값을 보낸 뒤 그 프로그램의 설정에서 직접 확인하세요. |
| 도구 결과: 키체인 새 항목 안내 (`new_item: true`. 부모에게 가는 결과의 키체인 줄 `new_item`으로 판단한다) | 새 항목입니다. 이 항목을 읽는 프로그램은 아직 없습니다. 값을 쓸 프로그램이 이 항목 이름과 키체인 계정 이름으로 읽게 되어 있는지는 사용자가 그 프로그램의 설정에서 확인해야 합니다. 사용자에게 두 이름을 알려 주고, 키체인 항목의 값은 읽지 마세요. |
| 화면: 키체인 덮어쓰기 안내 (`exists: true`) | 이 이름의 항목에 이미 값이 있습니다. 보내면 그 값을 바꿉니다. 예전 값은 되돌릴 수 없습니다. |
| 화면: 저장 중 표시 | 저장 중입니다. 이 창을 닫지 마세요. |
| 화면: 저장 중에 응답이 끊기거나 `result_unknown: true`일 때, 저장하는 종류의 제출이 410 `deadline_passed`를 받았을 때 | 이 화면은 저장 결과를 받지 못했습니다. Slack 대화의 결과 메시지를 확인하세요. |
| 화면: `api_key`의 `.env`가 꺼져 있을 때의 경고 | Hermes는 이 키를 `.env`에서 읽습니다. 끄면 Hermes는 이번에 넣는 키를 쓰지 못하고, `.env`에 이미 값이 있으면 그 값은 바뀌지 않습니다. |
| 도구 결과: 결과를 모를 때 | 저장 여부를 확인하지 못했습니다. |
| 도구 결과, Slack 결과 메시지: 서버가 결과를 알리지 못하고 끝남(`reason`이 `child_exited`이고 `otp_code`가 아님) | 저장 여부를 확인하지 못했습니다. |
| 도구 결과: 키체인에만 저장된 `api_key` | Hermes가 이 값을 쓰려면 본체 설정 `secrets.command`가 필요합니다. (뒤에 service와 account를 적는다) |
| 도구 결과: 허용 목록의 이름과 겹침 (2.2절 4번) | `<넘긴 이름>`은 허용 목록의 항목 `<id>`가 쓰는 이름입니다. keychain_item에 `<id>`를 넘기세요. |
| 도구 결과: `api_key`의 기본 이름을 쓸 수 없고 `stores`에 `keychain`이 있음 (2.2절 7번) | keychain_item을 직접 넘기세요. |
| 도구 결과: `api_key`에서 `keychain_item`이 허용 목록의 `id`와 같음 (2.2절 3번) | 허용 목록의 항목 `<id>`는 kind `secret`으로만 쓸 수 있습니다. |
| 도구 결과: 키체인 줄이 `saved: false`이고 `main_touched: true`, 또는 `keychain_left.main_touched`가 참 (2차 재확인 RC2-1) | 키체인 항목 `<service>`의 기존 값이 바뀌었을 수 있습니다. |
| 도구 결과, Slack 결과 메시지: 키체인 줄이 `saved: false`이고 `main_created: true` (재확인 RC-1), 또는 `keychain_left.main_created`가 참 (2차 재확인 RC2-1) | 키체인에 `<service>` 항목이 새로 만들어졌고 이번에 넣은 값이 들어 있을 수 있습니다. |
| 화면: 저장 실패 알림의 키체인 줄 아래, 완료 화면의 실패한 키체인 줄, 키체인 줄이 `saved: false`이고 `main_created: true` | 이 이름의 키체인 항목이 새로 만들어졌고, 이번에 넣은 값이 들어 있을 수 있습니다. |
| 화면: 그런 답을 받은 뒤의 취소 끝 화면 | 보낸 값을 쓰려던 키체인 항목이 새로 만들어졌고, 이번에 넣은 값이 들어 있을 수 있습니다. Slack 대화의 취소 결과 메시지를 확인하세요. |
| 화면: 저장 실패(422 `store_unavailable`, 422 `masked_value`, 또는 `result_unknown`이 참이 아닌 422 `storage_failed`) 뒤 다시 보내지 않고 시한이 지난 끝 화면의 첫 두 줄 (재확인 RC-2) | 앞서 보낸 값은 저장하지 못했고, 다시 보내지 않은 채 제출 시간이 지났습니다. / 입력 칸에 남아 있던 값은 지웠습니다. (뒤에 받은 키체인 줄에 따라 예전 값 문장, 새 항목 문장, 임시 항목 문장이 이어진다. 끝은 "Slack 대화의 결과 메시지를 확인하세요."다) |
| 화면: 저장 실패 답을 받은 뒤의 완료 화면, "시도 횟수를 넘었습니다" 끝 화면, "저장했는지 알 수 없습니다" 끝 화면 (2차 재확인 RC2-1, RC2-3) | 받은 키체인 줄에 따라 취소 끝 화면과 같은 예전 값 문장, 새 항목 문장, 임시 항목 문장을 보인다. 앞 두 문장의 끝은 "Slack 대화의 결과 메시지를 확인하세요."다. 완료 화면은 마지막 답에 키체인에 저장된 줄이 있으면 앞 두 문장을 보이지 않고, 마지막 답의 저장소 줄이 이미 말한 사실은 다시 말하지 않는다. 같은 문장은 한 화면에 한 번만 나온다. |
| 화면: 임시 항목이 남았을 수 있는 키체인 줄(`tmp_left: true` 등)을 받은 뒤의 저장 실패 알림, 취소 끝 화면, 시간 초과 끝 화면 (재확인 RC-3) | 임시 키체인 항목에 이번에 넣은 값이 남아 있을 수 있습니다. Hermes가 도는 컴퓨터에서 README의 '남은 임시 키체인 항목' 절의 명령으로 확인해 지우세요. |
| 도구 설명: 허용 목록이 비어 있음 | 허용된 기존 항목 없음 |

## 14. 실측

### 14.1 Tailscale Serve가 경로를 넘기는 방식 (2026-11-23, Tailscale 1.102.3)

- `tailscale serve --bg --https=443 --set-path /probeA http://127.0.0.1:N`에 `https://<호스트>/probeA/x/y?q=1`을 보내면 백엔드에는 `GET /x/y?q=1`이 닿았다. Serve는 `--set-path` 앞머리를 떼고 넘긴다. 대상을 `http://127.0.0.1:N/probeB`로 하면 백엔드에는 `/probeB/x/y`가 닿았다. 그래서 서버는 대상을 `http://127.0.0.1:<port>/<토큰>`으로 등록하고, 백엔드는 늘 `/<토큰>/...`을 받는다.
- Serve는 `Host`, `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto: https`와 계정 헤더 `Tailscale-User-Login`, `Tailscale-User-Name`, `Tailscale-User-Profile-Pic`, `Tailscale-Headers-Info`를 붙인다(헤더 이름은 2026-11-24 `scripts/live_identity_check.py`로 쟀다). 서버가 쓰는 것은 `Tailscale-User-Login`뿐이다.
- 요청이 끝나 경로를 지운 뒤 다른 Serve 설정이 없으면 tailscaled가 443을 듣지 않으므로 같은 주소는 연결을 거부한다. 다른 경로가 있으면 404다.
- 요청 둘이 살아 있을 때 하나의 경로를 `off`로 지워도 다른 하나는 200으로 남았다. 지워진 쪽은 404였다. `off`는 그 `--set-path`만 지운다.
- Serve를 거친 TLS는 1.3이었다.

### 14.2 2판 통합 실측 (2026-11-25)

- `scripts/real_roundtrip_v2.py`, 결과 `docs/plans/storage-targets-impl-probes/real_roundtrip_v2.json`. 진짜 서버 프로세스, 저장 프로세스, 키체인 모듈, `/usr/bin/security`로 여섯 경우를 돌렸다(Tailscale은 가짜). `api_key`를 `.env`와 키체인 새 항목에, `login`을 vault에, `secret`을 허용 목록의 이미 있는 항목과 허용 목록 밖의 새 항목에 넣은 네 경우가 `saved`였고 되읽은 값이 같았다. `.env` 쓰기가 실패하게 한 `api_key`는 `partial`이었고 키체인 값은 남아 있었다. 접근 허용 목록에 `/usr/bin/security`가 없는 항목에 보낸 `secret`은 6번 모두 422 `store_unavailable`(`keychain_acl_denied`)이었다. 6번 모두 실패로 세지 않았고, 요청은 그 뒤에도 열려 있어 취소할 수 있었다.
- `scripts/live_tailscale_v2.py`, 결과 `docs/plans/storage-targets-impl-probes/live_tailscale_v2.json`. 진짜 Tailscale Serve를 거쳐 두 저장소 `api_key` 제출이 `saved`였다. 저장을 25초 늦춘 제출의 응답도 끊기지 않고 25.96초에 왔다. `serve ... off`는 5회 모두 0.1초 미만이었다. 기준은 4초 미만이다. 취소 뒤 기다리는 시간에서 저장소 시한을 뺀 여유가 4초이기 때문이다.

## 계획서 부록 A와 다른 점

구현이 계획서 부록 A와 다른 곳은 다음 일곱 가지다. 1번부터 5번은 앞 구현 리뷰가 받아들였고, 6번은 보안 확인 3차의 지적(R3-1)으로, 7번은 그 재확인의 지적(RC-2)으로 고쳤다. 이 문서는 위의 해당 절에 구현대로 적었다.

1. **점검 실패 뒤 결과 없이 끝난 저장 프로세스.** 부록 A.9 7번은 "점검 단계에서 `done` 줄 없이 끝났으면 켠 저장소를 모두 결과 모름으로 채운다"고 정했다. 구현은 저장 프로세스가 `available: false` 점검 줄을 하나라도 낸 뒤 `done` 줄 없이 끝나면(시한으로 끝낸 경우 포함), 결과 모름으로 채우지 않고 `store_unavailable`(422, `opened`로 돌아감)로 답한다(`secure_input/storage.py`의 `save_outcome`). 저장 프로세스는 그 경우 쓰기 단계에 들어가지 않으므로 아무 데도 쓰지 않은 것이 확실하기 때문이다(6.3절).
2. **저장 중 두 번째 제출의 로그 줄.** 부록 A.2는 저장 중 두 번째 제출을 409 `saving_in_progress`로 거절한다고만 정했다. 구현은 그 거절마다 로그에 `failed` 줄(`error_code` `saving_in_progress`, `final` false)을 쓴다(`server.py`의 `saving_refusal`). 값은 들어가지 않는다. 저장 중 화면 취소의 거절은 로그 줄을 쓰지 않는다(6.2절, 12절).
3. **끝난 요청의 결과 보고를 한 잠금으로 묶음.** 부록 A에는 없는 장치다. 구현은 끝난 요청의 결과 보고를 `server.py`의 `_end_lock`(RLock)과 `report_end()`로 한 줄로 세운다. 저장이 막 끝난 순간의 새로 고침이나 두 번째 제출이, 일부만 저장된 요청을 저장소 줄 없이 "모두 저장됨"처럼 먼저 보고하지 않게 하기 위해서다(6.2절 "결과를 반영하는 곳").
4. **SIGINT.** 부록 A.2는 SIGTERM의 처리만 정했다. 구현에서 SIGINT는 파이썬 기본 동작(KeyboardInterrupt)으로 서버 실행을 끝내고, `main()`이 그것을 잡아 정리한 뒤 `done` 줄을 낸다(6.2절).
5. **키체인 `save()`가 쓰는 기본 키체인 경로.** 부록 A.11은 `save()`가 점검 1번부터 4번을 다시 하지 않는다고만 정했다. 그런데 쓰기 순서 (나)에는 점검 2번이 얻는 기본 키체인 경로가 필요하다. 구현의 `save()`는 같은 프로세스에서 같은 `security_path`로 먼저 돈 `preflight()`가 모듈 안에 기억해 둔 경로를 쓴다. 기억된 경로가 없으면 쓰지 않고 `keychain_unavailable`로 끝난다(9.3절).
6. **저장하는 동안 제출 시한이 지나고 하나도 저장하지 못한 요청의 끝 사유.** 부록 A.2는 이때 보류된 끝 사유를 쓰고, 없으면 `expired`(detail `submit_window_passed`)를 쓴다고 정했다. 구현은 보류된 사유가 취소(`parent_gone`, `terminated`)일 때만 그 사유를 쓴다. 보류된 사유가 없거나 제출 시한이면 `expired`(detail `window_passed_while_saving`)로 끝낸다(`lifecycle.py`의 `end_saving`, 6.3절). 사용자는 시한 안에 제출했으므로 "연 뒤 5분 안에 제출하지 않았다"는 문장이 사실과 다르기 때문이다(보안 확인 3차 R3-1). 화면이 받는 답은 그대로 410 `deadline_passed`다.
7. **저장이 실패해 `opened`로 돌아간 뒤 제출 시한이 지난 요청의 끝 사유.** 부록 A.2는 `opened`에서 제출 시한이 지나면 `expired`(detail `submit_window_passed`)로 끝낸다고만 정했다. 구현은 보낸 값을 저장하지 못한 적이 있으면(저장이 실패해 `opened`로 돌아감, 또는 서버가 저장 전에 `masked_value`나 프로필 오류 `storage_failed`로 거절함) `expired`(detail `window_passed_after_failed_save`)로 끝낸다(`lifecycle.py`의 `tick`, `check_submit`, `note_failed_save`, 6.3절). 사용자는 값을 한 번 보냈으므로 "연 뒤 5분 안에 제출하지 않았다"는 문장이 사실과 다르기 때문이다(재확인 RC-2). 화면이 받는 답은 그대로 410 `deadline_passed`다.
