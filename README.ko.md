# hermes-secure-input

[English README](README.md)

`secure-input`은 Hermes에 자격증명을 넣을 때 값이 Slack을 거치지 않게 하는 Hermes 플러그인이다.
Hermes(Hermes Agent)는 Slack 같은 채팅에서 AI 에이전트를 돌리는 프로그램이다.
플러그인은 Hermes에 도구와 명령을 더하는 추가 기능 묶음이다.
자격증명은 API 키, 사이트 로그인 정보(아이디와 비밀번호), 이 Mac의 스크립트가 키체인에서 읽는 비밀번호, 로그인 도중 사이트가 요구하는 일회용 코드를 말한다.

이 플러그인이 하는 일은 이렇다.

- Slack 대화에는 "입력 페이지 열기" 링크 버튼이 달린 메시지만 간다.
- 링크는 Hermes가 도는 컴퓨터가 그 요청 하나를 위해 잠깐 띄운 입력 페이지를 연다.
- 사용자는 그 페이지에 값을 넣는다. 값은 브라우저에서 암호화된 채 Hermes가 도는 컴퓨터로 바로 간다.
- Hermes가 도는 컴퓨터가 값을 받아 사용자가 고른 저장 위치에 저장한다. Slack 메시지는 "저장 완료" 같은 결과 문장으로 바뀐다.

## 왜 Slack을 거치지 않는가

채팅 메시지에 적은 값은 Slack 서버를 지나간다.
Slack은 기본 설정에서 메시지를 워크스페이스가 있는 동안 계속 보관한다([Slack 도움말](https://slack.com/help/articles/115005393586-Edit-message-retention-settings-for-specific-conversations): "By default, Slack will retain all messages for the lifetime of your workspace").
Slack 모달(Slack 앱이 띄우는 입력 창)에 넣은 값도 Slack 서버를 지나간다.
Slack 공식 문서도 모달에서 비밀번호 같은 정보를 받지 말라고 한다([Slack Modals 문서](https://docs.slack.dev/surfaces/modals/)의 "Don't prompt for login information").
Hermes 본체에도 로그인 일회용 코드를 받는 Slack 버튼이 있다. 그 버튼이 여는 입력 창이 Slack 모달이다.
그래서 이 플러그인은 값을 Slack이 아닌 별도 페이지로 받는다.

## 넣을 수 있는 것과 저장되는 곳

먼저 용어 두 가지를 푼다.

- 프로필: Hermes 안의 독립된 작업 공간이다. 프로필마다 설정, `.env`, vault가 따로 있다. `default` 프로필의 폴더는 `~/.hermes`이고, 다른 프로필의 폴더는 `~/.hermes/profiles/<프로필 이름>`이다.
- 저장 위치: 값을 넣는 곳이다. 아래 세 곳이 있다. 괄호 안은 입력 페이지가 쓰는 이름이다.
  - `.env`("설정 파일(.env)"): 프로필 폴더에 있는 환경 변수 파일이다. Hermes는 API 키를 이 파일에서 읽는다. 값은 암호화되지 않는다.
  - vault("Hermes 암호화 저장소(vault)"): 프로필마다 있는 Hermes의 암호화 저장소다. Hermes는 여기에 저장한 로그인 정보로 브라우저의 로그인 화면을 자동으로 채운다.
  - Mac 키체인("Mac 키체인"): macOS가 비밀번호를 보관하는 곳이다. 플러그인은 이 Mac 사용자의 기본 키체인에 macOS의 `/usr/bin/security` 명령으로 쓴다. Mac 키체인은 프로필과 상관없이 쓰인다. 값이 들어가는 곳은 이 Mac에서 Hermes를 돌리는 사용자 계정의 로그인 키체인이다.

| 넣는 것 | 고를 수 있는 저장 위치 | 처음에 켜져 있는 저장 위치 |
|---|---|---|
| API 키 | `.env`, Mac 키체인. 둘 다 켜도 된다. | `.env` |
| 사이트 로그인(아이디 종류, 아이디, 비밀번호, 선택으로 인증 앱 설정 키) | vault만 | vault |
| 키체인 비밀번호(이 Mac의 스크립트가 키체인에서 읽는 비밀번호) | Mac 키체인만 | Mac 키체인 |
| 로그인 도중의 일회용 코드 | 없음. 어디에도 저장되지 않는다. | 없음 |

저장 위치마다 저장되는 모양은 이렇다.

- `.env`: 저장할 프로필의 `.env`에 `변수이름=값` 꼴의 한 줄로 저장된다. 같은 변수의 줄이 이미 있으면 그 줄이 바뀐다. 다른 변수의 줄은 바뀌지 않는다. 저장이 실패하면 파일은 저장 전 그대로다.
- vault: 저장할 프로필의 vault에 그 사이트 주소의 로그인 항목으로 저장된다. 같은 사이트 주소에 같은 아이디로 저장해 둔 항목이 있으면, 새 항목을 저장한 뒤 예전 항목을 지운다. 예전 항목의 인증 앱 설정 키도 함께 지워진다. 다른 아이디로 저장한 항목은 그대로 남는다.
- Mac 키체인: 키체인 항목 하나에 저장된다. 키체인 항목은 service와 account라는 두 이름으로 찾는다. 이름이 정해지는 방법은 아래 "키체인 항목의 이름"에 있다. 같은 이름의 항목이 이미 있으면 그 값을 바꾸고, 예전 값은 되돌릴 수 없다.
- 일회용 코드: Hermes가 지금 진행 중인 로그인 화면의 코드 칸에 한 번 입력하고 버린다.

API 키와 키체인 비밀번호에는 영문 키보드로 칠 수 있는 글자(ASCII의 영문, 숫자, 기호, 공백)만 넣을 수 있다. Mac 키체인에 넣는 값(키체인 비밀번호, 그리고 Mac 키체인을 켠 API 키)은 1,024자 이하여야 하고, 맨 앞과 맨 뒤에 공백을 둘 수 없다.

vault를 미리 만들거나 잠금을 풀어 둘 필요는 없다. 그 프로필에 vault가 아직 없으면 첫 로그인을 저장할 때 Hermes가 vault 파일과 그 열쇠를 만든다.

아이디 종류는 입력 페이지에서 "이메일", "사용자 이름", "전화번호" 버튼 중 하나를 눌러 고른다.
고른 종류에 따라 입력 페이지의 아이디 칸 이름과 예시가 바뀌고, 종류는 vault 항목에 함께 저장된다. Hermes가 로그인 화면을 채우는 방식은 종류와 관계없이 같다.
인증 앱은 시간마다 바뀌는 로그인 코드를 만드는 휴대폰 앱이다. 이런 방식의 코드를 TOTP라고 부른다.
인증 앱 설정 키는 사이트가 인증 앱에 계정을 등록할 때 보여 주는 영문 키다.
설정 키를 함께 저장하면, 나중에 그 사이트가 로그인 도중 코드를 물을 때 Hermes가 키로 코드를 직접 만들어 넣는다. 이때는 입력 페이지가 열리지 않는다.

### 키체인 비밀번호

키체인 비밀번호 요청은 이 Mac의 스크립트가 `security` 명령으로 Mac 키체인에서 읽는 비밀번호를 받을 때 쓴다. 예를 들어 백업 스크립트가 읽는 비밀번호다.
값은 Mac 키체인에만 저장된다.
입력 페이지에서 같은 비밀번호를 두 칸에 한 번씩 넣는다. 두 칸이 같아야 보낼 수 있다.
값의 규칙은 위의 Mac 키체인 규칙과 같다.
Slack 메시지와 입력 페이지에서 이 요청의 종류는 "비밀번호"로 나온다.
입력 페이지에서 프로필은 고르지 않는다. Slack 메시지에 나오는 "로그를 남길 프로필"은 기록(아래 "기록")을 남길 프로필이고, 에이전트가 도구 인자 `target_profile`로 정하지 않으면 요청이 나온 대화의 프로필이다.

### 키체인 항목의 이름

에이전트나 명령은 키체인 항목의 이름 하나(`keychain_item`)만 넘긴다. 플러그인이 그 이름으로 실제 항목을 정한다.

- 키체인 허용 목록에 있는 이름: 허용 목록은 사용자가 설정 `keychain_items`에 적어 둔 기존 키체인 항목의 목록이다(아래 "기존 키체인 항목을 쓰게 하기"). 넘긴 이름이 목록 항목의 `id`와 같으면 그 항목에 적힌 service와 account의 기존 키체인 항목에 쓴다. 허용 목록 항목은 키체인 비밀번호 요청에서만 쓸 수 있다.
- 허용 목록에 없는 이름: 이 플러그인 전용 항목이 된다. service는 `hermes-secure-input.<이름>`, account는 `hermes-secure-input`이다. 이름은 영문 소문자, 숫자, `-`로 된 1자부터 40자까지이고, 첫 글자는 영문 소문자나 숫자다.
- 이 플러그인 전용 항목이 아직 없으면 입력 페이지에 "새 항목입니다. 값을 쓸 프로그램이 이 항목 이름과 키체인 계정 이름으로 읽게 되어 있는지는 값을 보낸 뒤 그 프로그램의 설정에서 직접 확인하세요."가 나온다. 에이전트가 받는 결과에는 다른 안내가 붙는다. 그 안내는 이 항목을 읽는 프로그램이 아직 없고, 확인은 사용자가 그 프로그램의 설정에서 해야 하며, 에이전트는 사용자에게 항목 이름과 키체인 계정 이름을 알려 주고 키체인 항목의 값은 읽지 말라고 말한다. 새 항목을 읽게 스크립트를 고치는 일은 사용자가 한다.
- API 키를 Mac 키체인에 저장할 때 에이전트가 이름을 넘기지 않으면(`!secure-input key` 명령은 넘기지 않는다), 변수 이름을 소문자로 바꾸고 `_`를 `-`로 바꾼 이름을 쓴다. 예를 들어 `EXA_API_KEY`는 service `hermes-secure-input.exa-api-key`에 저장된다.

### 저장 위치가 미리 켜지는 방식

입력 페이지의 "저장 위치" 목록에는 그 종류가 쓸 수 있는 저장 위치가 한 줄씩 나온다.

- 에이전트는 요청할 때 켤 저장 위치와 그 이유를 정할 수 있다. 에이전트가 정한 저장 위치는 미리 켜져 있고, 이유는 "AI 모델이 이 저장 위치에 적은 이유" 아래에 따옴표로 묶인 인용으로 보인다. Slack 메시지에도 `Hermes가 적은 이유(Mac 키체인): "..."` 같은 줄로 나온다. 이유 안의 큰따옴표(`"`)는 작은따옴표(`'`)로 바뀌어 나온다. 그래서 이유 글이 따옴표를 닫고 플러그인이 한 말처럼 이어 쓸 수 없다.
- Slack 메시지에서 제목만 굵은 글씨다. 이유, 목적 문구, 이름표, 허용 목록의 `label`과 `used_by`는 서식 없는 글(Block Kit `plain_text`)로 간다. 그래서 그 글에 `*굵게*`, `_기울임_`, `~취소선~`, `` `코드` ``, `:smile:` 같은 이모지 이름, 주소, `<!channel>` 같은 멘션을 적어도, Slack 문서의 설명대로라면 Slack은 그 글을 서식, 이모지 그림, 링크, 멘션으로 바꾸지 않고 적힌 글자 그대로 보인다. 결과 메시지(이름표가 들어간다)도 같다. 다만 Slack이 아닌 대화(CLI, Desktop, 다른 메신저)의 글 메시지와, Slack 버튼 메시지를 보내지 못해 대신 보내는 글 메시지는 Hermes 게이트웨이가 보이는 모양을 정한다. 이 플러그인은 그 글 메시지의 서식을 막지 못하므로, 그곳에서는 이 글이 서식이나 링크로 보일 수 있다.
- 에이전트가 정하지 않으면 위 표의 "처음에 켜져 있는 저장 위치"가 켜진다.
- API 키는 에이전트가 정했든 정하지 않았든, 어느 프로필에서든 그 변수 이름으로 저장에 성공한 적이 있는 저장 위치도 켜진다(그 값을 지운 뒤에도 켜진다. 아래 "사본 기록 파일").
- 저장 위치가 두 곳인 API 키는 사용자가 줄마다 켜고 끈다. 저장 위치가 한 곳뿐인 사이트 로그인과 키체인 비밀번호는 끌 수 없다. 한 곳 이상 켜야 보낼 수 있다.
- API 키의 `.env`를 끄면 "Hermes는 이 키를 `.env`에서 읽습니다. 끄면 Hermes는 이번에 넣는 키를 쓰지 못하고, `.env`에 이미 값이 있으면 그 값은 바뀌지 않습니다."라는 경고가 나온다.
- 경고가 나와도 그대로 보낼 수 있다. 에이전트는 저장 위치를 켜거나 끄지 못하게 잠글 수 없다.

### 여러 저장 위치에 저장할 때

켠 저장 위치마다 같은 값을 `.env`, vault, Mac 키체인 순서로 쓴다.

- 플러그인은 쓰기 전에 켠 저장 위치를 모두 점검한다. 하나라도 쓸 수 없으면 아무 데도 쓰지 않는다. 페이지에는 "아무 데도 저장하지 않았습니다"와 쓸 수 없는 저장 위치, 그 이유가 나온다. 이 경우는 실패 횟수에 세지 않고, 입력한 값은 페이지에 그대로 있다. 원인을 고치거나, API 키라면 그 저장 위치를 끈 뒤 같은 페이지에서 다시 보낸다.
- 쓰는 도중에 한 곳이 실패해도 이미 저장된 곳은 되돌리지 않는다. 페이지 제목은 "일부만 저장했습니다"이고, 저장 위치마다 저장했는지가 나온다. 저장하지 못한 곳에 넣으려면 새 링크를 요청하고, 그 링크의 페이지에서 저장하지 못한 저장 위치를 켜고 보낸다(이미 저장된 곳이 함께 켜져 있으면 그곳에도 이번에 넣은 값을 다시 쓴다).
- 켠 저장 위치에 하나도 저장하지 못했으면 실패 1회로 세고, 같은 페이지에서 다시 보낼 수 있다.

## 필요한 것

- Hermes Agent: v0.23.3에서 만들고 시험했다. 그보다 오래된 버전은 확인하지 않았다. 더 오래된 버전이면 먼저 Hermes를 v0.23.3 이상으로 올린다(`hermes update`, [Hermes 업데이트 문서](https://hermes-agent.nousresearch.com/docs/getting-started/updating)). 설치된 버전은 `hermes --version`으로 본다. 첫 줄이 `Hermes Agent v0.23.3 (2026.9.24) · ...`처럼 나온다. 플러그인이 쓰는 Python 패키지(웹 서버와 암호화 라이브러리)는 Hermes 설치에 이미 들어 있어서 따로 설치할 것이 없다.
- 운영체제: Hermes가 도는 컴퓨터는 macOS에서만 시험했다. 다른 운영체제는 확인하지 않았다. Mac 키체인 저장 위치는 macOS에서만 쓸 수 있다.
- Tailscale: 여러 기기를 하나의 사설 네트워크로 묶어 주는 서비스다. 이 사설 네트워크를 tailnet이라고 부른다. 설치하고 기기를 tailnet에 넣는 방법은 [Tailscale quickstart](https://tailscale.com/docs/how-to/quickstart)를 따른다. 아래를 모두 갖춰야 한다.
  - Hermes가 도는 컴퓨터에 Tailscale이 설치되어 있고 로그인되어 있다.
  - 값을 입력할 기기(휴대폰이나 PC)도 같은 tailnet에 들어 있고 Tailscale이 켜져 있다. 입력은 그 기기의 브라우저에서 한다.
  - 값을 입력할 기기의 Tailscale은 Hermes 컴퓨터의 Tailscale과 같은 계정으로 로그인되어 있다. 다른 계정을 허용하는 방법은 아래 "링크를 열 수 있는 Tailscale 계정"에 있다.
  - Slack을 보는 기기가 tailnet에 없으면 그 기기에서는 입력 페이지가 열리지 않는다. 이때는 같은 계정으로 tailnet에 든 다른 기기에서 같은 Slack 메시지의 버튼을 누른다. 링크를 만든 뒤 60초 안이면 된다. 열리지 않은 시도는 링크를 쓴 것으로 치지 않는다.
  - tailnet 관리 화면에서 MagicDNS(tailnet 기기에 이름 주소를 붙이는 기능)와 HTTPS 인증서 사용이 켜져 있다. 둘 다 관리 화면의 [DNS 페이지](https://console.tailscale.com/admin/dns)에서 켠다. MagicDNS는 그 페이지의 MagicDNS 항목에서 켠다([MagicDNS 문서](https://tailscale.com/docs/features/magicdns)). HTTPS 인증서는 그 페이지의 "HTTPS Certificates" 아래 "Enable HTTPS"로 켠다([Enabling HTTPS 문서](https://tailscale.com/docs/how-to/set-up-https-certificates)). HTTPS를 켜면 인증서를 받은 기기의 이름이 공개 인증서 기록에 올라간다는 안내가 나온다. 이 플러그인은 HTTPS 인증서 없이는 동작하지 않는다. 기기 이름이 공개 기록에 올라가는 것을 받아들일 수 없으면 이 플러그인을 쓸 수 없다.
  - Tailscale Serve를 쓸 수 있다. Tailscale Serve는 이 컴퓨터 안의 웹 서버를 같은 tailnet의 기기에만 HTTPS 주소로 열어 주는 기능이다. Serve는 tailnet에서 HTTPS 인증서 사용을 켜야 동작한다([Tailscale Serve 문서](https://tailscale.com/docs/features/tailscale-serve)).
  - 플러그인은 Tailscale 명령줄 도구를 이 순서로 찾는다. 환경 변수 `SECURE_INPUT_TAILSCALE_BIN`에 값이 있으면 그 경로에 파일이 없어도 그 값을 쓴다. 없으면 `/Applications/Tailscale.app/Contents/MacOS/Tailscale`을 쓰고, 그것도 없으면 `PATH`의 `tailscale`을 쓴다. macOS 앱으로 설치했다면 위의 앱 경로가 명령줄 도구이므로 따로 설정할 것이 없다. 이때는 `which tailscale`이 아무것도 내지 않아도 된다.
  - `SECURE_INPUT_TAILSCALE_BIN`은 게이트웨이를 띄운 프로필의 `.env`에 `SECURE_INPUT_TAILSCALE_BIN=<경로>` 한 줄로 적는다. 기본 구성에서는 `default` 프로필이 게이트웨이를 띄우므로 `~/.hermes/.env`에 적는다. Hermes는 시작할 때 그 `.env`를 프로세스 환경 변수로 읽으므로, 적은 뒤 게이트웨이를 다시 시작한다(`hermes gateway restart`).
- Slack: Hermes 게이트웨이가 Slack에 연결되어 있어야 Slack에서 쓸 수 있다. 게이트웨이는 Slack 같은 메신저의 대화와 CLI 대화를 처리하는 Hermes 프로세스다.
  - `hermes gateway status`는 게이트웨이가 도는지만 보여 주고 Slack 연결은 보여 주지 않는다. Slack 연결은 Hermes 컴퓨터에서 `grep -E "slack (connected|failed to connect)" ~/.hermes/logs/gateway.log | tail -1`로 본다. 나온 줄에 `✓ slack connected`가 있으면 연결된 것이고, `✗ slack failed to connect`가 있으면 연결하지 못한 것이다. 아무 줄도 나오지 않으면 `hermes gateway restart`로 게이트웨이를 다시 시작한 뒤 같은 명령을 다시 실행한다. 게이트웨이는 시작할 때 Slack이 켜져 있으면 연결을 시도하고 두 줄 중 하나를 이 파일에 쓴다. 그래도 아무 줄도 나오지 않으면 이 게이트웨이에는 Slack이 켜져 있지 않다.
  - 연결되어 있지 않거나 Slack이 켜져 있지 않으면 [Hermes Slack 설정 문서](https://hermes-agent.nousresearch.com/docs/user-guide/messaging/slack)를 따른다.
- 입력 페이지 화면은 git 저장소에 빌드된 상태(`secure_input/static/`)로 들어 있다. 쓰기만 할 때는 Node.js가 필요 없다.

Tailscale 준비 상태는 설치 전에 Hermes 컴퓨터에서 아래 두 명령으로 확인한다. 두 명령은 설정을 바꾸지 않는다. macOS 앱으로 설치해 `tailscale` 명령이 없으면 `tailscale` 대신 `/Applications/Tailscale.app/Contents/MacOS/Tailscale`을 쓴다. 이 README의 다른 `tailscale` 명령에도 같은 규칙이 적용된다.

```bash
tailscale status --json | grep -E '"BackendState"|"MagicDNSEnabled"|"CertDomains"|ts\.net"$'
tailscale serve status
```

정상이면 첫 명령은 아래와 같은 줄을 보여 준다. 기기 이름과 tailnet 이름은 설치마다 다르다.

```text
  "BackendState": "Running",
    "MagicDNSEnabled": true
  "CertDomains": [
    "my-mac.tail1234.ts.net"
```

- `"BackendState": "Running"`은 이 컴퓨터가 Tailscale에 로그인되어 연결되어 있다는 뜻이다.
- `"MagicDNSEnabled": true`는 MagicDNS가 켜져 있다는 뜻이다.
- `"CertDomains"` 다음 줄의 이름은 이 컴퓨터가 HTTPS 인증서를 받을 수 있는 이름 주소다. 이 이름이 나오면 HTTPS 인증서 사용이 켜져 있다. 입력 페이지 주소는 `https://<이 이름>/`으로 시작한다. `"CertDomains": null`처럼 이름이 나오지 않으면 HTTPS 인증서 사용이 꺼져 있으므로 위의 DNS 페이지에서 켠다.
- `tailscale serve status`는 지금 Serve에 열린 주소를 보여 준다. 다른 Serve 설정이 없으면 "No serve config"가 나온다. 이 명령이 오류 없이 끝나면 이 컴퓨터에서 Serve 명령을 쓸 수 있다. 오류가 나면 터미널에 나온 오류 문장을 [Tailscale Serve 문서](https://tailscale.com/docs/features/tailscale-serve)에서 찾아 고친 뒤 이 명령을 다시 실행한다.

## 설치, 켜기, 끄기, 지우기

아래 명령은 Hermes가 도는 컴퓨터에서 실행한다.

### 설치하고 켜기

git 저장소를 내려받는다.

```bash
git clone https://github.com/junhoolee/hermes-secure-input.git ~/hermes-secure-input
```

Hermes의 사용자 플러그인 폴더에 내려받은 폴더를 가리키는 링크를 만든다. 링크 이름은 `secure-input`이어야 한다.

```bash
mkdir -p ~/.hermes/plugins
ln -s ~/hermes-secure-input ~/.hermes/plugins/secure-input
```

플러그인을 켠다. Hermes는 사용자 플러그인을 켜기 전에는 불러오지 않는다.

```bash
hermes plugins enable secure-input
```

제대로 들어갔는지 확인한다.

```bash
hermes plugins list --user
hermes plugins doctor secure-input
hermes tools list --platform slack
```

- `hermes plugins list --user`에서 `secure-input`이 `enabled`로 보여야 한다.
- `hermes plugins doctor secure-input`은 "OK: runtime discovery, manifest parsing, import, and registration passed"를 출력해야 한다.
- `hermes tools list --platform slack`에서 `secure_input`이 `enabled`로 보여야 한다. 이것은 Slack 대화의 에이전트가 이 플러그인의 도구를 쓸 수 있다는 뜻이다.
- 결과가 다르면 아래 "문제 해결"의 첫 줄을 본다.

마지막으로 게이트웨이를 다시 시작한다. 게이트웨이는 시작할 때 한 번만 플러그인을 찾는다. 그래서 다시 시작해야 Slack 대화에서 도구와 명령이 보인다.

```bash
hermes gateway restart
```

CLI 대화만 쓸 때도 이 명령으로 게이트웨이를 다시 시작한다.
아래에서 게이트웨이를 다시 시작하라고 한 곳도 CLI 대화에 똑같이 적용된다.

### Slack에서 도구가 꺼져 있을 때

`hermes tools list --platform slack`에서 `secure_input`이 꺼져 있으면 켠 뒤 게이트웨이를 다시 시작한다.
예전에 Slack에서 이 도구를 한 번 끈 적이 있으면 꺼져 있을 수 있다.

```bash
hermes tools enable secure_input --platform slack
hermes gateway restart
```

### 다른 프로필에서도 쓰기

플러그인 폴더와 켜기 설정은 프로필마다 따로 있다.
`default`가 아닌 프로필(예: `worker`)에서도 쓰려면 그 프로필 폴더에도 링크를 만들고 그 프로필에서 켠다.

```bash
mkdir -p ~/.hermes/profiles/worker/plugins
ln -s ~/hermes-secure-input ~/.hermes/profiles/worker/plugins/secure-input
hermes -p worker plugins enable secure-input
hermes gateway restart
```

다른 프로필을 다룰 때의 규칙은 세 가지다. 이 README의 설치, 확인, 끄기, 지우기, 설정 명령에 모두 같은 규칙이 적용된다.

- 링크 경로: `default`의 링크는 `~/.hermes/plugins/secure-input`이다. 다른 프로필의 링크는 `~/.hermes/profiles/<프로필>/plugins/secure-input`이다. `mkdir`, `ln -s`, `rm`에 적는 경로를 이렇게 바꾼다.
- `-p <프로필>`: `hermes plugins ...`, `hermes tools ...`, `hermes config ...`, `hermes vault ...` 명령은 `hermes` 바로 뒤에 `-p <프로필>`을 붙이면 그 프로필에 적용된다. 예를 들어 `hermes -p worker plugins list --user`, `hermes -p worker tools list --platform slack`처럼 쓴다. `-p`를 붙이지 않으면 기본 프로필에 적용된다. 기본 프로필은 `hermes profile use`로 바꾸지 않았다면 `default`이고, 바꿔 두었다면 위 "설치하고 켜기"의 `hermes` 명령에도 `-p default`를 붙인다.
- 게이트웨이 재시작: 프로필마다 하지 않고 한 번만 한다. Hermes는 기본 구성에서 `default` 프로필이 띄운 게이트웨이 하나가 모든 프로필의 대화를 처리한다. 그래서 기본 구성에서는 어느 프로필을 바꾸었든 `hermes gateway restart`를 한 번 실행한다. 이 명령은 모든 프로필의 메신저 연결을 다시 맺는다. `hermes profile use`로 기본 프로필을 바꿔 두었다면 `hermes -p default gateway restart`로 실행한다.

어떤 프로필이 공유 게이트웨이로 도는지는 `hermes -p <프로필> gateway status`로 본다.
첫 줄이 "✓ Gateway is running via the default-profile multiplexer"이면 그 프로필은 `default`의 게이트웨이를 함께 쓴다.
첫 줄이 "✗ Gateway is not running"이면 지금 그 프로필의 대화를 처리하는 게이트웨이가 없으므로, `hermes -p default gateway status`로 `default`의 게이트웨이가 도는지부터 본다.
그 밖의 첫 줄이면 그 프로필은 자기 게이트웨이를 따로 띄운 것이므로, 그 프로필을 바꾼 뒤에는 `hermes gateway restart` 대신 `hermes -p <프로필> gateway restart`로 그 게이트웨이를 다시 시작한다.

플러그인 설정(아래 "Hermes 본체의 입력 방식 가로채기"의 두 설정, `keychain_items`, `allowed_tailscale_logins`)은 프로필마다 따로 있다. 플러그인은 요청이 나온 대화의 프로필 설정을 읽는다. 값을 저장할 프로필의 설정은 읽지 않는다.

### 기존 키체인 항목을 쓰게 하기(`keychain_items`)

이 Mac의 스크립트가 이미 읽고 있는 키체인 항목에 키체인 비밀번호 요청으로 새 값을 넣으려면, 그 항목을 허용 목록 `keychain_items`에 적는다.
플러그인은 허용 목록에 적지 않은 키체인 항목에는 쓰지 않는다. 예외는 이 플러그인 전용 항목(service가 `hermes-secure-input.`로 시작)이다.

허용 목록의 항목마다 다섯 칸을 모두 적는다.

- `id`: 에이전트와 명령이 넘기는 이름이다. 영문 소문자, 숫자, `-`로 된 1자부터 40자까지이고, 첫 글자는 영문 소문자나 숫자다.
- `service`, `account`: 기존 키체인 항목의 두 이름이다. 영문, 숫자, `.`, `_`, `@`, `-`로 된 128자 이하이고, 첫 글자는 영문이나 숫자다.
- `label`: 그 값이 무엇인지 적는 한 줄(120자 이하)이다.
- `used_by`: 그 값을 읽는 프로그램을 적는 한 줄(120자 이하)이다.

아래는 지어낸 예다. 목록 전체를 한 번에 적는다.

```bash
hermes config set plugins.entries.secure-input.settings.keychain_items '[{"id": "nightly-backup", "service": "backup-script", "account": "backup", "label": "백업 스크립트 비밀번호", "used_by": "매일 밤 도는 백업 스크립트"}]'
hermes gateway restart
```

- 에이전트는 도구 설명에서 허용 목록의 `id`, `label`, `used_by`를 본다. service와 account는 도구 설명에 나오지 않는다.
- 요청을 만들면 Slack 메시지와 에이전트가 받는 결과에 그 항목의 service가 나온다. account는 나오지 않고 입력 페이지에만 보인다. 이 컴퓨터의 감사 로그에는 account도 남는다(아래 "기록").
- 에이전트가 `keychain_item`에 허용 목록 항목의 `id`가 아니라 그 항목의 service나 account와 같은 이름(대소문자는 가리지 않는다)을 넘기면, 도구는 요청을 만들지 않는다. 대신 그 이름이 어느 허용 목록 항목(`id`)이 쓰는 이름인지 답한다. 도구가 account를 새로 알려 주지는 않는다. 다만 에이전트는 이 답으로, 짐작한 이름이 어떤 항목의 account와 같은지를 사용자 모르게 확인할 수 있다.
- 규칙에 맞지 않는 항목은 목록에서 빠진다. 다섯 칸 가운데 빠진 칸이 있거나 다른 칸이 더 있는 항목, 칸의 글자가 위 규칙에 맞지 않는 항목, service가 `hermes-secure-input.`로 시작하는 항목, 앞 항목과 `id`가 같은 항목이 빠진다.
- 규칙에 맞는 항목 가운데 앞의 20개만 쓴다. 넘는 항목은 빠지고 경고가 로그에 남는다. 허용 목록은 에이전트가 모델을 부를 때마다 도구 설명에 실리므로, 20개면 도구 설명이 최대 약 6,000자 늘어난다.
- 빠진 항목마다 Hermes 로그에 `secure-input: keychain_items item <번호> left out (field <칸 이름>)` 경고가 한 줄 남는다. 개수를 넘어 빠진 항목들은 경고 한 줄만 남긴다. 그 줄의 번호는 처음으로 빠진 항목의 번호이고 칸 이름은 `limit`이다. 경고에는 칸의 글자를 적지 않는다.
- 목록에서 빠진 항목의 `id`를 넘기면 플러그인은 그 이름을 허용 목록 밖의 이름으로 다룬다. 그래서 기존 항목이 아니라 이 플러그인 전용 항목(service `hermes-secure-input.<id>`)에 쓴다. 그 항목이 아직 없으면 페이지에 "새 항목입니다. 값을 쓸 프로그램이 이 항목 이름과 키체인 계정 이름으로 읽게 되어 있는지는 값을 보낸 뒤 그 프로그램의 설정에서 직접 확인하세요."가 나온다. 기존 항목에 쓰려던 요청에서 이 문장이 나오면 보내지 말고 허용 목록을 다시 확인한다.

플러그인은 이미 있는 키체인 항목(허용 목록의 항목이든 이 플러그인 전용 항목이든)의 접근 허용 목록에 `/usr/bin/security`가 있을 때만 그 항목에 쓴다. 접근 허용 목록은 키체인이 항목마다 정해 두는, 그 항목을 읽을 수 있는 프로그램의 목록이다.
이 조건은 내려받은 폴더에서 아래 명령으로 플러그인과 같은 점검을 돌려 확인한다. `backup-script`와 `backup` 자리에 그 항목의 service와 account를 넣는다. 이 점검은 값을 읽지 않고 아무것도 쓰지 않는다.

```bash
cd ~/hermes-secure-input
python3 -c 'from secure_input.stores import keychain; print(keychain.preflight({"service": "backup-script", "account": "backup"}))'
```

- `{'available': True, 'reason': None, 'exists': True}`: 항목이 있고 플러그인이 쓸 수 있다.
- `{'available': False, 'reason': 'keychain_acl_denied', 'exists': True}`: 항목은 있지만 접근 허용 목록에 `/usr/bin/security`가 없다. 플러그인은 이 항목에 쓰지 않는다. 키체인 접근 앱에서 접근 설정이 "모든 프로그램 허용"인 항목도 이 결과가 나온다. 점검은 목록에 `/usr/bin/security`가 글자로 있어야 통과하기 때문이다. Slack 결과와 에이전트가 받는 결과에는 `keychain_acl_denied: 접근 허용 목록에 /usr/bin/security 없음`으로 나온다. 어느 경우든 `keychain_items`에 없는 새 이름으로 이 플러그인 전용 항목을 만들어 저장하고, 스크립트가 그 항목을 읽게 고친다.
- `{'available': True, 'reason': None, 'exists': False}`: 그 이름의 항목이 없다. 허용 목록의 항목이면 이대로 저장할 때 그 이름으로 새 항목을 만든다. 이때 입력 페이지는 키체인 줄에 "허용 목록에 적힌 이름의 항목이 키체인에 아직 없습니다. 보내면 이 이름으로 새 항목을 만듭니다. 보내기 전에, 허용 목록에 적은 키체인 항목 이름과 키체인 계정 이름이 맞는지 확인하세요."라는 안내를 보인다. service와 account를 잘못 적지 않았는지 본다.
- `python3`가 없다고 나오면 Hermes가 쓰는 Python으로 바꿔 실행한다. 기본 설치에서는 `~/.hermes/hermes-agent/.venv/bin/python`이다. 이 점검은 Python 표준 기능만 쓰므로 Python 3이면 어느 것이든 된다.

### 끄기

플러그인을 끄고 게이트웨이를 다시 시작한다. 파일은 그대로 남는다.

```bash
hermes plugins disable secure-input
hermes gateway restart
```

### 지우기

먼저 끈 다음 링크를 지운다. `rm`에 적는 경로는 링크이므로 내려받은 폴더는 지워지지 않는다.
`hermes plugins remove secure-input`은 이 설치 방식에서는 쓰지 않는다. 이 명령은 링크가 플러그인 폴더 바깥을 가리킨다는 "Error: Plugin 'secure-input' is a link to ..., outside the plugins directory" 오류를 내고 아무것도 지우지 않는다. 그래서 `rm`으로 링크를 지운다.

```bash
hermes plugins disable secure-input
rm ~/.hermes/plugins/secure-input
hermes gateway restart
```

내려받은 폴더까지 지우려면 아래를 실행한다.

```bash
rm -rf ~/hermes-secure-input
```

플러그인을 지워도 이미 저장한 값은 남는다. 그 값은 플러그인 폴더가 아니라 각 프로필의 `.env`와 vault, 그리고 Mac 키체인에 들어 있기 때문이다. 지우는 방법은 아래 "저장한 값 찾기와 지우기"에 있다.

### Hermes 본체의 입력 방식 가로채기(기본으로 켜짐, 끌 수 있음)

이 플러그인은 켜져 있는 동안 Hermes 본체의 두 동작을 막는다. 대신 에이전트에게 이 플러그인의 도구를 쓰라고 알린다.
두 설정 모두 기본값은 켜짐이다. 따로 설정하지 않으면 두 동작을 모두 막는다.
이 가로채기는 대화가 Slack인지 CLI인지 가리지 않는다. 플러그인이 켜진 프로필의 모든 대화에 적용된다.

- 로그인 일회용 코드 입력(`browser_vault`의 `enter_code`): Slack 대화에서는 Hermes 본체가 이 코드를 Slack 모달로 묻기 때문에 막는다.
- 로그인 정보 저장(`browser_vault`의 `save_login`): Slack 대화에서는 Hermes 본체에 이 정보를 받을 입력 창이 없다. 그래서 본체는 터미널에서 `hermes vault add`로 직접 넣으라고 안내한다. 이 플러그인은 본체의 그 동작을 막고, 에이전트가 입력 페이지 링크를 띄우게 한다.

CLI 대화에서는 Hermes 본체가 일회용 코드와 로그인 정보를 그 CLI 화면 안의 입력 칸에서 직접 묻는다. 코드는 입력한 그대로 보이고, 로그인 정보는 아이디를 받은 뒤 비밀번호를 가려서 받는다. 이 본체 방식은 Slack을 거치지 않는다.
가로채기가 켜져 있으면 CLI 대화에서도 본체의 입력 칸 대신 입력 페이지 링크가 나온다.

둘 중 하나의 가로채기를 끄려면 아래 명령으로 해당 설정을 `false`로 바꾼다. 바꾼 설정은 다음 도구 호출부터 적용되므로 게이트웨이를 다시 시작하지 않는다.
설정을 `false`로 바꾸면 플러그인이 본체의 그 동작을 더 막지 않는다.
이 플러그인의 도구는 그대로 남아 있어서, 에이전트는 본체 방식과 입력 페이지 링크 중 어느 쪽이든 쓸 수 있다.
본체 방식만 쓰게 하려면 플러그인을 끈다(위 "끄기").
다른 프로필에 적용하려면 위의 규칙대로 `hermes -p <프로필> config set ...`으로 쓴다.

```bash
hermes config set plugins.entries.secure-input.settings.intercept_core_code_prompt false
hermes config set plugins.entries.secure-input.settings.intercept_core_save_login false
```

다시 켜려면 같은 명령의 `false`를 `true`로 바꿔 실행한다. 이것도 다음 도구 호출부터 적용된다.

## 사용법

### 에이전트가 스스로 링크를 띄우는 경우

에이전트가 일하다가 자격증명이 없어 막히면 스스로 이 플러그인의 도구를 부른다.

- API 키가 없을 때(환경 변수가 비어 있거나 서비스가 인증 오류를 낼 때) 에이전트는 `secure_input_request` 도구를 API 키 종류로 부른다.
- 로그인 화면은 열었는데 그 사이트의 저장된 로그인이 없을 때 에이전트는 같은 도구를 사이트 로그인 종류로 부른다.
- 이 Mac의 스크립트가 키체인에서 읽는 비밀번호가 필요할 때 에이전트는 같은 도구를 키체인 비밀번호 종류로 부른다.
- 로그인 도중 사이트가 일회용 코드를 물을 때 에이전트는 `secure_input_enter_code` 도구를 부른다.

사용자가 보게 되는 순서는 이렇다.

첫째, 같은 Slack 대화(스레드)에 Hermes 봇이 메시지 하나를 올린다. 메시지에는 아래 내용과 "입력 페이지 열기" 버튼이 있다.

```text
자격증명 입력 요청: API 키
이름표: Exa API 키
목적: Exa 웹 검색 도구를 쓰려면 API 키가 필요합니다
변수: EXA_API_KEY
저장 위치: .env (페이지에서 켜고 끌 수 있음)
키체인 항목(켜면 저장): hermes-secure-input.exa-api-key (계정 hermes-secure-input, 이 플러그인 전용 이름)
저장될 프로필: default (페이지에서 바꿀 수 있음)
60초 안에 열어야 하고 한 번만 열 수 있습니다. 연 뒤 5분 안에 제출하세요.
```

사이트 로그인이면 `변수:` 줄 대신 `사이트: https://admin.example.com` 같은 줄이 나온다.
키체인 비밀번호면 제목이 `자격증명 입력 요청: 비밀번호`이고, `저장될 프로필:` 줄 대신 `로그를 남길 프로필: default (Mac 키체인은 프로필과 무관합니다)`가 나온다.
일회용 코드면 저장 위치 줄이 없고, `저장될 프로필:` 줄 대신 "저장: 하지 않음(코드는 로그인 페이지에 바로 입력됩니다)"이 나온다.

둘째, 버튼을 누르면 입력 페이지가 열린다. 페이지에는 누가 요청했는지, 저장 위치 목록, 입력칸, 저장할 프로필 선택 상자, 남은 시간이 보인다.
사용자는 저장 위치를 확인하고 값을 넣은 뒤 "암호화해서 보내기"를 누른다. 넣고 싶지 않으면 "요청 취소"를 누른다. 취소하면 페이지가 "요청을 취소했습니다"로 바뀐다.

셋째, 페이지가 "저장했습니다"로 바뀌고 저장 위치마다의 결과가 보인다. 일회용 코드면 "전달했습니다"로 바뀐다.
같은 때 Slack 메시지는 버튼이 사라지고 결과 문장으로 바뀐다. 결과 문장의 예는 아래와 같다.

```text
저장 완료: EXA_API_KEY, 프로필 default
저장 완료: EXA_API_KEY, 프로필 default; Mac 키체인 hermes-secure-input.exa-api-key
저장 완료: https://admin.example.com 로그인, 프로필 worker
저장 완료: Mac 키체인 hermes-secure-input.backup-script-password
일부만 저장: EXA_API_KEY, 프로필 default; 실패: Mac 키체인 hermes-secure-input.exa-api-key(사유 keychain_write_failed) (API 키 'Exa API 키')
전달 완료: accounts.example.com 일회용 코드를 로그인 페이지로 넘겼습니다
만료: 60초 안에 열리지 않았습니다 (API 키 'Exa API 키')
취소: 사용자가 입력 페이지에서 취소했습니다 (API 키 'Exa API 키')
```

넷째, 에이전트가 결과를 받는다. 결과에는 값이 없다. 그 뒤의 일은 종류마다 다르다.
에이전트가 받는 항목은 아래 "보안" 절의 "이 플러그인이 모델에게 주는 것"에 있다.

- 사이트 로그인: 저장되면 에이전트는 그 vault 항목으로 로그인 화면을 채우고 하던 일을 이어 간다.
- 일회용 코드: 전달되면 Hermes가 코드를 로그인 화면의 코드 칸에 넣고, 에이전트는 하던 일을 이어 간다.
- 키체인 비밀번호: 저장되면 에이전트는 저장한 키체인 항목의 이름을 받는다. 그 값을 읽는 스크립트는 Mac 키체인에서 바로 읽는다.
- API 키: 저장되어도 에이전트는 그 키가 필요한 일을 이어 가지 않는다. 아래 "API 키를 저장한 뒤 할 일"을 사용자에게 알린다.

에이전트는 결과가 올 때까지 다음 일로 넘어가지 않고 기다린다. 길어도 6분 40초다(여는 시한 60초 + 제출 시한 5분 + 저장 시한 최대 30초 + 여유 10초).

로그인 일회용 코드의 경우, 저장된 로그인에 인증 앱 설정 키가 있으면 링크 없이 Hermes가 코드를 만들어 넣는다. 키가 없을 때만 링크가 온다.

### API 키를 저장한 뒤 할 일

플러그인은 API 키를 `.env` 파일에 쓰기만 하고, 실행 중인 Hermes에 직접 넣지 않는다.
에이전트는 저장 결과와 함께, 사용자에게 아래 두 가지를 알리라는 안내를 받는다.

1. 게이트웨이를 한 번 다시 시작한다. Slack 대화에 `!restart`를 보내거나 Hermes 컴퓨터에서 `hermes gateway restart`를 실행한다. 게이트웨이는 진행 중인 작업을 마친 뒤 다시 시작한다. 저장한 프로필이 자기 게이트웨이를 따로 띄우고 있으면 `hermes -p <프로필> gateway restart`로 그 게이트웨이를 다시 시작한다. `!restart`를 보냈다면 다시 시작이 끝났을 때 그 대화에 "♻ Gateway restarted successfully. Your session continues." 같은 재시작 알림이 나온다.
2. 다시 시작된 뒤 같은 대화에서 그 키가 필요했던 일을 다시 요청한다.

### Mac 키체인에만 저장한 API 키를 Hermes가 쓰게 하기

API 키를 저장할 때 `.env`를 끄고 Mac 키체인만 켜면, Hermes는 그 키를 읽지 못한다. Hermes는 API 키를 `.env`에서 읽기 때문이다.
이때 에이전트 결과에는 "Hermes가 이 값을 쓰려면 본체 설정 `secrets.command`가 필요합니다."와 그 항목의 service, account가 나온다.
`secrets.command`는 Hermes 본체의 설정이다. 게이트웨이는 시작할 때 이 설정이 있는 프로필마다 명령을 한 번 실행하고, 그 명령이 내는 `변수이름=값` 줄을 그 프로필의 환경 변수로 읽는다.
아래 명령은 `EXA_API_KEY`를 키체인 항목 `hermes-secure-input.exa-api-key`에서 읽게 한다. 키를 쓸 프로필에 설정하고(다른 프로필이면 `-p <프로필>`), 게이트웨이를 다시 시작한다.

```bash
hermes config set secrets.command.enabled true
hermes config set secrets.command.command "printf 'EXA_API_KEY=%s\n' \"\$(/usr/bin/security find-generic-password -s hermes-secure-input.exa-api-key -a hermes-secure-input -w)\""
hermes gateway restart
```

- 이 모양의 명령으로 Hermes 본체가 키체인의 값을 읽는 것을 이 Mac에서 시험 항목으로 확인했다.
- `.env`나 셸에 같은 변수가 이미 있으면 Hermes는 `.env`나 셸의 값을 쓰고 이 명령의 값을 쓰지 않는다.
- Hermes는 이 명령이 3초 안에 끝나지 않으면 값을 읽지 않는다.
- 키가 여럿이면 한 명령이 `변수이름=값` 줄을 여러 줄 내게 만든다. `secrets.command.command`는 프로필마다 하나다.

**API 키는 `.env`와 Mac 키체인 중 어디에 두는가.**
`.env`는 평문 파일이다. 이 파일이 어딘가로 복사되면(백업, 파일 첨부, 에이전트가 파일을 읽어 대화에 옮기는 일) 그 안의 키가 모두 함께 간다. 키체인 항목은 암호화되어 있어 파일 복사로 딸려 가지 않는다.
키체인도 같은 macOS 사용자로 도는 프로그램은 막지 못한다. Hermes는 사람이 없을 때도 키를 읽어야 하므로 이 플러그인의 항목은 `/usr/bin/security`가 묻지 않고 읽을 수 있고, 에이전트의 터미널 도구도 마찬가지다(아래 "막지 못하는 것").
키체인에는 실패하는 경우가 하나 더 생긴다. 게이트웨이가 시작할 때 키체인이 잠겨 있으면(예: 재부팅 뒤 화면 로그인 전, SSH로만 Hermes를 띄운 경우) 명령이 키를 읽지 못할 수 있고, 그러면 그 키가 필요한 일이 모두 실패한다.

### 사용자가 Slack 명령으로 직접 띄우는 경우

API 키, 로그인, 키체인 비밀번호를 미리 넣어 두고 싶으면 명령으로 링크를 띄운다.
Slack에서는 명령 앞에 `/` 대신 `!`를 쓴다. Hermes CLI에서는 `/secure-input`으로 쓴다.

```text
!secure-input key <변수 이름> [--profile <프로필>] [--purpose "<목적 문구>"] [--label "<이름표>"]
!secure-input login <https://사이트 주소> [--profile <프로필>] [--purpose "<목적 문구>"] [--label "<이름표>"]
!secure-input secret <키체인 항목 이름> [--purpose "<목적 문구>"] [--label "<이름표>"]
!secure-input help
```

예시는 아래와 같다.

```text
!secure-input key EXA_API_KEY
!secure-input key OPENROUTER_API_KEY --profile worker --label "OpenRouter 키"
!secure-input login https://admin.example.com --label "예시 쇼핑몰 관리자"
!secure-input secret backup-script-password --label "백업 스크립트 비밀번호"
```

- 변수 이름은 영문 대문자, 숫자, `_`로만 쓰고 숫자로 시작하지 않는다.
- Hermes가 프로그램 실행이나 보안 설정에 쓰는 이름(예: `PATH`, `PYTHONPATH`, `HERMES_HOME`)과 `SECURE_INPUT_`로 시작하는 이름은 이 플러그인으로 저장할 수 없다. 이런 이름을 넣으면 링크를 만들지 않고 "이 변수 이름으로는 저장할 수 없습니다."로 시작하는 답이 온다.
- 사이트 주소는 `https://`로 시작해야 한다. 주소 뒤에 경로를 붙여 보내도 플러그인이 경로를 떼고 사이트 주소만 쓴다. 예를 들어 `https://admin.example.com/login`을 보내면 `https://admin.example.com`으로 저장한다.
- 한글 같은 글자가 든 사이트 주소는 `xn--`로 시작하는 ASCII 주소로 바뀌어 저장되고, Slack 메시지와 입력 페이지에도 그 모양으로 보인다. 예를 들어 `https://한글.example`은 `https://xn--bj0bj06e.example`이 된다.
- 키체인 항목 이름은 위 "키체인 항목의 이름"의 규칙을 따른다. 허용 목록의 `id`를 적으면 그 기존 항목에, 다른 이름을 적으면 이 플러그인 전용 항목에 저장한다.
- `--label`을 빼면 이름표는 변수 이름, 사이트의 호스트 이름, 또는 키체인 항목 이름이 된다. `--purpose`를 빼면 "직접 등록합니다"로 끝나는 기본 문구가 들어간다.
- 목적 문구는 200자까지, 이름표는 80자까지의 한 줄이다. 줄바꿈, 제어 문자, 보이지 않는 서식 글자(유니코드 Cf 범주. 예: U+200B 폭 없는 공백, U+202E 글자 방향 바꿈)가 들어 있으면 링크를 만들지 않는다. 거절하는 답에는 그 글을 다시 싣지 않는다. 이모지 여러 개를 하나로 이어 붙이는 U+200D도 Cf 글자라서, 가족 이모지처럼 이어 붙인 이모지는 목적 문구와 이름표에 넣을 수 없다. 에이전트가 도구로 요청할 때도 같은 규칙이 쓰인다.
- 명령에는 저장 위치를 고르는 옵션이 없다. 저장 위치는 입력 페이지에서 켜고 끈다.
- 값은 명령에 적지 않는다. 명령은 링크만 띄우고, 값은 입력 페이지에만 넣는다.
- 일회용 코드는 명령으로 띄우지 않는다. 일회용 코드 링크는 로그인 도중에 에이전트가 띄운다.

명령을 보내면 Hermes가 바로 "입력 링크를 보냈습니다(변수 EXA_API_KEY, 프로필 default). 결과는 링크 메시지에 표시됩니다."라고 답한다.
그 뒤의 링크 메시지, 입력 페이지, 결과 표시는 에이전트가 띄운 경우와 같다.

CLI에는 Slack 버튼이 없다. CLI 대화에서는 Slack 메시지와 같은 내용이 대화 창에 글 메시지로 나오고, 마지막 줄에 `입력 페이지 열기: https://...` 꼴로 링크 주소가 붙는다.
그 주소를 tailnet에 든 기기의 브라우저에서 연다.
요청이 끝나면 결과 문장이 같은 대화 창에 나온다.

### 저장할 프로필 정하기

`.env`와 vault는 프로필마다 따로 있으므로 저장할 프로필을 정한다.
기본값은 요청이 나온 대화의 프로필이다. 예를 들어 `worker` 프로필로 도는 대화에서 요청하면 `worker`에 저장된다.
바꾸는 방법은 세 가지다.

- 에이전트 도구 인자: 에이전트가 `secure_input_request`를 부를 때 `target_profile`에 프로필 이름을 넣는다.
- 명령 옵션: 명령에 `--profile <프로필>`을 붙인다.
- 입력 페이지의 "저장할 프로필" 선택 상자: 이 컴퓨터의 Hermes 프로필 목록에서 고른다. 선택 상자에는 앞의 두 방법으로 정한 프로필이 미리 골라져 있다. 사용자가 바꾸면 바꾼 프로필에 저장된다.

선택 상자에는 이 플러그인을 설치하지 않은 프로필도 나온다. 그런 프로필을 골라도 값은 그 프로필의 `.env`나 vault에 저장된다. 저장된 값을 쓰는 데에는 플러그인이 필요 없다.

Mac 키체인은 프로필과 상관없다. 키체인 비밀번호와 일회용 코드에는 프로필을 고르는 칸이 없다.

## 링크의 수명

- 링크는 만든 뒤 60초 안에 열어야 한다.
- 링크는 한 번만 열린다. 이미 열린 링크를 다시 열면 "이미 열린 링크입니다" 화면이 나온다.
- 연 뒤 5분 안에 값을 보내야 한다. 이 5분은 처음 연 때부터 세고, 저장 중에도 흐른다. 5분이 지났을 때 저장 중이 아니면 페이지가 입력한 값을 지우고 "제출 시간이 지났습니다"로 바뀐다.
- 보내기를 누르면 페이지에 "저장 중입니다. 이 창을 닫지 마세요."가 나온다. 저장 중에는 5분이 지나도, "요청 취소"를 눌러도 저장이 멈추지 않는다. 플러그인은 저장을 끝까지 하고 결과를 알린다.
- 저장 자체에도 시한이 있다. 시한은 켠 저장 위치마다 `.env` 10초, vault 30초, Mac 키체인 20초를 더한 시간이다. 저장 위치를 둘 켤 수 있는 것은 API 키(`.env`와 Mac 키체인, 합쳐 30초)뿐이라 저장 시한은 길어야 30초다. 그 안에 끝나지 않으면 플러그인이 저장을 멈춘다.
- 값 보내기가 실패하면 다시 보낼 수 있다. 실패가 5번이 되면 요청이 끝난다.
- 실패로 세는 것은 Hermes 컴퓨터가 보낸 내용을 받았지만 풀지 못했거나 저장하지 못한 경우다. 받은 내용의 형식이 맞지 않을 때, 암호를 풀지 못했을 때, 켠 저장 위치에 하나도 저장하지 못했을 때, 가려진 값으로 보일 때가 여기에 든다. 이 경우에는 페이지에서 다시 보낼 수 있다.
- 쓰기 전 점검에서 쓸 수 없는 저장 위치가 있어 아무 데도 쓰지 않은 경우는 실패로 세지 않는다.
- 연결이 끊겨 Hermes 컴퓨터에 닿지 못한 시도는 실패로 세지 않는다. 이때 페이지에는 "Hermes 컴퓨터에 연결하지 못했습니다. 연결을 확인하고 다시 보내세요."가 나온다.
- 사이트가 비밀번호나 코드가 틀렸다고 하는 것도 실패로 세지 않는다. 플러그인은 값이 맞는지 사이트에 확인하지 않는다.
- 한 컴퓨터에서 동시에 열려 있을 수 있는 요청은 모든 프로필을 합쳐 3개까지다.
- 요청이 끝나면(저장, 일부만 저장, 전달, 만료, 취소, 실패) 입력 페이지를 띄운 서버가 꺼진다. 주소도 Tailscale Serve에서 지워진다. 그 주소는 다시 열리지 않는다.
- 놓쳤거나 틀린 값을 넣었으면 에이전트에게 다시 요청하라고 하거나 명령을 다시 보낸다. 매번 새 링크가 만들어진다.

## 보안: 값이 지나가는 길

값이 지나가는 길과 구간마다 누가 값을 볼 수 없는지는 아래와 같다.

| 구간 | 보호 | 이 구간에서 값을 볼 수 없는 쪽 |
|---|---|---|
| 입력 기기의 브라우저 안 | 보내기 전에 브라우저가 값을 암호화한다. 열쇠는 요청마다 새로 만든다. 방식은 브라우저 표준 WebCrypto의 ECDH 키 교환과 AES-GCM 암호화다. | 입력 기기를 떠난 뒤 입력 페이지 서버가 풀기 전까지 요청을 볼 수 있는 모든 쪽 |
| 입력 기기에서 Hermes 컴퓨터까지 | Tailscale이 기기 사이의 연결을 암호화한다([What is Tailscale?](https://tailscale.com/docs/concepts/what-is-tailscale)). 그 안에서 Tailscale Serve의 HTTPS가 한 번 더 암호화한다. | 같은 와이파이나 인터넷 구간에 있는 사람 |
| Hermes 컴퓨터 안, Tailscale Serve에서 입력 페이지 서버까지 | HTTPS가 풀린 뒤에도 요청 본문에는 브라우저가 암호화한 값만 있다. | Tailscale Serve, 그리고 이 구간의 요청을 기록하는 프로그램 |
| 입력 페이지 서버 | 서버가 메모리에서 값을 풀어 바로 저장한다. 값은 로그에 쓰지 않는다. | 감사 로그를 읽는 사람 |
| 저장 | 사용자가 켠 저장 위치(`.env`, vault, Mac 키체인)에 들어간다. 일회용 코드는 로그인 화면에 입력되고 버려진다. | 저장된 값을 누가 읽을 수 있는지는 아래 "막지 못하는 것"에 적었다. |

Slack으로 가는 것과 가지 않는 것은 이렇다.

- 가는 것: 링크 주소, 목적 문구, 종류, 이름표, 저장할 프로필, 저장 위치, 변수 이름이나 사이트 주소나 키체인 항목 이름(service), 에이전트가 적은 이유, 결과 상태. 이 플러그인 전용 항목이면 키체인 계정 이름(고정값 `hermes-secure-input`)도 간다. 허용 목록 항목이면 그 항목의 `id`, `label`, `used_by`도 간다.
- 가지 않는 것: 값(API 키, 비밀번호, 인증 앱 설정 키, 일회용 코드)과 로그인 아이디, 허용 목록 항목의 키체인 계정 이름(account). 허용 목록 항목의 계정 이름은 Tailscale로만 열리는 입력 페이지에만 보인다.

AI 모델이 보는 것과 보지 않는 것은 이렇다.

- 이 플러그인이 모델에게 주는 것: 결과 상태, 요청 번호, 종류, 이름표, 저장한 프로필, 저장 위치마다의 결과, 변수 이름이나 사이트 주소나 키체인 항목 이름(service), vault 항목 핸들, 안내 문장. vault 항목 핸들은 저장된 로그인 항목을 가리키는 이름표다. 이 플러그인 전용 항목이면 키체인 계정 이름(고정값 `hermes-secure-input`)도 준다. 허용 목록 항목이면 그 항목의 `id`와 `label`을 준다(도구 설명에는 `used_by`도 있다).
- 이 플러그인이 모델에게 주지 않는 것: 값, 로그인 아이디, 링크 주소, 허용 목록 항목의 키체인 계정 이름(account).
- 다만 Hermes 본체는 저장된 로그인 목록을 보여 줄 때 로그인 아이디를 함께 보여 준다. 그래서 에이전트는 vault에 저장된 로그인 아이디를 볼 수 있다. 비밀번호와 인증 앱 설정 키는 그 목록에 나오지 않는다.
- 저장된 로그인으로 로그인 화면을 채울 때도 비밀번호는 Hermes가 화면에 직접 넣는다. 그 비밀번호는 모델에게 보이지 않는다.

입력 페이지에 닿을 수 있는 기기는 같은 tailnet에서 이 컴퓨터에 접근할 수 있는 기기뿐이다.
tailnet에 접근 규칙을 두었다면 그 규칙도 Serve에 똑같이 적용된다([Tailscale Serve 문서](https://tailscale.com/docs/features/tailscale-serve)).
페이지는 인터넷에 공개되지 않는다. 플러그인은 인터넷 공개 기능인 Tailscale Funnel을 쓰지 않는다.
링크 주소에는 요청마다 새로 만든, 추측할 수 없는 무작위 문자열이 들어 있다. 주소의 경로가 그 문자열로 시작하지 않으면 서버가 404 응답과 "찾을 수 없습니다."로 답한다.
플러그인은 자기 요청의 주소 하나만 Tailscale Serve에 더하고 지운다. 다른 Serve 설정은 건드리지 않는다.

### 링크를 열 수 있는 Tailscale 계정

- 입력 화면은 허용된 Tailscale 계정으로 로그인한 기기에서만 열린다. 입력 페이지 서버는 Tailscale Serve가 요청에 붙여 주는 접속 계정을 보고 판단한다.
- 기본으로 허용되는 계정은 Hermes 컴퓨터의 Tailscale이 로그인한 계정 하나다.
- 다른 계정의 기기에서 링크를 열면 "이 기기의 Tailscale 계정으로는 열 수 없습니다" 화면이 나온다. 이때 링크는 쓰이지 않으므로, 링크를 만든 뒤 60초 안이면 허용된 계정의 기기에서 열 수 있다.
- Hermes 컴퓨터의 계정은 Hermes 컴퓨터에서 아래 두 줄로 본다. `plutil`은 macOS에 들어 있는 명령이다. 입력 기기의 계정은 그 기기의 Tailscale 앱에서 본다.

```bash
uid=$(tailscale status --json | plutil -extract Self.UserID raw -o - -)
tailscale status --json | plutil -extract "User.$uid.LoginName" raw -o - -
```

- 둘째 줄은 `someone@example.com`이나 `octocat@github`처럼 로그인한 계정 이름 한 줄을 낸다.
- 다른 계정도 허용하려면 `allowed_tailscale_logins` 설정에 그 계정을 넣는다. 이 설정은 Hermes 컴퓨터의 계정에 더해 허용할 계정 목록이고, 기본값은 빈 목록이다. 아래처럼 목록 전체를 한 번에 적는다. 바꾼 값은 다음 요청부터 적용되므로 게이트웨이를 다시 시작하지 않는다.

```bash
hermes config set plugins.entries.secure-input.settings.allowed_tailscale_logins '["someone@example.com", "other@example.com"]'
hermes config set plugins.entries.secure-input.settings.allowed_tailscale_logins '[]'
```

- 둘째 줄은 추가 계정을 모두 지우는 명령이다.
- 플러그인은 요청이 나온 대화의 프로필에 있는 이 설정을 읽는다. 그래서 `worker` 프로필로 도는 대화에서 나온 링크를 다른 사람이 열게 하려면 `hermes -p worker config set ...`으로 `worker`에 넣는다. 값을 저장할 프로필의 설정은 읽지 않는다.
- 이 설정에 넣은 계정은 그 프로필의 대화에서 나온 모든 요청의 링크를 열 수 있다. 요청마다 계정을 고르는 기능은 없다.

## 막지 못하는 것

- 허용된 Tailscale 계정으로 로그인한 기기를 쓰는 다른 사람(예: 같은 계정으로 로그인한 공용 PC를 쓰는 사람)은 60초 안에 링크를 먼저 열 수 있다. 플러그인은 계정만 확인하고 기기는 구분하지 않는다. 먼저 연 사람은 이미 저장된 값을 볼 수 없지만, 자기가 정한 값을 넣어 저장시킬 수 있다. 이때 본인이 링크를 열면 "이미 열린 링크입니다"가 나온다. 본인이 연 적이 없는데 이 화면이 나오면, 새 링크를 요청해 값을 다시 넣는다.
- Hermes 컴퓨터 안에서 도는 프로그램은 Tailscale Serve를 거치지 않고 입력 페이지 서버에 직접 닿을 수 있다. 그런 프로그램에는 계정 확인이 적용되지 않는다.
- 링크 버튼은 그 Slack 대화에 있는 모든 사람에게 보인다.
- Hermes가 도는 컴퓨터 자체가 침해되면 보호되지 않는다. 그 컴퓨터가 값을 풀어서 저장하기 때문이다.
- 저장된 `.env`는 평문 파일이다. 플러그인은 소유자만 읽고 쓸 수 있는 권한으로 파일을 쓴다. 하지만 그 컴퓨터의 같은 사용자 계정으로 도는 프로그램은 값을 읽을 수 있다.
- vault는 저장한 항목 전체(사이트 주소, 로그인 아이디, 비밀번호, 인증 앱 설정 키)를 파일 하나로 암호화한다. 그 파일을 푸는 열쇠는 기본 설정에서 같은 폴더의 `vault.key` 파일에 있다. 그래서 이 컴퓨터의 같은 사용자 계정으로 도는 프로그램은 그 열쇠로 vault를 풀어 읽을 수 있다.
- Mac 키체인의 값은 이 Mac에 로그인한 같은 사용자 계정의 프로그램이 `security` 명령으로 읽을 수 있다. Hermes의 터미널 도구도 여기에 든다.
- 터미널 도구를 쓸 수 있는 에이전트는 `security` 명령으로 키체인 항목을 직접 읽고 덮어쓸 수 있다. 같은 에이전트는 설정 파일의 `keychain_items`도 스스로 고칠 수 있다. 허용 목록이 막는 것은 에이전트가 이 플러그인의 도구에 다른 항목의 이름을 넘기는 경우뿐이다. 예를 들어 웹 페이지의 글에 속아 엉뚱한 이름을 넘기는 경우다.
- 기존 키체인 항목에 저장하면 그 항목의 예전 값은 되돌릴 수 없다. 플러그인은 예전 값을 따로 보관하지 않는다.
- 한국어 라벨만 붙은 일회용 코드 입력칸은 Hermes가 코드 칸으로 인식하지 못할 수 있다(예: 네이버의 "일회용 번호" 칸). 그러면 링크는 오지 않는다. 에이전트는 코드를 채팅으로 묻지 않는다. 에이전트는 이 사이트의 코드 칸은 자동 입력이 되지 않는다고 알린 뒤, 코드가 필요 없는 다른 로그인 방법을 쓰거나 로그인을 멈춘다. 이 플러그인의 로그인 요청 도구 설명에는, 일회용 번호로 로그인하는 방식이나 QR 방식이 따로 있는 사이트에서는 아이디와 비밀번호 방식을 쓰라는 문장이 늘 들어 있다. 플러그인이 로그인 화면을 보고 판단하는 것은 아니다.
- Slack 버튼 메시지를 보내는 데에는 Hermes 게이트웨이의 내부 기능을 쓴다. Hermes가 바뀌어 그 기능이 없어지면 버튼 대신 링크 주소가 들어간 일반 글 메시지가 간다. 그때도 값은 Slack으로 가지 않는다.

## 저장한 값 찾기와 지우기

모든 저장 위치에서 한 번에 지우는 기능은 없다. 사본 기록 파일로 어디에 사본이 있는지 보고, 저장 위치마다 따로 지운다.

### 사본 기록 파일

- 위치: `~/.hermes/secure-input/placements.json`이다. 이 파일은 프로필과 상관없이 하나다. 플러그인은 소유자만 읽고 쓸 수 있는 권한으로 이 파일을 쓴다.
- 적히는 것: 저장에 성공할 때마다 자격증명마다 저장된 곳이 적힌다. `.env`는 프로필과 변수 이름, vault는 프로필과 사이트 주소와 항목 핸들(`item_id`), Mac 키체인은 service와 account다. 저장한 시각도 적힌다.
- 적히지 않는 것: 값과 로그인 아이디는 적히지 않는다. 저장에 실패한 곳과 저장됐는지 알 수 없는 곳은 적히지 않는다.
- 이 파일은 저장한 기록이다. 지금도 그 자리에 값이 있다는 뜻은 아니다. 아래 방법으로 지워도 기록은 남는다.

### 저장 위치마다 지우는 방법

`.env`의 변수 줄은 아래 명령으로 지운다. 다른 프로필이면 `hermes -p <프로필> config unset ...`으로 쓴다. 나머지 줄은 그대로 남는다. 지운 뒤 게이트웨이를 다시 시작해야 실행 중인 Hermes도 그 값을 잊는다.

```bash
hermes config unset EXA_API_KEY
hermes gateway restart
```

vault의 로그인 항목은 핸들로 지운다. 핸들은 `vault_`로 시작하는 항목 이름이고, 사본 기록 파일의 `item_id`나 `hermes vault list`의 Handle 칸에서 본다. 아래 `<핸들>` 자리에 그 이름을 넣는다. 다른 프로필이면 `hermes -p <프로필> vault ...`로 쓴다. 지우면 "Removed <핸들>"이 나온다.

```bash
hermes vault list
hermes vault rm <핸들>
```

Mac 키체인 항목은 service와 account로 지운다. 이 명령은 값을 화면에 내지 않는다. 지우면 "password has been deleted."가 나온다.

```bash
security delete-generic-password -s hermes-secure-input.exa-api-key -a hermes-secure-input
```

이 플러그인이 만든 키체인 항목(전용 항목, 그리고 아래 "남은 임시 키체인 항목"의 임시 항목)은 아래 명령으로 찾는다. 이 명령은 항목의 service 이름만 보여 주고 값은 보여 주지 않는다.

```bash
security dump-keychain | grep '"svce"<blob>="hermes-secure-input\.'
```

### 남은 임시 키체인 항목

이미 값이 있는 키체인 항목을 바꿀 때, 플러그인은 먼저 임시 항목에 같은 값을 써서 다시 읽어 본 뒤 본 항목에 쓴다.
임시 항목의 service는 `hermes-secure-input.tmp.`로 시작하고, account는 `hermes-secure-input`이다.
저장이 끝나면 플러그인이 임시 항목을 지우지만, 지우기가 실패하거나 저장이 시한을 넘겨 멈추면 이번에 넣은 값이 든 임시 항목이 남을 수 있다.
그럴 때 입력 페이지(저장 실패 알림과 그 뒤의 끝 화면, 완료 화면)와 Slack 결과 메시지는 "임시 키체인 항목에 이번에 넣은 값이 남아 있을 수 있습니다."를 붙이고, 이 절의 명령으로 확인해 지우라고 한다. 플러그인은 남은 임시 항목을 나중에 지우지 않는다.
요청이 끝날 때의 Slack 결과 메시지와 에이전트가 받는 도구 결과는 그 요청의 모든 시도가 키체인에 남긴 것을 말한다. 그래서 한 번 보낸 값이 임시 항목을 남기고, 같은 페이지에서 다시 보낸 값이 다른 이유로 실패하거나 다른 저장 위치에 저장돼도 이 문장이 붙는다. 기존 항목의 예전 값이 바뀌었을 수 있다는 문장과 항목이 새로 만들어졌다는 문장도 같다. 다만 뒤 시도가 그 키체인 항목에 저장되면 앞의 두 문장은 붙지 않는다. 그 항목에는 이제 저장됐다고 알린 값이 들어 있기 때문이다.
임시 항목이 남았는지는 아래 명령으로 본다. 아무 줄도 나오지 않으면 남은 항목이 없다.

```bash
security dump-keychain | grep '"svce"<blob>="hermes-secure-input\.tmp\.'
```

남은 항목이 있으면 나온 줄의 따옴표 안 이름을 service로 넣어 지운다. 아래 이름은 예다.

```bash
security delete-generic-password -s hermes-secure-input.tmp.0123456789ab -a hermes-secure-input
```

## 기록

플러그인은 요청에 일이 생길 때마다(만들어짐, 열림, 저장 등) 감사 로그 파일에 한 줄씩 더한다.

- 위치: 요청을 만들 때 정한 프로필(정하지 않았으면 요청이 나온 대화의 프로필) 폴더의 `logs/secure-input.jsonl`이다. `default`면 `~/.hermes/logs/secure-input.jsonl`이고, 다른 프로필이면 `~/.hermes/profiles/<프로필 이름>/logs/secure-input.jsonl`이다.
- 입력 페이지에서 다른 프로필을 고르면, 저장 단계부터의 줄은 두 프로필의 로그에 모두 남고 처음 요청한 프로필이 `requested_profile`로 적힌다.
- 파일은 소유자만 읽고 쓸 수 있는 권한으로 만든다.
- 남는 것: 시각, 사건 종류(만들어짐, 열림, 계정 거절, 제출, 저장 중, 저장, 전달, 만료, 취소, 실패, 서버 정리), 요청 번호, 링크 주소를 대신하는 짧은 식별값, 요청자(에이전트인지 사용자인지, 프로필, 플랫폼, 대화의 식별값, 메신저의 사용자 ID), 목적 문구, 종류, 이름표, 저장할 프로필, 미리 켜진 저장 위치와 에이전트가 적은 이유, 변수 이름이나 사이트 주소, 키체인 항목 이름(service)과 키체인 계정 이름(account), 실패 사유. 키체인 계정 이름은 허용 목록 항목의 것도 남는다. Slack과 에이전트에게는 가지 않는 이름이다.
- 저장 줄(`saved`)의 `detail.stores`에는 저장 위치마다 저장했는지(`saved`), 예전 값을 바꿨는지(`replaced`), 실패 사유(`error`)가 남는다. 키체인 줄에는 쓰기 전에 있던 항목에 썼는지(`main_touched`), 없던 항목에 써서 항목을 새로 만들었는지(`main_created`), 임시 항목이 남았는지(`tmp_left`)도 남는다. 일부만 저장했으면 `detail.partial`이 `true`다.
- 요청을 끝내는 줄(저장, 실패로 끝남, 만료, 취소)의 `detail.keychain_left`에는 그 요청의 앞선 시도까지 합쳐 키체인에 남았을 수 있는 것(`main_touched`, `main_created`, `tmp_left`)과 그 항목의 service가 남는다. 셋 가운데 하나도 없으면 이 칸은 없다. 이 칸에는 키체인 계정 이름을 넣지 않는다. 에이전트가 받는 도구 결과의 `keychain_left`도 같은 모양이다.
- 절대 남지 않는 것: 값과 값의 길이, 사이트 로그인의 아이디, 링크 주소 자체, 암호화 열쇠, 암호문.

## 문제 해결

| 증상 | 원인과 확인 방법 |
|---|---|
| 설치 확인 결과가 기대와 다르다 | `hermes plugins list --user`에 `secure-input`이 없거나 `hermes plugins doctor secure-input`이 "ERROR: Plugin 'secure-input' was not found as a path or installed plugin id"를 내면 링크를 본다. `ls -l ~/.hermes/plugins/`로 링크 이름이 정확히 `secure-input`인지, 화살표 뒤의 경로가 내려받은 폴더인지 확인한다. 목록에 `not enabled`로 보이거나 `hermes tools list --platform slack`에 `secure_input`이 없으면 `hermes plugins enable secure-input`을 실행한다. 다른 프로필이면 위 "다른 프로필에서도 쓰기"의 규칙대로 링크 경로와 `-p`를 바꿔 확인한다. 그 밖의 오류는 doctor 출력의 `ERROR:` 줄에 실패한 단계와 오류 원문이 나온다(예: `ERROR: Plugin registration failed: No module named ...`). 이때는 먼저 `git -C ~/hermes-secure-input pull`로 내려받은 폴더를 최신 상태로 맞추고 `hermes plugins doctor secure-input`을 다시 실행한다. 그래도 같은 오류가 나오면 `hermes --version`으로 Hermes 버전이 위 "필요한 것"의 v0.23.3 이상인지 본다. 버전도 맞는데 같은 오류가 나오면 `HERMES_PLUGINS_DEBUG=1 hermes plugins doctor secure-input`을 실행한다. 이렇게 실행하면 `ERROR:` 줄 위에 `Traceback`으로 시작하는 오류 기록이 함께 나온다. 그 기록의 마지막 `File "…", line …` 줄이 오류가 난 파일과 줄이고, 바로 다음 줄이 오류 원문이다. 이 두 줄을 GitHub issue로 알린다. |
| 버튼을 눌러도 페이지가 열리지 않거나, 페이지에 "Hermes 컴퓨터에 연결하지 못했습니다"가 나온다 | 입력 기기의 Tailscale이 꺼져 있거나, 입력 기기가 Hermes 컴퓨터와 다른 tailnet에 있다. 입력 기기에서 Tailscale을 켜고 같은 tailnet인지 확인한다. Hermes 컴퓨터가 켜져 있는지, 그 컴퓨터에서 위 "필요한 것"의 준비 확인 명령이 `"BackendState": "Running"`을 보여 주는지도 본다. tailnet에 접근 규칙(ACL)을 쓰고 있다면 입력 기기가 Hermes 컴퓨터의 443번 포트에 닿도록 허용되어 있는지 관리 화면에서 본다([Tailscale ACL 문서](https://tailscale.com/docs/features/access-control/acls)). 요청이 이미 끝난 링크도 열리지 않는다. 만든 뒤 60초 안에 열지 않은 링크도 여기에 든다. 이때 Slack 메시지는 "만료:"로 시작하는 문장으로 바뀌어 있다. 요청이 끝난 링크를 열면 브라우저에는 연결 실패 화면이나 404(찾을 수 없음)가 나온다. 새 링크를 요청한다. |
| "이미 열린 링크입니다" | 그 링크가 이미 한 번 열렸다. 다른 창이나, 허용된 Tailscale 계정으로 로그인한 다른 기기에서 먼저 열었을 수 있다. 새 링크를 요청한다. |
| "이 기기의 Tailscale 계정으로는 열 수 없습니다" | 링크를 연 기기의 Tailscale이 허용되지 않은 계정으로 로그인되어 있다. 그 기기의 Tailscale 앱에서 로그인한 계정을 보고, 위 "링크를 열 수 있는 Tailscale 계정"의 명령으로 본 Hermes 컴퓨터의 계정과 같은지 비교한다. 링크는 쓰이지 않았으므로, 링크를 만든 뒤 60초 안이면 같은 계정의 기기에서 다시 열 수 있다. 60초가 지났으면 새 링크를 요청한다. 다른 사람의 기기에서 열어야 하면 그 사람의 계정을 `allowed_tailscale_logins`에 넣는다. |
| 에이전트나 명령이 "Tailscale 계정을 확인하지 못해 입력 페이지를 띄우지 못했습니다"라고 답한다 | 플러그인이 Hermes 컴퓨터의 Tailscale 계정을 읽지 못했다. 위 "필요한 것"의 준비 확인 명령이 `"BackendState": "Running"`을 보여 주는지 본다. `"Running"`이 아니면 Hermes 컴퓨터의 Tailscale 앱을 켜고 로그인한 뒤 다시 요청한다. |
| API 키 칸 아래에 "API 키에는 영문, 숫자, 기호, 공백만 넣을 수 있습니다."가 나온다 | 붙여 넣은 값에 영문, 숫자, 기호, 공백 말고 다른 글자(한글, 전각 문자, 보이지 않는 줄 구분 문자)가 섞였다. 서비스 관리 화면에서 키를 다시 복사해 붙여 넣는다. 이 오류는 보내기 전에 화면이 잡으므로 실패 5번에 세지 않는다. |
| "제출 시간이 지났습니다"와 "값은 링크를 연 뒤 5분 안에 보내야 합니다." | 연 뒤 5분 안에 한 번도 보내지 않았다. 값은 어디에도 가지 않았고, 페이지는 입력한 값을 지웠다. Slack 메시지도 "만료: 연 뒤 5분 안에 제출되지 않았습니다"로 시작하는 문장으로 바뀐다. 새 링크를 요청한다. |
| "제출 시간이 지났습니다"와 "앞서 보낸 값은 저장하지 못했고, 다시 보내지 않은 채 제출 시간이 지났습니다.", 또는 Slack 메시지 "만료: 보낸 값은 저장하지 못했고, 다시 보내지 않은 채 제출 시간이 지났습니다" | 값을 보냈지만 저장하지 못했고("값을 저장하지 못했습니다", "아무 데도 저장하지 않았습니다", "가려진 값처럼 보여 저장하지 않았습니다" 알림), 같은 페이지에서 다시 보내지 않은 채 연 뒤 5분이 지났다. 저장됐다고 알린 곳은 없다. 페이지는 입력 칸에 남아 있던 값을 지웠다. 페이지와 Slack 메시지에 키체인 문장("기존 값이 바뀌었을 수 있습니다", "새로 만들어졌고 이번에 넣은 값이 들어 있을 수 있습니다", "임시 키체인 항목에 이번에 넣은 값이 남아 있을 수 있습니다")이 붙어 있으면 그 키체인 항목이나 임시 항목에 이번 값이 들어 있을 수 있다. 같은 페이지에서 여러 번 보냈으면 이 문장은 마지막 시도가 아니라 앞선 시도가 남긴 것일 수도 있다. 새 링크를 요청해 다시 저장한다. 임시 항목은 위 "남은 임시 키체인 항목"의 명령으로 확인해 지운다. |
| Slack 메시지가 "만료: 저장하는 동안 제출 시간이 지났고 저장하지 못했습니다"로 시작하고, 페이지에는 "저장했는지 알 수 없습니다"가 나온다 | 연 뒤 5분 안에 보냈지만, 저장하는 동안 5분이 지났고 켠 저장 위치에 하나도 저장하지 못했다. 페이지는 서버의 답을 받은 때 이미 시간이 지나 있어서 결과를 확인하지 못했다고만 보인다. 저장됐다고 알린 곳은 없다. Slack 메시지에 위 키체인 문장이 붙어 있으면 그 키체인 항목이나 임시 항목에 이번 값이 들어 있을 수 있다. 새 링크를 요청해 다시 저장한다. |
| 페이지에 "아무 데도 저장하지 않았습니다"와 저장 위치, 이유가 나온다 | 쓰기 전 점검에서 켠 저장 위치 가운데 지금 쓸 수 없는 곳이 있었다. 아무 데도 쓰지 않았고, 실패 횟수에 세지 않는다. 이유가 "이 키체인 항목의 접근 허용 목록에 /usr/bin/security가 없어서 Hermes가 이 항목의 값을 바꾸지 않습니다."로 시작하면 그 기존 항목의 접근 허용 목록에 `/usr/bin/security`가 없다. 접근 설정이 "모든 프로그램 허용"인 항목도 여기에 해당한다. 위 "기존 키체인 항목을 쓰게 하기"의 점검 명령으로 확인하고, `keychain_acl_denied`가 나오면 그 절의 안내대로 새 이름으로 다시 요청한다. 이유가 키체인에 접근하지 못했거나 키체인이 답하지 않았다는 문장이면 Hermes 컴퓨터에서 `security default-keychain`이 `"/Users/<사용자>/Library/Keychains/login.keychain-db"` 같은 경로를 내는지 본다. 경로가 나오면 같은 페이지에서 다시 보내고, 나오지 않으면 macOS의 기본 키체인부터 고쳐야 한다(이 README는 그 방법을 다루지 않는다). 원인을 고친 뒤 같은 페이지에서 다시 보낸다. API 키라면 그 저장 위치를 끄고 보낼 수도 있다. |
| 페이지 제목이 "일부만 저장했습니다"이고, Slack 메시지가 "일부만 저장:"으로 시작한다 | 켠 저장 위치 가운데 일부에만 저장했다. 저장된 곳의 값은 그대로 남는다. 페이지와 Slack 메시지에 저장 위치마다 저장했는지와 사유가 나온다. 다시 넣는 방법은 위 "여러 저장 위치에 저장할 때"에 있다. |
| 페이지에 "저장했는지 알 수 없습니다"가 나오거나, Slack 메시지가 "저장 여부를 확인하지 못했습니다."로 시작한다 | 저장 결과를 확인하지 못했다. 값은 저장됐을 수도 있고 저장되지 않았을 수도 있다. 요청은 실패로 끝났으므로 같은 페이지에서는 다시 보낼 수 없다. 새 링크를 요청해 다시 저장한다. 같은 자리에 저장하면 그 값으로 바뀐다. Slack 메시지에 "키체인 항목 `…`의 기존 값이 바뀌었을 수 있습니다."가 붙어 있으면 그 키체인 항목의 예전 값은 이미 없어졌을 수 있다. |
| 페이지에 "값을 저장하지 못했습니다"와 저장 위치마다의 이유가 나온다 | Hermes 컴퓨터가 값을 받았지만 켠 저장 위치에 하나도 쓰지 못했다. 이 실패도 5번 중 한 번으로 센다. 페이지에서 다시 보낼 수 있다. 키체인 줄 아래에 "이 이름의 키체인 항목이 새로 만들어졌고, 이번에 넣은 값이 들어 있을 수 있습니다."가 나오면, 없던 항목에 쓰는 명령은 성공했지만 다시 읽어 본 값이 달랐다. 그 이름의 항목이 키체인에 새로 생겼다. 쓰는 명령 자체가 실패했으면 항목이 생기지 않으므로 이 문장은 나오지 않는다. 같은 페이지에서 다시 보내 저장되면 그 항목에 새 값이 들어간다. 키체인을 끄고 다른 저장 위치에만 저장하면, 완료 화면과 Slack 결과 메시지가 그 항목이 새로 만들어졌다는 문장을 다시 붙인다. 다시 보내지 않으면 위 "저장 위치마다 지우는 방법"의 키체인 명령으로 그 항목을 지울 수 있다. 플러그인은 그 항목을 지우지 않는다. 이때 Slack 메시지는 바로 바뀌지 않는다. 요청이 끝나면 결과 문장으로 바뀐다. vault에서 되풀이되면 저장할 프로필에 vault가 이미 있는데 `vault/vault.key`만 없어지지 않았는지 확인한다. `vault.key`가 없으면 Hermes는 기존 vault를 풀 수 없어서 저장을 거부한다. 백업에 그 프로필의 `vault/vault.key`가 있으면 제자리에 되돌린다. 백업이 없으면 `vault` 폴더를 다른 이름(예: `vault.old`)으로 옮긴 뒤 다시 보낸다. 그러면 Hermes가 새 vault와 새 열쇠를 만들고, 기존 vault에 있던 로그인은 다시 넣어야 한다. |
| 페이지에 "보내지 못했습니다."와 "가려진 값처럼 보여 저장하지 않았습니다. 원래 키 전체를 붙여 넣어 주세요."가 나온다 | 붙여 넣은 값이 `***`, `sk-abc...wxyz`, `[REDACTED]`처럼 가려서 보여 주는 모양이라 Hermes가 저장을 거부했다(오류 코드 `masked_value`). 아무 저장 위치에도 쓰지 않았다. 서비스 관리 화면에서 원래 키 전체를 복사해 같은 페이지에서 다시 보낸다. 이 실패도 5번 중 한 번으로 센다. |
| "시도 횟수를 넘었습니다" | 값 보내기가 5번 실패해 요청이 끝났다. Slack 메시지는 사유 `too_many_attempts`가 붙은 실패 문장으로 바뀐다. API 키, 로그인, 키체인 비밀번호면 "실패: 저장하지 못했습니다"로 시작하고, 일회용 코드면 "실패: 코드를 로그인 페이지로 넘기지 못했습니다"로 시작한다. 실패한 시도가 키체인 항목을 새로 만들었거나 기존 항목에 썼으면, Slack 메시지에 위 키체인 문장이 붙는다. 페이지에는 앞선 네 번의 시도가 남긴 것만 붙고, 다섯 번째 시도만 남긴 것은 붙지 않는다. 새 링크를 요청한다. |
| 에이전트나 명령이 "입력 페이지를 띄우지 못했습니다(…)"라고 답한다 | 괄호 안이 원인이다. "tailscale CLI not found"가 있으면 Tailscale 명령줄 도구를 찾지 못한 것이다. `/Applications/Tailscale.app/Contents/MacOS/Tailscale`이 있으면 이 오류는 나오지 않는다. 그 경로에 없을 때 터미널에서 `which tailscale`이 경로를 보여 주면, 그 경로를 `SECURE_INPUT_TAILSCALE_BIN`에 적고 게이트웨이를 다시 시작한다. 게이트웨이 프로세스의 `PATH`는 터미널의 `PATH`와 다를 수 있기 때문이다. `which tailscale`도 아무것도 내지 않으면 이 컴퓨터에 Tailscale 명령줄 도구가 없는 것이므로, 위 "필요한 것"의 quickstart를 따라 Tailscale을 설치한다. "MagicDNS off?"가 있으면 MagicDNS를 켠다. "serve_add_failed"가 있으면 Tailscale Serve가 주소를 열지 못한 것이다. 먼저 위 "필요한 것"의 Tailscale 준비 확인 명령을 실행해 `"CertDomains"` 다음 줄에 이 컴퓨터의 이름이 나오는지 본다. 이름이 없으면 관리 화면의 DNS 페이지에서 HTTPS를 켠 뒤 다시 요청한다. 이름이 있으면 같은 출력의 `"BackendState"`를 본다. `"Running"`이 아니면 Hermes 컴퓨터의 Tailscale 앱을 켜고 로그인한 뒤 다시 요청한다. `"Running"`이면 `tailscale serve status`를 실행한다. 이 명령이 오류를 내면, 터미널에 나온 오류 문장을 [Tailscale Serve 문서](https://tailscale.com/docs/features/tailscale-serve)에서 찾아 고친 뒤 다시 요청한다. 이 README는 Tailscale의 오류별 해결 방법을 다루지 않는다. 이 명령이 오류 없이 끝나는데도 되풀이되면 Tailscale의 오류 문장을 직접 본다. 플러그인은 그 문장을 감사 로그나 Hermes 로그에 남기지 않는다. Hermes 컴퓨터에서 `tailscale serve --bg --https=443 --set-path /secure-input-test http://127.0.0.1:9/secure-input-test`로 시험용 주소를 더하면 실패 원인이 터미널에 나온다. 이 시험 명령은 플러그인이 주소를 더할 때 쓰는 명령과 같은 모양이고, 주소 경로와 포트만 다르다. `127.0.0.1:9`는 아무 서버도 없는 주소다. 이 시험은 Serve가 주소를 더할 수 있는지만 본다. 성공하면 "Serve started and running in the background."가 나온다. 시험 뒤에는 `tailscale serve --https=443 --set-path /secure-input-test off`로 그 주소를 지우고, `tailscale serve status`가 시험 전과 같은지 본다. 시험 명령이 오류를 냈으면 터미널에 나온 오류 문장을 Tailscale Serve 문서에서 찾아 고친 뒤 다시 요청한다. 시험 명령이 성공하는데도 플러그인이 계속 실패하면, 터미널의 `tailscale`과 플러그인이 쓰는 명령줄 도구가 다른 프로그램일 수 있다. 플러그인은 위 "필요한 것"에 적은 순서로 도구를 고른다(`SECURE_INPUT_TAILSCALE_BIN`, 다음에 `/Applications/Tailscale.app/Contents/MacOS/Tailscale`, 다음에 `PATH`의 `tailscale`). 그 순서로 고른 도구의 경로를 `tailscale` 자리에 넣어 시험 명령과 지우는 명령을 다시 실행한다. 이때 나온 오류 문장이 플러그인이 받은 오류다. |
| "이미 열린 요청이 3개라 새 요청을 만들지 않았습니다" | 이 컴퓨터에 끝나지 않은 요청이 3개 있다. 앞의 요청이 끝난 뒤 다시 요청한다. |
| "프로필을 찾지 못해 요청을 만들지 않았습니다" | `--profile`이나 `target_profile`에 적은 프로필의 폴더가 없다. `hermes profile list`로 프로필 이름을 확인한다. |
| 에이전트가 이 도구를 모르고 채팅으로 비밀번호를 묻는다. 또는 Slack에서 `!secure-input`이 알 수 없는 명령이라고 나온다 | 플러그인이 꺼져 있거나, 그 대화의 프로필에 설치되지 않았거나, 게이트웨이를 다시 시작하지 않았다. 그 프로필을 대상으로 `hermes -p <프로필> plugins list --user`와 `hermes -p <프로필> tools list --platform slack`을 확인하고 게이트웨이를 다시 시작한다. |
| Slack에 버튼 대신 링크 주소가 들어간 일반 글 메시지가 왔다 | 플러그인이 Slack 버튼 메시지를 보내지 못해 일반 글 메시지로 대신 보냈다. 링크는 똑같이 쓸 수 있고, 값은 Slack으로 가지 않는다. |

## 개발

테스트는 Hermes에 들어 있는 Python으로 내려받은 폴더에서 실행한다.

```bash
~/.hermes/hermes-agent/.venv/bin/python -m pytest tests -q
```

시험용 설정 `allow_no_identity_header`(기본값 `false`)를 `true`로 바꾸면 계정 정보가 없는 접속도 받으므로, 실제로 쓰는 Hermes에서는 켜지 않는다.

화면 빌드와 시험은 Node.js 22(`node --version` 출력 `v22.23.1`)와 npm 10.9.8에서 확인했다. 다른 주 버전은 확인하지 않았다. Node.js는 [Node.js 내려받기 페이지](https://nodejs.org/en/download)에서 설치한다.
입력 페이지 화면을 고친 뒤에는 `ui/` 폴더에서 다시 빌드한다. 빌드 결과는 `secure_input/static/`에 쓰이고, 이 폴더를 함께 커밋한다.
브라우저 시험은 Playwright로 돌린다. 시험 설정에는 Chromium 두 프로젝트(`chromium-mobile`, `chromium-desktop`)와 WebKit 두 프로젝트가 있다. 아래 명령은 Chromium 두 프로젝트만 돌린다. WebKit 프로젝트는 이 플러그인을 만든 Mac에서 Playwright WebKit이 버튼 클릭을 처리하지 못해 확인하지 못했다.

```bash
cd ui
npm ci
npx playwright install chromium
npm run build
npm run test
npx playwright test --project=chromium-mobile --project=chromium-desktop
```

실제 Tailscale Serve와 Mac 키체인을 거치는 확인 스크립트는 두 개다. 둘 다 가짜 값만 쓰고, 시험이 만든 키체인 항목을 지운다.

- `scripts/real_roundtrip_v2.py`: 실제 입력 페이지 서버, 저장 과정, `/usr/bin/security`로 여섯 가지 저장을 돌린다. Tailscale은 가짜를 쓴다.
- `scripts/live_tailscale_v2.py`: 실제 Tailscale Serve 주소를 거쳐 저장을 돌린다. `tailscale serve status`가 "No serve config"일 때만 시작한다.

git 저장소 구조는 이렇다.
`plugin.yaml`과 `__init__.py`는 Hermes가 플러그인을 불러올 때 읽는 파일이다.
`secure_input/`에는 에이전트 도구와 명령 등록, 요청마다 뜨는 입력 페이지 서버, Tailscale Serve 관리, 저장 위치마다의 저장, 감사 로그 코드가 있다.
`secure_input/static/`은 빌드된 입력 페이지 화면이고, 그 원본은 `ui/`에 있다.
`tests/`는 Python 테스트이고, `scripts/`는 실제 Tailscale, Mac 키체인, Slack으로 확인할 때 쓴 스크립트다.
`docs/`에는 서버와 화면 사이의 약속(`docs/protocol.md`), Hermes 연동 조사(`docs/integration-notes.md`), 일회용 코드 방식(`docs/otp-code-feasibility.md`)이 있다.

## 라이선스

[MIT](LICENSE)
