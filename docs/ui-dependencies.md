# 입력 화면(ui/) 의존성

`ui/package.json`에 적힌 패키지 전부입니다. 버전 칸은 `ui/package-lock.json`으로 실제 설치된 버전입니다. 화면은 실행 중에 외부로 요청을 보내지 않습니다. 아래 패키지는 모두 빌드할 때 `secure_input/static/`에 묶이거나, 개발과 시험에만 쓰입니다.

## dependencies (빌드 결과물에 묶여 브라우저에서 실행됨)

| 이름 | 버전 | 역할 |
|---|---|---|
| react | 19.3.1 | 화면 구성 요소를 그리는 UI 라이브러리입니다. |
| react-dom | 19.3.1 | React 구성 요소를 브라우저 DOM에 붙입니다. |
| react-hook-form | 7.92.0 | 입력칸 값, 오류, 첫 오류 칸 포커스 이동을 관리합니다. |
| zod | 4.6.7 | 입력값 규칙(공백 자르기, 줄바꿈 금지, 4-10자 코드 등)을 선언하고 검사합니다. CSP 때문에 `jitless` 모드로 씁니다. |
| @hookform/resolvers | 7.0.8 | zod 규칙을 react-hook-form 검사기로 연결합니다. |
| radix-ui | 1.8.1 | shadcn/ui의 Label과 Checkbox 구성 요소가 쓰는 접근성 기본 부품입니다. |
| class-variance-authority | 0.7.1 | shadcn/ui 버튼과 알림의 모양 변형(variant)을 정의합니다. |
| cn | 0.5.2 | Tailwind 클래스 이름을 합치고 충돌을 정리합니다(shadcn 공식 패키지). |
| lucide-react | 1.78.0 | 자물쇠, 시계, 눈 모양 등 아이콘을 SVG로 번들에 넣습니다. |

### `cn` 패키지의 출처 확인 (2026-11-23 조회)

`cn` 코드는 입력 페이지의 JS 번들에 들어가므로 게시자, 저장소, 공식 문서 세 가지를 따로 확인했습니다. 세 가지 모두 확인되어 패키지를 그대로 씁니다.

1. 게시자: `npm view cn maintainers repository time dist-tags --json`의 `maintainers`는 `shadcn <m@shadcn.com>` 한 명입니다. `latest`는 0.5.2(2026-11-02 게시)입니다. `npm view cn@0.5.2 _npmUser`는 `GitHub Actions` trusted publisher(OIDC)입니다. 출처 증명 https://registry.npmjs.org/-/npm/v1/attestations/cn@0.5.2 의 SLSA provenance는 빌드 저장소를 `https://github.com/shadcn-ui/cn`, 워크플로를 `.github/workflows/release.yml`(`refs/heads/main`)로 적고 있습니다. 0.1.0-0.1.1은 2013년에 게시된 같은 이름의 옛 버전입니다. 지금 저장소는 2026-08-31에 만들어졌고, 0.2.0은 그 다음 날 게시되었습니다. 출처 증명은 이 저장소가 쓰는 0.5.2에 대해서만 확인했습니다.
2. 저장소: `repository` 값 `git+https://github.com/shadcn-ui/cn.git`의 저장소 https://github.com/shadcn-ui/cn 가 실제로 있습니다. GitHub API(https://api.github.com/repos/shadcn-ui/cn)에서 소유자는 `shadcn-ui`이고 종류는 `Organization`이며, 보관(archived) 상태가 아닙니다. 릴리스 https://github.com/shadcn-ui/cn/releases/tag/cn%400.5.2 가 npm 게시 시각과 같은 2026-11-02에 만들어졌습니다.
3. 공식 문서: https://ui.shadcn.com/docs/installation/manual 은 의존성 목록에 `cn`을 넣고 "Components import `cn` directly from the `cn` package."라고 안내합니다. https://ui.shadcn.com/docs/changelog/2026-09-cn 은 "Every shadcn component now imports `cn` from the `cn` package."라고 적고, 그 패키지를 https://github.com/shadcn-ui/cn 로 연결합니다.

## devDependencies (빌드와 시험에만 쓰임)

| 이름 | 버전 | 역할 |
|---|---|---|
| vite | 8.3.8 | 개발 서버와 빌드 도구입니다. `base: './'`로 상대 경로 산출물을 만듭니다. |
| @vitejs/plugin-react | 6.3.0 | Vite에서 React JSX를 변환합니다. |
| typescript | 7.0.2 | 타입 검사(`tsc -b`)를 합니다. |
| tailwindcss | 4.3.5 | 유틸리티 클래스로 스타일을 만들고 CSS 파일 하나로 내보냅니다. |
| @tailwindcss/vite | 4.3.5 | Tailwind를 Vite 빌드에 연결합니다. |
| shadcn | 4.23.0 | shadcn/ui 구성 요소를 받아 온 CLI이며, `shadcn/tailwind.css` 기본 스타일을 제공합니다. |
| tw-animate-css | 1.4.0 | shadcn/ui가 쓰는 애니메이션 CSS입니다. `prefers-reduced-motion`에서는 꺼집니다. |
| vitest | 5.1.1 | 암호화와 입력 규칙 단위 시험을 돌립니다. |
| @playwright/test | 1.65.1 | chromium과 webkit에서 390x844, 1280x800 화면 시험과 캡처를 돌립니다. |
| @axe-core/playwright | 4.14.0 | 화면 시험 중 접근성(WCAG 2.2 AA) 위반을 측정합니다. |
| @types/node | 24.19.2 | 시험 코드와 설정 파일의 Node 타입 정의입니다. |
| @types/react | 19.3.0 | React 타입 정의입니다. |
| @types/react-dom | 19.3.0 | React DOM 타입 정의입니다. |

암호화는 브라우저 내장 WebCrypto만 씁니다. 암호 라이브러리는 없습니다.

## shadcn/ui에서 받아 온 구성 요소

`ui/src/components/ui/`의 파일은 `npx shadcn@4.23.0 add <이름>`으로 받아 온 소스입니다. 패키지가 아니므로 위 표에는 없습니다.

| 구성 요소 | 파일 | 쓰는 곳 |
|---|---|---|
| alert | `alert.tsx` | 오류와 경고 상자 |
| button | `button.tsx` | 보내기, 취소, 보이기 버튼 |
| checkbox | `checkbox.tsx` | 저장 위치 목록(규약 2판, 2026-11-25 추가). `radix-ui`의 Checkbox와 `lucide-react`의 CheckIcon을 씁니다. 새 패키지는 더하지 않았습니다. |
| field | `field.tsx` | 입력칸 묶음, 설명, 오류 문장 |
| input | `input.tsx` | 글자 입력칸 |
| label | `label.tsx` | 입력칸 이름 |
| native-select | `native-select.tsx` | 프로필, 아이디 종류 고르기 |
| separator | `separator.tsx` | 구역 나누는 선 |
