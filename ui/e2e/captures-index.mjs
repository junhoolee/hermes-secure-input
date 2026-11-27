// Writes ui/captures/CAPTURES.md: one row per capture file in ui/captures/screens, with the screen name,
// viewport and colour mode read from the file name (<iphone|desktop>-<light|dark>-<screen>.png).
// Run after `npm run screenshots`: `node e2e/captures-index.mjs`.

import { execFileSync } from 'node:child_process'
import { readdir, stat, writeFile } from 'node:fs/promises'
import path from 'node:path'

const DIR = path.resolve(import.meta.dirname, '../captures/screens')
const OUT = path.resolve(import.meta.dirname, '../captures/CAPTURES.md')

const SCREENS = {
  'login-form': ['로그인 입력: Hermes 암호화 저장소 한 줄(끌 수 없음), 같은 로그인 바꾸기 규칙, 인증 앱 설정 키 경고(칸을 펼치지 않음)', '바뀜'],
  'apikey-form': ['API 키 입력: .env 켜짐(기본값), Mac 키체인 꺼짐', '바뀜'],
  'apikey-both': ['API 키 입력: .env(지난 저장 기록)와 Mac 키체인(Hermes가 고름, 이유 인용, 덮어쓰기 안내) 둘 다 켜짐', '바뀜'],
  'apikey-env-off': ['API 키 입력: .env를 끔(A.12 .env 경고), 프로필 고르기 숨김', '바뀜'],
  'apikey-needed-off': ['API 키 입력: Hermes가 필요하다고 표시한 Mac 키체인을 끔(경고)', '바뀜'],
  'secret-form': ['비밀번호 입력: 허용 목록의 기존 키체인 항목, 덮어쓰기 안내(A.12), 두 번 입력', '새 화면'],
  'secret-new': ['비밀번호 입력: 새 키체인 항목 안내(A.12)', '새 화면'],
  'secret-listed-missing': ['비밀번호 입력: 허용 목록 항목이 키체인에 없음(새 항목을 만든다는 안내, 보안 확인 3차 R3-4)', '새 화면'],
  saving: ['저장 중 표시(A.12), 보내기와 취소 버튼 누를 수 없음', '새 화면'],
  unavailable: ['쓸 수 없는 저장 위치 오류(Mac 키체인 접근 목록), 다시 보낼 수 있음', '새 화면'],
  'done-all': ['완료: 켠 저장 위치에 모두 저장', '바뀜'],
  'done-partial': ['완료: 일부만 저장(.env 저장, Mac 키체인 실패)', '새 화면'],
  'done-keychain': ['완료: Mac 키체인에 저장(비밀번호)', '새 화면'],
  unknown: ['끝: 저장 결과를 확인하지 못함(A.12)', '새 화면'],
  'storage-failed': ['저장 실패 알림: 실패 전에 키체인 항목에 썼음(예전 값이 바뀌었을 수 있음, 보안 확인 3차 R3-2)', '새 화면'],
  'cancelled-sent': ['끝: 키체인 항목에 쓴 제출 뒤 취소(보안 확인 3차 R3-2)', '새 화면'],
  'cancelled-code': ['끝: 서버가 답한 일회용 코드 제출 뒤 취소(보안 확인 3차 R3-2)', '새 화면'],
  'unknown-tmp-left': ['끝: 저장 결과를 확인하지 못함, 키체인 줄이 시간 제한에 걸림(임시 항목 안내, 보안 확인 3차 R3-3)', '새 화면'],
  'storage-failed-tmp-left': ['저장 실패 알림: 임시 키체인 항목이 남았을 수 있음(재확인 RC-3)', '새 화면'],
  'timeout-after-failed': ['끝: 저장 실패 뒤 다시 보내지 않고 제출 시간 지남(예전 값, 임시 항목 안내, 재확인 RC-2)', '새 화면'],
  'cancelled-created': ['끝: 키체인 항목을 새로 만든 저장 실패 뒤 취소(재확인 RC-1)', '새 화면'],
  'done-after-created': ['완료: 키체인에만 보낸 값이 새 항목을 만들고 실패한 뒤 .env에 저장(새 항목 안내, 2차 재확인 RC2-1)', '새 화면'],
  'too-many-created': ['끝: 키체인 항목을 새로 만든 저장 실패가 이어져 시도 횟수를 넘음(새 항목 안내, 2차 재확인 RC2-3)', '새 화면'],
  denied: ['끝: 허용되지 않은 Tailscale 계정(지난 독자 시험 지적 1, 4 고침)', '문장 바뀜'],
  'otp-form': ['일회용 코드 입력', '요청자 줄 문장 바뀜(독자 시험 1회차 P1)'],
  'otp-filled': ['일회용 코드 입력(코드 넣음)', '요청자 줄 문장 바뀜(독자 시험 1회차 P1)'],
  'otp-done': ['일회용 코드 완료', '바뀌지 않음'],
  opened: ['끝: 이미 열린 링크', '바뀌지 않음'],
  timeout: ['끝: 제출 시간 지남', '바뀌지 않음'],
  cancelled: ['끝: 요청 취소', '바뀌지 않음'],
}
const VIEW = { iphone: '휴대폰 세로 390x844', desktop: 'PC 1280x800' }
const MODE = { light: '밝은 화면', dark: '어두운 화면' }

const files = (await readdir(DIR)).filter((f) => f.endsWith('.png')).sort()
const rows = []
for (const f of files) {
  const m = /^(iphone|desktop)-(light|dark)-(.+)\.png$/.exec(f)
  if (!m) throw new Error(`unexpected capture name: ${f}`)
  const [, view, mode, screen] = m
  const s = SCREENS[screen]
  if (!s) throw new Error(`no screen name for ${screen}`)
  rows.push({ f, screen, view, mode, s, size: (await stat(path.join(DIR, f))).size })
}
const order = Object.keys(SCREENS)
rows.sort((a, b) => order.indexOf(a.screen) - order.indexOf(b.screen) || a.view.localeCompare(b.view) || a.mode.localeCompare(b.mode))

// The commit whose build (secure_input/static) was captured: HEAD when this runs right after the captures.
const commit = process.env.CAPTURE_COMMIT ?? execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim()
const md = [
  '# 캡처 목록',
  '',
  '`cd ui && npm run screenshots` 뒤 `node e2e/captures-index.mjs`가 이 파일을 만든다.',
  `찍은 커밋은 \`${commit}\`이다. 그 커밋의 빌드 결과(\`secure_input/static\`)를 찍었다.`,
  '뷰포트는 휴대폰 세로 390x844(`chromium-mobile`)와 PC 1280x800(`chromium-desktop`)이다.',
  '캡처는 가짜 서버(`e2e/harness.ts`, 시나리오 `e2e/fixtures.json`)로 찍었다. 저장 중, 일부만 저장, 결과 확인 못 함 같은 상태를 정해진 대로 만들기 위해서다.',
  '넣은 값은 모두 가짜(`SECRET-CANARY-...`)다. 모든 캡처는 첫 제목부터 마지막 버튼까지 담은 전체 페이지 캡처다.',
  '화면 배율은 1이다. 파일 옆의 같은 이름 `.txt`는 화면에 보이는 글자(화면 읽기 전용 글자 제외)다.',
  '',
  `캡처 파일은 ${rows.length}장이다(화면 ${new Set(rows.map((r) => r.screen)).size}종 x 화면 크기 2 x 밝기 2).`,
  '',
  '| 파일 | 화면 | 바뀐 정도 | 뷰포트 | 색 모드 |',
  '|---|---|---|---|---|',
  ...rows.map((r) => `| \`screens/${r.f}\` | ${r.s[0]} | ${r.s[1]} | ${VIEW[r.view]} | ${MODE[r.mode]} |`),
  '',
]
await writeFile(OUT, md.join('\n'))
console.log(`wrote ${rows.length} rows to ${OUT}`)
