// Global teardown: merge per-worker axe results (e2e/a11y.spec.ts) into
//   ui/captures/axe-results.json  (every scan, every violation with its nodes)
//   ui/captures/axe-summary.md    (violations per screen by impact)
// and the same two files into docs/ui-review/, which the screen review record (web-design-guidelines.md) cites.
// Skips writing when the run did not cover all 112 scans (e.g. a filtered run), so a partial run never
// overwrites the full record. The output holds no timestamps, so an unchanged page gives unchanged files.

import { mkdir, readdir, readFile, stat, writeFile } from 'node:fs/promises'
import path from 'node:path'

const PROJECTS: Record<string, string> = { 'chromium-mobile': '390x844', 'chromium-desktop': '1280x800' }
const SCREENS: Record<string, string> = {
  'A-input': '입력 화면, 시나리오 A(API 키)',
  'B-input': '입력 화면, 시나리오 B(로그인, 인증 앱 설정 키 칸 펼침)',
  'C-input': '입력 화면, 시나리오 C(일회용 코드)',
  'D-input': '입력 화면, 시나리오 D(비밀번호, 허용 목록의 기존 키체인 항목, 덮어쓰기 안내)',
  'B-input-changed': '입력 화면, 시나리오 B에서 요청한 쪽과 다른 프로필과 아이디 종류를 고름(프로필 경고 줄 표시)',
  'A-input-error': '오류가 표시된 입력 화면(A에서 빈 값 제출)',
  'A2-input': '입력 화면, 시나리오 A2(API 키, .env와 Mac 키체인 둘 다 켜짐)',
  'A2-input-off': '입력 화면, 시나리오 A2에서 두 저장 위치를 모두 끄고 보내려 함(경고와 오류 표시)',
  'D2-input': '입력 화면, 시나리오 D2(비밀번호, 새 키체인 항목 안내)',
  'D3-input': '입력 화면, 시나리오 D3(비밀번호, 허용 목록 항목이 키체인에 없음, 보안 확인 3차 R3-4)',
  'D-storage-failed': '저장 실패 알림, 시나리오 D(실패 전에 키체인 항목에 썼음, 보안 확인 3차 R3-2)',
  'D-storage-failed-tmp-left': '저장 실패 알림, 시나리오 D(임시 키체인 항목이 남았을 수 있음, 재확인 RC-3)',
  saving: '저장 중 표시(시나리오 A2)',
  'A2-unavailable': '쓸 수 없는 저장 위치 오류(시나리오 A2, 키체인 접근 목록)',
  'A-done': '완료 화면, 시나리오 A',
  'B-done': '완료 화면, 시나리오 B',
  'C-done': '완료 화면, 시나리오 C',
  'D-done': '완료 화면, 시나리오 D',
  'A2-done-partial': '완료 화면, 일부만 저장(시나리오 A2)',
  'A2-done-after-created': '완료 화면, 키체인에만 보낸 값이 새 항목을 만들고 실패한 뒤 .env에 저장(시나리오 A2, 2차 재확인 RC2-1)',
  'end-opened': '끝 화면: 이미 열린 링크',
  'end-denied': '끝 화면: 허용되지 않은 Tailscale 계정',
  'end-cancelled': '끝 화면: 요청 취소',
  'end-timeout': '끝 화면: 제출 시간 지남',
  'end-timeout-after-failed': '끝 화면: 저장 실패 뒤 다시 보내지 않고 제출 시간 지남(재확인 RC-2)',
  'end-cancelled-created': '끝 화면: 키체인 항목을 새로 만든 저장 실패 뒤 취소(재확인 RC-1)',
  'end-too-many-created': '끝 화면: 키체인 항목을 새로 만든 저장 실패 뒤 시도 횟수를 넘음(시나리오 D2, 2차 재확인 RC2-3)',
  'end-unknown': '끝 화면: 저장 결과를 확인하지 못함',
}
const SCHEMES = ['light', 'dark']
const IMPACTS = ['critical', 'serious', 'moderate', 'minor'] as const
const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa', 'best-practice']

type Row = {
  project: string
  viewport: string
  screen: string
  colorScheme: string
  violations: { id: string; impact: string | null; help: string; nodes: unknown[] }[]
  incomplete: { id: string; impact: string | null; help: string; nodes: number }[]
  passes: number
  inapplicable: number
  axeVersion: string
}

export default async function mergeAxe() {
  const dir = path.resolve(import.meta.dirname, '../test-results/axe')
  let files: string[] = []
  try {
    files = (await readdir(dir)).filter((f) => f.endsWith('.json'))
  } catch {
    return
  }
  const rows: Row[] = []
  for (const f of files) rows.push(...(JSON.parse(await readFile(path.join(dir, f), 'utf8')) as Row[]))

  const order = (r: Row) =>
    [Object.keys(SCREENS).indexOf(r.screen), Object.keys(PROJECTS).indexOf(r.project), SCHEMES.indexOf(r.colorScheme)]
  rows.sort((a, b) => {
    const x = order(a)
    const y = order(b)
    return x[0] - y[0] || x[1] - y[1] || x[2] - y[2]
  })
  const key = (r: { project: string; screen: string; colorScheme: string }) => `${r.project}|${r.screen}|${r.colorScheme}`
  const seen = new Set(rows.map(key))
  const expected = Object.keys(PROJECTS).flatMap((p) =>
    Object.keys(SCREENS).flatMap((s) => SCHEMES.map((c) => ({ project: p, screen: s, colorScheme: c }))),
  )
  const missing = expected.filter((x) => !seen.has(key(x)))
  if (missing.length || rows.length !== expected.length) {
    console.log(`[merge-axe] ${missing.length} of ${expected.length} scans missing; ui/captures/axe-* left unchanged.`)
    return
  }

  const by = (r: Row, impact: string) => r.violations.filter((v) => v.impact === impact).length
  const total = (impact: string) => rows.reduce((n, r) => n + by(r, impact), 0)
  const summary = Object.fromEntries(IMPACTS.map((i) => [i, total(i)]))
  const out = {
    tool: '@axe-core/playwright',
    axeVersion: rows[0].axeVersion,
    browser: 'chromium',
    tags: TAGS,
    viewports: PROJECTS,
    screens: SCREENS,
    scans: rows.length,
    summary,
    results: rows,
  }
  const target = path.resolve(import.meta.dirname, '../captures')
  await mkdir(target, { recursive: true })
  await writeFile(path.join(target, 'axe-results.json'), JSON.stringify(out, null, 2) + '\n')

  const incompleteIds = [...new Set(rows.flatMap((r) => r.incomplete.map((i) => i.id)))].sort()
  const md = [
    '# axe-core 접근성 측정 요약',
    '',
    '이 파일과 `axe-results.json`은 `cd ui && npm run test:e2e`가 끝날 때 `ui/e2e/merge-axe.ts`가 다시 만든다.',
    `측정 도구는 @axe-core/playwright(axe-core ${out.axeVersion}), 브라우저는 Chromium이다.`,
    `적용한 규칙 묶음은 ${TAGS.join(', ')}이다.`,
    '화면 크기는 390x844(iPhone 세로)와 1280x800(데스크톱)이다.',
    '밝기는 `prefers-color-scheme`의 light와 dark다.',
    '',
    `측정한 화면 수는 ${rows.length}이다(화면 ${Object.keys(SCREENS).length}종 x 화면 크기 2 x 밝기 2).`,
    `위반 합계는 critical ${summary.critical}, serious ${summary.serious}, moderate ${summary.moderate}, minor ${summary.minor}이다.`,
    '',
    '| 화면 | 크기 | 밝기 | critical | serious | moderate | minor | 통과 규칙 | 판정 보류(incomplete) |',
    '|---|---|---|---|---|---|---|---|---|',
    ...rows.map(
      (r) =>
        `| ${SCREENS[r.screen]} | ${r.viewport} | ${r.colorScheme} | ${IMPACTS.map((i) => by(r, i)).join(' | ')} | ${r.passes} | ${r.incomplete.length} |`,
    ),
    `| 합계 | | | ${IMPACTS.map((i) => summary[i]).join(' | ')} | | |`,
    '',
    '## 판정 보류(incomplete) 항목',
    '',
    'axe가 자동으로 통과나 위반을 정하지 못해 사람이 확인해야 하는 항목이다. 위반 수에는 들어가지 않는다.',
    '',
    ...(incompleteIds.length
      ? incompleteIds.map((id) => {
          const hit = rows.filter((r) => r.incomplete.some((i) => i.id === id))
          const help = hit[0].incomplete.find((i) => i.id === id)!.help
          return `- \`${id}\` (${help}): ${hit.length}개 측정에서 나왔다.`
        })
      : ['- 없음']),
    '',
  ].join('\n')
  await writeFile(path.join(target, 'axe-summary.md'), md)
  // A screen review record (docs/ui-review/) that cites the same measurement gets the same two files, when it exists.
  const review = path.resolve(import.meta.dirname, '../../docs/ui-review')
  const hasReview = await stat(review).then((s) => s.isDirectory(), () => false)
  if (hasReview) {
    await writeFile(path.join(review, 'axe-results.json'), JSON.stringify(out, null, 2) + '\n')
    await writeFile(path.join(review, 'axe-summary.md'), md)
  }
  console.log(`[merge-axe] wrote ${rows.length} scans to ui/captures/${hasReview ? ' and docs/ui-review/' : ''} (axe-results.json, axe-summary.md)`, summary)
}
