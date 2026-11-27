// axe-core on every screen a user can see, in light and dark colour schemes:
//   input A, B, C, D / input B with another profile and id type chosen (profile mismatch line shown) /
//   input with a field error (A, empty submit) / done A, B, C, D /
//   input A2 (both stores on) and with both switched off / input D2 (new keychain item) /
//   input D3 (listed item the keychain does not have) / storage-failed alert (keychain item touched) /
//   storage-failed alert (temporary item may be left) / saving / store-unavailable error / done partly saved /
//   end screens "link already opened", "Tailscale account not allowed", "request cancelled", "submit time passed",
//   "submit time passed after a failed save", "cancelled after a failed save that made the item", "too many attempts
//   after failed saves that made the item" and "result unknown" / done saved to .env after a keychain-only send that
//   made the item.
// 28 screens x 2 sizes (chromium-mobile 390x844, chromium-desktop 1280x800) x 2 schemes = 112 scans.
// serious + critical must be 0. Each worker writes test-results/axe/<project>-<worker>.json;
// e2e/merge-axe.ts combines them into ui/captures/axe-results.json and axe-summary.md.
// The axe record is taken on Chromium only, so it holds exactly one scan per screen, size and scheme;
// WebKit layouts are covered by flows.spec.ts.

import { mkdir, writeFile } from 'node:fs/promises'
import path from 'node:path'
import AxeBuilder from '@axe-core/playwright'
import { expect, test, type Page } from '@playwright/test'
import { mockServer, PAGE_PATH, type Scenario } from './harness.ts'

const AXE_TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa', 'best-practice']

type Row = {
  project: string
  viewport: string
  screen: string
  colorScheme: 'light' | 'dark'
  violations: {
    id: string
    impact: string | null | undefined
    help: string
    helpUrl: string
    nodes: { target: string[]; html: string; failureSummary?: string }[]
  }[]
  incomplete: { id: string; impact: string | null | undefined; help: string; nodes: number }[]
  passes: number
  inapplicable: number
  axeVersion: string
}

const rows: Row[] = []

test.beforeEach(({}, info) => {
  test.skip(!info.project.name.startsWith('chromium-'), 'the axe record is taken on the two Chromium projects')
})

async function scan(page: Page, project: string, screen: string, colorScheme: 'light' | 'dark') {
  const r = await new AxeBuilder({ page }).withTags(AXE_TAGS).analyze()
  const vp = page.viewportSize()!
  rows.push({
    project,
    viewport: `${vp.width}x${vp.height}`,
    screen,
    colorScheme,
    violations: r.violations.map((v) => ({
      id: v.id,
      impact: v.impact,
      help: v.help,
      helpUrl: v.helpUrl,
      nodes: v.nodes.map((n) => ({ target: n.target.map(String), html: n.html, failureSummary: n.failureSummary })),
    })),
    incomplete: r.incomplete.map((v) => ({ id: v.id, impact: v.impact, help: v.help, nodes: v.nodes.length })),
    passes: r.passes.length,
    inapplicable: r.inapplicable.length,
    axeVersion: r.testEngine.version,
  })
  const bad = r.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical')
  expect(bad.map((v) => `${v.id}: ${v.help} (${v.nodes.map((n) => n.target.join(' ')).join(', ')})`), `${screen} ${colorScheme}`).toEqual([])
}

async function fillAndSubmit(page: Page, s: Scenario) {
  if (s === 'A') await page.getByLabel('API 키', { exact: true }).fill('SECRET-CANARY-axe')
  if (s === 'B') {
    await page.getByLabel('이메일 주소').fill('tester@example.com')
    await page.getByLabel('비밀번호', { exact: true }).fill('SECRET-CANARY-axe')
  }
  if (s === 'C') await page.getByLabel('일회용 코드', { exact: true }).fill('123456')
  if (s === 'D') {
    await page.getByLabel('비밀번호', { exact: true }).fill('SECRET-CANARY-axe')
    await page.getByLabel('비밀번호 다시 입력', { exact: true }).fill('SECRET-CANARY-axe')
  }
  await page.getByTestId('submit').click()
  await expect(page.getByTestId('done-screen')).toBeVisible()
}

for (const scheme of ['light', 'dark'] as const) {
  test.describe(`axe (${scheme})`, () => {
    test.use({ colorScheme: scheme })

    for (const s of ['A', 'B', 'C', 'D'] as const) {
      test(`scenario ${s}: input and done`, async ({ page }, info) => {
        await mockServer(page, s)
        await page.goto(PAGE_PATH)
        await expect(page.getByTestId('credential-form')).toBeVisible()
        // The folded authenticator-key section is scanned open, so its field is measured too.
        if (s === 'B') await page.getByRole('button', { name: '인증 앱 설정 키 추가(선택)' }).click()
        await scan(page, info.project.name, `${s}-input`, scheme)
        await fillAndSubmit(page, s)
        await scan(page, info.project.name, `${s}-done`, scheme)
      })
    }

    test('scenario B: another profile than the requester chosen (mismatch line shown)', async ({ page }, info) => {
      await mockServer(page, 'B')
      await page.goto(PAGE_PATH)
      await page.getByLabel('저장할 프로필').selectOption('default')
      await page.getByText('사용자 이름', { exact: true }).click()
      await expect(page.getByTestId('profile-mismatch')).toContainText('쓰지 못합니다')
      await scan(page, info.project.name, 'B-input-changed', scheme)
    })

    test('scenario A: empty submit shows a field error', async ({ page }, info) => {
      await mockServer(page, 'A')
      await page.goto(PAGE_PATH)
      await page.getByTestId('submit').click()
      await expect(page.getByText('API 키를 입력하세요.')).toBeVisible()
      await scan(page, info.project.name, 'A-input-error', scheme)
    })

    test('scenario A2: both stores on (overwrite note), then both switched off (warnings, none-on error)', async ({ page }, info) => {
      await mockServer(page, 'A2')
      await page.goto(PAGE_PATH)
      await expect(page.getByTestId('keychain-overwrite')).toBeVisible()
      await scan(page, info.project.name, 'A2-input', scheme)
      await page.getByRole('checkbox', { name: 'Mac 키체인' }).click()
      await page.getByRole('checkbox', { name: '설정 파일(.env)' }).click()
      await page.getByLabel('API 키', { exact: true }).fill('SECRET-CANARY-axe')
      await page.getByTestId('submit').click()
      await expect(page.getByTestId('stores-none')).toBeVisible()
      await expect(page.getByTestId('store-warning-env')).not.toBeEmpty()
      await scan(page, info.project.name, 'A2-input-off', scheme)
    })

    test('scenario D2: secret for a new keychain item', async ({ page }, info) => {
      await mockServer(page, 'D2')
      await page.goto(PAGE_PATH)
      await expect(page.getByTestId('keychain-new')).toBeVisible()
      await scan(page, info.project.name, 'D2-input', scheme)
    })

    test('scenario D3: listed item the keychain does not have (security review 3, R3-4)', async ({ page }, info) => {
      await mockServer(page, 'D3')
      await page.goto(PAGE_PATH)
      await expect(page.getByTestId('keychain-listed-missing')).toBeVisible()
      await scan(page, info.project.name, 'D3-input', scheme)
    })

    test('storage failed alert: keychain item written before the failure (security review 3, R3-2)', async ({ page }, info) => {
      await mockServer(page, 'D', {
        submitReplies: [
          {
            status: 422,
            body: {
              ok: false,
              error_code: 'storage_failed',
              message: '값을 저장하지 못했습니다. 다시 시도해 주세요.',
              result_unknown: false,
              stores: [{ store: 'keychain', saved: false, replaced: null, error: 'keychain_verify_failed', tmp_left: false, main_touched: true }],
            },
          },
        ],
      })
      await page.goto(PAGE_PATH)
      await page.getByLabel('비밀번호', { exact: true }).fill('SECRET-CANARY-axe')
      await page.getByLabel('비밀번호 다시 입력', { exact: true }).fill('SECRET-CANARY-axe')
      await page.getByTestId('submit').click()
      await expect(page.getByTestId('store-alert')).toContainText('예전 값이 바뀌었을 수 있습니다')
      await scan(page, info.project.name, 'D-storage-failed', scheme)
    })

    // Recheck of security review 3 (RC-1 to RC-3): the three screens that state added.
    const kcFail = (o: Record<string, boolean>) => ({
      status: 422,
      body: {
        ok: false,
        error_code: 'storage_failed',
        message: '값을 저장하지 못했습니다. 다시 시도해 주세요.',
        result_unknown: false,
        stores: [
          { store: 'keychain', saved: false, replaced: null, error: 'keychain_verify_failed', tmp_left: false, main_touched: false, main_created: false, ...o },
        ],
      },
    })
    const sendSecret = async (page: Page) => {
      await page.getByLabel('비밀번호', { exact: true }).fill('SECRET-CANARY-axe')
      await page.getByLabel('비밀번호 다시 입력', { exact: true }).fill('SECRET-CANARY-axe')
      await page.getByTestId('submit').click()
      await expect(page.getByTestId('store-alert')).toBeVisible()
    }

    test('storage failed alert: a temporary keychain item may be left (recheck RC-3)', async ({ page }, info) => {
      await mockServer(page, 'D', { submitReplies: [kcFail({ tmp_left: true })] })
      await page.goto(PAGE_PATH)
      await sendSecret(page)
      await expect(page.getByTestId('store-alert')).toContainText('임시 키체인 항목에 이번에 넣은 값이 남아 있을 수 있습니다.')
      await scan(page, info.project.name, 'D-storage-failed-tmp-left', scheme)
    })

    test('end screen: submit time passed after a failed save (recheck RC-2)', async ({ page }, info) => {
      await mockServer(page, 'D', { openPatch: { submit_deadline_s: 3 }, submitReplies: [kcFail({ main_touched: true, tmp_left: true })] })
      await page.goto(PAGE_PATH)
      await sendSecret(page)
      await expect(page.getByTestId('end-screen')).toHaveAttribute('data-reason', 'deadline_passed', { timeout: 10_000 })
      await expect(page.getByTestId('end-screen')).toContainText('앞서 보낸 값은 저장하지 못했고')
      await scan(page, info.project.name, 'end-timeout-after-failed', scheme)
    })

    test('end screen: cancelled after a failed save that made the keychain item (recheck RC-1)', async ({ page }, info) => {
      await mockServer(page, 'D', { submitReplies: [kcFail({ main_created: true })] })
      await page.goto(PAGE_PATH)
      await sendSecret(page)
      await page.getByRole('button', { name: '요청 취소', exact: true }).click()
      await page.getByRole('button', { name: '요청 취소하기' }).click()
      await expect(page.getByTestId('end-screen')).toContainText('새로 만들어졌고')
      await scan(page, info.project.name, 'end-cancelled-created', scheme)
    })

    // Second recheck of security review 3 (RC2-1, RC2-3): the two screens that state added.
    test('done: saved to .env after a keychain-only send that made the item (recheck 2, RC2-1)', async ({ page }, info) => {
      await mockServer(page, 'A2', { submitReplies: [kcFail({ main_created: true })] })
      await page.goto(PAGE_PATH)
      await page.getByLabel('API 키', { exact: true }).fill('SECRET-CANARY-axe')
      await page.getByRole('checkbox', { name: '설정 파일(.env)' }).click()
      await page.getByTestId('submit').click()
      await expect(page.getByTestId('store-alert')).toBeVisible()
      await page.getByRole('checkbox', { name: 'Mac 키체인' }).click()
      await page.getByRole('checkbox', { name: '설정 파일(.env)' }).click()
      await page.getByTestId('submit').click()
      await expect(page.getByTestId('done-screen')).toContainText('새로 만들어졌고')
      await scan(page, info.project.name, 'A2-done-after-created', scheme)
    })

    test('end screen: too many attempts after failed saves that made the item (recheck 2, RC2-3)', async ({ page }, info) => {
      const tooMany = { status: 429, body: { ok: false, error_code: 'too_many_attempts', message: '실패가 너무 많아 이 요청을 끝냈습니다. 새 링크를 요청하세요.' } }
      await mockServer(page, 'D2', { submitReplies: [kcFail({ main_created: true }), tooMany] })
      await page.goto(PAGE_PATH)
      await sendSecret(page)
      await page.getByTestId('submit').click()
      await expect(page.getByTestId('end-screen')).toHaveAttribute('data-reason', 'too_many_attempts')
      await expect(page.getByTestId('end-screen')).toContainText('새로 만들어졌고')
      await scan(page, info.project.name, 'end-too-many-created', scheme)
    })

    test('saving state', async ({ page }, info) => {
      const mock = await mockServer(page, 'A2', { holdSubmit: true })
      await page.goto(PAGE_PATH)
      await page.getByLabel('API 키', { exact: true }).fill('SECRET-CANARY-axe')
      await page.getByTestId('submit').click()
      await expect(page.getByTestId('saving')).toBeVisible()
      await scan(page, info.project.name, 'saving', scheme)
      mock.release()
    })

    test('store unavailable error', async ({ page }, info) => {
      await mockServer(page, 'A2', {
        submitReplies: [
          { status: 422, body: { ok: false, error_code: 'store_unavailable', message: 'x', stores: [{ store: 'keychain', reason: 'keychain_acl_denied' }] } },
        ],
      })
      await page.goto(PAGE_PATH)
      await page.getByLabel('API 키', { exact: true }).fill('SECRET-CANARY-axe')
      await page.getByTestId('submit').click()
      await expect(page.getByTestId('store-alert')).toBeVisible()
      await scan(page, info.project.name, 'A2-unavailable', scheme)
    })

    test('done: partly saved', async ({ page }, info) => {
      await mockServer(page, 'A2', { successLines: { keychain: { saved: false, replaced: null, error: 'keychain_write_failed', main_touched: false } } })
      await page.goto(PAGE_PATH)
      await page.getByLabel('API 키', { exact: true }).fill('SECRET-CANARY-axe')
      await page.getByTestId('submit').click()
      await expect(page.getByTestId('done-store-keychain')).toHaveAttribute('data-status', 'failed')
      await scan(page, info.project.name, 'A2-done-partial', scheme)
    })

    test('end screen: result unknown', async ({ page }, info) => {
      await mockServer(page, 'A2', { submitReplies: [{ abort: true }] })
      await page.goto(PAGE_PATH)
      await page.getByLabel('API 키', { exact: true }).fill('SECRET-CANARY-axe')
      await page.getByTestId('submit').click()
      await expect(page.getByTestId('end-screen')).toHaveAttribute('data-reason', 'result_unknown')
      await scan(page, info.project.name, 'end-unknown', scheme)
    })

    test('end screen: link already opened', async ({ page }, info) => {
      await mockServer(page, 'A', { openReply: { status: 410, body: { ok: false, error_code: 'already_opened' } } })
      await page.goto(PAGE_PATH)
      await expect(page.getByTestId('end-screen')).toHaveAttribute('data-reason', 'already_opened')
      await scan(page, info.project.name, 'end-opened', scheme)
    })

    test('end screen: opened on a device whose Tailscale account is not allowed', async ({ page }, info) => {
      await mockServer(page, 'A', { openReply: { status: 403, body: { ok: false, error_code: 'identity_not_allowed' } } })
      await page.goto(PAGE_PATH)
      await expect(page.getByTestId('end-screen')).toHaveAttribute('data-reason', 'identity_denied')
      await scan(page, info.project.name, 'end-denied', scheme)
    })

    test('end screen: request cancelled', async ({ page }, info) => {
      await mockServer(page, 'A')
      await page.goto(PAGE_PATH)
      await page.getByRole('button', { name: '요청 취소', exact: true }).click()
      await page.getByRole('button', { name: '요청 취소하기' }).click()
      await expect(page.getByTestId('end-screen')).toHaveAttribute('data-reason', 'cancelled')
      await scan(page, info.project.name, 'end-cancelled', scheme)
    })

    test('end screen: submit time passed', async ({ page }, info) => {
      await mockServer(page, 'A', { openPatch: { submit_deadline_s: 2 } })
      await page.goto(PAGE_PATH)
      await expect(page.getByTestId('end-screen')).toHaveAttribute('data-reason', 'deadline_passed', { timeout: 10_000 })
      await scan(page, info.project.name, 'end-timeout', scheme)
    })
  })
}

test.afterAll(async ({}, info) => {
  if (!rows.length) return
  const dir = path.resolve(import.meta.dirname, '../test-results/axe')
  await mkdir(dir, { recursive: true })
  await writeFile(path.join(dir, `${info.project.name}-${info.workerIndex}.json`), JSON.stringify(rows, null, 2))
})
