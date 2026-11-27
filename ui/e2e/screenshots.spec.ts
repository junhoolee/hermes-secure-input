// Captures for review and reader tests (protocol 2 screens, card t_ce4fbc04).
//
// The real server on this branch still speaks protocol 1, so these captures use the protocol 2 mock
// (e2e/harness.ts) with the built page served by e2e/server.mjs. Values typed are fake (SECRET-CANARY-...).
// Run with `npm run screenshots` (chromium-mobile 390x844, chromium-desktop 1280x800; both at device scale 1,
// light and dark colour schemes). Output (CAPTURE_DIR, default ui/captures/screens):
//   <iphone|desktop>-<light|dark>-<screen>.png  full-page capture (first heading to last button)
//   <iphone|desktop>-<light|dark>-<screen>.txt  the text a sighted reader sees (no .sr-only text)
// `node e2e/captures-index.mjs` writes the list file ui/captures/CAPTURES.md from those names.
//
// CAPTURE_ONLY=unchanged takes only the screens this card does not change (one-time code, end screens);
// with CAPTURE_PROTOCOL=1 and STATIC_ROOT=<baseline bundle> the same tests capture the baseline page, so
// the two sets can be compared byte for byte (criterion 8).

import { mkdir, writeFile } from 'node:fs/promises'
import path from 'node:path'
import { expect, test, type Page } from '@playwright/test'
import { mockServer, PAGE_PATH, type MockOptions, type Scenario } from './harness.ts'

test.skip(!process.env.SCREENSHOTS, 'captures run only via npm run screenshots')
test.use({ deviceScaleFactor: 1 })

const OUT = path.resolve(process.env.CAPTURE_DIR ?? path.join(import.meta.dirname, '../captures/screens'))
const ONLY = process.env.CAPTURE_ONLY ?? 'all'
const V = Number(process.env.CAPTURE_PROTOCOL ?? 2)
const T0 = new Date('2026-11-25T12:00:00+09:00').getTime()

function sizeName(page: Page) {
  return page.viewportSize()!.width <= 400 ? 'iphone' : 'desktop'
}

async function capture(page: Page, scheme: string, screen: string) {
  await mkdir(OUT, { recursive: true })
  await page.mouse.move(0, 0)
  // A focused field that holds more than it can show scrolls to its end, so a masked value starts with a
  // half-cut dot. Move focus off a text field and show every field from the first character.
  await page.evaluate(() => {
    const active = document.activeElement
    if (active instanceof HTMLInputElement) active.blur()
    for (const el of document.querySelectorAll('input')) el.scrollLeft = 0
    window.scrollTo(0, 0)
  })
  await page.waitForTimeout(200)
  const name = `${sizeName(page)}-${scheme}-${screen}`
  await page.screenshot({ path: path.join(OUT, `${name}.png`), fullPage: true, animations: 'disabled', caret: 'hide' })
  // Visible text only: hide the screen-reader-only text for the moment of reading, then restore it.
  // (Through the CSSOM: the page's CSP blocks an injected <style> element.)
  const visible = await page.evaluate(() => {
    const hidden = [...document.querySelectorAll<HTMLElement>('.sr-only')]
    const before = hidden.map((el) => el.style.getPropertyValue('display'))
    for (const el of hidden) el.style.setProperty('display', 'none', 'important')
    const text = document.body.innerText
    hidden.forEach((el, i) => (before[i] ? el.style.setProperty('display', before[i]) : el.style.removeProperty('display')))
    return text
  })
  await writeFile(path.join(OUT, `${name}.txt`), visible + '\n')
}

async function open(page: Page, s: Scenario, opts: MockOptions = {}) {
  await page.clock.setFixedTime(T0)
  const mock = await mockServer(page, s, { ...opts, openPatch: { v: V, ...opts.openPatch } })
  await page.goto(PAGE_PATH)
  return mock
}

async function fillSecret(page: Page, v = 'SECRET-CANARY-vault-4c1d') {
  await page.getByLabel('비밀번호', { exact: true }).fill(v)
  await page.getByLabel('비밀번호 다시 입력', { exact: true }).fill(v)
}

const PARTIAL = { keychain: { saved: false, replaced: null, error: 'keychain_write_failed', main_touched: false } }

// 422 storage_failed: the read-back of the keychain item did not match, after the item was written (main_touched).
const KC_TOUCHED = {
  status: 422,
  body: {
    ok: false,
    error_code: 'storage_failed',
    message: '값을 저장하지 못했습니다. 다시 시도해 주세요.',
    result_unknown: false,
    stores: [
      {
        store: 'keychain',
        saved: false,
        replaced: null,
        error: 'keychain_verify_failed',
        service: 'example-unlock-item',
        account: 'example-unlock-item',
        listed: true,
        new_item: false,
        tmp_left: false,
        main_touched: true,
      },
    ],
  },
}

// 422 storage_failed with one keychain line (the item of scenario D); `o` sets main_touched, main_created, tmp_left.
const kcFail = (o: Record<string, boolean>) => ({
  ...KC_TOUCHED,
  body: { ...KC_TOUCHED.body, stores: [{ ...KC_TOUCHED.body.stores[0], main_touched: false, main_created: false, ...o }] },
})

async function cancelRequest(page: Page) {
  await page.getByRole('button', { name: '요청 취소', exact: true }).click()
  await page.getByRole('button', { name: '요청 취소하기' }).click()
  await expect(page.getByTestId('end-screen')).toHaveAttribute('data-reason', 'cancelled')
}

for (const scheme of ['light', 'dark'] as const) {
  test.describe(`captures (${scheme})`, () => {
    test.use({ colorScheme: scheme })

    // ---- Screens this card changes (plan 4.2 "다시 시험한다" and the four reader-test fixes) ----
    test.describe('changed', () => {
      test.skip(ONLY === 'unchanged', 'only the unchanged screens were asked for')

      test('login form: fixed vault row, replace rule, setup-key warning', async ({ page }) => {
        await open(page, 'B')
        await page.getByLabel('이메일 주소').fill('tester@example.com')
        await page.getByLabel('비밀번호', { exact: true }).fill('SECRET-CANARY-password')
        await capture(page, scheme, 'login-form')
      })

      test('api key form: .env on by default, keychain off', async ({ page }) => {
        await open(page, 'A')
        await capture(page, scheme, 'apikey-form')
      })

      test('api key form: both stores on, agent reason, overwrite note', async ({ page }) => {
        await open(page, 'A2')
        await page.getByLabel('API 키', { exact: true }).fill('SECRET-CANARY-apikey-7f3a9c')
        await capture(page, scheme, 'apikey-both')
      })

      test('api key form: .env switched off (A.12 warning)', async ({ page }) => {
        await open(page, 'A2')
        await page.getByRole('checkbox', { name: '설정 파일(.env)' }).click()
        await capture(page, scheme, 'apikey-env-off')
      })

      test('api key form: needed keychain switched off (warning)', async ({ page }) => {
        await open(page, 'A2')
        await page.getByRole('checkbox', { name: 'Mac 키체인' }).click()
        await capture(page, scheme, 'apikey-needed-off')
      })

      test('secret form: listed item, overwrite note', async ({ page }) => {
        await open(page, 'D')
        await fillSecret(page)
        await capture(page, scheme, 'secret-form')
      })

      test('secret form: new item note', async ({ page }) => {
        await open(page, 'D2')
        await capture(page, scheme, 'secret-new')
      })

      test('secret form: listed item the keychain does not have (security review 3, R3-4)', async ({ page }) => {
        await open(page, 'D3')
        await expect(page.getByTestId('keychain-listed-missing')).toBeVisible()
        await capture(page, scheme, 'secret-listed-missing')
      })

      test('saving', async ({ page }) => {
        const mock = await open(page, 'D', { holdSubmit: true })
        await fillSecret(page)
        await page.getByTestId('submit').click()
        await expect(page.getByTestId('saving')).toBeVisible()
        await capture(page, scheme, 'saving')
        mock.release()
        await expect(page.getByTestId('done-screen')).toBeVisible()
      })

      test('store unavailable error', async ({ page }) => {
        await open(page, 'A2', {
          submitReplies: [
            { status: 422, body: { ok: false, error_code: 'store_unavailable', message: 'x', stores: [{ store: 'keychain', reason: 'keychain_acl_denied' }] } },
          ],
        })
        await page.getByLabel('API 키', { exact: true }).fill('SECRET-CANARY-apikey-7f3a9c')
        await page.getByTestId('submit').click()
        await expect(page.getByTestId('store-alert')).toBeVisible()
        await capture(page, scheme, 'unavailable')
      })

      test('done: every store saved', async ({ page }) => {
        await open(page, 'A2')
        await page.getByLabel('API 키', { exact: true }).fill('SECRET-CANARY-apikey-7f3a9c')
        await page.getByTestId('submit').click()
        await expect(page.getByTestId('done-screen')).toBeVisible()
        await capture(page, scheme, 'done-all')
      })

      test('done: partly saved', async ({ page }) => {
        await open(page, 'A2', { successLines: PARTIAL })
        await page.getByLabel('API 키', { exact: true }).fill('SECRET-CANARY-apikey-7f3a9c')
        await page.getByTestId('submit').click()
        await expect(page.getByTestId('done-store-keychain')).toHaveAttribute('data-status', 'failed')
        await capture(page, scheme, 'done-partial')
      })

      test('done: keychain', async ({ page }) => {
        await open(page, 'D')
        await fillSecret(page)
        await page.getByTestId('submit').click()
        await expect(page.getByTestId('done-screen')).toBeVisible()
        await capture(page, scheme, 'done-keychain')
      })

      test('end: result unknown', async ({ page }) => {
        await open(page, 'D', { submitReplies: [{ abort: true }] })
        await fillSecret(page)
        await page.getByTestId('submit').click()
        await expect(page.getByTestId('end-screen')).toHaveAttribute('data-reason', 'result_unknown')
        await capture(page, scheme, 'unknown')
      })

      // Security review 3 (merge card t_664b8b7c): the changed sentences no earlier capture showed.
      test('store failed alert: keychain item written before the failure (R3-2)', async ({ page }) => {
        await open(page, 'D', { submitReplies: [KC_TOUCHED] })
        await fillSecret(page)
        await page.getByTestId('submit').click()
        await expect(page.getByTestId('store-alert')).toBeVisible()
        await capture(page, scheme, 'storage-failed')
      })

      test('end: cancelled after a submit that wrote the keychain item (R3-2)', async ({ page }) => {
        await open(page, 'D', { submitReplies: [KC_TOUCHED] })
        await fillSecret(page)
        await page.getByTestId('submit').click()
        await expect(page.getByTestId('store-alert')).toBeVisible()
        await cancelRequest(page)
        await capture(page, scheme, 'cancelled-sent')
      })

      test('end: one-time code cancelled after a submit the server answered (R3-2)', async ({ page }) => {
        await open(page, 'C', { submitReplies: [{ status: 422, body: { ok: false, error_code: 'invalid_payload' } }] })
        await page.getByLabel('일회용 코드', { exact: true }).fill('482913')
        await page.getByTestId('submit').click()
        await expect(page.getByTestId('submit')).toBeEnabled()
        await cancelRequest(page)
        await capture(page, scheme, 'cancelled-code')
      })

      test('end: result unknown, keychain line stopped at its time limit (R3-3)', async ({ page }) => {
        await open(page, 'D2', {
          submitReplies: [
            {
              status: 422,
              body: {
                ok: false,
                error_code: 'storage_failed',
                message: 'x',
                result_unknown: true,
                stores: [{ store: 'keychain', saved: null, replaced: null, error: 'store_timeout', tmp_left: null, main_touched: false }],
              },
            },
          ],
        })
        await fillSecret(page)
        await page.getByTestId('submit').click()
        await expect(page.getByTestId('end-screen')).toHaveAttribute('data-reason', 'result_unknown')
        await capture(page, scheme, 'unknown-tmp-left')
      })

      // Recheck of security review 3 (RC-1 to RC-3): the three screens that state added.
      test('store failed alert: a temporary keychain item may be left (recheck RC-3)', async ({ page }) => {
        await open(page, 'D', { submitReplies: [kcFail({ tmp_left: true })] })
        await fillSecret(page)
        await page.getByTestId('submit').click()
        await expect(page.getByTestId('store-alert')).toContainText('임시 키체인 항목')
        await capture(page, scheme, 'storage-failed-tmp-left')
      })

      test('end: submit time passed after a failed save (recheck RC-2)', async ({ page }) => {
        await open(page, 'D', { submitReplies: [kcFail({ main_touched: true, tmp_left: true })] })
        await fillSecret(page)
        await page.getByTestId('submit').click()
        await expect(page.getByTestId('store-alert')).toBeVisible()
        await page.clock.setFixedTime(T0 + 301_000) // the page's clock passes its submit deadline
        await expect(page.getByTestId('end-screen')).toHaveAttribute('data-reason', 'deadline_passed', { timeout: 10_000 })
        await capture(page, scheme, 'timeout-after-failed')
      })

      test('end: cancelled after a failed save that made the keychain item (recheck RC-1)', async ({ page }) => {
        await open(page, 'D', { submitReplies: [kcFail({ main_created: true })] })
        await fillSecret(page)
        await page.getByTestId('submit').click()
        await expect(page.getByTestId('store-alert')).toBeVisible()
        await cancelRequest(page)
        await capture(page, scheme, 'cancelled-created')
      })

      // Second recheck of security review 3 (RC2-1, RC2-3): the two screens that state added.
      test('done: saved to .env after a keychain-only send that made the item (recheck 2, RC2-1)', async ({ page }) => {
        const made = kcFail({ main_created: true })
        made.body.stores = [{ ...made.body.stores[0], service: 'hermes-secure-input.exa-api-key', account: 'hermes-secure-input', listed: false, new_item: true }]
        await open(page, 'A2', { submitReplies: [made] })
        await page.getByLabel('API 키', { exact: true }).fill('SECRET-CANARY-apikey-7f3a9c')
        await page.getByRole('checkbox', { name: '설정 파일(.env)' }).click()
        await page.getByTestId('submit').click()
        await expect(page.getByTestId('store-alert')).toBeVisible()
        await page.getByRole('checkbox', { name: 'Mac 키체인' }).click()
        await page.getByRole('checkbox', { name: '설정 파일(.env)' }).click()
        await page.getByTestId('submit').click()
        await expect(page.getByTestId('done-screen')).toContainText('새로 만들어졌고')
        await capture(page, scheme, 'done-after-created')
      })

      test('end: too many attempts after failed saves that made the item (recheck 2, RC2-3)', async ({ page }) => {
        const made = kcFail({ main_created: true })
        made.body.stores = [{ ...made.body.stores[0], service: 'hermes-secure-input.backup-archive', account: 'hermes-secure-input', listed: false, new_item: true }]
        const tooMany = { status: 429, body: { ok: false, error_code: 'too_many_attempts', message: '실패가 너무 많아 이 요청을 끝냈습니다. 새 링크를 요청하세요.' } }
        await open(page, 'D2', { submitReplies: [made, made, made, made, tooMany] })
        await fillSecret(page)
        for (let i = 0; i < 4; i++) {
          await page.getByTestId('submit').click()
          await expect(page.getByTestId('store-alert')).toBeVisible()
          await expect(page.getByTestId('submit')).toBeEnabled()
        }
        await page.getByTestId('submit').click()
        await expect(page.getByTestId('end-screen')).toHaveAttribute('data-reason', 'too_many_attempts')
        await capture(page, scheme, 'too-many-created')
      })

      test('end: Tailscale account not allowed (reader-test fixes 1 and 4)', async ({ page }) => {
        await open(page, 'A', { openReply: { status: 403, body: { ok: false, error_code: 'identity_not_allowed' } } })
        await expect(page.getByTestId('end-screen')).toHaveAttribute('data-reason', 'identity_denied')
        await capture(page, scheme, 'denied')
      })
    })

    // ---- Screens this card does not change: compared with the baseline bundle (criterion 8) ----
    test.describe('unchanged', () => {
      test.skip(ONLY === 'changed', 'only the changed screens were asked for')

      test('one-time code: form, filled, done', async ({ page }) => {
        // A protocol 1 page ignores the extra `target.stores` field, so the same fixture serves both bundles.
        await open(page, 'C')
        await expect(page.getByTestId('countdown')).toContainText('5:00')
        await capture(page, scheme, 'otp-form')
        await page.getByLabel('일회용 코드', { exact: true }).fill('482913')
        await capture(page, scheme, 'otp-filled')
        await page.getByTestId('submit').click()
        await expect(page.getByTestId('done-screen')).toBeVisible()
        await capture(page, scheme, 'otp-done')
      })

      test('end: already opened', async ({ page }) => {
        await open(page, 'A', { openReply: { status: 410, body: { ok: false, error_code: 'already_opened' } } })
        await expect(page.getByTestId('end-screen')).toHaveAttribute('data-reason', 'already_opened')
        await capture(page, scheme, 'opened')
      })

      test('end: submit time passed', async ({ page }) => {
        await open(page, 'C', { openPatch: { submit_deadline_s: 0 } })
        await expect(page.getByTestId('end-screen')).toHaveAttribute('data-reason', 'deadline_passed')
        await capture(page, scheme, 'timeout')
      })

      test('end: cancelled', async ({ page }) => {
        await open(page, 'C')
        await page.getByRole('button', { name: '요청 취소', exact: true }).click()
        await page.getByRole('button', { name: '요청 취소하기' }).click()
        await expect(page.getByTestId('end-screen')).toHaveAttribute('data-reason', 'cancelled')
        await capture(page, scheme, 'cancelled')
      })
    })
  })
}
