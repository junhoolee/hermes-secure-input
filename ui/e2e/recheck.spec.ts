// Screens changed by the recheck of security review 3 (docs/security-review-3-recheck.md section 5): RC-1, RC-2,
// RC-3 and the last line of the pre-write check alert. With RECHECK_TEXT_DIR set, the chromium-mobile run also
// writes the visible text of each screen there (docs/security-review-3-recheck/results-after-fix/<item>__screen_text.txt).

import { appendFile, mkdir } from 'node:fs/promises'
import path from 'node:path'
import { expect, test, type Page, type TestInfo } from '@playwright/test'
import { canary, clientSideState, mockServer, PAGE_PATH, type Mock } from './harness.ts'

const MAIN_TOUCHED = '이 항목에 새 값을 쓰기 시작했으므로, 있던 예전 값이 바뀌었을 수 있습니다.'
const MAIN_CREATED = '이 이름의 키체인 항목이 새로 만들어졌고, 이번에 넣은 값이 들어 있을 수 있습니다.'
const TMP_LEFT = "임시 키체인 항목에 이번에 넣은 값이 남아 있을 수 있습니다. Hermes가 도는 컴퓨터에서 README의 '남은 임시 키체인 항목' 절의 명령으로 확인해 지우세요."
const VERIFY = 'Mac 키체인: Mac 키체인에 쓴 값을 다시 읽어 보니 넣은 값과 달랐습니다.'
const CREATED_CANCEL =
  '보낸 값을 쓰려던 키체인 항목이 새로 만들어졌고, 이번에 넣은 값이 들어 있을 수 있습니다. Slack 대화의 취소 결과 메시지를 확인하세요.'
const TOUCHED_DEADLINE =
  '보낸 값을 키체인 항목에 쓰기 시작했으므로, 그 항목에 있던 예전 값이 바뀌었을 수 있습니다. Slack 대화의 결과 메시지를 확인하세요.'

async function record(page: Page, info: TestInfo, item: string, title: string) {
  const dir = process.env.RECHECK_TEXT_DIR
  if (!dir || info.project.name !== 'chromium-mobile') return
  const text = await page.evaluate(() => {
    const hidden = [...document.querySelectorAll<HTMLElement>('.sr-only')]
    for (const el of hidden) el.style.setProperty('display', 'none', 'important')
    const t = document.body.innerText
    for (const el of hidden) el.style.removeProperty('display')
    return t
  })
  await mkdir(dir, { recursive: true })
  await appendFile(path.join(dir, `${item}__screen_text.txt`), `## ${title}\n\n${text}\n\n`)
}

async function noSecretLeft(page: Page, mock: Mock, secret: string) {
  const bodies = mock.submits.map((s) => s.raw).join('\n') + mock.cancels.join('\n')
  expect(bodies.includes(secret), 'secret in a request body').toBe(false)
  expect((await clientSideState(page)).includes(secret), 'secret left on the client').toBe(false)
  expect(mock.consoleLines.join('\n').includes(secret), 'secret in console').toBe(false)
}

async function fillSecret(page: Page, v: string) {
  await page.getByLabel('비밀번호', { exact: true }).fill(v)
  await page.getByLabel('비밀번호 다시 입력', { exact: true }).fill(v)
}

async function cancel(page: Page) {
  await page.getByRole('button', { name: '요청 취소', exact: true }).click()
  await page.getByRole('button', { name: '요청 취소하기' }).click()
  await expect(page.getByTestId('end-screen')).toHaveAttribute('data-reason', 'cancelled')
}

/** A 422 storage_failed with one keychain line (the item of scenario D). */
export const kcFail = (o: { main_touched?: boolean; main_created?: boolean; tmp_left?: boolean }) => ({
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
        tmp_left: o.tmp_left ?? false,
        main_touched: o.main_touched ?? false,
        main_created: o.main_created ?? false,
      },
    ],
  },
})

test.describe('RC-1: the failed save made the keychain item', () => {
  test('the alert says the item was made; cancel then says so and points at Slack', async ({ page }, info) => {
    const mock = await mockServer(page, 'D', { submitReplies: [kcFail({ main_created: true })] })
    await page.goto(PAGE_PATH)
    const v = canary('RC1C')
    await fillSecret(page, v)
    await page.getByTestId('submit').click()
    const alert = page.getByTestId('store-alert')
    await expect(alert.locator('li')).toHaveText([VERIFY, MAIN_CREATED])
    await expect(alert).not.toContainText(MAIN_TOUCHED)
    await record(page, info, 'RC-1', '없던 항목에 쓰고 되읽기가 어긋난 답(422, main_created true) 뒤의 입력 화면 알림')

    await cancel(page)
    await expect(page.getByTestId('end-screen').locator('li')).toHaveText([
      '보낸 값은 저장하지 못했습니다.',
      CREATED_CANCEL,
      'Slack 대화에도 취소 결과가 표시됩니다.',
      '요청한 AI 모델에도 취소했다고 전달됩니다.',
      '나중에 다시 넣으려면 링크를 받은 Slack 대화에서 Hermes에게 다시 요청하세요.',
      '이 창을 닫아도 됩니다.',
    ])
    await record(page, info, 'RC-1', '그 뒤 취소한 끝 화면')
    await noSecretLeft(page, mock, v)
  })

  test('a failure on an existing item says the old value, never that an item was made', async ({ page }) => {
    await mockServer(page, 'D', { submitReplies: [kcFail({ main_touched: true })] })
    await page.goto(PAGE_PATH)
    await fillSecret(page, canary('RC1E'))
    await page.getByTestId('submit').click()
    await expect(page.getByTestId('store-alert').locator('li')).toHaveText([VERIFY, MAIN_TOUCHED])
    await cancel(page)
    await expect(page.getByTestId('end-screen')).not.toContainText('새로 만들어졌고')
  })
})

test.describe('RC-2: the submit window passes after a retryable failure', () => {
  test('what was sent, what was cleared, and what the keychain may hold', async ({ page }, info) => {
    const mock = await mockServer(page, 'D', {
      openPatch: { submit_deadline_s: 4 },
      submitReplies: [kcFail({ main_touched: true, tmp_left: true })],
    })
    await page.goto(PAGE_PATH)
    const v = canary('RC2S')
    await fillSecret(page, v)
    await page.getByTestId('submit').click()
    await expect(page.getByTestId('store-alert')).toBeVisible()
    const end = page.getByTestId('end-screen')
    await expect(end).toHaveAttribute('data-reason', 'deadline_passed', { timeout: 10_000 })
    await expect(end.getByRole('heading')).toHaveText('제출 시간이 지났습니다')
    await expect(end.locator('li')).toHaveText([
      '앞서 보낸 값은 저장하지 못했고, 다시 보내지 않은 채 제출 시간이 지났습니다.',
      '입력 칸에 남아 있던 값은 지웠습니다.',
      TOUCHED_DEADLINE,
      TMP_LEFT,
      'Slack 대화에도 시간이 지났다는 결과가 표시됩니다.',
      '요청한 AI 모델에도 시간이 지났다고 전달됩니다.',
      '링크를 받은 Slack 대화에서 Hermes에게 다시 요청하세요.',
    ])
    await expect(end).not.toContainText('보내지 않았습니다.')
    await record(page, info, 'RC-2', '예전 값을 건드리고 임시 항목이 남은 실패(422) 뒤 다시 보내지 않고 시간이 지난 끝 화면')
    expect(mock.submits).toHaveLength(1)
    await noSecretLeft(page, mock, v)
  })

  test('nothing was sent: the screen is unchanged', async ({ page }, info) => {
    await mockServer(page, 'D', { openPatch: { submit_deadline_s: 2 } })
    await page.goto(PAGE_PATH)
    const end = page.getByTestId('end-screen')
    await expect(end).toHaveAttribute('data-reason', 'deadline_passed', { timeout: 10_000 })
    await expect(end.locator('li').nth(0)).toHaveText('값은 링크를 연 뒤 5분 안에 보내야 합니다.')
    await expect(end.locator('li').nth(1)).toHaveText('입력한 값은 지웠고 보내지 않았습니다.')
    await expect(end).not.toContainText('앞서 보낸 값')
    await record(page, info, 'RC-2', '한 번도 보내지 않고 시간이 지난 끝 화면(바뀌지 않음)')
  })

  test('a 400 refused before saving is not a failed save: the screen says nothing was saved-and-failed', async ({ page }) => {
    await mockServer(page, 'D', {
      openPatch: { submit_deadline_s: 4 },
      submitReplies: [{ status: 400, body: { ok: false, error_code: 'invalid_payload', message: 'x' } }],
    })
    await page.goto(PAGE_PATH)
    await fillSecret(page, canary('RC2B'))
    await page.getByTestId('submit').click()
    const end = page.getByTestId('end-screen')
    await expect(end).toHaveAttribute('data-reason', 'deadline_passed', { timeout: 10_000 })
    await expect(end.locator('li').nth(0)).toHaveText('값은 링크를 연 뒤 5분 안에 보내야 합니다.')
  })

  // Review round 1, item 3: the server marks the failed save on these answers too (secure_input/server.py
  // _checked_submit, Lifecycle.note_failed_save), so the screen must say the value was sent and not saved.
  const afterFailed = [
    {
      name: 'a masked_value answer',
      reply: { status: 422, body: { ok: false, error_code: 'masked_value', message: '가려진 값처럼 보여 저장하지 않았습니다. 원래 키 전체를 붙여 넣어 주세요.' } },
    },
    {
      name: 'a storage_failed answer without store lines (profile error)',
      reply: { status: 422, body: { ok: false, error_code: 'storage_failed', message: '값을 저장하지 못했습니다. 다시 시도해 주세요.', result_unknown: false, stores: [] } },
    },
  ]
  for (const c of afterFailed) {
    test(`after ${c.name} the screen says the sent value was not saved`, async ({ page }) => {
      const mock = await mockServer(page, 'A', { openPatch: { submit_deadline_s: 4 }, submitReplies: [c.reply] })
      await page.goto(PAGE_PATH)
      const v = canary('RC2M')
      await page.getByLabel('API 키', { exact: true }).fill(v)
      await page.getByTestId('submit').click()
      const end = page.getByTestId('end-screen')
      await expect(end).toHaveAttribute('data-reason', 'deadline_passed', { timeout: 10_000 })
      await expect(end.locator('li').nth(0)).toHaveText('앞서 보낸 값은 저장하지 못했고, 다시 보내지 않은 채 제출 시간이 지났습니다.')
      await expect(end.locator('li').nth(1)).toHaveText('입력 칸에 남아 있던 값은 지웠습니다.')
      await expect(end).not.toContainText('보내지 않았습니다.')
      expect(mock.submits).toHaveLength(1)
      await noSecretLeft(page, mock, v)
    })
  }
})

test.describe('RC-3: a temporary keychain item may be left', () => {
  test('the alert says it under the keychain line; cancel then says it', async ({ page }, info) => {
    const mock = await mockServer(page, 'D', { submitReplies: [kcFail({ tmp_left: true })] })
    await page.goto(PAGE_PATH)
    const v = canary('RC3T')
    await fillSecret(page, v)
    await page.getByTestId('submit').click()
    const alert = page.getByTestId('store-alert')
    await expect(alert.locator('li')).toHaveText([VERIFY, TMP_LEFT])
    await expect(alert).toContainText('입력한 값은 입력 칸에 그대로 있습니다.')
    await record(page, info, 'RC-3', '임시 항목을 지우지 못한 답(422, tmp_left true) 뒤의 입력 화면 알림')

    await cancel(page)
    await expect(page.getByTestId('end-screen').locator('li').nth(1)).toHaveText(TMP_LEFT)
    await record(page, info, 'RC-3', '그 뒤 취소한 끝 화면')
    await noSecretLeft(page, mock, v)
  })

  test('tmp_left false: no temporary item sentence anywhere', async ({ page }) => {
    await mockServer(page, 'D', { submitReplies: [kcFail({})] })
    await page.goto(PAGE_PATH)
    await fillSecret(page, canary('RC3F'))
    await page.getByTestId('submit').click()
    await expect(page.getByTestId('store-alert').locator('li')).toHaveText([VERIFY])
    await cancel(page)
    await expect(page.getByTestId('end-screen')).not.toContainText('임시 키체인 항목')
  })
})

test('the pre-write check alert ends with "입력한 값은 입력 칸에 그대로 있습니다."', async ({ page }) => {
  await mockServer(page, 'D', {
    submitReplies: [
      { status: 422, body: { ok: false, error_code: 'store_unavailable', message: 'x', stores: [{ store: 'keychain', reason: 'keychain_unavailable' }] } },
    ],
  })
  await page.goto(PAGE_PATH)
  await fillSecret(page, canary('RCSU'))
  await page.getByTestId('submit').click()
  const alert = page.getByTestId('store-alert')
  await expect(alert).toContainText('입력한 값은 입력 칸에 그대로 있습니다.')
  await expect(alert).not.toContainText('입력한 값은 그대로 있습니다.')
})
