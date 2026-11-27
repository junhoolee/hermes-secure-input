// Screens changed by the second recheck of security review 3 (docs/security-review-3-recheck-2.md section 5):
// RC2-1 (the done screen and the result unknown screen also say what an earlier send left in the keychain) and
// RC2-3 (the too many attempts screen says it too). The cases are the recheck's; their server side, with the Slack
// sentence each screen points at, is tests/test_recheck2_fix.py.

import { expect, test, type Page } from '@playwright/test'
import { canary, clientSideState, mockServer, PAGE_PATH, type Mock } from './harness.ts'

const RESULT = 'Slack 대화의 결과 메시지를 확인하세요.'
const CANCEL = 'Slack 대화의 취소 결과 메시지를 확인하세요.'
const TOUCHED = '보낸 값을 키체인 항목에 쓰기 시작했으므로, 그 항목에 있던 예전 값이 바뀌었을 수 있습니다.'
const CREATED = '보낸 값을 쓰려던 키체인 항목이 새로 만들어졌고, 이번에 넣은 값이 들어 있을 수 있습니다.'
const TMP_LEFT = "임시 키체인 항목에 이번에 넣은 값이 남아 있을 수 있습니다. Hermes가 도는 컴퓨터에서 README의 '남은 임시 키체인 항목' 절의 명령으로 확인해 지우세요."

type Facts = { main_touched?: boolean; main_created?: boolean; tmp_left?: boolean; error?: string }

/** A 422 storage_failed with one keychain line for the item `service` (`listed` for an allow-list item). */
export const kcFailed = (service: string, listed: boolean, o: Facts) => ({
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
        error: o.error ?? 'keychain_verify_failed',
        service,
        account: listed ? 'example-unlock-item' : 'hermes-secure-input',
        listed,
        new_item: !listed && o.main_created === true,
        tmp_left: o.tmp_left ?? false,
        main_touched: o.main_touched ?? false,
        main_created: o.main_created ?? false,
      },
    ],
  },
})
const LISTED = (o: Facts) => kcFailed('example-unlock-item', true, o) // scenario D's item
const OWN_KEY = (o: Facts) => kcFailed('hermes-secure-input.exa-api-key', false, o) // scenario A2's item
const OWN_NEW = (o: Facts) => kcFailed('hermes-secure-input.backup-archive', false, o) // scenario D2's item
const TOO_MANY = { status: 429, body: { ok: false, error_code: 'too_many_attempts', message: '실패가 너무 많아 이 요청을 끝냈습니다. 새 링크를 요청하세요.' } }

async function fillSecret(page: Page, v: string) {
  await page.getByLabel('비밀번호', { exact: true }).fill(v)
  await page.getByLabel('비밀번호 다시 입력', { exact: true }).fill(v)
}

async function send(page: Page) {
  await page.getByTestId('submit').click()
}

/** Send, and wait for the retryable alert of the answer. */
async function sendFails(page: Page) {
  await send(page)
  await expect(page.getByTestId('store-alert')).toBeVisible()
  await expect(page.getByTestId('submit')).toBeEnabled()
}

async function cancel(page: Page) {
  await page.getByRole('button', { name: '요청 취소', exact: true }).click()
  await page.getByRole('button', { name: '요청 취소하기' }).click()
  await expect(page.getByTestId('end-screen')).toHaveAttribute('data-reason', 'cancelled')
}

async function toggle(page: Page, name: '설정 파일(.env)' | 'Mac 키체인', on: boolean) {
  const box = page.getByRole('checkbox', { name })
  if ((await box.getAttribute('aria-checked')) !== String(on)) await box.click()
  await expect(box).toHaveAttribute('aria-checked', String(on))
}

async function noSecretLeft(page: Page, mock: Mock, secret: string) {
  const bodies = mock.submits.map((s) => s.raw).join('\n') + mock.cancels.join('\n')
  expect(bodies.includes(secret), 'secret in a request body').toBe(false)
  expect((await clientSideState(page)).includes(secret), 'secret left on the client').toBe(false)
  expect(mock.consoleLines.join('\n').includes(secret), 'secret in console').toBe(false)
}

/** rc1_g and rc1_i: .env off, a keychain-only send fails; keychain off, .env on, the send saves to .env only. */
async function keychainOnlyThenEnvOnly(page: Page, first: Facts) {
  const mock = await mockServer(page, 'A2', { submitReplies: [OWN_KEY(first)] })
  await page.goto(PAGE_PATH)
  const v = canary('RC21')
  await page.getByLabel('API 키', { exact: true }).fill(v)
  await toggle(page, '설정 파일(.env)', false)
  await sendFails(page)
  await toggle(page, 'Mac 키체인', false)
  await toggle(page, '설정 파일(.env)', true)
  await send(page)
  await expect(page.getByTestId('done-screen')).toBeVisible()
  expect(mock.submits.map((s) => s.plaintext?.stores)).toEqual([['keychain'], ['env']])
  await noSecretLeft(page, mock, v)
  return page.getByTestId('done-screen')
}

test.describe('RC2-1: the done screen', () => {
  test('rc1_g: the keychain-only send made the item; the done screen says so and points at Slack', async ({ page }) => {
    const done = await keychainOnlyThenEnvOnly(page, { main_created: true })
    await expect(done.getByRole('heading')).toHaveText('저장했습니다')
    await expect(done.locator(':scope > ul:not([data-testid="done-stores"]) > li')).toHaveText([
      '값은 화면에 다시 보여 주지 않습니다.',
      `${CREATED} ${RESULT}`,
      '입력한 값은 이 브라우저 화면에서 지웠습니다.',
      '저장 결과는 Hermes 안의 AI 모델과 Slack 대화에도 전달됩니다.',
      '이 창을 닫아도 됩니다.',
    ])
  })

  test('rc1_i: the keychain-only send wrote the existing item; the done screen says the old value may have changed', async ({ page }) => {
    const done = await keychainOnlyThenEnvOnly(page, { main_touched: true })
    await expect(done).toContainText(`${TOUCHED} ${RESULT}`)
    await expect(done).not.toContainText('새로 만들어졌고')
  })

  test('a failed send, then a send that saves to the keychain: no old value and no made item sentence', async ({ page }) => {
    const mock = await mockServer(page, 'D2', { submitReplies: [OWN_NEW({ main_created: true })] })
    await page.goto(PAGE_PATH)
    const v = canary('RC2S')
    await fillSecret(page, v)
    await sendFails(page)
    await send(page)
    const done = page.getByTestId('done-screen')
    await expect(done).toBeVisible()
    await expect(done).not.toContainText('새로 만들어졌고')
    await expect(done).not.toContainText('예전 값이 바뀌었을 수')
    await expect(done).not.toContainText(RESULT)
    await noSecretLeft(page, mock, v)
  })

  test('one send that saves: the done screen has no keychain sentence', async ({ page }) => {
    await mockServer(page, 'A2')
    await page.goto(PAGE_PATH)
    await page.getByLabel('API 키', { exact: true }).fill(canary('RC2O'))
    await send(page)
    const done = page.getByTestId('done-screen')
    await expect(done).toBeVisible()
    await expect(done).not.toContainText(RESULT)
  })
})

test.describe('RC2-3: the too many attempts end screen', () => {
  test('rc1_h: five failed sends on the item the first one made; the end screen says it was made', async ({ page }) => {
    const replies = [...Array(4)].map(() => OWN_NEW({ main_created: true }))
    const mock = await mockServer(page, 'D2', { submitReplies: [...replies, TOO_MANY] })
    await page.goto(PAGE_PATH)
    const v = canary('RC2H')
    await fillSecret(page, v)
    for (let i = 0; i < 4; i++) await sendFails(page)
    await send(page)
    const end = page.getByTestId('end-screen')
    await expect(end).toHaveAttribute('data-reason', 'too_many_attempts')
    await expect(end.locator('li')).toHaveText([
      '보안을 위해 이 링크를 닫았습니다.',
      '입력한 값은 지웠습니다.',
      `${CREATED} ${RESULT}`,
      '링크를 받은 Slack 대화에서 Hermes에게 다시 요청하세요.',
    ])
    expect(mock.submits).toHaveLength(5)
    await noSecretLeft(page, mock, v)
  })

  test('too many attempts with no keychain fact: unchanged', async ({ page }) => {
    await mockServer(page, 'D', { submitReplies: [TOO_MANY] })
    await page.goto(PAGE_PATH)
    await fillSecret(page, canary('RC2N'))
    await send(page)
    await expect(page.getByTestId('end-screen').locator('li')).toHaveText([
      '보안을 위해 이 링크를 닫았습니다.',
      '입력한 값은 지웠습니다.',
      '링크를 받은 Slack 대화에서 Hermes에게 다시 요청하세요.',
    ])
  })
})

test.describe('the result unknown end screen keeps what an earlier send said', () => {
  test('a send touched the item, the next send ran past the submit window (410): the old value sentence', async ({ page }) => {
    await mockServer(page, 'D', {
      submitReplies: [LISTED({ main_touched: true }), { status: 410, body: { ok: false, error_code: 'deadline_passed', message: 'x' } }],
    })
    await page.goto(PAGE_PATH)
    await fillSecret(page, canary('RC2U'))
    await sendFails(page)
    await send(page)
    const end = page.getByTestId('end-screen')
    await expect(end).toHaveAttribute('data-reason', 'result_unknown')
    await expect(end).toContainText(`${TOUCHED} ${RESULT}`)
  })

  test('a temporary item left by the earlier send and by this one: the sentence comes once', async ({ page }) => {
    await mockServer(page, 'D', {
      submitReplies: [
        LISTED({ tmp_left: true }),
        { status: 422, body: { ...LISTED({ error: 'store_timeout' }).body, result_unknown: true } },
      ],
    })
    await page.goto(PAGE_PATH)
    await fillSecret(page, canary('RC2T'))
    await sendFails(page)
    await send(page)
    const end = page.getByTestId('end-screen')
    await expect(end).toHaveAttribute('data-reason', 'result_unknown')
    await expect(end.locator('li', { hasText: '임시 키체인 항목' })).toHaveCount(1)
  })
})

test.describe('the cases whose end screen already said it', () => {
  test('rc2_l: touched, then a send that failed before the temp step, then the time ran out', async ({ page }) => {
    await mockServer(page, 'D', {
      openPatch: { submit_deadline_s: 5 },
      submitReplies: [LISTED({ main_touched: true }), LISTED({ error: 'keychain_write_failed' })],
    })
    await page.goto(PAGE_PATH)
    await fillSecret(page, canary('RC2L'))
    await sendFails(page)
    await sendFails(page)
    const end = page.getByTestId('end-screen')
    await expect(end).toHaveAttribute('data-reason', 'deadline_passed', { timeout: 10_000 })
    await expect(end).toContainText(`${TOUCHED} ${RESULT}`)
  })

  test('rc2_m: the same two sends, then cancel', async ({ page }) => {
    await mockServer(page, 'D', { submitReplies: [LISTED({ main_touched: true }), LISTED({ error: 'keychain_write_failed' })] })
    await page.goto(PAGE_PATH)
    await fillSecret(page, canary('RC2M'))
    await sendFails(page)
    await sendFails(page)
    await cancel(page)
    await expect(page.getByTestId('end-screen').locator('li').nth(1)).toHaveText(`${TOUCHED} ${CANCEL}`)
  })

  test('rc3_c: a temporary item left, then a send that failed before the temp step, then cancel', async ({ page }) => {
    await mockServer(page, 'D', { submitReplies: [LISTED({ tmp_left: true }), LISTED({ error: 'keychain_acl_denied' })] })
    await page.goto(PAGE_PATH)
    await fillSecret(page, canary('RC3C'))
    await sendFails(page)
    await sendFails(page)
    await cancel(page)
    await expect(page.getByTestId('end-screen').locator('li').nth(1)).toHaveText(TMP_LEFT)
  })
})
