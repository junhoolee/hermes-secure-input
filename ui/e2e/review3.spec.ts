// Screens changed by security review 3 (docs/security-review-3.md, section 2): R3-2, R3-3, R3-4, N-5.
// With REVIEW3_TEXT_DIR set, the chromium-mobile run also writes the visible text of each fixed screen there
// (docs/security-review-3/results-after-fix/<item>__screen_text.txt).

import { appendFile, mkdir } from 'node:fs/promises'
import path from 'node:path'
import { expect, test, type Page, type TestInfo } from '@playwright/test'
import { canary, clientSideState, mockServer, PAGE_PATH, SCENARIOS, type Mock } from './harness.ts'

const MAIN_TOUCHED = '이 항목에 새 값을 쓰기 시작했으므로, 있던 예전 값이 바뀌었을 수 있습니다.'
const TMP_LEFT = "임시 키체인 항목에 이번에 넣은 값이 남아 있을 수 있습니다. Hermes가 도는 컴퓨터에서 README의 '남은 임시 키체인 항목' 절의 명령으로 확인해 지우세요."
const LISTED_MISSING =
  '허용 목록에 적힌 이름의 항목이 키체인에 아직 없습니다. 보내면 이 이름으로 새 항목을 만듭니다. 보내기 전에, 허용 목록에 적은 키체인 항목 이름과 키체인 계정 이름이 맞는지 확인하세요.'
const SCOPE = '프로필과 상관없이, Hermes를 돌리는 사용자 계정의 로그인 키체인에 저장합니다.'

/** Append the visible text of the page (no .sr-only text) under a heading, for the after-fix evidence files. */
async function record(page: Page, info: TestInfo, item: string, title: string) {
  const dir = process.env.REVIEW3_TEXT_DIR
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

const kcFail = (main_touched: boolean) => ({
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
        error: main_touched ? 'keychain_verify_failed' : 'keychain_write_failed',
        service: 'example-unlock-item',
        account: 'example-unlock-item',
        listed: true,
        new_item: false,
        tmp_left: false,
        main_touched,
      },
    ],
  },
})

test.describe('R3-2: a written keychain item, then cancel', () => {
  test('the alert says the old value may have changed; cancel then says what was sent and points at Slack', async ({ page }, info) => {
    const mock = await mockServer(page, 'D', { submitReplies: [kcFail(true)] })
    await page.goto(PAGE_PATH)
    const v = canary('R32T')
    await fillSecret(page, v)
    await page.getByTestId('submit').click()
    const alert = page.getByTestId('store-alert')
    await expect(alert).toBeVisible()
    await expect(alert.locator('li')).toHaveText(['Mac 키체인: Mac 키체인에 쓴 값을 다시 읽어 보니 넣은 값과 달랐습니다.', MAIN_TOUCHED])
    await expect(alert).toContainText('입력한 값은 입력 칸에 그대로 있습니다.')
    await record(page, info, 'R3-2', '4b와 같은 답(422 storage_failed, main_touched true) 뒤의 입력 화면 알림')

    await cancel(page)
    await expect(page.getByTestId('end-screen').locator('li')).toHaveText([
      '보낸 값은 저장하지 못했습니다.',
      '보낸 값을 키체인 항목에 쓰기 시작했으므로, 그 항목에 있던 예전 값이 바뀌었을 수 있습니다. Slack 대화의 취소 결과 메시지를 확인하세요.',
      'Slack 대화에도 취소 결과가 표시됩니다.',
      '요청한 AI 모델에도 취소했다고 전달됩니다.',
      '나중에 다시 넣으려면 링크를 받은 Slack 대화에서 Hermes에게 다시 요청하세요.',
      '이 창을 닫아도 됩니다.',
    ])
    await expect(page.getByTestId('end-screen')).not.toContainText('아무 값도 보내지 않았습니다.')
    await record(page, info, 'R3-2', '그 뒤 취소한 끝 화면')
    expect(mock.submits).toHaveLength(1)
    expect(mock.cancels).toHaveLength(1)
    await noSecretLeft(page, mock, v)
  })

  test('a failed submit that touched no item: cancel says the value sent was not saved, nothing more', async ({ page }, info) => {
    const mock = await mockServer(page, 'D', { submitReplies: [kcFail(false)] })
    await page.goto(PAGE_PATH)
    const v = canary('R32F')
    await fillSecret(page, v)
    await page.getByTestId('submit').click()
    const alert = page.getByTestId('store-alert')
    await expect(alert).toBeVisible()
    await expect(alert.locator('li')).toHaveText(['Mac 키체인: Mac 키체인에 쓰지 못했습니다.'])
    await expect(alert).not.toContainText(MAIN_TOUCHED)

    await cancel(page)
    const end = page.getByTestId('end-screen')
    await expect(end.locator('li').first()).toHaveText('보낸 값은 저장하지 못했습니다.')
    await expect(end).not.toContainText('아무 값도 보내지 않았습니다.')
    await expect(end).not.toContainText('예전 값이 바뀌었을 수 있습니다')
    await record(page, info, 'R3-2', '예전 값을 건드리지 않은 실패(main_touched false) 뒤 취소한 끝 화면')
    await noSecretLeft(page, mock, v)
  })

  test('cancel without sending keeps "아무 값도 보내지 않았습니다."', async ({ page }) => {
    await mockServer(page, 'D')
    await page.goto(PAGE_PATH)
    await cancel(page)
    await expect(page.getByTestId('end-screen').locator('li').first()).toHaveText('아무 값도 보내지 않았습니다.')
  })
})

test.describe('R3-4: a listed item the keychain does not have', () => {
  test('no "existing item" line; a note says the send creates the item and to check the allow-list', async ({ page }, info) => {
    const mock = await mockServer(page, 'D3')
    await page.goto(PAGE_PATH)
    const kc = page.getByTestId('store-keychain')
    await expect(kc.getByTestId('store-ident')).toHaveText('deploy-signing')
    await expect(kc.getByTestId('keychain-listed-label')).toHaveText('허용 목록 항목: 배포 서명 키 비밀번호')
    await expect(kc).not.toContainText('기존 항목입니다')
    await expect(kc.getByTestId('keychain-listed-missing')).toHaveText(LISTED_MISSING)
    await expect(kc.getByTestId('keychain-overwrite')).toHaveCount(0)
    await expect(kc.getByTestId('keychain-new')).toHaveCount(0)
    await record(page, info, 'R3-4', '허용 목록 항목이 키체인에 없음(시나리오 D3)')

    const v = canary('R34')
    await fillSecret(page, v)
    await page.getByTestId('submit').click()
    await expect(page.getByTestId('done-store-keychain')).toContainText('저장했습니다.')
    await noSecretLeft(page, mock, v)
  })

  test('a listed item the keychain has: "existing item" line and no missing-item note', async ({ page }) => {
    await mockServer(page, 'D')
    await page.goto(PAGE_PATH)
    const kc = page.getByTestId('store-keychain')
    await expect(kc.getByTestId('keychain-listed-label')).toHaveText('기존 항목입니다: Example Vault 비밀번호')
    await expect(kc.getByTestId('keychain-listed-missing')).toHaveCount(0)
    await expect(kc.getByTestId('keychain-overwrite')).toBeVisible()
  })

  test('exists unknown (null): neither "existing item" nor the missing-item note', async ({ page }) => {
    const base = SCENARIOS.D3.target
    await mockServer(page, 'D3', { targetPatch: { stores: [{ ...base.stores[0], exists: null }] } })
    await page.goto(PAGE_PATH)
    const kc = page.getByTestId('store-keychain')
    await expect(kc.getByTestId('keychain-listed-label')).toHaveText('허용 목록 항목: 배포 서명 키 비밀번호')
    await expect(kc.getByTestId('keychain-listed-missing')).toHaveCount(0)
  })
})

test.describe('N-5: the keychain scope line', () => {
  test('names the login keychain of the account that runs Hermes', async ({ page }, info) => {
    await mockServer(page, 'D3')
    await page.goto(PAGE_PATH)
    const kc = page.getByTestId('store-keychain')
    await expect(kc).toContainText(SCOPE)
    await expect(page.locator('body')).not.toContainText('컴퓨터 전체')
    await record(page, info, 'N-5', '키체인 줄(시나리오 D3)')
  })
})

test.describe('R3-3: a temporary keychain item may be left', () => {
  test('done screen: tmp_left true on the keychain line', async ({ page }, info) => {
    const mock = await mockServer(page, 'D', { successLines: { keychain: { tmp_left: true } } })
    await page.goto(PAGE_PATH)
    const v = canary('R33A')
    await fillSecret(page, v)
    await page.getByTestId('submit').click()
    const done = page.getByTestId('done-store-keychain')
    await expect(done).toHaveAttribute('data-status', 'saved')
    await expect(done).toContainText(TMP_LEFT)
    await record(page, info, 'R3-3', '저장했습니다, 키체인 줄 tmp_left true')
    await noSecretLeft(page, mock, v)
  })

  test('result unknown: a storage_failed answer whose keychain line stopped at store_timeout', async ({ page }, info) => {
    const mock = await mockServer(page, 'D2', {
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
    await page.goto(PAGE_PATH)
    const v = canary('R33B')
    await fillSecret(page, v)
    await page.getByTestId('submit').click()
    const end = page.getByTestId('end-screen')
    await expect(end).toHaveAttribute('data-reason', 'result_unknown')
    await expect(end).toContainText(TMP_LEFT)
    await record(page, info, 'R3-3', '저장했는지 알 수 없습니다, 422 storage_failed result_unknown, 키체인 줄 store_timeout')
    await noSecretLeft(page, mock, v)
  })

  test('result unknown from a lost reply: no temporary-item line', async ({ page }) => {
    await mockServer(page, 'D2', { submitReplies: [{ abort: true }] })
    await page.goto(PAGE_PATH)
    await fillSecret(page, canary('R33C'))
    await page.getByTestId('submit').click()
    const end = page.getByTestId('end-screen')
    await expect(end).toHaveAttribute('data-reason', 'result_unknown')
    await expect(end).not.toContainText('임시 키체인 항목')
  })
})
