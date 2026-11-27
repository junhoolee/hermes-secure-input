import { expect, test, type Page } from '@playwright/test'
import { canary, clientSideState, mockServer, PAGE_PATH, SCENARIOS, type Mock } from './harness.ts'

const ORIGIN = `http://127.0.0.1:${process.env.E2E_PORT ?? 4719}`

/** Contract checks that hold on every screen test. */
async function commonChecks(page: Page, mock: Mock, secrets: string[] = []) {
  // 9.5: the page talked to the test server only.
  const foreign = mock.requests.filter((u) => !u.startsWith('data:') && new URL(u).origin !== ORIGIN)
  expect(foreign, 'requests to other hosts').toEqual([])
  // 9.6: nothing was blocked by the CSP.
  expect(await mock.cspViolations(), 'CSP violations').toEqual([])
  expect(mock.consoleLines.filter((l) => /Content Security Policy|Refused to/i.test(l)), 'CSP console errors').toEqual([])
  // 9.8: no horizontal scroll.
  const { sw, iw } = await page.evaluate(() => ({ sw: document.documentElement.scrollWidth, iw: window.innerWidth }))
  expect(sw).toBeLessThanOrEqual(iw)
  // 9.3: no secret left anywhere on the client, in any request body, or in the console.
  if (secrets.length) {
    const state = await clientSideState(page)
    const bodies = mock.submits.map((s) => s.raw).join('\n') + mock.cancels.join('\n')
    const consoleText = mock.consoleLines.join('\n')
    for (const s of secrets) {
      expect(bodies.includes(s), 'secret in a request body').toBe(false)
      expect(state.includes(s), 'secret left in storage, cookie, URL, DOM or inputs').toBe(false)
      expect(consoleText.includes(s), 'secret in console').toBe(false)
    }
    expect(bodies).not.toContain('SECRET-CANARY')
  }
}

async function gotoPage(page: Page) {
  await page.goto(PAGE_PATH)
}

test.describe('scenario A: API key', () => {
  test('explains what, why, where and how; encrypts and saves', async ({ page }) => {
    const mock = await mockServer(page, 'A')
    await gotoPage(page)
    const main = page.locator('body')

    // (a) what
    await expect(page.getByTestId('kind-band')).toHaveText('API 키 입력 요청')
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('Exa API 키')
    await expect(page.getByLabel('API 키', { exact: true })).toBeVisible()
    await expect(main).toContainText('예: 3f9a0c2e71b44d0e9a58c1d27b6e0f4a')
    // (b) why and who
    await expect(main).toContainText('Exa 웹 검색 도구를 쓰려면 API 키가 필요합니다')
    await expect(page.getByTestId('requester')).toHaveText('Hermes(default 프로필) 안의 AI 모델이 작업 중에 위 이유를 적어 요청했습니다.')
    // (c) where: the storage list, .env on by default, the keychain off
    const env = page.getByTestId('store-env')
    await expect(page.getByRole('checkbox', { name: '설정 파일(.env)' })).toBeChecked()
    await expect(page.getByRole('checkbox', { name: 'Mac 키체인' })).not.toBeChecked()
    await expect(env.getByTestId('store-ident')).toHaveText('EXA_API_KEY')
    await expect(env).toContainText('default 프로필만 씁니다.')
    await expect(env.getByTestId('store-by')).toContainText('API 키를 기본으로 저장하는 곳이라 켜 두었습니다.')
    await expect(page.getByTestId('store-keychain')).toContainText('프로필과 상관없이, Hermes를 돌리는 사용자 계정의 로그인 키체인에 저장합니다.')
    await expect(page.getByLabel('저장할 프로필')).toHaveValue('default')
    // (d) how it is used
    await expect(main).toContainText('Hermes가 이 키를 쓰는 서비스를 호출할 때 이 값을 읽습니다.')
    // (e) time left and what happens next
    await expect(page.getByTestId('countdown')).toContainText(/남은 시간 [45]:\d\d/)
    await expect(main).toContainText('보내기 전에 이 기기에서 값을 암호화합니다.')
    await expect(main).toContainText('값은 Slack을 거치지 않습니다.')
    await expect(main).toContainText('Slack 대화에는 저장 결과만 표시됩니다.')
    await expect(main).toContainText('이 링크는 한 번만 열립니다. 이 창을 닫거나 새로 고치면 다시 열 수 없습니다.')
    await expect(main).toContainText('남은 시간이 끝나면 입력한 값을 지우고, 이 링크는 더 쓸 수 없게 됩니다.')
    await expect(main).toContainText('Hermes가 도는 컴퓨터만 풀 수 있습니다.')
    // How the key is kept and where it never shows.
    await expect(page.getByTestId('destination-notes')).toHaveText(
      ['이 페이지는 키 값을 Hermes 안의 AI 모델에게 보내지 않습니다.', 'AI 모델은 저장 위치마다 저장했는지를 받고, 사용자가 처음 상태에서 바꿔 끄거나 켠 저장 위치도 받습니다.'].join(''),
    )
    await expect(env).toContainText('이 파일은 암호화되지 않습니다. Hermes가 도는 컴퓨터에서 Hermes를 돌리는 사용자 계정만 읽을 수 있게 저장하고, Hermes 안의 AI 모델도 그 계정으로 명령을 실행하면 이 파일을 읽을 수 있습니다.')
    await expect(main).not.toContainText(['AI 모델은', '키를'].join(' '))
    await expect(main).not.toContainText(['에이', '전트'].join(''))
    await expect(main).toContainText('프로필은 Hermes 안에서 설정과 저장소를 따로 쓰는 작업 공간입니다.')
    // Which profile a store reaches is said once, on its row (above), not again under the select.
    await expect(main).not.toContainText('값은 여기서 고른 프로필에만 저장되고')
    await expect(main).not.toContainText('Mac 키체인은 프로필과 무관하게')
    // The mismatch line stays empty while the requester's own profile is chosen.
    await expect(page.getByTestId('profile-mismatch')).toHaveText('')

    // Changing the profile changes the scope sentence of the profile store.
    await page.getByLabel('저장할 프로필').selectOption('worker')
    await expect(env).toContainText('worker 프로필만 씁니다.')

    const secret = canary('A')
    const input = page.getByLabel('API 키', { exact: true })
    await expect(input).toHaveAttribute('type', 'password')
    await expect(input).toHaveAttribute('autocomplete', 'off')
    await expect(input).toHaveAttribute('autocapitalize', 'none')
    await expect(input).toHaveAttribute('autocorrect', 'off')
    await expect(input).toHaveAttribute('spellcheck', 'false')
    await input.fill(`  ${secret}  `)
    await page.getByRole('button', { name: '보이기' }).click()
    await expect(input).toHaveAttribute('type', 'text')
    await page.getByRole('button', { name: '가리기' }).click()
    await page.getByTestId('submit').click()

    await expect(page.getByTestId('done-screen')).toBeVisible()
    const doneEnv = page.getByTestId('done-store-env')
    await expect(doneEnv).toHaveAttribute('data-status', 'saved')
    await expect(doneEnv).toContainText('설정 파일(.env)')
    await expect(doneEnv).toContainText('worker')
    await expect(doneEnv).toContainText('EXA_API_KEY')
    await expect(page.getByTestId('done-store-keychain')).toHaveCount(0)
    await expect(page.getByTestId('done-screen')).toContainText('이 창을 닫아도 됩니다.')
    await expect(page.getByTestId('live')).toHaveText('저장했습니다')
    await expect(page.locator('input')).toHaveCount(0)

    expect(mock.submits).toHaveLength(1)
    const sub = mock.submits[0]
    expect(Object.keys(sub.json).sort()).toEqual(['ciphertext', 'client_public_key', 'iv', 'sid', 'v'])
    expect(sub.json.sid).toBe(mock.sid)
    // Protocol 2: v is 2 and the plaintext carries the chosen stores (A.7). Whitespace trimmed, chosen profile sent.
    expect(sub.json.v).toBe(2)
    expect(sub.plaintext).toEqual({ kind: 'api_key', target_profile: 'worker', value: secret, stores: ['env'] })
    await commonChecks(page, mock, [secret])
  })

  test('empty submit shows the error next to the field and focuses it', async ({ page }) => {
    const mock = await mockServer(page, 'A')
    await gotoPage(page)
    await page.getByTestId('submit').click()
    const input = page.getByLabel('API 키', { exact: true })
    await expect(page.getByText('API 키를 입력하세요.')).toBeVisible()
    await expect(input).toBeFocused()
    await expect(input).toHaveAttribute('aria-invalid', 'true')
    expect(mock.submits).toHaveLength(0)
    await commonChecks(page, mock)
  })

  test('storage_failed keeps the form, shows the error and allows a fresh resubmit', async ({ page }) => {
    const mock = await mockServer(page, 'A', {
      submitReplies: [
        { status: 422, body: { ok: false, error_code: 'storage_failed', message: '프로필 설정 파일에 쓰지 못했습니다.' } },
      ],
    })
    await gotoPage(page)
    const secret = canary('A2')
    await page.getByLabel('API 키', { exact: true }).fill(secret)
    await page.getByTestId('submit').click()

    const alert = page.getByRole('alert').filter({ hasText: '프로필 설정 파일에 쓰지 못했습니다.' })
    await expect(alert).toBeVisible()
    await expect(alert).toContainText('다시 보낼 수 있습니다.')
    await expect(page.getByTestId('credential-form')).toBeVisible()
    await expect(page.getByLabel('API 키', { exact: true })).toHaveValue(secret)

    await page.getByTestId('submit').click()
    await expect(page.getByTestId('done-screen')).toBeVisible()
    expect(mock.submits).toHaveLength(2)
    const [a, b] = mock.submits.map((s) => s.json)
    expect(a.client_public_key).not.toBe(b.client_public_key)
    expect(a.iv).not.toBe(b.iv)
    expect(mock.submits[1].plaintext).toEqual({ kind: 'api_key', target_profile: 'default', value: secret, stores: ['env'] })
    await commonChecks(page, mock, [secret])
  })

  test('masked_value keeps the form, shows the server sentence and allows a fresh resubmit', async ({ page }) => {
    const masked = '가려진 값처럼 보여 저장하지 않았습니다. 원래 키 전체를 붙여 넣어 주세요.'
    const mock = await mockServer(page, 'A', {
      submitReplies: [{ status: 422, body: { ok: false, error_code: 'masked_value', message: masked } }],
    })
    await gotoPage(page)
    await page.getByLabel('API 키', { exact: true }).fill('sk-abc...wxyz')
    await page.getByTestId('submit').click()

    const alert = page.getByRole('alert').filter({ hasText: masked })
    await expect(alert).toBeVisible()
    await expect(alert).toContainText('다시 보낼 수 있습니다.')
    await expect(page.getByTestId('credential-form')).toBeVisible()
    await expect(page.getByLabel('API 키', { exact: true })).toHaveValue('sk-abc...wxyz')

    const secret = canary('A3')
    await page.getByLabel('API 키', { exact: true }).fill(secret)
    await page.getByTestId('submit').click()
    await expect(page.getByTestId('done-screen')).toBeVisible()
    expect(mock.submits).toHaveLength(2)
    expect(mock.submits[0].plaintext).toEqual({ kind: 'api_key', target_profile: 'default', value: 'sk-abc...wxyz', stores: ['env'] })
    expect(mock.submits[1].plaintext).toEqual({ kind: 'api_key', target_profile: 'default', value: secret, stores: ['env'] })
    await commonChecks(page, mock, [secret])
  })
})

test.describe('scenario B: site login', () => {
  test('explains the vault destination and saves login + authenticator key', async ({ page }) => {
    const mock = await mockServer(page, 'B')
    await gotoPage(page)
    const main = page.locator('body')

    await expect(page.getByTestId('kind-band')).toHaveText('사이트 로그인 정보 입력 요청')
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('예시 쇼핑몰 관리자')
    await expect(main).toContainText('쇼핑몰 관리자 페이지를 점검하려면 로그인 정보가 필요합니다')
    await expect(page.getByTestId('requester')).toHaveText('Hermes(worker 프로필) 안의 AI 모델이 작업 중에 위 이유를 적어 요청했습니다.')
    const vault = page.getByTestId('store-hermes_vault')
    await expect(vault).toContainText('worker 프로필만 씁니다.')
    await expect(vault.getByTestId('store-ident')).toHaveText('https://admin.example.com')
    await expect(main).toContainText('Hermes가 앞으로 https://admin.example.com에 로그인할 때마다 이 로그인 정보를 로그인 화면에 자동으로 입력합니다.')
    // Reader-test fix 3: the replace rule names every id type, so "아이디" no longer doubles as the button word.
    await expect(vault).toContainText(
      '저장할 프로필에 같은 사이트 주소로 저장해 둔 로그인 가운데, 아래에 넣는 이메일 주소, 사용자 이름 또는 전화번호와 값이 같은 로그인이 있으면 그 로그인을 되돌릴 수 없게 지우고 이번에 넣은 것으로 바꿉니다.',
    )
    await expect(vault).toContainText('예전 로그인의 아이디 종류가 이번과 달라도 값이 같으면 바꿉니다.')
    await expect(vault).toContainText(
      'Hermes 안의 AI 모델은 비밀번호와 인증 앱 설정 키를 건네받지 않지만, 그 계정으로 명령을 실행하면 풀어 읽을 수 있습니다. 이메일, 사용자 이름, 전화번호 중 어느 것을 넣든 그 값은 저장한 뒤 AI 모델이 볼 수 있습니다.',
    )
    // The old round-5 sentences about an item that already exists stay gone.
    await expect(main).not.toContainText('그것은 그대로 두고')
    await expect(main).not.toContainText('방금 저장한 새 항목')
    await expect(page.getByLabel('저장할 프로필')).toHaveValue('worker')
    await expect(page.getByTestId('profile-mismatch')).toHaveText('')
    await expect(page.getByRole('group', { name: '아이디 종류' })).toHaveAccessibleDescription(
      '로그인할 때 쓰는 아이디의 형태를 고르세요. 아래 칸의 이름과 예시만 바뀌고, 자동 입력 방식은 같습니다.',
    )

    // Choosing another profile than the requester's shows the mismatch line in a live region,
    // the route title follows the choice, and choosing the requester's profile again hides it.
    const mismatch = page.getByTestId('profile-mismatch')
    await expect(mismatch).toHaveAttribute('aria-live', 'polite')
    await page.getByLabel('저장할 프로필').selectOption('default')
    await expect(mismatch).toHaveText(
      '요청한 쪽은 worker 프로필입니다. default 프로필에 저장하면 worker 프로필의 Hermes는 이 값을 쓰지 못합니다. ' +
        '요청한 작업에 쓰려면 worker 프로필을 고르세요. ' +
        '그대로 보내면 요청한 AI 모델은 default 프로필에 저장했다는 결과만 받습니다.',
    )
    // Profile names inside the sentence are kept out of browser translation.
    await expect(mismatch.locator('[translate="no"]')).toHaveText(['worker', 'default', 'worker', 'worker', 'default'])
    await expect(vault).toContainText('default 프로필만 씁니다.')
    await page.getByLabel('저장할 프로필').selectOption('worker')
    await expect(mismatch).toHaveText('')
    await expect(main).not.toContainText('방금 저장한 새 항목')
    await expect(page.getByRole('radio', { name: '이메일' })).toBeChecked()
    await expect(page.getByLabel('이메일 주소')).toBeVisible()
    await expect(main).toContainText('예: admin@example.com')
    await expect(page.getByLabel('비밀번호', { exact: true })).toHaveAttribute('type', 'password')
    await expect(page.getByTestId('countdown')).toContainText('남은 시간')

    // Identifier type switches the label and example.
    await page.getByText('사용자 이름', { exact: true }).click()
    await expect(page.getByRole('textbox', { name: '사용자 이름', exact: true })).toBeVisible()
    await expect(main).toContainText('예: shop_admin')
    await page.getByText('이메일', { exact: true }).click()

    // The authenticator setup key is folded away until asked for.
    const toggle = page.getByRole('button', { name: '인증 앱 설정 키 추가(선택)' })
    await expect(toggle).toHaveAttribute('aria-expanded', 'false')
    await expect(page.getByLabel('인증 앱 설정 키(선택)')).toBeHidden()
    await toggle.click()
    await expect(toggle).toHaveAttribute('aria-expanded', 'true')
    await expect(main).toContainText('로그인 때 사이트가 6자리 코드를 물으면 Hermes가 이 키로 코드를 만들어 입력합니다.')
    await expect(main).toContainText('그때는 코드 입력 요청이 따로 오지 않습니다.')

    const idSecret = canary('Bid')
    const pwSecret = canary('Bpw')
    const otpSecret = 'JBSWY3DP' + Array.from({ length: 16 }, () => 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'[Math.floor(Math.random() * 32)]).join('')
    await page.getByLabel('이메일 주소').fill(`${idSecret}@example.com`)
    await page.getByLabel('비밀번호', { exact: true }).fill(pwSecret)
    await page.getByLabel('인증 앱 설정 키(선택)').fill(otpSecret.toLowerCase().replace(/(.{4})/g, '$1 '))
    await page.getByTestId('submit').click()

    await expect(page.getByTestId('done-screen')).toBeVisible()
    const doneVault = page.getByTestId('done-store-hermes_vault')
    await expect(doneVault).toHaveAttribute('data-status', 'saved')
    await expect(doneVault).toContainText('Hermes 암호화 저장소(vault)')
    await expect(doneVault).toContainText('worker')
    await expect(doneVault).toContainText('https://admin.example.com')
    await expect(page.getByTestId('done-screen').locator(':scope > ul:last-child > li')).toHaveText([
      '아이디와 비밀번호를 한 항목으로 저장했습니다.',
      '인증 앱 설정 키도 같은 항목에 저장했습니다.',
      '비밀번호는 화면에 다시 보여 주지 않습니다.',
      '입력한 값은 이 브라우저 화면에서 지웠습니다.',
      '저장 결과는 Hermes 안의 AI 모델과 Slack 대화에도 전달됩니다.',
      '이 창을 닫아도 됩니다.',
    ])
    await expect(page.locator('input')).toHaveCount(0)

    expect(mock.submits[0].plaintext).toEqual({
      kind: 'login',
      target_profile: 'worker',
      identifier_type: 'email',
      identifier: `${idSecret}@example.com`,
      password: pwSecret,
      otp_secret: otpSecret,
      stores: ['hermes_vault'],
    })
    await commonChecks(page, mock, [idSecret, pwSecret, otpSecret])
  })
})

// Protocol 2 storage list, secret form, saving state and store results (card t_ce4fbc04, criteria 4 and 5).
const A12_NEW = '새 항목입니다. 값을 쓸 프로그램이 이 항목 이름과 키체인 계정 이름으로 읽게 되어 있는지는 값을 보낸 뒤 그 프로그램의 설정에서 직접 확인하세요.'
const A12_OVERWRITE = '이 이름의 항목에 이미 값이 있습니다. 보내면 그 값을 바꿉니다. 예전 값은 되돌릴 수 없습니다.'
const A12_SAVING = '저장 중입니다. 이 창을 닫지 마세요.'
const A12_UNKNOWN = '이 화면은 저장 결과를 받지 못했습니다. Slack 대화의 결과 메시지를 확인하세요.'
const A12_ENV_OFF = 'Hermes는 이 키를 .env에서 읽습니다. 끄면 Hermes는 이번에 넣는 키를 쓰지 못하고, .env에 이미 값이 있으면 그 값은 바뀌지 않습니다.'

test.describe('storage list (protocol 2)', () => {
  test('fixed row: the only store of a kind is checked and cannot be switched off', async ({ page }) => {
    // secret: the Mac keychain; login: the Hermes vault (decision 3 of the plan).
    for (const [s, name] of [
      ['D', 'Mac 키체인'],
      ['B', 'Hermes 암호화 저장소(vault)'],
    ] as const) {
      const mock = await mockServer(page, s)
      await gotoPage(page)
      const box = page.getByRole('checkbox', { name })
      await expect(box).toBeChecked()
      await expect(box).toBeDisabled()
      await expect(page.getByRole('checkbox')).toHaveCount(1)
      await expect(page.getByTestId('store-list')).toContainText('이 요청의 저장 위치는 이 한 곳뿐이라 켜 두었고, 끌 수 없습니다.')
      // Reader round 4, U1: a fixed row's 처음 상태 is the fixed sentence alone, without why it started on.
      await expect(page.getByTestId('store-by')).toHaveText('이 요청의 저장 위치는 이 한 곳뿐이라 켜 두었고, 끌 수 없습니다.')
      await expect(page.getByTestId('store-switch')).toHaveText('끌 수 없음')
      // A screen reader hears why the box is dimmed: its state line and the fixed sentence describe it.
      await expect(box).toHaveAccessibleDescription(/^끌 수 없음 이 요청의 저장 위치는 이 한 곳뿐이라 켜 두었고, 끌 수 없습니다\.$/)
      // A click on the box or its label changes nothing (force: the box is disabled, so Playwright would wait).
      await box.click({ force: true })
      await page.locator('label', { hasText: name }).click({ force: true })
      await expect(box).toBeChecked()
      await commonChecks(page, mock)
      await page.unrouteAll({ behavior: 'ignoreErrors' })
    }
  })

  test('switchable row: a 44px hit area around the 20px box; no "처음 상태" for a row nobody turned on', async ({ page }) => {
    const mock = await mockServer(page, 'A')
    await gotoPage(page)
    const box = page.getByRole('checkbox', { name: 'Mac 키체인' })
    await expect(box).not.toBeChecked()
    // The keychain row started off with no `by`: the empty box and "꺼짐" already say so.
    await expect(page.getByTestId('store-keychain').getByTestId('store-by')).toHaveCount(0)
    await expect(page.getByTestId('store-keychain')).not.toContainText('처음 상태')
    await expect(page.getByTestId('store-env').getByTestId('store-by')).toHaveCount(1)
    // Mouse clicks use viewport coordinates: bring the box on screen first.
    await box.scrollIntoViewIfNeeded()
    const b = (await box.boundingBox())!
    expect(Math.round(b.width)).toBe(20)
    // 11px outside the box on each side, and the gap up to the name, still switch it (20 + 2 x 12 = 44px).
    await page.mouse.click(b.x - 11, b.y + b.height / 2)
    await expect(box).toBeChecked()
    await page.mouse.click(b.x + b.width / 2, b.y - 11)
    await expect(box).not.toBeChecked()
    await page.mouse.click(b.x + b.width / 2, b.y + b.height + 11)
    await expect(box).toBeChecked()
    await page.mouse.click(b.x + b.width + 11, b.y + b.height / 2)
    await expect(box).not.toBeChecked()
    // The text-less label adds nothing to the name.
    await expect(page.getByRole('checkbox', { name: 'Mac 키체인', exact: true })).toHaveCount(1)
    await commonChecks(page, mock)
  })

  test("the agent's reason shows only as a captioned quote, never as a plain sentence", async ({ page }) => {
    const mock = await mockServer(page, 'D')
    await gotoPage(page)
    const reason = '잠금 해제 스크립트는 이 값을 Mac 키체인에서만 읽습니다'
    const quote = page.getByTestId('store-reason')
    await expect(quote.locator('figcaption')).toHaveText('AI 모델이 이 저장 위치에 적은 이유')
    await expect(quote.locator('blockquote')).toHaveText(`“${reason}”`)
    // The sentence occurs once on the page, and that once is inside the blockquote.
    const count = await page.evaluate((r) => document.body.innerText.split(r).length - 1, reason)
    expect(count).toBe(1)
    // The only element whose own text holds the sentence is that blockquote.
    const owners = await page.evaluate((r) => {
      const out: string[] = []
      for (const el of document.querySelectorAll('body *')) {
        const own = [...el.childNodes].filter((n) => n.nodeType === Node.TEXT_NODE).map((n) => n.textContent).join('')
        if (own.includes(r)) out.push(el.tagName)
      }
      return out
    }, reason)
    expect(owners).toEqual(['BLOCKQUOTE'])
    // Plugin facts in the same row stay plain sentences, outside the quote.
    await expect(quote.locator('blockquote')).not.toContainText('이 Mac에 로그인한 사용자 계정')
    await commonChecks(page, mock)
  })

  test('saving: pressing send shows the A.12 saving line and disables send and cancel', async ({ page }) => {
    const mock = await mockServer(page, 'A', { holdSubmit: true })
    await gotoPage(page)
    const secret = canary('S')
    await page.getByLabel('API 키', { exact: true }).fill(secret)
    await page.getByTestId('submit').click()
    const saving = page.getByTestId('saving')
    await expect(saving).toBeVisible()
    await expect(saving).toContainText(A12_SAVING)
    await expect(saving).toHaveAttribute('role', 'status')
    await expect(page.getByTestId('submit')).toBeDisabled()
    await expect(page.getByTestId('submit')).toHaveText('저장 중…')
    await expect(page.getByRole('button', { name: '요청 취소', exact: true })).toBeDisabled()
    // The time left stays in view while saving (reader round 5, V3), and the storage list is frozen.
    await expect(page.getByTestId('countdown')).toBeVisible()
    await expect(page.getByTestId('countdown')).toContainText('남은 시간')
    // Nor is the deadline line, and the read-only field is dimmed by a ground-coloured fill (reader round 1, P8, P9).
    await expect(page.getByTestId('timeout-note')).toHaveCount(0)
    const field = page.getByLabel('API 키', { exact: true })
    await expect(field).toHaveAttribute('readonly', '')
    await expect(field).toHaveCSS('background-color', 'rgb(228, 233, 242)')
    await expect(page.getByRole('checkbox', { name: 'Mac 키체인' })).toBeDisabled()
    expect(mock.cancels).toHaveLength(0)
    mock.release()
    await expect(page.getByTestId('done-screen')).toBeVisible()
    await commonChecks(page, mock, [secret])
  })

  test('switching off a needed store warns; api_key with .env off shows the A.12 warning', async ({ page }) => {
    const mock = await mockServer(page, 'A2')
    await gotoPage(page)
    const kc = page.getByRole('checkbox', { name: 'Mac 키체인' })
    const env = page.getByRole('checkbox', { name: '설정 파일(.env)' })
    await expect(kc).toBeChecked()
    await expect(page.getByTestId('store-warning-keychain')).toHaveText('')
    await expect(page.getByTestId('store-keychain').getByTestId('store-by')).toContainText('AI 모델이 골라서 켜 두었습니다.')
    await expect(page.getByTestId('store-env').getByTestId('store-by')).toContainText('전에 이 입력 페이지로 같은 이름의 값을 저장할 때 쓴 저장 위치라 켜 두었습니다.')
    await kc.click()
    await expect(kc).not.toBeChecked()
    await expect(page.getByTestId('store-warning-keychain')).toHaveText(
      '끄면 이곳에서 이 값을 읽는 프로그램은 이번에 넣는 값을 쓰지 못하고, 이곳에 이미 값이 있으면 그 값은 바뀌지 않습니다.',
    )
    await kc.click()
    await env.click()
    await expect(page.getByTestId('store-warning-env')).toHaveText(A12_ENV_OFF)
    await expect(page.getByTestId('store-warning-env').locator('code')).toHaveText(['.env', '.env'])
    // With only the keychain on, no store is kept per profile, so the profile choice is hidden (plan 2.5).
    await expect(page.getByLabel('저장할 프로필')).toBeHidden()
    await commonChecks(page, mock)
  })

  test('api_key: the A.12 .env warning also shows when the agent left .env off', async ({ page }) => {
    const rows = structuredClone(SCENARIOS.A2.target.stores)
    rows[0] = { ...rows[0], selected: false, by: null }
    const mock = await mockServer(page, 'A2', { targetPatch: { stores: rows } })
    await gotoPage(page)
    await expect(page.getByRole('checkbox', { name: '설정 파일(.env)' })).not.toBeChecked()
    await expect(page.getByTestId('store-warning-env')).toHaveText(A12_ENV_OFF)
    await commonChecks(page, mock)
  })

  test('a reply lost while saving shows the A.12 result-unknown sentence', async ({ page }) => {
    const mock = await mockServer(page, 'A2', { submitReplies: [{ abort: true }] })
    await gotoPage(page)
    const secret = canary('U')
    await page.getByLabel('API 키', { exact: true }).fill(secret)
    await page.getByTestId('submit').click()
    const end = page.getByTestId('end-screen')
    await expect(end).toHaveAttribute('data-reason', 'result_unknown')
    await expect(end.locator('li').first()).toHaveText(A12_UNKNOWN)
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('저장했는지 알 수 없습니다')
    await expect(page.getByTestId('submit')).toHaveCount(0)
    await commonChecks(page, mock, [secret])
  })

  test('storage_failed with result_unknown shows the same sentence and no resend', async ({ page }) => {
    const mock = await mockServer(page, 'D2', {
      submitReplies: [
        {
          status: 422,
          body: {
            ok: false,
            error_code: 'storage_failed',
            message: 'x',
            result_unknown: true,
            stores: [{ store: 'keychain', saved: null, replaced: null, error: 'store_timeout' }],
          },
        },
      ],
    })
    await gotoPage(page)
    const v = canary('RU')
    await page.getByLabel('비밀번호', { exact: true }).fill(v)
    await page.getByLabel('비밀번호 다시 입력', { exact: true }).fill(v)
    await page.getByTestId('submit').click()
    await expect(page.getByTestId('end-screen')).toHaveAttribute('data-reason', 'result_unknown')
    await expect(page.getByTestId('end-screen')).toContainText(A12_UNKNOWN)
    await commonChecks(page, mock, [v])
  })

  test('a submit of a stored kind answered 410 deadline_passed shows result unknown, never "not sent"', async ({ page }) => {
    // The server says deadline_passed after a save when the submit window passed while saving and the save
    // ended retryable (secure_input/server.py _apply_save). The value was sent, and a keychain item may have
    // changed (main_touched), so the page must not show the timeout screen's "보내지 않았습니다" (reader round 6, X1).
    const mock = await mockServer(page, 'D2', {
      submitReplies: [
        { status: 410, body: { ok: false, error_code: 'deadline_passed', message: '제출 시간이 지났습니다. 새 링크를 요청하세요.' } },
      ],
    })
    await gotoPage(page)
    const v = canary('DP')
    await page.getByLabel('비밀번호', { exact: true }).fill(v)
    await page.getByLabel('비밀번호 다시 입력', { exact: true }).fill(v)
    await page.getByTestId('submit').click()
    const end = page.getByTestId('end-screen')
    await expect(end).toHaveAttribute('data-reason', 'result_unknown')
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('저장했는지 알 수 없습니다')
    await expect(end).toContainText(A12_UNKNOWN)
    await expect(end).not.toContainText('보내지 않았습니다')
    await expect(page.getByTestId('submit')).toHaveCount(0)
    expect(mock.submits).toHaveLength(1)
    await commonChecks(page, mock, [v])
  })

  test('every store off: the page does not send and says why', async ({ page }) => {
    const mock = await mockServer(page, 'A')
    await gotoPage(page)
    await page.getByRole('checkbox', { name: '설정 파일(.env)' }).click()
    await page.getByLabel('API 키', { exact: true }).fill(canary('N'))
    await page.getByTestId('submit').click()
    await expect(page.getByTestId('stores-none')).toHaveText('저장 위치를 한 곳 이상 켜세요. 모두 끄면 보낼 수 없습니다.')
    await expect(page.getByRole('checkbox', { name: '설정 파일(.env)' })).toBeFocused()
    expect(mock.submits).toHaveLength(0)
    // Switching one on clears the message and sends.
    await page.getByRole('checkbox', { name: 'Mac 키체인' }).click()
    await expect(page.getByTestId('stores-none')).toHaveCount(0)
    await page.getByTestId('submit').click()
    await expect(page.getByTestId('done-screen')).toBeVisible()
    expect(mock.submits[0].plaintext?.stores).toEqual(['keychain'])
  })

  test('store_unavailable: nothing saved, the store is named, and switching it off lets the page resend', async ({ page }) => {
    const mock = await mockServer(page, 'A2', {
      submitReplies: [
        {
          status: 422,
          body: { ok: false, error_code: 'store_unavailable', message: 'x', stores: [{ store: 'keychain', reason: 'keychain_acl_denied' }] },
        },
      ],
    })
    await gotoPage(page)
    const secret = canary('SU')
    await page.getByLabel('API 키', { exact: true }).fill(secret)
    await page.getByTestId('submit').click()
    const alert = page.getByTestId('store-alert')
    await expect(alert).toContainText('아무 데도 저장하지 않았습니다')
    await expect(alert).toContainText('Mac 키체인: 이 키체인 항목의 접근 허용 목록에 /usr/bin/security가 없어서 Hermes가 이 항목의 값을 바꾸지 않습니다.')
    await expect(alert).toContainText('켠 저장 위치 가운데 지금 쓸 수 없는 곳이 있어서, 어디에도 쓰지 않았습니다.')
    await expect(alert).toContainText('그 저장 위치를 끄고 이 화면에서 다시 보내면 나머지 저장 위치에만 저장합니다.')
    await expect(alert).not.toContainText('원인을 고친 뒤')
    await expect(page.getByTestId('store-keychain').getByTestId('store-unavailable')).toContainText('지금은 Mac 키체인에 저장할 수 없습니다.')
    // What to do next is said once, in the alert by the send button, not again on the row.
    await expect(page.getByTestId('store-keychain').getByTestId('store-unavailable')).not.toContainText('칸을 끄면 나머지 저장 위치에만')
    // The row that cannot be written drops who could read it; its overwrite note and the other row keep theirs (reader round 5, V1).
    await expect(page.getByTestId('store-keychain')).not.toContainText('읽을 수 있는 쪽')
    await expect(page.getByTestId('store-keychain').getByTestId('keychain-overwrite')).toBeVisible()
    await expect(page.getByTestId('store-env')).toContainText('읽을 수 있는 쪽')
    await expect(page.getByLabel('API 키', { exact: true })).toHaveValue(secret)
    await expect(page.getByTestId('countdown')).toBeVisible()
    await page.getByRole('checkbox', { name: 'Mac 키체인' }).click()
    await page.getByTestId('submit').click()
    await expect(page.getByTestId('done-screen')).toBeVisible()
    expect(mock.submits.map((x) => x.plaintext?.stores)).toEqual([['env', 'keychain'], ['env']])
    await commonChecks(page, mock, [secret])
  })

  test('partial save: the done screen says which store saved and which did not', async ({ page }) => {
    const mock = await mockServer(page, 'A2', {
      successLines: { keychain: { saved: false, replaced: null, error: 'keychain_write_failed', main_touched: false } },
    })
    await gotoPage(page)
    await page.getByLabel('API 키', { exact: true }).fill(canary('P'))
    await page.getByTestId('submit').click()
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('일부만 저장했습니다')
    await expect(page.getByTestId('done-store-env')).toHaveAttribute('data-status', 'saved')
    await expect(page.getByTestId('done-store-env')).toContainText('예전 값을 바꿔 저장했습니다.')
    await expect(page.getByTestId('done-store-keychain')).toHaveAttribute('data-status', 'failed')
    // keychain_write_failed gets no cause line: it would only repeat the status line (reader round 1, P13).
    // The item held a value before (A2 exists: true) and no write reached it (main_touched false): reader round 2, S18.
    await expect(page.getByTestId('done-store-keychain')).toContainText('저장하지 못했고, 예전 값은 그대로입니다.')
    await expect(page.getByTestId('done-store-keychain')).not.toContainText('Mac 키체인에 쓰지 못했습니다.')
    await expect(page.getByTestId('done-screen')).toContainText('입력한 항목')
    await expect(page.getByTestId('done-screen')).toContainText('저장 결과는 Hermes 안의 AI 모델과 Slack 대화에도 전달됩니다.')
    await expect(page.getByTestId('done-screen')).toContainText('저장하지 못한 곳에만 다시 넣으려면 링크를 받은 Slack 대화에서 Hermes에게 다시 요청하세요.')
    await commonChecks(page, mock)
  })

  test('a deadline that passed while saving closes the page once the server answers', async ({ page }) => {
    const mock = await mockServer(page, 'A', {
      holdSubmit: true,
      openPatch: { submit_deadline_s: 3 },
      submitReplies: [
        { status: 422, body: { ok: false, error_code: 'store_unavailable', message: 'x', stores: [{ store: 'env', reason: 'bad_home' }] } },
      ],
    })
    await gotoPage(page)
    await page.getByLabel('API 키', { exact: true }).fill(canary('DL'))
    await page.getByTestId('submit').click()
    await expect(page.getByTestId('saving')).toBeVisible()
    await page.waitForTimeout(3500)
    // Still saving: the page never closes itself while the server is writing. The time left stops at 0:00
    // and the typed value is kept until the server answers (reader round 5, V3).
    await expect(page.getByTestId('saving')).toBeVisible()
    await expect(page.getByTestId('countdown')).toContainText('남은 시간 0:00')
    await expect(page.getByTestId('timeout-note')).toHaveCount(0)
    await expect(page.getByLabel('API 키', { exact: true })).not.toHaveValue('')
    mock.release()
    await expect(page.getByTestId('end-screen')).toHaveAttribute('data-reason', 'deadline_passed')
  })
})

test.describe('scenario D: secret (a password kept only in the Mac keychain)', () => {
  test('names the keychain item, warns about the overwrite, compares the two entries', async ({ page }) => {
    const mock = await mockServer(page, 'D')
    await gotoPage(page)
    const main = page.locator('body')
    await expect(page.getByTestId('kind-band')).toHaveText('비밀번호 입력 요청')
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('Example Vault 비밀번호')
    const kc = page.getByTestId('store-keychain')
    await expect(kc.getByTestId('store-ident')).toHaveText('example-unlock-item')
    await expect(kc).toContainText('키체인 계정 이름 example-unlock-item')
    await expect(kc).toContainText('이 항목을 쓰는 곳: Example Vault 자동 잠금 해제 스크립트')
    await expect(kc.getByTestId('keychain-overwrite')).toHaveText(A12_OVERWRITE)
    await expect(kc.getByTestId('keychain-new')).toHaveCount(0)
    await expect(kc).toContainText('Hermes가 도는 컴퓨터에서 Hermes를 돌리는 사용자 계정의 프로그램만 이 값을 읽을 수 있고, Hermes 안의 AI 모델도 그 계정으로 명령을 실행하면 이 값을 읽을 수 있습니다.')
    await expect(kc).not.toContainText('터미널 도구로')
    await expect(kc).toContainText('프로필과 상관없이, Hermes를 돌리는 사용자 계정의 로그인 키체인에 저장합니다.')
    // No profile choice on this screen (plan 3.1 / card 3.6).
    await expect(page.getByLabel('저장할 프로필')).toHaveCount(0)
    await expect(main).not.toContainText('저장할 프로필')

    const value = canary('D')
    const pw = page.getByLabel('비밀번호', { exact: true })
    const again = page.getByLabel('비밀번호 다시 입력', { exact: true })
    await expect(pw).toHaveAttribute('type', 'password')
    await expect(again).toHaveAttribute('type', 'password')
    await pw.fill(value)
    await again.fill(value + 'x')
    await page.getByTestId('submit').click()
    await expect(page.getByText('두 칸의 값이 다릅니다. 같은 비밀번호를 다시 입력하세요.')).toBeVisible()
    await expect(again).toBeFocused()
    expect(mock.submits).toHaveLength(0)

    await again.fill(value)
    await page.getByTestId('submit').click()
    await expect(page.getByTestId('done-screen')).toBeVisible()
    const done = page.getByTestId('done-store-keychain')
    await expect(done).toHaveAttribute('data-status', 'saved')
    await expect(done).toContainText('예전 값을 바꿔 저장했습니다.')
    await expect(done).toContainText('example-unlock-item')
    await expect(page.getByTestId('done-screen')).toContainText('비밀번호는 화면에 다시 보여 주지 않습니다.')
    expect(mock.submits[0].json.v).toBe(2)
    expect(mock.submits[0].plaintext).toEqual({ kind: 'secret', target_profile: 'default', value, stores: ['keychain'] })
    await commonChecks(page, mock, [value])
  })

  test('a space at either end is refused, not trimmed', async ({ page }) => {
    const mock = await mockServer(page, 'D')
    await gotoPage(page)
    await page.getByLabel('비밀번호', { exact: true }).fill(' SECRET-CANARY-space')
    await page.getByLabel('비밀번호 다시 입력', { exact: true }).fill(' SECRET-CANARY-space')
    await page.getByTestId('submit').click()
    await expect(page.getByText('비밀번호의 맨 앞이나 맨 뒤에 공백이 있습니다.', { exact: false })).toBeVisible()
    expect(mock.submits).toHaveLength(0)
  })

  test('a new plugin item says no program reads that name yet', async ({ page }) => {
    const mock = await mockServer(page, 'D2')
    await gotoPage(page)
    const kc = page.getByTestId('store-keychain')
    await expect(kc.getByTestId('store-ident')).toHaveText('hermes-secure-input.backup-archive')
    await expect(kc).toContainText('키체인 계정 이름 hermes-secure-input')
    await expect(kc.getByTestId('keychain-new')).toHaveText(A12_NEW)
    await expect(kc.getByTestId('keychain-overwrite')).toHaveCount(0)
    await expect(kc.getByTestId('store-reason')).toHaveCount(0)
    await commonChecks(page, mock)
  })
})

test.describe('scenario B: authenticator key warning (reader-test fix 2)', () => {
  test('the old-key warning shows without opening the setup-key section', async ({ page }) => {
    const mock = await mockServer(page, 'B')
    await gotoPage(page)
    const toggle = page.getByRole('button', { name: '인증 앱 설정 키 추가(선택)' })
    await expect(toggle).toHaveAttribute('aria-expanded', 'false')
    await expect(page.getByLabel('인증 앱 설정 키(선택)')).toBeHidden()
    const loss = page.getByTestId('otp-secret-loss')
    await expect(loss).toBeVisible()
    await expect(loss).toContainText('이번에 설정 키를 넣지 않고 보내도 그 로그인의 인증 앱 설정 키가 함께 지워집니다.')
    await expect(toggle).toHaveAccessibleDescription(/함께 지워집니다/)
    await commonChecks(page, mock)
  })
})

test.describe('scenario C: one-time code', () => {
  test('says the code is not stored and delivers it once', async ({ page }) => {
    const mock = await mockServer(page, 'C')
    await gotoPage(page)
    const main = page.locator('body')

    await expect(page.getByTestId('kind-band')).toHaveText('일회용 코드 입력 요청')
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('accounts.example.com 일회용 코드')
    await expect(main).toContainText('accounts.example.com 로그인 도중 사이트가 일회용 코드를 요구했습니다')
    await expect(page.getByTestId('requester')).toHaveText('Hermes(default 프로필) 안의 AI 모델이 작업 중에 위 이유를 적어 요청했습니다.')
    await expect(main).toContainText('Hermes가 지금 진행 중인 accounts.example.com 로그인 화면에 한 번 입력하고 버립니다.')
    await expect(page.getByTestId('destination-notes')).toHaveText('이 페이지는 코드를 Hermes 안의 AI 모델에게 보내지 않습니다.')
    await expect(main).toContainText('일회용 코드는 어디에도 저장하지 않습니다.')
    // The code is not stored, so the Slack line must not speak of a "saved" result.
    await expect(main).toContainText('Slack 대화에는 전달 결과만 표시됩니다.')
    await expect(main).not.toContainText('저장 결과')
    await expect(page.getByLabel('저장할 프로필')).toHaveCount(0)
    await expect(page.getByRole('combobox')).toHaveCount(0)
    await expect(main).toContainText('예: 123456')
    await expect(main).toContainText('코드는 사이트에서 금방 만료되니 받은 즉시 보내세요.')
    await expect(page.getByTestId('countdown')).toContainText('남은 시간')

    const input = page.getByLabel('일회용 코드', { exact: true })
    await expect(input).toHaveAttribute('inputmode', 'numeric')
    await expect(input).toHaveAttribute('autocomplete', 'one-time-code')
    const code = String(10_000_000 + Math.floor(Math.random() * 89_999_999))
    await input.fill(`${code.slice(0, 4)}-${code.slice(4)} `)
    await page.getByTestId('submit').click()

    await expect(page.getByTestId('done-screen')).toBeVisible()
    await expect(page.getByTestId('done-screen')).toContainText('전달했습니다')
    await expect(page.getByTestId('done-screen')).toContainText('accounts.example.com 로그인 화면')
    await expect(page.getByTestId('done-screen').locator('li')).toHaveText([
      '코드를 Hermes에 넘겼습니다.',
      'Hermes가 곧바로 로그인 화면에 입력합니다.',
      '로그인이 됐는지, 코드가 틀렸는지는 이 화면에 나오지 않습니다. Slack 대화에서 확인하세요.',
      '일회용 코드는 어디에도 저장하지 않습니다.',
      '입력한 값은 이 브라우저 화면에서 지웠습니다.',
      'Slack 대화에도 전달 결과가 표시됩니다.',
      '이 창을 닫아도 됩니다.',
    ])
    await expect(page.getByTestId('done-screen')).toContainText('Slack 대화에도 전달 결과가 표시됩니다.')
    await expect(main).not.toContainText('저장 결과')
    expect(mock.submits[0].plaintext).toEqual({ kind: 'otp_code', code })
    await commonChecks(page, mock, [code])
  })
})

test.describe('end screens', () => {
  const expectEnd = async (page: Page, reason: string, heading: string) => {
    const end = page.getByTestId('end-screen')
    await expect(end).toBeVisible()
    await expect(end).toHaveAttribute('data-reason', reason)
    await expect(page.getByRole('heading', { level: 1 })).toHaveText(heading)
    await expect(page.locator('input, select, textarea')).toHaveCount(0)
    await expect(page.getByTestId('live')).toHaveText(heading)
  }

  test('already_opened', async ({ page }) => {
    const mock = await mockServer(page, 'A', { openReply: { status: 410, body: { ok: false, error_code: 'already_opened' } } })
    await gotoPage(page)
    await expectEnd(page, 'already_opened', '이미 열린 링크입니다')
    await commonChecks(page, mock)
  })

  for (const code of ['identity_required', 'identity_not_allowed']) {
    test(`open refused with ${code}: one identity end screen, no form`, async ({ page }) => {
      const mock = await mockServer(page, 'A', { openReply: { status: 403, body: { ok: false, error_code: code, message: 'x' } } })
      await gotoPage(page)
      await expectEnd(page, 'identity_denied', '이 기기의 Tailscale 계정으로는 열 수 없습니다')
      // Reader-test fixes 1 and 4: what "unused" means, and what to do once the 60 s are over.
      await expect(page.getByTestId('end-screen').locator('li')).toHaveText([
        '이 링크는 Hermes 컴퓨터에 허용된 Tailscale 계정으로 로그인한 기기에서만 열 수 있습니다.',
        '이 기기에서 열려고 한 것은 링크를 연 것으로 치지 않았습니다. 그래서 이 링크는 아직 한 번 열 수 있습니다.',
        '허용된 계정의 기기에서 링크를 만든 뒤 60초 안에 여세요. 60초가 지나면 링크가 만료되고, 그때는 링크를 받은 Slack 대화에서 새 링크를 요청해야 합니다.',
        '본인 기기에서 이 화면이 나왔다면 이 기기의 Tailscale 앱이 어느 계정으로 로그인되어 있는지 확인하세요.',
      ])
      await commonChecks(page, mock)
    })
  }

  test('reloading an opened page lands on already_opened', async ({ page }) => {
    const mock = await mockServer(page, 'A')
    await gotoPage(page)
    await expect(page.getByTestId('credential-form')).toBeVisible()
    await page.reload()
    await expectEnd(page, 'already_opened', '이미 열린 링크입니다')
    await expect(page.getByTestId('end-screen').locator('li')).toHaveText([
      '이 링크는 한 번만 열 수 있고, 이미 한 번 열렸습니다.',
      '지금 이 창에서는 값을 넣을 수 없습니다.',
      '먼저 연 창이 남아 있으면 그 창에서 계속 입력하세요.',
      '그 창을 닫았거나 새로 고쳤다면 새 링크가 필요합니다. 링크를 받은 Slack 대화에서 다시 요청하세요.',
      '직접 연 적이 없다면 다른 사람이 열었을 수 있습니다. 이 경우 값을 넣지 말고, 링크를 받은 Slack 대화에서 다시 요청하세요.',
    ])
    expect(mock.opened).toBe(2)
  })

  test('leaving an open form asks before unloading (the link cannot be reopened)', async ({ page }) => {
    await mockServer(page, 'A')
    await gotoPage(page)
    const input = page.getByLabel('API 키', { exact: true })
    await input.click()
    await page.keyboard.type('SECRET-CANARY-leave')
    const asked = new Promise<string>((resolve) => page.once('dialog', (d) => resolve(d.type())))
    await page.close({ runBeforeUnload: true })
    expect(await asked).toBe('beforeunload')
  })

  test('expired', async ({ page }) => {
    const mock = await mockServer(page, 'B', { openReply: { status: 410, body: { error_code: 'expired' } } })
    await gotoPage(page)
    await expectEnd(page, 'expired', '열 수 있는 시간이 지났습니다')
    await commonChecks(page, mock)
  })

  test('countdown reaching 0 clears the input and closes the page', async ({ page }) => {
    const mock = await mockServer(page, 'A', { openPatch: { submit_deadline_s: 3 } })
    await gotoPage(page)
    const secret = canary('T')
    await page.getByLabel('API 키', { exact: true }).fill(secret)
    await expectEnd(page, 'deadline_passed', '제출 시간이 지났습니다')
    expect(mock.submits).toHaveLength(0)
    await commonChecks(page, mock, [secret])
  })

  test('too_many_attempts', async ({ page }) => {
    const mock = await mockServer(page, 'C', {
      submitReplies: [{ status: 429, body: { ok: false, error_code: 'too_many_attempts', message: '시도 횟수를 넘었습니다.' } }],
    })
    await gotoPage(page)
    await page.getByLabel('일회용 코드', { exact: true }).fill('123456')
    await page.getByTestId('submit').click()
    await expectEnd(page, 'too_many_attempts', '시도 횟수를 넘었습니다')
    await commonChecks(page, mock)
  })

  test('cancel asks once, then tells the server and closes', async ({ page }) => {
    const mock = await mockServer(page, 'B')
    await gotoPage(page)
    const secret = canary('X')
    await page.getByLabel('비밀번호', { exact: true }).fill(secret)
    await page.getByRole('button', { name: '요청 취소', exact: true }).click()
    await expect(page.getByText('요청을 취소할까요? 이 링크는 다시 열 수 없습니다.')).toBeVisible()
    await page.getByRole('button', { name: '요청 취소하기' }).click()
    await expectEnd(page, 'cancelled', '요청을 취소했습니다')
    await expect(page.getByTestId('end-screen').locator('li')).toHaveText([
      '아무 값도 보내지 않았습니다.',
      'Slack 대화에도 취소 결과가 표시됩니다.',
      '요청한 AI 모델에도 취소했다고 전달됩니다.',
      '나중에 다시 넣으려면 링크를 받은 Slack 대화에서 Hermes에게 다시 요청하세요.',
      '이 창을 닫아도 됩니다.',
    ])
    expect(mock.cancels).toEqual([JSON.stringify({ sid: mock.sid })])
    expect(mock.submits).toHaveLength(0)
    await commonChecks(page, mock, [secret])
  })

  test('a request the user made by command: no Hermes-only lines, and the command way to ask again', async ({ page }) => {
    const mock = await mockServer(page, 'B', { openPatch: { requester: { type: 'user', profile: 'worker' } } })
    await gotoPage(page)
    const main = page.locator('body')
    await expect(page.getByTestId('requester')).toHaveText('본인이 명령으로 직접 요청했습니다(worker 프로필).')
    await expect(main).not.toContainText('그것은 그대로 두고')
    await expect(main).not.toContainText('방금 저장한 새 항목')
    // A user command: the mismatch line says what to pick and has no result-only sentence.
    await page.getByLabel('저장할 프로필').selectOption('default')
    await expect(page.getByTestId('profile-mismatch')).toHaveText(
      '요청한 쪽은 worker 프로필입니다. default 프로필에 저장하면 worker 프로필의 Hermes는 이 값을 쓰지 못합니다. ' +
        'worker 프로필에서 쓰려면 worker 프로필을 고르세요.',
    )
    await page.getByRole('button', { name: '요청 취소', exact: true }).click()
    await page.getByRole('button', { name: '요청 취소하기' }).click()
    await expectEnd(page, 'cancelled', '요청을 취소했습니다')
    await expect(page.getByTestId('end-screen').locator('li')).toHaveText([
      '아무 값도 보내지 않았습니다.',
      'Slack 대화에도 취소 결과가 표시됩니다.',
      '나중에 다시 넣으려면 링크를 띄울 때 보낸 명령을 같은 대화에 다시 보내세요.',
      '이 창을 닫아도 됩니다.',
    ])
    await commonChecks(page, mock)
  })
})
