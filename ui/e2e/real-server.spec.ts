// Real round trips (integration card, criterion 3 and 5): a real secure-input server process and
// storage grandchild (scripts/e2e_real_driver.py, Hermes' venv Python) serve the built page on
// http://127.0.0.1. The browser fills canary values and submits; the driver compares what was stored
// (.env line, vault read-back, delivered code) with what was typed and reports booleans only.

import { spawn, spawnSync, type ChildProcessWithoutNullStreams } from 'node:child_process'
import { mkdtempSync, rmSync } from 'node:fs'
import { homedir, tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { createInterface } from 'node:readline'
import { fileURLToPath } from 'node:url'
import { expect, test } from '@playwright/test'
import { canary } from './harness.ts'

// The drivers use a fake Tailscale whose owner is this account (tests/helpers/fake_tailscale.py
// FAKE_OWNER_LOGIN); the browser talks to 127.0.0.1 directly, so it sends the header Serve would add.
test.use({ extraHTTPHeaders: { 'Tailscale-User-Login': 'owner@example.test' } })

const HERE = dirname(fileURLToPath(import.meta.url))
const DRIVER = join(HERE, '..', '..', 'scripts', 'e2e_real_driver.py')
const PYTHON = process.env.HERMES_PYTHON ?? join(homedir(), '.hermes', 'hermes-agent', '.venv', 'bin', 'python')

type Ready = { event: 'ready'; local_url: string; request_id: string }
type Result = { event: 'result'; status: string; target_profile: string; checks: Record<string, boolean> }

class Driver {
  private lines: string[] = []
  private waiters: ((l: string) => void)[] = []
  stderr = ''
  constructor(readonly proc: ChildProcessWithoutNullStreams) {
    createInterface({ input: proc.stdout }).on('line', (l) => {
      const w = this.waiters.shift()
      if (w) w(l)
      else this.lines.push(l)
    })
    proc.stderr.on('data', (d) => (this.stderr += String(d)))
  }
  next<T>(timeoutMs = 30_000): Promise<T> {
    const l = this.lines.shift()
    if (l !== undefined) return Promise.resolve(JSON.parse(l) as T)
    return new Promise<T>((resolve, reject) => {
      const t = setTimeout(() => reject(new Error(`driver timeout; stderr: ${this.stderr.slice(-2000)}`)), timeoutMs)
      this.waiters.push((line) => {
        clearTimeout(t)
        resolve(JSON.parse(line) as T)
      })
    })
  }
  async finish(expectValues: Record<string, string>): Promise<Result> {
    this.proc.stdin.write(JSON.stringify({ expect: expectValues }) + '\n')
    this.proc.stdin.end()
    return this.next<Result>(60_000)
  }
}

// Every driver this test started, with the temp root it was given. A test that fails or times out leaves the
// driver waiting on stdin (and its server process with it), and the driver's own `finally` never runs, so
// afterEach ends them and removes the folder.
const started: { proc: ChildProcessWithoutNullStreams; tmp: string }[] = []
// Keychain items a `secret` test may leave behind when it stops before the driver deletes them.
const keychainLeft: string[] = []
const TEST_SERVICE = /^hermes-secure-input-test-[a-z0-9-]+$/

/**
 * Starts a driver script as the leader of its own process group (so the server process it starts can be ended
 * with it) and with its own TMPDIR under an `si-e2e-run-` folder (so the driver's `si-e2e-` folder lands inside).
 */
function spawnDriver(args: string[]): ChildProcessWithoutNullStreams {
  const tmp = mkdtempSync(join(tmpdir(), 'si-e2e-run-'))
  const proc = spawn(PYTHON, ['-P', ...args], {
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1', TMPDIR: tmp },
    detached: true,
  })
  started.push({ proc, tmp })
  return proc
}

function startDriver(kind: string, requested = 'default'): Driver {
  return new Driver(spawnDriver([DRIVER, '--kind', kind, '--requested', requested]))
}

const exited = (proc: ChildProcessWithoutNullStreams, ms: number) =>
  proc.exitCode !== null || proc.signalCode !== null
    ? Promise.resolve(true)
    : new Promise<boolean>((resolve) => {
        const t = setTimeout(() => resolve(false), ms)
        proc.once('exit', () => {
          clearTimeout(t)
          resolve(true)
        })
      })

function killGroup(pid: number | undefined, signal: NodeJS.Signals) {
  if (!pid) return
  try {
    process.kill(-pid, signal)
  } catch {
    // ESRCH: the whole group has already exited.
  }
}

test.afterEach(async () => {
  for (const { proc, tmp } of started.splice(0)) {
    // A passing test has already let the driver finish; give it a moment to run its own clean-up first.
    if (!(await exited(proc, 3_000))) {
      proc.stdin.destroy()
      killGroup(proc.pid, 'SIGTERM')
      if (!(await exited(proc, 5_000))) killGroup(proc.pid, 'SIGKILL')
      await exited(proc, 2_000)
    }
    // The server process stays in the driver's group even after the driver itself has gone.
    killGroup(proc.pid, 'SIGKILL')
    rmSync(tmp, { recursive: true, force: true })
  }
  for (const service of keychainLeft.splice(0)) {
    if (!TEST_SERVICE.test(service)) continue
    // Exit 44 = no such item: the driver already deleted it, which is the normal case.
    for (let i = 0; i < 3; i++) {
      if (spawnSync('/usr/bin/security', ['delete-generic-password', '-s', service], { stdio: 'ignore' }).status !== 0) break
    }
  }
})

// Real processes: run on one chromium and one webkit project (the mock-server specs cover the 4 layouts).
test.beforeEach(({}, testInfo) => {
  test.skip(!testInfo.project.name.endsWith('-desktop'), 'real-server round trips run on the desktop projects')
})

function allTrue(result: Result) {
  for (const [name, ok] of Object.entries(result.checks)) expect(ok, `driver check ${name}`).toBe(true)
}

test('api_key: canary saved to the profile chosen on the page, not the requested one', async ({ page }) => {
  const d = startDriver('api_key', 'default')
  const ready = await d.next<Ready>()
  await page.goto(ready.local_url)
  // Protocol 2: .env is pre-selected for an api_key without `stores`; the keychain row is there but off.
  await expect(page.getByRole('checkbox', { name: '설정 파일(.env)' })).toBeChecked()
  await expect(page.getByRole('checkbox', { name: 'Mac 키체인' })).not.toBeChecked()
  await expect(page.getByLabel('저장할 프로필')).toHaveValue('default')
  await page.getByLabel('저장할 프로필').selectOption('worker')
  const value = canary('RA')
  await page.getByLabel('API 키', { exact: true }).fill(value)
  await page.getByTestId('submit').click()
  await expect(page.getByTestId('done-screen')).toBeVisible()
  await expect(page.getByTestId('done-store-env')).toHaveAttribute('data-status', 'saved')
  await expect(page.getByTestId('done-store-env')).toContainText('worker')
  const result = await d.finish({ value })
  expect(result.status).toBe('saved')
  expect(result.target_profile).toBe('worker')
  expect(result.checks).toHaveProperty('env_line_matches')
  expect(result.checks).toHaveProperty('audit_in_chosen_profile')
  allTrue(result)
})

for (const withOtp of [true, false]) {
  test(`login ${withOtp ? 'with' : 'without'} authenticator setup key: vault read-back matches`, async ({ page }) => {
    const d = startDriver('login', 'default')
    const ready = await d.next<Ready>()
    await page.goto(ready.local_url)
    const identifier = `${canary('Rid')}@example.com`
    const password = canary('Rpw')
    const otpSecret = withOtp
      ? 'JBSWY3DP' + Array.from({ length: 16 }, () => 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'[Math.floor(Math.random() * 32)]).join('')
      : ''
    await page.getByLabel('이메일 주소').fill(identifier)
    await page.getByLabel('비밀번호', { exact: true }).fill(password)
    if (withOtp) {
      await page.getByRole('button', { name: '인증 앱 설정 키 추가(선택)' }).click()
      await page.getByLabel('인증 앱 설정 키(선택)').fill(otpSecret)
    }
    // Protocol 2: the vault is the login's only store, shown as a checked box that cannot be switched off.
    await expect(page.getByRole('checkbox', { name: 'Hermes 암호화 저장소(vault)' })).toBeChecked()
    await expect(page.getByRole('checkbox', { name: 'Hermes 암호화 저장소(vault)' })).toBeDisabled()
    await page.getByTestId('submit').click()
    await expect(page.getByTestId('done-screen')).toBeVisible()
    await expect(page.getByTestId('done-store-hermes_vault')).toHaveAttribute('data-status', 'saved')
    await expect(page.getByTestId('done-screen')).toContainText('아이디와 비밀번호를 한 항목으로 저장했습니다.')
    const keyLine = page.getByTestId('done-screen').getByText('인증 앱 설정 키도 같은 항목에 저장했습니다.')
    await expect(keyLine).toHaveCount(withOtp ? 1 : 0)
    const result = await d.finish({ identifier, password, otp_secret: otpSecret })
    expect(result.status).toBe('saved')
    expect(result.target_profile).toBe('default')
    expect(result.checks).toHaveProperty('password_matches')
    expect(result.checks).toHaveProperty('otp_secret_presence_matches')
    allTrue(result)
  })
}

test('reload: the real server opens a link once, so reloading the form lands on already_opened', async ({ page }) => {
  // e2e/capture_driver.py: one real request; after "finish" it waits briefly and cancels the open request.
  const proc = spawnDriver([join(HERE, 'capture_driver.py'), '--scenario', 'A', '--mode', 'form'])
  const d = new Driver(proc)
  const ready = await d.next<Ready>()
  await page.goto(ready.local_url)
  await expect(page.getByTestId('credential-form')).toBeVisible()
  await page.reload()
  await expect(page.getByTestId('end-screen')).toHaveAttribute('data-reason', 'already_opened')
  await expect(page.locator('input, select, textarea')).toHaveCount(0)
  proc.stdin.write(JSON.stringify({ finish: true }) + '\n')
  proc.stdin.end()
  const result = await d.next<{ status: string; reason: string }>(60_000)
  expect(result.status).toBe('cancelled')
})

test.describe('a Tailscale account that is not allowed', () => {
  // The fake owner is owner@example.test; this account is not on the allowed list.
  test.use({ extraHTTPHeaders: { 'Tailscale-User-Login': 'someone-else@example.test' } })

  test('the real server refuses open with 403, the page shows the identity end screen, the link stays unused', async ({ page }) => {
    const proc = spawnDriver([join(HERE, 'capture_driver.py'), '--scenario', 'A', '--mode', 'form'])
    const d = new Driver(proc)
    const ready = await d.next<Ready>()
    const refused = page.waitForResponse((r) => r.url().endsWith('/api/open'))
    await page.goto(ready.local_url)
    const res = await refused
    expect(res.status()).toBe(403)
    expect((await res.json()).error_code).toBe('identity_not_allowed')
    await expect(page.getByTestId('end-screen')).toHaveAttribute('data-reason', 'identity_denied')
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('이 기기의 Tailscale 계정으로는 열 수 없습니다')
    await expect(page.locator('input, select, textarea')).toHaveCount(0)
    // The refusal did not use the link: the allowed account still opens it.
    const again = await page.request.post(ready.local_url + 'api/open', {
      data: {},
      headers: { 'Content-Type': 'application/json', 'Tailscale-User-Login': 'owner@example.test' },
    })
    expect(again.status()).toBe(200)
    proc.stdin.write(JSON.stringify({ finish: true }) + '\n')
    proc.stdin.end()
    const result = await d.next<{ status: string }>(60_000)
    expect(result.status).toBe('cancelled')
  })
})

// Protocol 2 `secret` round trip (plan 7.3, task 5). Written by the screen card against the plan; it is run
// only after the integration card merges the protocol 2 server, whose driver takes `--kind secret` and uses
// an allow-listed keychain item whose service starts with `hermes-secure-input-test-` (deleted afterwards).
test('secret: the password typed twice is saved to the Mac keychain item and read back equal', async ({ page }) => {
  const d = startDriver('secret', 'default')
  const ready = await d.next<Ready>()
  await page.goto(ready.local_url)
  const box = page.getByRole('checkbox', { name: 'Mac 키체인' })
  await expect(box).toBeChecked()
  await expect(box).toBeDisabled()
  await expect(page.getByLabel('저장할 프로필')).toHaveCount(0)
  await expect(page.getByTestId('store-keychain').getByTestId('store-ident')).toContainText('hermes-secure-input-test-')
  keychainLeft.push((await page.getByTestId('store-keychain').getByTestId('store-ident').innerText()).trim())
  const value = canary('RS')
  await page.getByLabel('비밀번호', { exact: true }).fill(value)
  await page.getByLabel('비밀번호 다시 입력', { exact: true }).fill(value + 'x')
  await page.getByTestId('submit').click()
  await expect(page.getByText('두 칸의 값이 다릅니다. 같은 비밀번호를 다시 입력하세요.')).toBeVisible()
  await page.getByLabel('비밀번호 다시 입력', { exact: true }).fill(value)
  await page.getByTestId('submit').click()
  await expect(page.getByTestId('done-screen')).toBeVisible()
  await expect(page.getByTestId('done-store-keychain')).toHaveAttribute('data-status', 'saved')
  const result = await d.finish({ value })
  expect(result.status).toBe('saved')
  expect(result.checks).toHaveProperty('keychain_value_matches')
  allTrue(result)
})

test('otp_code: the typed code is delivered to the parent as Outcome.code', async ({ page }) => {
  const d = startDriver('otp_code')
  const ready = await d.next<Ready>()
  await page.goto(ready.local_url)
  await expect(page.getByLabel('저장할 프로필')).toHaveCount(0)
  const code = String(10_000_000 + Math.floor(Math.random() * 89_999_999))
  await page.getByLabel('일회용 코드', { exact: true }).fill(code)
  await page.getByTestId('submit').click()
  await expect(page.getByTestId('done-screen')).toContainText('전달했습니다')
  const result = await d.finish({ code })
  expect(result.status).toBe('delivered')
  expect(result.checks).toHaveProperty('code_matches')
  allTrue(result)
})
