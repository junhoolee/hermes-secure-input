// Criterion 8: ONE round trip through the real Tailscale Serve address (https://<tailnet host>/<token>/).
// Skipped unless SECURE_INPUT_LIVE_TAILSCALE=1 (run by scripts/live_tailscale_roundtrip.sh). The driver
// refuses to start if `tailscale serve status` is not "No serve config", stores into a temp home, and after
// the request ends checks that the same address answers 404 (or refuses the connection) and that
// `serve status` is back to "No serve config".

import { spawn } from 'node:child_process'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'
import { createInterface } from 'node:readline'
import { fileURLToPath } from 'node:url'
import { expect, test } from '@playwright/test'
import { canary } from './harness.ts'

const HERE = dirname(fileURLToPath(import.meta.url))
const DRIVER = join(HERE, '..', '..', 'scripts', 'e2e_real_driver.py')
const PYTHON = process.env.HERMES_PYTHON ?? join(homedir(), '.hermes', 'hermes-agent', '.venv', 'bin', 'python')

test('api_key through the real Tailscale Serve address', async ({ page }, testInfo) => {
  test.skip(process.env.SECURE_INPUT_LIVE_TAILSCALE !== '1', 'live Tailscale run only')
  test.skip(testInfo.project.name !== 'chromium-desktop', 'one live round trip')
  test.setTimeout(120_000)
  const proc = spawn(PYTHON, ['-P', DRIVER, '--kind', 'api_key', '--real-tailscale'])
  let stderr = ''
  proc.stderr.on('data', (d) => (stderr += String(d)))
  const lines = createInterface({ input: proc.stdout })[Symbol.asyncIterator]()
  const next = async () => JSON.parse(String((await lines.next()).value ?? '{}'))
  const ready = await next()
  expect(ready.event, stderr).toBe('ready')
  const url = new URL(ready.public_url)
  expect(url.protocol).toBe('https:')
  expect(url.pathname).toMatch(/^\/[A-Za-z0-9_-]{43}\/$/)
  await page.goto(ready.public_url)
  const value = canary('TS')
  await page.getByLabel('API 키', { exact: true }).fill(value)
  await page.getByTestId('submit').click()
  await expect(page.getByTestId('done-screen')).toBeVisible()
  proc.stdin.write(JSON.stringify({ expect: { value } }) + '\n')
  proc.stdin.end()
  const result = await next()
  console.log(JSON.stringify({ host: url.host, status: result.status, ended_url: result.ended_url,
                               serve_status: result.serve_status, checks: result.checks }))
  expect(result.status).toBe('saved')
  for (const [name, ok] of Object.entries(result.checks)) expect(ok, `driver check ${name}`).toBe(true)
  expect(result.checks).toHaveProperty('ended_url_404_or_refused')
  expect(result.serve_status).toBe('No serve config')
})
