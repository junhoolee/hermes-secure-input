// Mock of the one-time page server for screen tests (protocol 2, plan appendix A). It plays the server role
// for real: it holds an ECDH key pair, hands out the public key in api/open and decrypts every api/submit
// body (contract 4.3) so tests can check the plaintext, including the chosen `stores` (A.7).
// Scenario bodies come from e2e/fixtures.json through e2e/fake-v2.mjs (also used by e2e/server.mjs).

import { webcrypto } from 'node:crypto'
import type { Page, Request } from '@playwright/test'
import { SCENARIOS, successFor, type ScenarioName } from './fake-v2.mjs'

const subtle = webcrypto.subtle as unknown as SubtleCrypto
export const TOKEN = 't0k3n-e2e'
export const PAGE_PATH = `/${TOKEN}/`

export type Scenario = ScenarioName
export { SCENARIOS }

function b64u(bytes: ArrayBuffer | Uint8Array): string {
  return Buffer.from(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)).toString('base64url')
}
function unb64u(s: string): Uint8Array<ArrayBuffer> {
  return new Uint8Array(Buffer.from(s, 'base64url'))
}

export function canary(tag = ''): string {
  return `SECRET-CANARY-${tag}${b64u(webcrypto.getRandomValues(new Uint8Array(9)))}`
}

/** One reply to api/submit. `abort` drops the connection, so the page sees a network error. */
type Reply = { status: number; body: unknown } | { abort: true }

export type MockOptions = {
  /** Replace the api/open reply (e.g. 410 already_opened). */
  openReply?: { status: number; body: unknown }
  /** Override fields of the 200 api/open body. */
  openPatch?: Record<string, unknown>
  /** Override fields of api/open `target` (e.g. `stores`, `keychain`). */
  targetPatch?: Record<string, unknown>
  /** Replies for successive api/submit calls; when exhausted, a success reply is used. */
  submitReplies?: Reply[]
  /** Result-line overrides of the success reply, per store name (e.g. a partial save). */
  successLines?: Record<string, Record<string, unknown>>
  /** Hold every api/submit until mock.release() is called, to look at the saving state. */
  holdSubmit?: boolean
}

export type Mock = Awaited<ReturnType<typeof mockServer>>
type Plain = Record<string, unknown>

export async function mockServer(page: Page, scenario: Scenario, opts: MockOptions = {}) {
  const pair = (await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits'])) as CryptoKeyPair
  const serverPub = b64u(await subtle.exportKey('raw', pair.publicKey))
  const sid = b64u(webcrypto.getRandomValues(new Uint8Array(32)))
  const requestId = `req_${scenario}_${b64u(webcrypto.getRandomValues(new Uint8Array(6)))}`
  const base = SCENARIOS[scenario]
  const s = { ...base, target: { ...base.target, ...opts.targetPatch } } as typeof base

  const openBody = {
    v: 2,
    request_id: requestId,
    ...s,
    server_public_key: serverPub,
    sid,
    submit_deadline_s: 300,
    opened_at: new Date().toISOString(),
    ...opts.openPatch,
  }

  const submits: { raw: string; json: Record<string, unknown>; plaintext: Plain | null }[] = []
  const cancels: string[] = []
  const requests: string[] = []
  const consoleLines: string[] = []
  let opened = 0
  const replies = [...(opts.submitReplies ?? [])]
  let releaseGate: (() => void) | null = null
  let gate: Promise<void> = opts.holdSubmit ? new Promise<void>((r) => (releaseGate = r)) : Promise.resolve()

  page.on('request', (r: Request) => requests.push(r.url()))
  page.on('console', (m) => consoleLines.push(`${m.type()}: ${m.text()}`))
  page.on('pageerror', (e) => consoleLines.push(`pageerror: ${e.message}`))

  // Capture CSP violations from inside the page (works the same in Chromium and WebKit).
  await page.addInitScript(() => {
    const w = window as unknown as { __csp: string[] }
    w.__csp = []
    document.addEventListener('securitypolicyviolation', (e) => {
      w.__csp.push(`${e.violatedDirective} ${e.blockedURI}`)
    })
  })

  async function decrypt(body: Record<string, string>) {
    const clientPub = await subtle.importKey('raw', unb64u(body.client_public_key), { name: 'ECDH', namedCurve: 'P-256' }, false, [])
    const shared = await subtle.deriveBits({ name: 'ECDH', public: clientPub }, pair.privateKey, 256)
    const ikm = await subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey'])
    const key = await subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: unb64u(body.sid), info: new TextEncoder().encode('hermes-secure-input/v1/submit') },
      ikm,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt'],
    )
    const pt = await subtle.decrypt(
      { name: 'AES-GCM', iv: unb64u(body.iv), additionalData: new TextEncoder().encode(requestId), tagLength: 128 },
      key,
      unb64u(body.ciphertext),
    )
    return JSON.parse(new TextDecoder().decode(pt)) as Plain
  }

  const json = (status: number, body: unknown) => ({ status, contentType: 'application/json', body: JSON.stringify(body) })

  await page.route(`**${PAGE_PATH}api/open`, async (route) => {
    opened += 1
    if (opts.openReply) return route.fulfill(json(opts.openReply.status, opts.openReply.body))
    if (opened > 1) return route.fulfill(json(410, { ok: false, error_code: 'already_opened' }))
    return route.fulfill(json(200, openBody))
  })

  await page.route(`**${PAGE_PATH}api/submit`, async (route) => {
    const raw = route.request().postData() ?? ''
    const body = JSON.parse(raw) as Record<string, string>
    let plaintext: Plain | null = null
    try {
      plaintext = await decrypt(body)
    } catch {
      plaintext = null
    }
    submits.push({ raw, json: body, plaintext })
    await gate
    const next = replies.shift()
    if (next && 'abort' in next) return route.abort('connectionreset')
    if (next) return route.fulfill(json(next.status, next.body))
    if (!plaintext) return route.fulfill(json(400, { ok: false, error_code: 'decrypt_failed', message: '복호화하지 못했습니다.' }))
    const stores = Array.isArray(plaintext.stores) ? (plaintext.stores as string[]) : []
    return route.fulfill(json(200, successFor(s, stores, String(plaintext.target_profile ?? ''), opts.successLines)))
  })

  await page.route(`**${PAGE_PATH}api/cancel`, async (route) => {
    cancels.push(route.request().postData() ?? '')
    return route.fulfill(json(200, { ok: true }))
  })

  return {
    sid,
    requestId,
    openBody,
    submits,
    cancels,
    requests,
    consoleLines,
    get opened() {
      return opened
    },
    /** Let the held api/submit calls answer (holdSubmit). Later submits are held again. */
    release() {
      const open = releaseGate
      gate = new Promise<void>((r) => (releaseGate = r))
      open?.()
    },
    async cspViolations(): Promise<string[]> {
      return page.evaluate(() => (window as unknown as { __csp: string[] }).__csp)
    },
  }
}

/** Everything a page could have kept a secret in after submit. */
export async function clientSideState(page: Page): Promise<string> {
  return page.evaluate(() => {
    const dump = (st: Storage) => Array.from({ length: st.length }, (_, i) => `${st.key(i)}=${st.getItem(st.key(i)!)}`).join('\n')
    const inputs = Array.from(document.querySelectorAll('input, textarea')).map((el) => (el as HTMLInputElement).value)
    return [dump(localStorage), dump(sessionStorage), document.cookie, location.href, document.body.innerText, ...inputs].join('\n')
  })
}
