// Test-only server for the built page (secure_input/static), protocol 2.
// Serves it under /<token>/ with the exact CSP from contract 4.1, so the
// screen tests prove the bundle runs with no inline script or style.
//
// It also answers ./api/* in the protocol 2 shapes (plan appendix A.6 and A.8), so the page can be opened
// by hand: `E2E_SCENARIO=A2 node e2e/server.mjs`, then http://127.0.0.1:4719/t0k3n-e2e/. Each open hands
// out a fresh request; a submit is answered with the success reply for the stores the page turned on
// (the server reads `stores` from the plaintext it decrypts). Screen tests replace these answers with
// page.route (e2e/harness.ts), which takes precedence.
//
// STATIC_ROOT points at another built page (the baseline bundle used for the unchanged-screen comparison).

import { createServer } from 'node:http'
import { readFile } from 'node:fs/promises'
import { webcrypto } from 'node:crypto'
import path from 'node:path'
import { SCENARIOS, successFor } from './fake-v2.mjs'

export const PORT = Number(process.env.E2E_PORT ?? 4719)
export const TOKEN = 't0k3n-e2e'
export const CSP =
  "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"

const ROOT = path.resolve(process.env.STATIC_ROOT ?? path.resolve(import.meta.dirname, '../../secure_input/static'))
const SCENARIO = SCENARIOS[process.env.E2E_SCENARIO ?? 'A'] ?? SCENARIOS.A
const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.woff2': 'font/woff2',
}

const subtle = webcrypto.subtle
const b64u = (b) => Buffer.from(b instanceof Uint8Array ? b : new Uint8Array(b)).toString('base64url')
const unb64u = (s) => new Uint8Array(Buffer.from(s, 'base64url'))

/** The request handed out by the last api/open: its key pair, sid and request id. */
let current = null

async function openBody() {
  const pair = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits'])
  const sid = b64u(webcrypto.getRandomValues(new Uint8Array(32)))
  const requestId = `req_fake_${b64u(webcrypto.getRandomValues(new Uint8Array(6)))}`
  current = { pair, sid, requestId }
  return {
    v: 2,
    request_id: requestId,
    ...SCENARIO,
    server_public_key: b64u(await subtle.exportKey('raw', pair.publicKey)),
    sid,
    submit_deadline_s: 300,
    opened_at: new Date().toISOString(),
  }
}

async function decrypt(body) {
  const clientPub = await subtle.importKey('raw', unb64u(body.client_public_key), { name: 'ECDH', namedCurve: 'P-256' }, false, [])
  const shared = await subtle.deriveBits({ name: 'ECDH', public: clientPub }, current.pair.privateKey, 256)
  const ikm = await subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey'])
  const key = await subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: unb64u(body.sid), info: new TextEncoder().encode('hermes-secure-input/v1/submit') },
    ikm,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt'],
  )
  const pt = await subtle.decrypt(
    { name: 'AES-GCM', iv: unb64u(body.iv), additionalData: new TextEncoder().encode(current.requestId), tagLength: 128 },
    key,
    unb64u(body.ciphertext),
  )
  return JSON.parse(new TextDecoder().decode(pt))
}

async function readJson(req) {
  const chunks = []
  for await (const c of req) chunks.push(c)
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')
  } catch {
    return {}
  }
}

async function api(rel, req, res) {
  const send = (status, body) => res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }).end(JSON.stringify(body))
  if (req.method !== 'POST') return send(405, { ok: false, error_code: 'method_not_allowed' })
  if (rel === 'api/open') return send(200, await openBody())
  if (rel === 'api/cancel') return send(200, { ok: true })
  if (rel === 'api/submit') {
    const body = await readJson(req)
    if (!current || body.v !== 2 || body.sid !== current.sid) return send(400, { ok: false, error_code: 'bad_sid' })
    let pt
    try {
      pt = await decrypt(body)
    } catch {
      return send(400, { ok: false, error_code: 'decrypt_failed', message: '복호화하지 못했습니다.' })
    }
    // The plaintext is dropped right here; only the store names and the profile go into the reply.
    const stores = Array.isArray(pt.stores) ? pt.stores : []
    return send(200, successFor(SCENARIO, stores, String(pt.target_profile ?? '')))
  }
  return send(404, { ok: false, error_code: 'not_found' })
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url ?? '/', `http://${req.headers.host}`)
  if (url.pathname === '/healthz') {
    res.writeHead(200, { 'Content-Type': 'text/plain' }).end('ok')
    return
  }
  const prefix = `/${TOKEN}/`
  if (!url.pathname.startsWith(prefix)) {
    res.writeHead(404).end()
    return
  }
  const rel = url.pathname.slice(prefix.length)
  if (rel.startsWith('api/')) {
    await api(rel, req, res)
    return
  }
  const file = path.resolve(ROOT, rel === '' ? 'index.html' : rel)
  if (!file.startsWith(ROOT + path.sep)) {
    res.writeHead(403).end()
    return
  }
  try {
    const body = await readFile(file)
    res
      .writeHead(200, {
        'Content-Type': TYPES[path.extname(file)] ?? 'application/octet-stream',
        'Content-Security-Policy': CSP,
        'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'no-referrer',
        'Cache-Control': 'no-store',
      })
      .end(body)
  } catch {
    res.writeHead(404).end()
  }
})

server.listen(PORT, '127.0.0.1', () => {
  console.log(`e2e server (protocol 2) on http://127.0.0.1:${PORT}/${TOKEN}/ serving ${ROOT}`)
})
