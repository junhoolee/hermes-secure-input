import { describe, expect, it } from 'vitest'
import { b64urlDecode, b64urlEncode } from './b64'
import { encryptSubmission, HKDF_INFO } from './crypto'

const subtle = globalThis.crypto.subtle
const enc = new TextEncoder()
const dec = new TextDecoder()

function canary() {
  return `SECRET-CANARY-${b64urlEncode(crypto.getRandomValues(new Uint8Array(9)))}`
}

/** Server role: holds the static ECDH key pair it advertised in api/open. */
async function makeServer() {
  const pair = (await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, [
    'deriveBits',
  ])) as CryptoKeyPair
  const raw = new Uint8Array(await subtle.exportKey('raw', pair.publicKey))
  const sidBytes = crypto.getRandomValues(new Uint8Array(32))
  const open = {
    request_id: 'req_7f3a9c',
    server_public_key: b64urlEncode(raw),
    sid: b64urlEncode(sidBytes),
  }

  /** The inverse of section 4.3, written independently of crypto.ts. */
  async function decrypt(
    body: { sid: string; client_public_key: string; iv: string; ciphertext: string },
    requestId = open.request_id,
  ) {
    const clientPub = await subtle.importKey(
      'raw',
      b64urlDecode(body.client_public_key),
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      [],
    )
    const shared = await subtle.deriveBits({ name: 'ECDH', public: clientPub }, pair.privateKey, 256)
    const ikm = await subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey'])
    const key = await subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: b64urlDecode(body.sid), info: enc.encode('hermes-secure-input/v1/submit') },
      ikm,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt'],
    )
    const pt = await subtle.decrypt(
      { name: 'AES-GCM', iv: b64urlDecode(body.iv), additionalData: enc.encode(requestId), tagLength: 128 },
      key,
      b64urlDecode(body.ciphertext),
    )
    return JSON.parse(dec.decode(pt))
  }

  return { open, decrypt, sidBytes }
}

describe('base64url', () => {
  it('round-trips every length without padding', () => {
    for (let n = 0; n < 70; n++) {
      const bytes = crypto.getRandomValues(new Uint8Array(n))
      const s = b64urlEncode(bytes)
      expect(s).not.toMatch(/[=+/]/)
      expect(Array.from(b64urlDecode(s))).toEqual(Array.from(bytes))
    }
  })

  it('rejects characters outside the base64url alphabet', () => {
    expect(() => b64urlDecode('ab+c')).toThrow()
    expect(() => b64urlDecode('abc=')).toThrow()
  })
})

describe('encryptSubmission (contract 4.3)', () => {
  it('uses the agreed HKDF info string', () => {
    expect(HKDF_INFO).toBe('hermes-secure-input/v1/submit')
  })

  it('produces a body the server role decrypts back to the same plaintext', async () => {
    const server = await makeServer()
    // Protocol 2 (plan A.7): the chosen store names travel inside the encrypted plaintext.
    const plaintext = { kind: 'api_key', target_profile: 'worker', value: canary(), stores: ['env', 'keychain'] }
    const body = await encryptSubmission(server.open, plaintext)

    expect(Object.keys(body).sort()).toEqual(['ciphertext', 'client_public_key', 'iv', 'sid', 'v'])
    expect(body.v).toBe(2)
    expect(body.sid).toBe(server.open.sid)
    expect(await server.decrypt(body)).toEqual(plaintext)
  })

  it('has a 65-byte uncompressed public key, 12-byte iv, 16-byte tag and no padding', async () => {
    const server = await makeServer()
    const plaintext = { kind: 'otp_code', code: '123456' }
    const body = await encryptSubmission(server.open, plaintext)

    const pub = b64urlDecode(body.client_public_key)
    expect(pub.length).toBe(65)
    expect(pub[0]).toBe(0x04)
    expect(b64urlDecode(body.iv).length).toBe(12)
    const ptLen = enc.encode(JSON.stringify(plaintext)).length
    expect(b64urlDecode(body.ciphertext).length).toBe(ptLen + 16)
    for (const v of [body.client_public_key, body.iv, body.ciphertext, body.sid]) {
      expect(v).not.toContain('=')
    }
  })

  it('never puts the plaintext value into the request body', async () => {
    const server = await makeServer()
    const secret = canary()
    const body = await encryptSubmission(server.open, {
      kind: 'login',
      target_profile: 'worker',
      identifier_type: 'email',
      identifier: `${secret}@example.com`,
      password: secret,
      otp_secret: '',
    })
    expect(JSON.stringify(body)).not.toContain(secret)
    expect(JSON.stringify(body)).not.toContain('SECRET-CANARY')
  })

  it('uses a fresh key pair and iv on every submission', async () => {
    const server = await makeServer()
    const plaintext = { kind: 'api_key', target_profile: 'default', value: canary() }
    const a = await encryptSubmission(server.open, plaintext)
    const b = await encryptSubmission(server.open, plaintext)
    expect(a.client_public_key).not.toBe(b.client_public_key)
    expect(a.iv).not.toBe(b.iv)
    expect(a.ciphertext).not.toBe(b.ciphertext)
    expect(await server.decrypt(a)).toEqual(plaintext)
    expect(await server.decrypt(b)).toEqual(plaintext)
  })

  it('binds the ciphertext to request_id (AAD) and sid (salt)', async () => {
    const server = await makeServer()
    const body = await encryptSubmission(server.open, { kind: 'otp_code', code: '987654' })

    await expect(server.decrypt(body, 'req_other')).rejects.toThrow()

    const otherSid = b64urlEncode(crypto.getRandomValues(new Uint8Array(32)))
    await expect(server.decrypt({ ...body, sid: otherSid })).rejects.toThrow()
  })

  it('rejects a malformed server public key or sid before encrypting', async () => {
    const server = await makeServer()
    const pt = { kind: 'otp_code', code: '1234' }
    await expect(
      encryptSubmission({ ...server.open, server_public_key: b64urlEncode(new Uint8Array(33)) }, pt),
    ).rejects.toThrow(/server_public_key/)
    await expect(encryptSubmission({ ...server.open, sid: b64urlEncode(new Uint8Array(16)) }, pt)).rejects.toThrow(
      /sid/,
    )
  })
})
