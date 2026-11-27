// Browser-side encryption, contract section 4.3. WebCrypto only; no crypto library.
//
// ECDH P-256 (fresh ephemeral key pair per submission) -> 256-bit shared secret
// -> HKDF-SHA256(salt = raw sid bytes, info = HKDF_INFO, 32 bytes) -> AES-256-GCM key
// -> encrypt(iv = random 12 bytes, AAD = UTF-8 request_id, 128-bit tag appended).

import { b64urlDecode, b64urlEncode } from './b64'

export const HKDF_INFO = 'hermes-secure-input/v1/submit'

/** Protocol version 2 (plan appendix A). HKDF_INFO keeps its v1 text on purpose (A.1). */
export const PROTOCOL_VERSION = 2

export type SubmitBody = {
  v: typeof PROTOCOL_VERSION
  sid: string
  client_public_key: string
  iv: string
  ciphertext: string
}

export type EncryptionContext = {
  request_id: string
  server_public_key: string
  sid: string
}

const enc = new TextEncoder()

export async function encryptSubmission(
  ctx: EncryptionContext,
  plaintext: Record<string, unknown>,
  subtle: SubtleCrypto = globalThis.crypto.subtle,
): Promise<SubmitBody> {
  const serverRaw = b64urlDecode(ctx.server_public_key)
  if (serverRaw.length !== 65 || serverRaw[0] !== 0x04) {
    throw new Error('server_public_key must be a 65-byte uncompressed P-256 point')
  }
  const salt = b64urlDecode(ctx.sid)
  if (salt.length !== 32) throw new Error('sid must decode to 32 bytes')

  // 1. Fresh key pair. The private key is non-extractable; the public key is
  //    always exportable in WebCrypto, which is all we need.
  const pair = (await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, [
    'deriveBits',
  ])) as CryptoKeyPair
  const clientRaw = new Uint8Array(await subtle.exportKey('raw', pair.publicKey))

  // 2. Shared secret.
  const serverKey = await subtle.importKey('raw', serverRaw, { name: 'ECDH', namedCurve: 'P-256' }, false, [])
  const shared = await subtle.deriveBits({ name: 'ECDH', public: serverKey }, pair.privateKey, 256)

  // 3. HKDF -> AES-256-GCM key.
  const ikm = await subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey'])
  const key = await subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode(HKDF_INFO) },
    ikm,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt'],
  )

  // 4-5. Encrypt the UTF-8 JSON plaintext.
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12))
  const pt = enc.encode(JSON.stringify(plaintext))
  try {
    const ct = await subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: enc.encode(ctx.request_id), tagLength: 128 },
      key,
      pt,
    )
    return {
      v: PROTOCOL_VERSION,
      sid: ctx.sid,
      client_public_key: b64urlEncode(clientRaw),
      iv: b64urlEncode(iv),
      ciphertext: b64urlEncode(ct),
    }
  } finally {
    // 6. Do not leave the encoded plaintext lying around in this buffer.
    pt.fill(0)
  }
}
