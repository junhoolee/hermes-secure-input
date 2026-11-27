// base64url without padding (RFC 4648 section 5), as agreed with the server.

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
const LOOKUP = new Map<string, number>([...ALPHABET].map((c, i) => [c, i]))

export function b64urlEncode(bytes: Uint8Array | ArrayBuffer): string {
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)
  let out = ''
  let i = 0
  for (; i + 2 < b.length; i += 3) {
    const n = (b[i] << 16) | (b[i + 1] << 8) | b[i + 2]
    out += ALPHABET[(n >> 18) & 63] + ALPHABET[(n >> 12) & 63] + ALPHABET[(n >> 6) & 63] + ALPHABET[n & 63]
  }
  const rest = b.length - i
  if (rest === 1) {
    const n = b[i] << 16
    out += ALPHABET[(n >> 18) & 63] + ALPHABET[(n >> 12) & 63]
  } else if (rest === 2) {
    const n = (b[i] << 16) | (b[i + 1] << 8)
    out += ALPHABET[(n >> 18) & 63] + ALPHABET[(n >> 12) & 63] + ALPHABET[(n >> 6) & 63]
  }
  return out
}

export function b64urlDecode(s: string): Uint8Array<ArrayBuffer> {
  if (s.length % 4 === 1) throw new Error('invalid base64url length')
  const out = new Uint8Array(Math.floor((s.length * 3) / 4))
  let buf = 0
  let bits = 0
  let o = 0
  for (const c of s) {
    const v = LOOKUP.get(c)
    if (v === undefined) throw new Error('invalid base64url character')
    buf = (buf << 6) | v
    bits += 6
    if (bits >= 8) {
      bits -= 8
      out[o++] = (buf >> bits) & 0xff
    }
  }
  return out
}
