import { describe, expect, it } from 'vitest'
import { apiKeySchema, keychainValueOk, loginSchema, otpSchema, secretSchema } from './schemas'

describe('secretSchema (plan 3.1)', () => {
  const ok = (value: string, confirm = value) => secretSchema.safeParse({ value, confirm })
  const msg = (value: string, confirm = value) => {
    const r = ok(value, confirm)
    return r.success ? null : r.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`)
  }

  it('keeps the value exactly as typed when both fields match', () => {
    const r = ok('pa ss$\\"word')
    expect(r.success && r.data.value).toBe('pa ss$\\"word')
  })

  it('refuses to send when the two fields differ', () => {
    expect(msg('SECRET-CANARY-a', 'SECRET-CANARY-b')).toEqual(['confirm: 두 칸의 값이 다릅니다. 같은 비밀번호를 다시 입력하세요.'])
    expect(msg('SECRET-CANARY-a', '')).toEqual(['confirm: 같은 비밀번호를 한 번 더 입력하세요.'])
  })

  it('refuses a space at either end instead of trimming it', () => {
    expect(ok(' abc').success).toBe(false)
    expect(ok('abc ').success).toBe(false)
    expect(ok('a b c').success).toBe(true)
  })

  it('refuses non-ASCII text, line breaks, an empty value and more than 1,024 characters', () => {
    for (const bad of ['비밀번호', 'emoji😀', 'a\nb', 'tab\tx', '', 'x'.repeat(1025)]) expect(ok(bad).success, bad).toBe(false)
    expect(ok('x'.repeat(1024)).success).toBe(true)
  })

  it('keychainValueOk is the same rule (used for api_key values the keychain cannot take)', () => {
    expect(keychainValueOk('abc')).toBe(true)
    expect(keychainValueOk(' abc')).toBe(false)
    expect(keychainValueOk('é')).toBe(false)
    expect(keychainValueOk('x'.repeat(1025))).toBe(false)
  })
})

describe('apiKeySchema', () => {
  it('trims surrounding whitespace before submit', () => {
    const r = apiKeySchema.safeParse({ target_profile: 'default', value: '  abc-123\t ' })
    expect(r.success && r.data.value).toBe('abc-123')
  })
  it('rejects a value with a line break inside', () => {
    const r = apiKeySchema.safeParse({ target_profile: 'default', value: 'abc\ndef' })
    expect(r.success).toBe(false)
    expect(r.error?.issues[0].message).toContain('줄바꿈')
  })
  it('rejects Korean letters, U+2028, a tab and other non-printable or non-ASCII text, with one sentence', () => {
    const msg = 'API 키에는 영문, 숫자, 기호, 공백만 넣을 수 있습니다. 붙여 넣은 값에 다른 글자가 섞였는지 확인하세요.'
    for (const value of ['abc키def', 'abc\u2028def', 'abc\u2029def', 'abc\tdef', 'abc\u0085def', 'abc\u00a0def', 'ａbc']) {
      const r = apiKeySchema.safeParse({ target_profile: 'default', value })
      expect(r.success, JSON.stringify(value)).toBe(false)
      expect(r.error?.issues.map((i) => i.message), JSON.stringify(value)).toContain(msg)
    }
  })
  it('accepts an ordinary key made of letters, digits and symbols', () => {
    for (const value of ['3f9a0c2e71b44d0e9a58c1d27b6e0f4a', 'sk-proj_AbC.123~xyz+/=', 'key with inner space!@#$%^&*()']) {
      const r = apiKeySchema.safeParse({ target_profile: 'default', value })
      expect(r.success, value).toBe(true)
      expect(r.success && r.data.value).toBe(value)
    }
  })
  it('rejects an empty value', () => {
    expect(apiKeySchema.safeParse({ target_profile: 'default', value: '   ' }).success).toBe(false)
  })
})

describe('otpSchema', () => {
  it('removes spaces and hyphens', () => {
    const r = otpSchema.safeParse({ code: ' 123-456 ' })
    expect(r.success && r.data.code).toBe('123456')
  })
  it('accepts 4 to 10 characters only', () => {
    expect(otpSchema.safeParse({ code: '123' }).success).toBe(false)
    expect(otpSchema.safeParse({ code: '1234' }).success).toBe(true)
    expect(otpSchema.safeParse({ code: '1234567890' }).success).toBe(true)
    expect(otpSchema.safeParse({ code: '12345678901' }).success).toBe(false)
  })
})

describe('loginSchema', () => {
  const base = {
    target_profile: 'worker',
    identifier_type: 'email' as const,
    identifier: ' admin@example.com ',
    password: ' pass word ',
    otp_secret: '',
  }
  it('trims the identifier but keeps the password exactly as typed', () => {
    const r = loginSchema.safeParse(base)
    expect(r.success).toBe(true)
    expect(r.data?.identifier).toBe('admin@example.com')
    expect(r.data?.password).toBe(' pass word ')
  })
  it('checks the email shape only when the identifier type is email', () => {
    expect(loginSchema.safeParse({ ...base, identifier: 'shop_admin' }).success).toBe(false)
    expect(loginSchema.safeParse({ ...base, identifier_type: 'username', identifier: 'shop_admin' }).success).toBe(
      true,
    )
  })
  it('requires a password', () => {
    expect(loginSchema.safeParse({ ...base, password: '' }).success).toBe(false)
  })
  it('normalises the authenticator setup key and rejects non-base32 text', () => {
    const r = loginSchema.safeParse({ ...base, otp_secret: 'jbsw y3dp ehpk 3pxp' })
    expect(r.data?.otp_secret).toBe('JBSWY3DPEHPK3PXP')
    expect(loginSchema.safeParse({ ...base, otp_secret: 'not-a-key!' }).success).toBe(false)
  })
})
