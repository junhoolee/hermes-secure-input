import { z } from 'zod'

// zod v4 probes `new Function` to JIT-compile object parsers. The page CSP has no
// 'unsafe-eval', so the probe itself would raise a CSP violation. Stay interpreted.
z.config({ jitless: true })

const profile = z.string().min(1, '저장할 프로필을 고르세요.')

export const apiKeySchema = z.object({
  target_profile: profile,
  value: z
    .string()
    .transform((s) => s.trim())
    .pipe(
      z
        .string()
        .min(1, 'API 키를 입력하세요.')
        .max(4096, 'API 키가 너무 깁니다. 4,096자 이하만 받습니다.')
        .refine((s) => !/[\r\n]/.test(s), 'API 키에 줄바꿈이 들어 있습니다. 한 줄로 붙여 넣으세요.')
        // The server takes printable ASCII only for an API key: no non-ASCII letter, control character or
        // line separator such as U+2028 (secure_input/server.py validate_plain, secure_input/validation.py).
        .refine(
          (s) => /^[\x20-\x7E]*$/.test(s),
          'API 키에는 영문, 숫자, 기호, 공백만 넣을 수 있습니다. 붙여 넣은 값에 다른 글자가 섞였는지 확인하세요.',
        ),
    ),
})

export const otpSchema = z.object({
  code: z
    .string()
    .transform((s) => s.replace(/[\s-]/g, ''))
    .pipe(
      z
        .string()
        .min(1, '일회용 코드를 입력하세요.')
        .regex(/^[A-Za-z0-9]{4,10}$/, '코드는 숫자나 영문 4-10자입니다. 공백과 -는 빼고 셉니다.'),
    ),
})

const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

export const loginSchema = z
  .object({
    target_profile: profile,
    identifier_type: z.enum(['email', 'username', 'phone']),
    identifier: z
      .string()
      .transform((s) => s.trim())
      .pipe(z.string().min(1, '아이디를 입력하세요.').max(512, '아이디가 너무 깁니다. 512자 이하만 받습니다.')),
    // Passwords are sent exactly as typed: leading or trailing spaces can be real.
    password: z.string().min(1, '비밀번호를 입력하세요.').max(1024, '비밀번호가 너무 깁니다. 1,024자 이하만 받습니다.'),
    otp_secret: z
      .string()
      .transform((s) => s.replace(/\s/g, '').toUpperCase())
      .pipe(
        z
          .string()
          .regex(/^([A-Z2-7]+=*)?$/, '인증 앱 설정 키는 영문 A-Z와 숫자 2-7로만 이루어집니다.')
          .max(256, '인증 앱 설정 키가 너무 깁니다. 256자 이하만 받습니다.'),
      ),
  })
  .superRefine((v, ctx) => {
    if (v.identifier_type === 'email' && !EMAIL.test(v.identifier)) {
      ctx.addIssue({ code: 'custom', path: ['identifier'], message: '이메일 주소 형식이 아닙니다. 예: admin@example.com' })
    }
    if (v.identifier_type === 'phone' && !/^\+?[0-9][0-9\s-]{5,}$/.test(v.identifier)) {
      ctx.addIssue({ code: 'custom', path: ['identifier'], message: '전화번호는 숫자와 -만 씁니다. 예: 010-1234-5678' })
    }
  })

/** Max length of a value kept in the Mac keychain (plan 3.1). */
export const KEYCHAIN_MAX_CHARS = 1024

/**
 * True when a value meets the keychain value rule of plan 3.1: one line, printable ASCII (0x20-0x7E),
 * no space as the first or last character, 1-1,024 characters.
 */
export function keychainValueOk(s: string): boolean {
  return s.length >= 1 && s.length <= KEYCHAIN_MAX_CHARS && /^[\x20-\x7E]+$/.test(s) && s[0] !== ' ' && s[s.length - 1] !== ' '
}

// A secret is sent exactly as typed (no trimming): a space at either end is refused, not removed,
// because the script that reads the keychain item strips it (plan 3.1).
export const secretSchema = z
  .object({
    value: z
      .string()
      .min(1, '비밀번호를 입력하세요.')
      .max(KEYCHAIN_MAX_CHARS, '비밀번호가 너무 깁니다. 1,024자 이하만 받습니다.')
      .refine((s) => !/[\r\n]/.test(s), '비밀번호에 줄바꿈이 들어 있습니다. 한 줄로 넣으세요.')
      .refine(
        (s) => /^[\x20-\x7E]*$/.test(s),
        '비밀번호에는 영문, 숫자, 기호, 공백만 넣을 수 있습니다. 한글이나 이모지는 Mac 키체인에서 다른 값으로 읽힙니다.',
      )
      .refine(
        (s) => !s.startsWith(' ') && !s.endsWith(' '),
        '비밀번호의 맨 앞이나 맨 뒤에 공백이 있습니다. 이 값을 읽는 프로그램은 앞뒤 공백을 지우고 읽으므로 받지 않습니다.',
      ),
    confirm: z.string(),
  })
  .superRefine((v, ctx) => {
    if (v.confirm === '') {
      ctx.addIssue({ code: 'custom', path: ['confirm'], message: '같은 비밀번호를 한 번 더 입력하세요.' })
    } else if (v.confirm !== v.value) {
      ctx.addIssue({ code: 'custom', path: ['confirm'], message: '두 칸의 값이 다릅니다. 같은 비밀번호를 다시 입력하세요.' })
    }
  })

export type SecretInput = z.input<typeof secretSchema>
export type SecretOutput = z.output<typeof secretSchema>
export type ApiKeyInput = z.input<typeof apiKeySchema>
export type ApiKeyOutput = z.output<typeof apiKeySchema>
export type LoginInput = z.input<typeof loginSchema>
export type LoginOutput = z.output<typeof loginSchema>
export type OtpInput = z.input<typeof otpSchema>
export type OtpOutput = z.output<typeof otpSchema>
