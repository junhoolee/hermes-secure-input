import { describe, expect, it } from 'vitest'

import {
  A12,
  destination,
  doneCommon,
  doneText,
  endReasonFor,
  endText,
  FORM,
  formErrorText,
  NEW_LINK,
  NEW_LINK_AGENT,
  NEW_LINK_USER,
  objectParticle,
  pageNotes,
  plainText,
  REASON_TEXT,
  reasonText,
  requesterText,
  STORES,
  storeReaders,
  storeUse,
  whyOn,
} from './copy'
import { RETRYABLE, STORE_NAMES } from './types'
import type { EndReason, OpenResponse, StoreRow, SubmitResult } from './types'

// Phrases that must never appear on screen are built from parts, so a repository grep for them stays at zero.
const OLD_ROUND1 = ['Slack에서', '새 링크를', '요청'].join(' ')
const OLD_COMMAND_HINT = ['명령으로', '띄웠다면'].join(' ')
const MODEL_NEVER_SEES_KEY = ['AI 모델은', '키'].join(' ')
const AGENT_WORD = ['에이', '전트'].join('')

const AGENT = { type: 'agent', profile: 'worker' } as const
const USER = { type: 'user', profile: 'worker' } as const
const REASONS: EndReason[] = [
  'already_opened',
  'expired',
  'deadline_passed',
  'cancelled',
  'too_many_attempts',
  'already_submitted',
  'unusable',
  'unreachable',
  'identity_denied',
  'result_unknown',
]

function open(kind: OpenResponse['kind'], requester: OpenResponse['requester']): OpenResponse {
  return {
    kind,
    label: '예시 쇼핑몰 관리자',
    requester,
    target: {
      profile: 'worker',
      profiles: ['default', 'worker'],
      profile_editable: true,
      env_var: 'EXA_API_KEY',
      origin: 'https://admin.example.com',
      site: 'accounts.example.com',
    },
  } as unknown as OpenResponse
}
const loginOpen = open('login', AGENT)
const vaultResult: SubmitResult = {
  status: 'saved',
  storage: { type: 'vault', profile: 'worker', origin: 'https://admin.example.com', item_id: 'x' },
  label: '예시 쇼핑몰 관리자',
}

/** Every sentence the copy module produces for one request, its input screen and all end screens. */
function allText(o: OpenResponse): string {
  const ends = REASONS.map((r) => JSON.stringify(endText(r, o.requester)) + JSON.stringify(endText(r)))
  const stores = STORE_NAMES.map((s) => storeUse(s, o) + storeReaders(s).join(''))
  return [
    requesterText(o.requester),
    JSON.stringify(destination(o)),
    JSON.stringify(pageNotes(o)),
    JSON.stringify(FORM),
    JSON.stringify(STORES),
    JSON.stringify(REASON_TEXT),
    ...stores,
    ...ends,
  ].join('\n')
}

describe('who acts', () => {
  it('names only Hermes and the AI model, never an agent', () => {
    for (const kind of ['api_key', 'login', 'otp_code', 'secret'] as const) {
      for (const r of [AGENT, USER]) expect(allText(open(kind, r))).not.toContain(AGENT_WORD)
    }
  })

  it('says who asked, per requester type', () => {
    expect(requesterText(AGENT)).toBe('Hermes(worker 프로필) 안의 AI 모델이 작업 중에 위 이유를 적어 요청했습니다.')
    expect(requesterText(USER)).toBe('본인이 명령으로 직접 요청했습니다(worker 프로필).')
  })
})

describe('what the AI model sees', () => {
  it('api key: the page never sends the key to the model; the result line only for a Hermes request', () => {
    const agent = pageNotes(open('api_key', AGENT))
    expect(agent).toContain('이 페이지는 키 값을 Hermes 안의 AI 모델에게 보내지 않습니다.')
    expect(agent).toContain('AI 모델은 저장 위치마다 저장했는지를 받고, 사용자가 처음 상태에서 바꿔 끄거나 켠 저장 위치도 받습니다.')
    const user = pageNotes(open('api_key', USER))
    expect(user).toContain('이 페이지는 키 값을 Hermes 안의 AI 모델에게 보내지 않습니다.')
    expect(user).not.toContain('AI 모델은 저장 위치마다 저장했는지를 받고, 사용자가 처음 상태에서 바꿔 끄거나 켠 저장 위치도 받습니다.')
    expect(JSON.stringify(agent)).not.toContain(MODEL_NEVER_SEES_KEY)
  })

  it('login: autofill sentence and what the model does and does not see', () => {
    expect(storeUse('hermes_vault', loginOpen)).toBe(
      'Hermes가 앞으로 https://admin.example.com에 로그인할 때마다 이 로그인 정보를 로그인 화면에 자동으로 입력합니다.',
    )
    expect(storeReaders('hermes_vault')).toContain(
      'Hermes 안의 AI 모델은 비밀번호와 인증 앱 설정 키를 건네받지 않지만, 그 계정으로 명령을 실행하면 풀어 읽을 수 있습니다. 이메일, 사용자 이름, 전화번호 중 어느 것을 넣든 그 값은 저장한 뒤 AI 모델이 볼 수 있습니다.',
    )
  })

  it('keychain: never says the model cannot see the value, and names only the user account (reader round 3, T1)', () => {
    const readers = storeReaders('keychain').join(' ')
    expect(readers).toBe('Hermes가 도는 컴퓨터에서 Hermes를 돌리는 사용자 계정의 프로그램만 이 값을 읽을 수 있고, Hermes 안의 AI 모델도 그 계정으로 명령을 실행하면 이 값을 읽을 수 있습니다.')
    expect(readers).not.toContain('터미널 도구로')
    expect(readers).not.toContain('보지 않습니다')
    expect(pageNotes(open('secret', AGENT))).toEqual([
      '이 페이지는 비밀번호를 Hermes 안의 AI 모델에게 보내지 않습니다.',
      'AI 모델은 저장 결과와 키체인 항목 이름, 이 플러그인이 정한 키체인 계정 이름만 받습니다.',
    ])
  })

  it('vault: says that programs of the user account running Hermes can decrypt it (reader round 1, P19)', () => {
    expect(storeReaders('hermes_vault')[1]).toBe('Hermes가 도는 컴퓨터에서 Hermes를 돌리는 사용자 계정의 프로그램은 풀어 읽을 수 있습니다.')
  })

  it('one-time code: the page never sends the code to the model', () => {
    expect(destination(open('otp_code', AGENT)).notes).toEqual(['이 페이지는 코드를 Hermes 안의 AI 모델에게 보내지 않습니다.'])
  })
})

describe('done screen lines (reader round 1)', () => {
  it('P16: a Hermes request says the result also goes to Hermes; a user command and a code keep their line', () => {
    expect(doneCommon('api_key', AGENT)).toContain('저장 결과는 Hermes 안의 AI 모델과 Slack 대화에도 전달됩니다.')
    expect(doneCommon('api_key', USER)).toContain('Slack 대화에도 저장 결과가 표시됩니다.')
    expect(doneCommon('otp_code', AGENT)).toContain('Slack 대화에도 전달 결과가 표시됩니다.')
  })
})

describe('fixed sentences of plan appendix A.12', () => {
  it('are written exactly as in the plan', () => {
    expect(A12.newItem).toBe('새 항목입니다. 값을 쓸 프로그램이 이 항목 이름과 키체인 계정 이름으로 읽게 되어 있는지는 값을 보낸 뒤 그 프로그램의 설정에서 직접 확인하세요.')
    expect(A12.overwrite).toBe('이 이름의 항목에 이미 값이 있습니다. 보내면 그 값을 바꿉니다. 예전 값은 되돌릴 수 없습니다.')
    expect(A12.saving).toBe('저장 중입니다. 이 창을 닫지 마세요.')
    expect(A12.resultUnknown).toBe('이 화면은 저장 결과를 받지 못했습니다. Slack 대화의 결과 메시지를 확인하세요.')
    expect(plainText(A12.envOff)).toBe('Hermes는 이 키를 .env에서 읽습니다. 끄면 Hermes는 이번에 넣는 키를 쓰지 못하고, .env에 이미 값이 있으면 그 값은 바뀌지 않습니다.')
  })

  it('the result-unknown screen leads with the A.12 sentence and offers no resubmit', () => {
    const t = endText('result_unknown', AGENT)
    expect(t.lines[0]).toBe(A12.resultUnknown)
    expect(t.lines).toContain('이 화면에서는 다시 보낼 수 없습니다.')
    expect(endReasonFor('saving_in_progress')).toBe('result_unknown')
  })
})

describe('store failure words (plan appendix A.4)', () => {
  const WORDS = [
    'store_timeout', 'keychain_unavailable', 'keychain_timeout', 'keychain_acl_denied', 'keychain_name_invalid',
    'keychain_value_unsupported', 'keychain_line_too_long', 'keychain_write_failed', 'keychain_verify_failed',
    'invalid_env_var', 'invalid_value', 'env_write_failed', 'bad_home', 'env_not_writable', 'masked_value',
    'verify_failed', 'invalid_identifier_type', 'vault_rejected', 'unsupported_kind', 'internal_error', 'no_result',
  ]
  it('every word in use has its own screen sentence', () => {
    expect(Object.keys(REASON_TEXT).sort()).toEqual([...WORDS].sort())
    const texts = WORDS.map((w) => reasonText(w))
    expect(new Set(texts).size).toBe(WORDS.length)
  })
  it('an unknown word or another program\'s text never reaches the screen', () => {
    expect(reasonText('security: SecKeychainItemCopyContent failed')).toBe('저장 위치가 이유를 알려 주지 않았습니다.')
    expect(reasonText(null)).toBe('저장 위치가 이유를 알려 주지 않았습니다.')
  })
})

describe('profile mismatch line', () => {
  const head = '요청한 쪽은 worker 프로필입니다. default 프로필에 저장하면 worker 프로필의 Hermes는 이 값을 쓰지 못합니다.'
  const resultOnly = '그대로 보내면 요청한 AI 모델은 default 프로필에 저장했다는 결과만 받습니다.'

  it('Hermes request: says what to pick and that the requesting Hermes gets only the saved result', () => {
    expect(FORM.profileMismatch('worker', 'default', true)).toBe(
      `${head} 요청한 작업에 쓰려면 worker 프로필을 고르세요. ${resultOnly}`,
    )
  })

  it('user command: says what to pick, without the result-only sentence', () => {
    const line = FORM.profileMismatch('worker', 'default', false)
    expect(line).toBe(`${head} worker 프로필에서 쓰려면 worker 프로필을 고르세요.`)
    expect(line).not.toContain('결과만 받습니다')
  })

  it('appears only when the chosen profile is not the requester profile', () => {
    expect(FORM.profileMismatch('worker', 'worker', true)).toBeNull()
    expect(FORM.profileMismatch('worker', 'worker', false)).toBeNull()
    expect(FORM.profileMismatch('worker', '', true)).toBeNull()
  })
})

describe('login: an item saved before for the same site and id is replaced', () => {
  const removed = ['그것은 그대로 두고', '방금 저장한 새 항목']

  it('the replace rule matches on the value, whatever id type it was saved with (reader-test fix 3)', () => {
    expect(STORES.vaultReplace).toEqual([
      '저장할 프로필에 같은 사이트 주소로 저장해 둔 로그인 가운데, 아래에 넣는 이메일 주소, 사용자 이름 또는 전화번호와 값이 같은 로그인이 있으면 그 로그인을 되돌릴 수 없게 지우고 이번에 넣은 것으로 바꿉니다.',
      '예전 로그인의 아이디 종류가 이번과 달라도 값이 같으면 바꿉니다.',
    ])
    // The old sentence used "아이디" for any id, the same word as the id-type button.
    expect(STORES.vaultReplace.join('')).not.toContain('같은 아이디로')
    for (const s of removed) expect(JSON.stringify(STORES)).not.toContain(s)
  })

  it('the one-time code screen keeps no identNotes', () => {
    expect(destination(open('otp_code', AGENT)).identNotes).toEqual([])
  })

  it('authenticator key help: Hermes makes the code, no separate code request', () => {
    expect(FORM.otpSecretUse).toEqual([
      '로그인 때 사이트가 6자리 코드를 물으면 Hermes가 이 키로 코드를 만들어 입력합니다.',
      '그때는 코드 입력 요청이 따로 오지 않습니다.',
    ])
  })

  it('the old key goes even without opening the section, and says when (reader-test fix 2)', () => {
    expect(FORM.otpSecretLoss).toEqual([
      '저장할 프로필에 같은 사이트 주소와 이번과 같은 이메일 주소, 사용자 이름 또는 전화번호로 저장해 둔 로그인이 있으면, 이번에 설정 키를 넣지 않고 보내도 그 로그인의 인증 앱 설정 키가 함께 지워집니다.',
      '그 설정 키를 계속 쓰려면 위의 인증 앱 설정 키 추가(선택)를 눌러 이번에도 넣으세요.',
    ])
  })

  it('id type help says only the field label and example change', () => {
    expect(FORM.idTypeHelp).toBe('로그인할 때 쓰는 아이디의 형태를 고르세요. 아래 칸의 이름과 예시만 바뀌고, 자동 입력 방식은 같습니다.')
  })
})

describe('end screens: how to get a new link', () => {
  const KNOWN = ['deadline_passed', 'too_many_attempts', 'unusable'] as const
  const UNKNOWN = ['already_opened', 'expired', 'unreachable'] as const

  it('screens that know the requester show only the requester-specific sentence', () => {
    for (const reason of KNOWN) {
      const a = endText(reason, AGENT).lines
      expect(a, reason).toContain(NEW_LINK_AGENT)
      expect(a, reason).not.toContain(NEW_LINK_USER)
      const u = endText(reason, USER).lines
      expect(u, reason).toContain(NEW_LINK_USER)
      expect(u, reason).not.toContain(NEW_LINK_AGENT)
      // Reached without an opened request, the same screen falls back to the neutral sentence.
      expect(endText(reason).lines, reason).toContain(NEW_LINK)
    }
  })

  it('screens that cannot know the requester always use the neutral sentence', () => {
    for (const reason of UNKNOWN) {
      const text = JSON.stringify(endText(reason, AGENT)) + JSON.stringify(endText(reason, USER))
      expect(text, reason).toContain(NEW_LINK)
      expect(text, reason).not.toContain(NEW_LINK_AGENT)
      expect(text, reason).not.toContain(NEW_LINK_USER)
    }
  })

  it('drops the old round-1 and "if you used a command" sentences everywhere', () => {
    for (const r of [AGENT, USER, undefined]) {
      for (const reason of REASONS) {
        const text = JSON.stringify(endText(reason, r))
        expect(text, reason).not.toContain(OLD_COMMAND_HINT)
        expect(text, reason).not.toContain(OLD_ROUND1)
      }
    }
  })

  it('already opened: a closed or reloaded window needs a new link', () => {
    expect(endText('already_opened').lines).toEqual([
      '이 링크는 한 번만 열 수 있고, 이미 한 번 열렸습니다.',
      '지금 이 창에서는 값을 넣을 수 없습니다.',
      '먼저 연 창이 남아 있으면 그 창에서 계속 입력하세요.',
      '그 창을 닫았거나 새로 고쳤다면 새 링크가 필요합니다. 링크를 받은 Slack 대화에서 다시 요청하세요.',
      '직접 연 적이 없다면 다른 사람이 열었을 수 있습니다. 이 경우 값을 넣지 말고, 링크를 받은 Slack 대화에서 다시 요청하세요.',
    ])
  })
})

describe('identity denied screen', () => {
  it('both 403 identity codes from open map to one end screen', () => {
    expect(endReasonFor('identity_required')).toBe('identity_denied')
    expect(endReasonFor('identity_not_allowed')).toBe('identity_denied')
  })

  it('heading and four lines, the same for any requester (reader-test fixes 1 and 4)', () => {
    const lines = [
      '이 링크는 Hermes 컴퓨터에 허용된 Tailscale 계정으로 로그인한 기기에서만 열 수 있습니다.',
      '이 기기에서 열려고 한 것은 링크를 연 것으로 치지 않았습니다. 그래서 이 링크는 아직 한 번 열 수 있습니다.',
      '허용된 계정의 기기에서 링크를 만든 뒤 60초 안에 여세요. 60초가 지나면 링크가 만료되고, 그때는 링크를 받은 Slack 대화에서 새 링크를 요청해야 합니다.',
      '본인 기기에서 이 화면이 나왔다면 이 기기의 Tailscale 앱이 어느 계정으로 로그인되어 있는지 확인하세요.',
    ]
    for (const r of [AGENT, USER, undefined]) {
      expect(endText('identity_denied', r)).toEqual({ heading: '이 기기의 Tailscale 계정으로는 열 수 없습니다', lines })
    }
  })
})

describe('cancelled screen', () => {
  it('Hermes request: says Hermes was told, and how to ask again', () => {
    expect(endText('cancelled', AGENT).lines).toEqual([
      '아무 값도 보내지 않았습니다.',
      'Slack 대화에도 취소 결과가 표시됩니다.',
      '요청한 AI 모델에도 취소했다고 전달됩니다.',
      '나중에 다시 넣으려면 링크를 받은 Slack 대화에서 Hermes에게 다시 요청하세요.',
      '이 창을 닫아도 됩니다.',
    ])
  })

  it('user command: no "Hermes was told" line, and the command way to ask again', () => {
    expect(endText('cancelled', USER).lines).toEqual([
      '아무 값도 보내지 않았습니다.',
      'Slack 대화에도 취소 결과가 표시됩니다.',
      '나중에 다시 넣으려면 링크를 띄울 때 보낸 명령을 같은 대화에 다시 보내세요.',
      '이 창을 닫아도 됩니다.',
    ])
  })
})

describe('submit time passed screen', () => {
  it('Hermes request: says Slack shows the result and Hermes was told, then how to ask again', () => {
    expect(endText('deadline_passed', AGENT).lines).toEqual([
      '값은 링크를 연 뒤 5분 안에 보내야 합니다.',
      '입력한 값은 지웠고 보내지 않았습니다.',
      'Slack 대화에도 시간이 지났다는 결과가 표시됩니다.',
      '요청한 AI 모델에도 시간이 지났다고 전달됩니다.',
      '링크를 받은 Slack 대화에서 Hermes에게 다시 요청하세요.',
    ])
  })

  it('user command: no "Hermes was told" line', () => {
    expect(endText('deadline_passed', USER).lines).toEqual([
      '값은 링크를 연 뒤 5분 안에 보내야 합니다.',
      '입력한 값은 지웠고 보내지 않았습니다.',
      'Slack 대화에도 시간이 지났다는 결과가 표시됩니다.',
      '링크를 띄울 때 보낸 명령을 같은 대화에 다시 보내세요.',
    ])
  })
})

describe('done screens', () => {
  it('login: saved as one item, and the setup key only when one was sent', () => {
    const without = doneText(loginOpen, vaultResult, 'worker', false).lines
    expect(without[0]).toBe('아이디와 비밀번호를 한 항목으로 저장했습니다.')
    expect(without.join('\n')).not.toContain('인증 앱 설정 키')
    const withKey = doneText(loginOpen, vaultResult, 'worker', true).lines
    expect(withKey.slice(0, 2)).toEqual(['아이디와 비밀번호를 한 항목으로 저장했습니다.', '인증 앱 설정 키도 같은 항목에 저장했습니다.'])
  })

  it('one-time code: handed over, entered right away, the outcome only in Slack', () => {
    const t = doneText(open('otp_code', AGENT), { status: 'delivered', storage: { type: 'browser_page' }, label: 'x' }, '')
    expect(t.heading).toBe('전달했습니다')
    expect(t.lines.slice(0, 3)).toEqual([
      '코드를 Hermes에 넘겼습니다.',
      'Hermes가 곧바로 로그인 화면에 입력합니다.',
      '로그인이 됐는지, 코드가 틀렸는지는 이 화면에 나오지 않습니다. Slack 대화에서 확인하세요.',
    ])
  })
})

describe('masked_value (a masked-looking key was refused before saving)', () => {
  const MASKED = '가려진 값처럼 보여 저장하지 않았습니다. 원래 키 전체를 붙여 넣어 주세요.'

  it('is a retryable code, not an end screen', () => {
    expect(RETRYABLE.has('masked_value')).toBe(true)
    expect(endReasonFor('masked_value')).toBe('unusable') // only used for terminal codes; masked_value is not one
  })

  it("shows the server's sentence as is", () => {
    expect(formErrorText('masked_value', MASKED)).toBe(MASKED)
  })

  it('without a server sentence shows the generic line without the code', () => {
    expect(formErrorText('masked_value')).toBe(FORM.genericError)
    expect(formErrorText('storage_failed')).toBe(FORM.genericError)
    expect(formErrorText('something_new')).toBe(`${FORM.genericError} (something_new)`)
  })
})

describe('reader round 2 fixes', () => {
  const row = (by: StoreRow['by']) => ({ store: 'env', by }) as unknown as StoreRow

  it('S13: the default-store sentence names the kind with the right particle', () => {
    expect(whyOn(row('default'), 'api_key')).toBe('API 키를 기본으로 저장하는 곳이라 켜 두었습니다.')
    expect(whyOn(row('default'), 'login')).toBe('사이트 로그인 정보를 기본으로 저장하는 곳이라 켜 두었습니다.')
    expect(whyOn(row('default'), 'secret')).toBe('비밀번호를 기본으로 저장하는 곳이라 켜 두었습니다.')
    expect(objectParticle('계정')).toBe('을')
    expect(objectParticle('키')).toBe('를')
  })

  function keychainOpen(exists: boolean | null): OpenResponse {
    const o = open('secret', AGENT)
    o.target.stores = [{ store: 'keychain', exists } as unknown as StoreRow]
    o.target.keychain = { service: 'svc', account: 'acct' } as unknown as OpenResponse['target']['keychain']
    return o
  }
  const failed = (main_touched: boolean | undefined): SubmitResult =>
    ({
      status: 'saved',
      storage: { type: 'keychain' },
      label: 'x',
      partial: true,
      stores: [{ store: 'keychain', saved: false, error: 'keychain_write_failed', main_touched }],
    }) as unknown as SubmitResult
  const status = (o: OpenResponse, r: SubmitResult) => doneText(o, r, 'worker').stores![0].statusText

  it('S18: a failed keychain row says the old value is kept only when the item existed and no write reached it', () => {
    expect(status(keychainOpen(true), failed(false))).toBe('저장하지 못했고, 예전 값은 그대로입니다.')
    expect(status(keychainOpen(true), failed(true))).toBe('저장하지 못했습니다.')
    expect(status(keychainOpen(true), failed(undefined))).toBe('저장하지 못했습니다.')
    expect(status(keychainOpen(false), failed(false))).toBe('저장하지 못했습니다.')
    expect(status(keychainOpen(null), failed(false))).toBe('저장하지 못했습니다.')
  })
})
