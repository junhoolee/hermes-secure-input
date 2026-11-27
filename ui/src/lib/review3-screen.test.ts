// Screen sentences changed by security review 3 (docs/security-review-3.md, section 2): R3-2, R3-3, R3-4, N-5.
import { describe, expect, it } from 'vitest'

import { doneText, endText, MAIN_TOUCHED, scopeText, STORES, storageFailedAlert, TMP_LEFT, tmpMayBeLeft } from './copy'
import type { OpenResponse, StoreResult, StoreRow, SubmitResult } from './types'

const AGENT = { type: 'agent', profile: 'default' } as const

const KC_ROW: StoreRow = {
  store: 'keychain',
  selected: true,
  fixed: true,
  by: 'default',
  reason: null,
  needed: false,
  scope: 'mac',
  ident: 'svc',
  available: true,
  unavailable_reason: null,
  exists: true,
}

function secretOpen(exists: boolean | null = true): OpenResponse {
  return {
    v: 2,
    request_id: 'r',
    kind: 'secret',
    purpose: 'p',
    label: '가짜 비밀번호',
    requester: AGENT,
    target: {
      profile: 'default',
      profiles: ['default'],
      profile_editable: true,
      env_var: null,
      origin: null,
      site: null,
      stores: [{ ...KC_ROW, exists }],
      keychain: { id: 'k', service: 'svc', account: 'acct', listed: true, new_item: false, label: '점검용 항목', used_by: null },
    },
    server_public_key: '',
    sid: '',
    submit_deadline_s: 300,
    opened_at: '',
  }
}

const kcLine = (o: Partial<StoreResult>): StoreResult => ({
  store: 'keychain',
  saved: false,
  replaced: null,
  error: 'keychain_verify_failed',
  service: 'svc',
  account: 'acct',
  listed: true,
  new_item: false,
  tmp_left: false,
  main_touched: false,
  ...o,
})

const doneFor = (line: StoreResult, partial = false) =>
  doneText(secretOpen(), { status: 'saved', partial, stores: [line], storage: { type: 'keychain' }, label: 'x' } as SubmitResult, 'default')

// The HTTP answer the third security review measured for case 4b (main item written, read-back differs,
// inside the submit window), copied from its results file.
const CASE_4B = {
  http: 422,
  body: {
    error_code: 'storage_failed', message: '값을 저장하지 못했습니다. 다시 시도해 주세요.', ok: false, result_unknown: false,
    stores: [{ account: 'sr3-acct', error: 'keychain_verify_failed', listed: true, main_touched: true, new_item: false,
      replaced: null, saved: false, service: 'hermes-secure-input-test-sr3-listed-b', store: 'keychain', tmp_left: false }],
  },
}

describe('R3-2 (a): the retryable storage_failed alert', () => {
  it('a keychain line with main_touched true is followed by the done screen sentence', () => {
    const a = storageFailedAlert([kcLine({ main_touched: true })])
    expect(a.lines).toEqual(['Mac 키체인: Mac 키체인에 쓴 값을 다시 읽어 보니 넣은 값과 달랐습니다.', MAIN_TOUCHED])
    expect(MAIN_TOUCHED).toBe('이 항목에 새 값을 쓰기 시작했으므로, 있던 예전 값이 바뀌었을 수 있습니다.')
    // The same words as the done screen's store line for the same failure.
    expect(doneFor(kcLine({ main_touched: true })).stores![0].notes).toContain(MAIN_TOUCHED)
  })

  it('a line with main_touched false or missing adds nothing', () => {
    expect(storageFailedAlert([kcLine({ main_touched: false })]).lines).toEqual([
      'Mac 키체인: Mac 키체인에 쓴 값을 다시 읽어 보니 넣은 값과 달랐습니다.',
    ])
    const env: StoreResult = { store: 'env', saved: false, replaced: null, error: 'env_write_failed' }
    expect(storageFailedAlert([env]).lines).toEqual(['설정 파일(.env): 설정 파일(.env)에 쓰지 못했습니다. 파일은 저장하기 전 그대로입니다.'])
  })

  it('the last line speaks of the form fields, not of the keychain item', () => {
    expect(storageFailedAlert([kcLine({ main_touched: true })]).next).toEqual(['다시 보낼 수 있습니다.', '입력한 값은 입력 칸에 그대로 있습니다.'])
  })

  it('case 4b as measured: the alert says the old value may have changed', () => {
    expect(CASE_4B.http).toBe(422)
    expect(CASE_4B.body.result_unknown).toBe(false)
    const a = storageFailedAlert(CASE_4B.body.stores, CASE_4B.body.message)
    console.log('R3-2 4b alert:', JSON.stringify(a))
    expect(a.lines).toContain(MAIN_TOUCHED)
  })
})

describe('R3-2 (b): the cancelled screen', () => {
  const first = (f: Parameters<typeof endText>[2]) => endText('cancelled', AGENT, f).lines.slice(0, 2)

  it('nothing was sent: unchanged', () => {
    expect(endText('cancelled', AGENT).lines[0]).toBe('아무 값도 보내지 않았습니다.')
    expect(first({ sent: false, touched: false })).toEqual(['아무 값도 보내지 않았습니다.', 'Slack 대화에도 취소 결과가 표시됩니다.'])
  })

  it('a submit was answered and no keychain item was touched', () => {
    expect(first({ sent: true, touched: false })).toEqual(['보낸 값은 저장하지 못했습니다.', 'Slack 대화에도 취소 결과가 표시됩니다.'])
  })

  it('a submit answer had main_touched true: the old value may have changed, see Slack', () => {
    expect(endText('cancelled', AGENT, { sent: true, touched: true }).lines).toEqual([
      '보낸 값은 저장하지 못했습니다.',
      '보낸 값을 키체인 항목에 쓰기 시작했으므로, 그 항목에 있던 예전 값이 바뀌었을 수 있습니다. Slack 대화의 취소 결과 메시지를 확인하세요.',
      'Slack 대화에도 취소 결과가 표시됩니다.',
      '요청한 AI 모델에도 취소했다고 전달됩니다.',
      '나중에 다시 넣으려면 링크를 받은 Slack 대화에서 Hermes에게 다시 요청하세요.',
      '이 창을 닫아도 됩니다.',
    ])
  })

  it('a one-time code that was sent says it was not delivered, never "saved"', () => {
    expect(first({ sent: true, touched: false, code: true })).toEqual([
      '보낸 코드는 로그인 화면에 전달하지 못했습니다.',
      'Slack 대화에도 취소 결과가 표시됩니다.',
    ])
  })

  it('case 4b as measured, then cancel: the page saw main_touched, so it says so', () => {
    const touched = (CASE_4B.body.stores as StoreResult[]).some((r) => r.store === 'keychain' && r.main_touched === true)
    const t = endText('cancelled', AGENT, { sent: true, touched })
    console.log('R3-2 4b then cancel:', JSON.stringify(t))
    expect(t.lines.slice(0, 2)).toEqual([
      '보낸 값은 저장하지 못했습니다.',
      '보낸 값을 키체인 항목에 쓰기 시작했으므로, 그 항목에 있던 예전 값이 바뀌었을 수 있습니다. Slack 대화의 취소 결과 메시지를 확인하세요.',
    ])
    expect(t.lines).not.toContain('아무 값도 보내지 않았습니다.')
  })
})

describe('R3-4: a listed item the keychain does not have', () => {
  it('exists true: called an existing item', () => {
    expect(STORES.listedLabel('점검용 항목', true)).toBe('기존 항목입니다: 점검용 항목')
  })
  it('exists false: called an allow-list item', () => {
    expect(STORES.listedLabel('점검용 항목', false)).toBe('허용 목록 항목: 점검용 항목')
  })
  it('exists unknown (null): not called existing either', () => {
    expect(STORES.listedLabel('점검용 항목', null)).toBe('허용 목록 항목: 점검용 항목')
  })
  it('the note says a new item will be made and to check the allow-list', () => {
    expect(STORES.listedMissing).toBe(
      '허용 목록에 적힌 이름의 항목이 키체인에 아직 없습니다. 보내면 이 이름으로 새 항목을 만듭니다. 보내기 전에, 허용 목록에 적은 키체인 항목 이름과 키체인 계정 이름이 맞는지 확인하세요.',
    )
  })
})

describe('N-5: the keychain scope line', () => {
  it('names the login keychain of the account that runs Hermes, not the whole computer', () => {
    const s = scopeText(KC_ROW, 'default')
    expect(s).toBe('프로필과 상관없이, Hermes를 돌리는 사용자 계정의 로그인 키체인에 저장합니다.')
    expect(s).not.toContain('전체')
    expect(s).not.toContain('이 Mac')
    expect(scopeText({ ...KC_ROW, store: 'env', scope: 'profile' }, 'worker')).toBe('worker 프로필만 씁니다. 다른 프로필의 Hermes는 이 값을 읽지 않습니다.')
  })
})

describe('R3-3: a temporary keychain item may be left', () => {
  it('the sentence is the one Slack uses', () => {
    expect(TMP_LEFT).toBe("임시 키체인 항목에 이번에 넣은 값이 남아 있을 수 있습니다. Hermes가 도는 컴퓨터에서 README의 '남은 임시 키체인 항목' 절의 명령으로 확인해 지우세요.")
  })

  it('tmp_left true on a saved line (case 9e): the done screen store line says it', () => {
    const t = doneFor(kcLine({ saved: true, replaced: true, error: null, tmp_left: true, main_touched: true }))
    expect(t.heading).toBe('저장했습니다')
    expect(t.stores![0].notes).toEqual([TMP_LEFT])
  })

  it('store_timeout on the keychain line (case 9f), in a partial save: the store line says it', () => {
    const t = doneFor(kcLine({ saved: null, error: 'store_timeout', tmp_left: null, main_touched: false }), true)
    expect(t.heading).toBe('일부만 저장했습니다')
    expect(t.stores![0].notes).toEqual(['정해진 시간 안에 확인이 끝나지 않았습니다.', TMP_LEFT])
  })

  it('no_result counts; tmp_left false with another error does not; another store never does', () => {
    expect(tmpMayBeLeft(kcLine({ error: 'no_result', tmp_left: null }))).toBe(true)
    expect(tmpMayBeLeft(kcLine({ error: 'keychain_verify_failed', tmp_left: false }))).toBe(false)
    expect(tmpMayBeLeft({ store: 'env', saved: null, replaced: null, error: 'store_timeout' })).toBe(false)
    const t = doneFor(kcLine({ saved: true, replaced: true, error: null, tmp_left: false }))
    expect(t.stores![0].notes).toEqual([])
  })

  it('result unknown: the line is added only when the answer had such a store line', () => {
    const withTmp = endText('result_unknown', AGENT, { tmpLeft: true }).lines
    expect(withTmp).toEqual([
      '이 화면은 저장 결과를 받지 못했습니다. Slack 대화의 결과 메시지를 확인하세요.',
      '값이 저장됐을 수도 있고 저장되지 않았을 수도 있습니다.',
      TMP_LEFT,
      '이 화면에서는 다시 보낼 수 없습니다.',
      '입력한 값은 이 브라우저 화면에서 지웠습니다.',
      '저장되지 않았다고 나오면 링크를 받은 Slack 대화에서 Hermes에게 다시 요청하세요.',
    ])
    expect(endText('result_unknown', AGENT).lines).not.toContain(TMP_LEFT)
    expect(endText('result_unknown', AGENT, { tmpLeft: false }).lines).not.toContain(TMP_LEFT)
  })
})
