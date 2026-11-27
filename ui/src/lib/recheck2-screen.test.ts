// Screens changed by the second recheck of security review 3 (docs/security-review-3-recheck-2.md section 5):
// RC2-1 (the done screen also says what an earlier attempt left in the keychain) and RC2-3 (the "시도 횟수를
// 넘었습니다" and "저장했는지 알 수 없습니다" end screens say it too). The case names are the recheck's; the server side
// of the same cases is tests/test_recheck2_fix.py.
import { describe, expect, it } from 'vitest'

import { doneText, endText, MAIN_CREATED, MAIN_TOUCHED, TMP_LEFT } from './copy'
import type { OpenResponse, StoreResult, SubmitResult } from './types'

const AGENT = { type: 'agent', profile: 'default' } as const

const RESULT = 'Slack 대화의 결과 메시지를 확인하세요.'
const TOUCHED_RESULT = `보낸 값을 키체인 항목에 쓰기 시작했으므로, 그 항목에 있던 예전 값이 바뀌었을 수 있습니다. ${RESULT}`
const CREATED_RESULT = `보낸 값을 쓰려던 키체인 항목이 새로 만들어졌고, 이번에 넣은 값이 들어 있을 수 있습니다. ${RESULT}`
const CANCEL = 'Slack 대화의 취소 결과 메시지를 확인하세요.'
const TOUCHED_CANCEL = `보낸 값을 키체인 항목에 쓰기 시작했으므로, 그 항목에 있던 예전 값이 바뀌었을 수 있습니다. ${CANCEL}`
const COMMON_AGENT = ['입력한 값은 이 브라우저 화면에서 지웠습니다.', '저장 결과는 Hermes 안의 AI 모델과 Slack 대화에도 전달됩니다.', '이 창을 닫아도 됩니다.']
const NEW_LINK_AGENT = '링크를 받은 Slack 대화에서 Hermes에게 다시 요청하세요.'

const apiKeyOpen = {
  kind: 'api_key',
  label: 'Exa API 키',
  requester: AGENT,
  target: { profile: 'default', env_var: 'EXA_API_KEY', stores: [], keychain: { service: 'hermes-secure-input.exa-api-key', account: 'hermes-secure-input' } },
} as unknown as OpenResponse
const secretOpen = { ...apiKeyOpen, kind: 'secret', label: '배포 비밀번호' } as unknown as OpenResponse

const envSaved: StoreResult = { store: 'env', saved: true, replaced: false, error: null, env_var: 'EXA_API_KEY', profile: 'default' } as StoreResult
const kcSaved: StoreResult = {
  store: 'keychain',
  saved: true,
  replaced: true,
  error: null,
  service: 'hermes-secure-input.exa-api-key',
  account: 'hermes-secure-input',
  listed: false,
  new_item: false,
  tmp_left: false,
  main_touched: true,
  main_created: false,
} as StoreResult
const saved = (stores: StoreResult[], partial = false) =>
  ({ status: 'saved', partial, stores, storage: { type: stores[0].store === 'env' ? 'env' : 'keychain' }, label: 'x' }) as SubmitResult

describe('RC2-1: the done screen says what an earlier attempt left in the keychain', () => {
  it('rc1_g: a keychain-only send made the item, then .env only saved: the made item sentence, pointing at Slack', () => {
    expect(doneText(apiKeyOpen, saved([envSaved]), 'default', false, { created: true }).lines).toEqual([
      '값은 화면에 다시 보여 주지 않습니다.',
      CREATED_RESULT,
      ...COMMON_AGENT,
    ])
  })

  it('rc1_i: the earlier send wrote an existing item, then .env only saved: the old value sentence', () => {
    expect(doneText(apiKeyOpen, saved([envSaved]), 'default', false, { touched: true }).lines).toEqual([
      '값은 화면에 다시 보여 주지 않습니다.',
      TOUCHED_RESULT,
      ...COMMON_AGENT,
    ])
  })

  it('a keychain line that saved: no old value and no made item sentence, the temporary item sentence stays', () => {
    const lines = doneText(secretOpen, saved([kcSaved]), 'default', false, { touched: true, created: true, tmpLeft: true }).lines
    expect(lines).toEqual(['비밀번호는 화면에 다시 보여 주지 않습니다.', TMP_LEFT, ...COMMON_AGENT])
  })

  it('a partial save whose keychain line says it already: the store line keeps it, the list does not repeat it', () => {
    const failed = { ...kcSaved, saved: false, replaced: null, error: 'keychain_verify_failed', main_touched: true, tmp_left: true } as StoreResult
    const t = doneText(apiKeyOpen, saved([envSaved, failed], true), 'default', false, { touched: true, tmpLeft: true })
    const kc = t.stores!.find((s) => s.store === 'keychain')!
    expect(kc.notes).toContain(MAIN_TOUCHED)
    expect(kc.notes).toContain(TMP_LEFT)
    expect(t.lines).not.toContain(TOUCHED_RESULT)
    expect(t.lines).not.toContain(TMP_LEFT)
  })

  it('one send that saved, or no facts: the lines are the same as before', () => {
    const before = ['값은 화면에 다시 보여 주지 않습니다.', ...COMMON_AGENT]
    expect(doneText(apiKeyOpen, saved([envSaved]), 'default').lines).toEqual(before)
    expect(doneText(apiKeyOpen, saved([envSaved]), 'default', false, {}).lines).toEqual(before)
    expect(doneText(apiKeyOpen, saved([envSaved]), 'default', false, { sent: true }).lines).toEqual(before)
  })

  it('the made item sentence never comes with a saved keychain line', () => {
    expect(doneText(secretOpen, saved([kcSaved]), 'default', false, { created: true }).lines.join('\n')).not.toContain('새로 만들어졌고')
    expect(MAIN_CREATED).toBe('이 이름의 키체인 항목이 새로 만들어졌고, 이번에 넣은 값이 들어 있을 수 있습니다.')
  })
})

describe('RC2-3: the too many attempts end screen', () => {
  it('rc1_h: five failed sends on an item the first one made: the made item sentence, pointing at Slack', () => {
    expect(endText('too_many_attempts', AGENT, { created: true }).lines).toEqual([
      '보안을 위해 이 링크를 닫았습니다.',
      '입력한 값은 지웠습니다.',
      CREATED_RESULT,
      NEW_LINK_AGENT,
    ])
  })

  it('without the facts it is the same as before', () => {
    expect(endText('too_many_attempts', AGENT).lines).toEqual(['보안을 위해 이 링크를 닫았습니다.', '입력한 값은 지웠습니다.', NEW_LINK_AGENT])
  })
})

describe('the result unknown end screen', () => {
  it('an earlier send touched the item: the old value sentence; the temporary item sentence only once', () => {
    const lines = endText('result_unknown', AGENT, { touched: true, tmpLeft: true }).lines
    expect(lines.slice(0, 4)).toEqual([
      '이 화면은 저장 결과를 받지 못했습니다. Slack 대화의 결과 메시지를 확인하세요.',
      '값이 저장됐을 수도 있고 저장되지 않았을 수도 있습니다.',
      TOUCHED_RESULT,
      TMP_LEFT,
    ])
    expect(lines.filter((l) => l === TMP_LEFT)).toHaveLength(1)
  })

  it('only the temporary item: the same lines as before', () => {
    expect(endText('result_unknown', AGENT, { tmpLeft: true }).lines).toEqual([
      '이 화면은 저장 결과를 받지 못했습니다. Slack 대화의 결과 메시지를 확인하세요.',
      '값이 저장됐을 수도 있고 저장되지 않았을 수도 있습니다.',
      TMP_LEFT,
      '이 화면에서는 다시 보낼 수 없습니다.',
      '입력한 값은 이 브라우저 화면에서 지웠습니다.',
      `저장되지 않았다고 나오면 ${NEW_LINK_AGENT}`,
    ])
  })
})

describe('the cases whose end screen already said it (the server now says it too)', () => {
  it('rc2_l: touched, then a send that failed earlier, then the time ran out', () => {
    expect(endText('deadline_passed', AGENT, { sent: true, touched: true }).lines).toContain(TOUCHED_RESULT)
  })

  it('rc2_m: the same two sends, then cancel', () => {
    expect(endText('cancelled', AGENT, { sent: true, touched: true }).lines.slice(0, 2)).toEqual(['보낸 값은 저장하지 못했습니다.', TOUCHED_CANCEL])
  })

  it('rc3_c: a temporary item left, then a send that failed before the temporary step, then cancel', () => {
    expect(endText('cancelled', AGENT, { sent: true, tmpLeft: true }).lines.slice(0, 2)).toEqual(['보낸 값은 저장하지 못했습니다.', TMP_LEFT])
  })
})
