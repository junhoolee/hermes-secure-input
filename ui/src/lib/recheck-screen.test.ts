// Screen sentences changed by the recheck of security review 3 (docs/security-review-3-recheck.md section 5):
// RC-1 (a keychain item made by a failed save), RC-2 (the submit window passes after a retryable failure),
// RC-3 (the temporary keychain item sentence on the retryable alert and the end screens that follow it).
import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

import { doneText, endText, MAIN_CREATED, MAIN_TOUCHED, storageFailedAlert, storeUnavailableAlert, TMP_LEFT } from './copy'
import type { OpenResponse, StoreResult, SubmitResult } from './types'

const AGENT = { type: 'agent', profile: 'default' } as const
const USER = { type: 'user', profile: 'default' } as const

const kcLine = (o: Partial<StoreResult>): StoreResult => ({
  store: 'keychain',
  saved: false,
  replaced: null,
  error: 'keychain_verify_failed',
  service: 'hermes-secure-input.deploy-token',
  account: 'hermes-secure-input',
  listed: false,
  new_item: true,
  tmp_left: false,
  main_touched: false,
  main_created: true,
  ...o,
})

const CREATED_END =
  '보낸 값을 쓰려던 키체인 항목이 새로 만들어졌고, 이번에 넣은 값이 들어 있을 수 있습니다. Slack 대화의 취소 결과 메시지를 확인하세요.'
const TOUCHED_DEADLINE =
  '보낸 값을 키체인 항목에 쓰기 시작했으므로, 그 항목에 있던 예전 값이 바뀌었을 수 있습니다. Slack 대화의 결과 메시지를 확인하세요.'
const CREATED_DEADLINE =
  '보낸 값을 쓰려던 키체인 항목이 새로 만들어졌고, 이번에 넣은 값이 들어 있을 수 있습니다. Slack 대화의 결과 메시지를 확인하세요.'

describe('RC-1: a keychain item the failed save made', () => {
  it('the alert sentence is the one the card fixed', () => {
    expect(MAIN_CREATED).toBe('이 이름의 키체인 항목이 새로 만들어졌고, 이번에 넣은 값이 들어 있을 수 있습니다.')
  })

  it('the storage_failed alert says it right under the keychain line', () => {
    expect(storageFailedAlert([kcLine({})]).lines).toEqual([
      'Mac 키체인: Mac 키체인에 쓴 값을 다시 읽어 보니 넣은 값과 달랐습니다.',
      MAIN_CREATED,
    ])
  })

  it('a failure on an existing item (main_created false) does not say it', () => {
    const a = storageFailedAlert([kcLine({ new_item: false, main_touched: true, main_created: false })])
    expect(a.lines).toEqual(['Mac 키체인: Mac 키체인에 쓴 값을 다시 읽어 보니 넣은 값과 달랐습니다.', MAIN_TOUCHED])
    expect(a.lines).not.toContain(MAIN_CREATED)
  })

  it('the cancelled screen says it and points at Slack', () => {
    expect(endText('cancelled', AGENT, { sent: true, created: true }).lines.slice(0, 3)).toEqual([
      '보낸 값은 저장하지 못했습니다.',
      CREATED_END,
      'Slack 대화에도 취소 결과가 표시됩니다.',
    ])
  })

  it('the cancelled screen without it is unchanged', () => {
    expect(endText('cancelled', AGENT, { sent: true }).lines.slice(0, 2)).toEqual([
      '보낸 값은 저장하지 못했습니다.',
      'Slack 대화에도 취소 결과가 표시됩니다.',
    ])
  })

  it('a partial save: the failed keychain line of the done screen says it, a saved line never does', () => {
    const open = { target: { stores: [], keychain: null } } as unknown as OpenResponse
    const res = (line: StoreResult) =>
      doneText(open, { status: 'saved', partial: true, stores: [line], storage: { type: 'env' }, label: 'x' } as SubmitResult, 'default')
    expect(res(kcLine({})).stores![0].notes).toContain(MAIN_CREATED)
    expect(res(kcLine({ saved: true, replaced: false, error: null })).stores![0].notes).not.toContain(MAIN_CREATED)
  })

  it('a retry that saved to the item the first try made says "saved", not "replaced" (the server sends replaced false)', () => {
    const open = { target: { stores: [], keychain: null } } as unknown as OpenResponse
    const line = kcLine({ saved: true, replaced: false, error: null, main_created: false, main_touched: true })
    const t = doneText(open, { status: 'saved', partial: false, stores: [line], storage: { type: 'keychain' }, label: 'x' } as SubmitResult, 'default')
    expect(t.stores![0].statusText).toBe('저장했습니다.')
  })
})

describe('RC-2: the submit window passes after a retryable failure', () => {
  it('nothing was sent: the two first lines are unchanged', () => {
    expect(endText('deadline_passed', AGENT).lines.slice(0, 2)).toEqual([
      '값은 링크를 연 뒤 5분 안에 보내야 합니다.',
      '입력한 값은 지웠고 보내지 않았습니다.',
    ])
    expect(endText('deadline_passed', AGENT, { sent: false }).lines).toEqual(endText('deadline_passed', AGENT).lines)
  })

  it('a save failed and was not retried: what was sent, then what was cleared', () => {
    expect(endText('deadline_passed', AGENT, { sent: true }).lines).toEqual([
      '앞서 보낸 값은 저장하지 못했고, 다시 보내지 않은 채 제출 시간이 지났습니다.',
      '입력 칸에 남아 있던 값은 지웠습니다.',
      'Slack 대화에도 시간이 지났다는 결과가 표시됩니다.',
      '요청한 AI 모델에도 시간이 지났다고 전달됩니다.',
      '링크를 받은 Slack 대화에서 Hermes에게 다시 요청하세요.',
    ])
    expect(endText('deadline_passed', USER, { sent: true }).lines).not.toContain('요청한 AI 모델에도 시간이 지났다고 전달됩니다.')
  })

  it('the old value sentence, the made item sentence and the temporary item sentence follow, in the Slack order', () => {
    const t = endText('deadline_passed', AGENT, { sent: true, touched: true, created: true, tmpLeft: true })
    expect(t.lines.slice(0, 6)).toEqual([
      '앞서 보낸 값은 저장하지 못했고, 다시 보내지 않은 채 제출 시간이 지났습니다.',
      '입력 칸에 남아 있던 값은 지웠습니다.',
      TOUCHED_DEADLINE,
      CREATED_DEADLINE,
      TMP_LEFT,
      'Slack 대화에도 시간이 지났다는 결과가 표시됩니다.',
    ])
  })

  it('"5분 안에" stays on the screen where nothing was sent only', () => {
    expect(endText('deadline_passed', AGENT).lines.join(' ')).toContain('5분 안에')
    expect(endText('deadline_passed', AGENT, { sent: true }).lines.join(' ')).not.toContain('5분 안에')
    expect(endText('deadline_passed', AGENT, { sent: true }).lines.join(' ')).not.toContain('보내지 않았습니다.')
  })
})

describe('RC-3: the temporary keychain item sentence', () => {
  it('is the first sentence of the Slack text, letter for letter', () => {
    const notify = readFileSync(new URL('../../../secure_input/notify.py', import.meta.url), 'utf8')
    const first = TMP_LEFT.split('. ')[0] + '.'
    expect(first).toBe('임시 키체인 항목에 이번에 넣은 값이 남아 있을 수 있습니다.')
    expect(notify).toContain(`TMP_LEFT_TEXT = ("${first} "`)
  })

  it('the storage_failed alert says it right under a keychain line with tmp_left true', () => {
    const a = storageFailedAlert([kcLine({ new_item: false, main_created: false, error: 'keychain_verify_failed', tmp_left: true })])
    expect(a.lines).toEqual(['Mac 키체인: Mac 키체인에 쓴 값을 다시 읽어 보니 넣은 값과 달랐습니다.', TMP_LEFT])
  })

  it('after the old value and the made item sentences', () => {
    const a = storageFailedAlert([kcLine({ main_touched: true, tmp_left: true })])
    expect(a.lines.slice(1)).toEqual([MAIN_TOUCHED, MAIN_CREATED, TMP_LEFT])
  })

  it('tmp_left false or missing: no sentence', () => {
    expect(storageFailedAlert([kcLine({ main_created: false, tmp_left: false })]).lines).not.toContain(TMP_LEFT)
    expect(storageFailedAlert([kcLine({ main_created: false, tmp_left: undefined })]).lines).not.toContain(TMP_LEFT)
  })

  it('the cancelled screen says it after the failed save', () => {
    const t = endText('cancelled', AGENT, { sent: true, tmpLeft: true })
    expect(t.lines.slice(0, 3)).toEqual(['보낸 값은 저장하지 못했습니다.', TMP_LEFT, 'Slack 대화에도 취소 결과가 표시됩니다.'])
    expect(endText('cancelled', AGENT, { sent: true }).lines).not.toContain(TMP_LEFT)
  })

  it('the deadline screen after a failed save says it; the one where nothing was sent never does', () => {
    expect(endText('deadline_passed', AGENT, { sent: true, tmpLeft: true }).lines[2]).toBe(TMP_LEFT)
    expect(endText('deadline_passed', AGENT, { tmpLeft: true }).lines).not.toContain(TMP_LEFT)
  })
})

describe('the pre-write check alert ends like the storage_failed alert', () => {
  it('"입력한 값은 입력 칸에 그대로 있습니다." in both of its forms', () => {
    const open = {
      target: { stores: [{ store: 'env', fixed: false }, { store: 'keychain', fixed: true }] },
    } as unknown as OpenResponse
    for (const store of ['env', 'keychain'] as const) {
      const a = storeUnavailableAlert(open, [{ store, reason: 'bad_home' }])
      expect(a.next.at(-1)).toBe('입력한 값은 입력 칸에 그대로 있습니다.')
      expect(a.next).not.toContain('입력한 값은 그대로 있습니다.')
    }
  })
})
