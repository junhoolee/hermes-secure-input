import { describe, expect, it } from 'vitest'

import { pageNotes, plainText, REASON_TEXT, reasonText } from './copy'
import type { KeychainTarget, OpenResponse } from './types'

// Security review 3: R3-5 (what the AI model receives for a keychain item) and N-3 (keychain_acl_denied).

const AGENT = { type: 'agent', profile: 'worker' } as const
const USER = { type: 'user', profile: 'worker' } as const

const LISTED: KeychainTarget = {
  id: 'canary-cred',
  service: 'Canary-Service',
  account: 'acct-canary@example.com',
  listed: true,
  new_item: false,
  label: '카나리 비밀번호',
  used_by: '카나리 스크립트',
}
const OWN: KeychainTarget = {
  id: 'own-new',
  service: 'hermes-secure-input.own-new',
  account: 'hermes-secure-input',
  listed: false,
  new_item: true,
  label: null,
  used_by: null,
}

function secretOpen(requester: OpenResponse['requester'], keychain: KeychainTarget): OpenResponse {
  return {
    kind: 'secret',
    label: '카나리 비밀번호',
    requester,
    target: { profile: 'worker', profiles: ['worker'], profile_editable: false, keychain },
  } as unknown as OpenResponse
}

describe('R3-5: the page says what the AI model receives for the keychain item', () => {
  it('allow-list item: the model gets the item name, not the keychain account name', () => {
    expect(pageNotes(secretOpen(AGENT, LISTED))).toEqual([
      '이 페이지는 비밀번호를 Hermes 안의 AI 모델에게 보내지 않습니다.',
      'AI 모델은 저장 결과와 키체인 항목 이름만 받습니다. 키체인 계정 이름은 받지 않습니다.',
    ])
  })

  it("the plugin's own item: the model also gets the plugin's fixed account name", () => {
    expect(pageNotes(secretOpen(AGENT, OWN))).toEqual([
      '이 페이지는 비밀번호를 Hermes 안의 AI 모델에게 보내지 않습니다.',
      'AI 모델은 저장 결과와 키체인 항목 이름, 이 플러그인이 정한 키체인 계정 이름만 받습니다.',
    ])
  })

  it('a user command says nothing about the AI model', () => {
    expect(pageNotes(secretOpen(USER, LISTED))).toEqual(['이 페이지는 비밀번호를 Hermes 안의 AI 모델에게 보내지 않습니다.'])
  })
})

describe('N-3: keychain_acl_denied names the access list and the "allow all programs" case', () => {
  const text = REASON_TEXT.keychain_acl_denied

  it('names /usr/bin/security in code font and the allow-all case', () => {
    expect(text).toBe(
      "이 키체인 항목의 접근 허용 목록에 `/usr/bin/security`가 없어서 Hermes가 이 항목의 값을 바꾸지 않습니다. 접근 설정이 '모든 프로그램 허용'인 항목의 값도 Hermes는 바꾸지 않습니다.",
    )
    expect(reasonText('keychain_acl_denied')).toBe(text)
  })

  it('reads without backticks in plain text', () => {
    expect(plainText(text)).toContain('접근 허용 목록에 /usr/bin/security가 없어서')
  })
})
