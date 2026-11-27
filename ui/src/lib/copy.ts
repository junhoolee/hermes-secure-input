// Every user-facing sentence lives here so wording stays consistent across
// the input, done and end screens. One fact per sentence.
//
// Text between backticks is a literal name (a file, a command) and is drawn in the code face
// by the components (see Literal in form-parts.tsx); the backticks themselves are not shown.

import {
  RETRYABLE,
  type EndReason,
  type Kind,
  type OpenResponse,
  type StoreName,
  type StoreResult,
  type StoreRow,
  type SubmitResult,
  type UnavailableStore,
} from './types'

export const KIND_NAME: Record<Kind, string> = {
  api_key: 'API 키',
  login: '사이트 로그인 정보',
  otp_code: '일회용 코드',
  secret: '비밀번호',
}

export const requestBand = (kind: Kind) => `${KIND_NAME[kind]} 입력 요청`

export type Requester = OpenResponse['requester']

export function requesterText(r: Requester): string {
  return r.type === 'agent'
    ? `Hermes(${r.profile} 프로필) 안의 AI 모델이 작업 중에 위 이유를 적어 요청했습니다.`
    : `본인이 명령으로 직접 요청했습니다(${r.profile} 프로필).`
}

export const ENV_FILE = '설정 파일(.env)'
export const VAULT = 'Hermes 암호화 저장소(vault)'
export const KEYCHAIN = 'Mac 키체인'

export const STORE_NAME: Record<StoreName, string> = {
  env: ENV_FILE,
  hermes_vault: VAULT,
  keychain: KEYCHAIN,
}

// ---------------------------------------------------------------------------
// Fixed sentences of plan appendix A.12. Written exactly as there.
// ---------------------------------------------------------------------------
export const A12 = {
  newItem: '새 항목입니다. 값을 쓸 프로그램이 이 항목 이름과 키체인 계정 이름으로 읽게 되어 있는지는 값을 보낸 뒤 그 프로그램의 설정에서 직접 확인하세요.',
  overwrite: '이 이름의 항목에 이미 값이 있습니다. 보내면 그 값을 바꿉니다. 예전 값은 되돌릴 수 없습니다.',
  saving: '저장 중입니다. 이 창을 닫지 마세요.',
  resultUnknown: '이 화면은 저장 결과를 받지 못했습니다. Slack 대화의 결과 메시지를 확인하세요.',
  envOff: 'Hermes는 이 키를 `.env`에서 읽습니다. 끄면 Hermes는 이번에 넣는 키를 쓰지 못하고, `.env`에 이미 값이 있으면 그 값은 바뀌지 않습니다.',
} as const

/** Strip the backticks: the sentence as a reader sees it. */
export const plainText = (s: string) => s.replace(/`/g, '')

// ---------------------------------------------------------------------------
// Store failure words of plan appendix A.4 (closed list). Every word has its own sentence; an
// unknown word falls back to a general sentence, so no other program's text reaches the screen.
// ---------------------------------------------------------------------------
export const REASON_TEXT: Record<string, string> = {
  store_timeout: '정해진 시간 안에 확인이 끝나지 않았습니다.',
  keychain_unavailable: 'Hermes가 도는 컴퓨터에서 키체인에 접근하지 못했습니다.',
  keychain_timeout: 'Mac 키체인이 5초 안에 답하지 않았습니다.',
  keychain_acl_denied:
    "이 키체인 항목의 접근 허용 목록에 `/usr/bin/security`가 없어서 Hermes가 이 항목의 값을 바꾸지 않습니다. 접근 설정이 '모든 프로그램 허용'인 항목의 값도 Hermes는 바꾸지 않습니다.",
  keychain_name_invalid: '키체인 항목 이름이 이름 규칙에 맞지 않습니다.',
  keychain_value_unsupported:
    'Mac 키체인에는 영문, 숫자, 기호와 가운데 공백으로 된 1,024자 이하의 값만 넣을 수 있습니다. 맨 앞과 맨 뒤에는 공백을 둘 수 없습니다.',
  keychain_line_too_long: '값이 너무 길어 Mac 키체인에 넣지 못합니다.',
  keychain_write_failed: 'Mac 키체인에 쓰지 못했습니다.',
  keychain_verify_failed: 'Mac 키체인에 쓴 값을 다시 읽어 보니 넣은 값과 달랐습니다.',
  invalid_env_var: '변수 이름이 Hermes의 이름 규칙에 맞지 않습니다.',
  invalid_value: '값이 한 줄의 영문, 숫자, 기호가 아닙니다.',
  env_write_failed: '설정 파일(.env)에 쓰지 못했습니다. 파일은 저장하기 전 그대로입니다.',
  bad_home: '이 프로필의 폴더를 찾지 못했습니다.',
  env_not_writable: 'Hermes가 이 변수를 이 방법으로 바꾸지 못하게 막아 두었습니다.',
  masked_value: '가려진 값처럼 보여 저장하지 않았습니다.',
  verify_failed: '설정 파일(.env)에 쓴 값을 다시 읽어 보니 넣은 값과 달랐습니다. 파일은 저장하기 전으로 되돌렸습니다.',
  invalid_identifier_type: '아이디 종류가 올바르지 않습니다.',
  vault_rejected: 'Hermes 암호화 저장소가 이 항목을 받지 않았습니다.',
  unsupported_kind: '이 종류의 값을 저장하는 방법이 없습니다.',
  internal_error: '저장하는 도중 예상하지 못한 오류가 났습니다.',
  no_result: '저장 결과를 받지 못했습니다.',
}

export const reasonText = (word: string | null | undefined) =>
  (word && REASON_TEXT[word]) || '저장 위치가 이유를 알려 주지 않았습니다.'

// ---------------------------------------------------------------------------
// The storage list (plan 4.1): one row per store the kind can use.
// ---------------------------------------------------------------------------
export const STORES = {
  heading: '저장 위치',
  /**
   * Shown when the user can switch stores on and off. A screen with one store says nothing here: its row
   * already says the value goes to that one place only (STORES.fixed). That a page with every row off cannot
   * be sent is said by noneOn, when it happens.
   */
  choose: '켠 곳마다 같은 값을 저장합니다.',
  noneOn: '저장 위치를 한 곳 이상 켜세요. 모두 끄면 보낼 수 없습니다.',
  reasonCaption: 'AI 모델이 이 저장 위치에 적은 이유',
  identCaption: { env: '변수 이름', hermes_vault: '사이트 주소', keychain: '키체인 항목 이름' } as Record<StoreName, string>,
  scopeTerm: '쓰는 범위',
  whyOnTerm: '처음 상태',
  readTerm: '읽을 수 있는 쪽',
  accountTerm: '키체인 계정 이름',
  /**
   * A listed item (plan 3.2, rule 3): the user put it on the plugin's allow-list under this label. It is called
   * an existing item only when the keychain has it (row `exists` true); otherwise the send creates it (R3-4).
   */
  listedLabel: (l: string, exists: boolean | null) => (exists === true ? `기존 항목입니다: ${l}` : `허용 목록 항목: ${l}`),
  /** Keychain row on, listed, and the keychain has no item of that name (row `exists` false): the send creates it (R3-4). */
  listedMissing:
    '허용 목록에 적힌 이름의 항목이 키체인에 아직 없습니다. 보내면 이 이름으로 새 항목을 만듭니다. 보내기 전에, 허용 목록에 적은 키체인 항목 이름과 키체인 계정 이름이 맞는지 확인하세요.',
  usedBy: (u: string) => `이 항목을 쓰는 곳: ${u}`,
  switchable: '켜고 끌 수 있습니다.',
  fixed: '이 요청의 저장 위치는 이 한 곳뿐이라 켜 두었고, 끌 수 없습니다.',
  envExists: '이 변수에는 이미 값이 있습니다. 보내면 그 값을 바꿉니다. 예전 값은 되돌릴 수 없습니다.',
  /** Fix 3 of the last reader test: the match is on the value, whatever id type it was saved with. */
  vaultReplace: [
    '저장할 프로필에 같은 사이트 주소로 저장해 둔 로그인 가운데, 아래에 넣는 이메일 주소, 사용자 이름 또는 전화번호와 값이 같은 로그인이 있으면 그 로그인을 되돌릴 수 없게 지우고 이번에 넣은 것으로 바꿉니다.',
    '예전 로그인의 아이디 종류가 이번과 달라도 값이 같으면 바꿉니다.',
  ],
  keychainNameMissing: '이 키의 키체인 항목 이름을 정하지 못했습니다.',
  unavailable: (s: StoreName) => `지금은 ${STORE_NAME[s]}에 저장할 수 없습니다.`,
  unavailableNext: (fixed: boolean, s: StoreName) =>
    fixed ? '원인을 고친 뒤 보내세요.' : `${STORE_NAME[s]} 칸을 끄면 나머지 저장 위치에만 저장할 수 있습니다.`,
  /** The page-level warning when an agent-marked store is off (plan 2.4). Not used for api_key's .env (A.12 covers it). */
  neededOff: (_s: StoreName) => '끄면 이곳에서 이 값을 읽는 프로그램은 이번에 넣는 값을 쓰지 못하고, 이곳에 이미 값이 있으면 그 값은 바뀌지 않습니다.',
}

/** 을 or 를 after a Korean word: 을 when the last syllable has a final consonant. */
export function objectParticle(word: string): string {
  const code = word.charCodeAt(word.length - 1)
  if (code < 0xac00 || code > 0xd7a3) return '를'
  return (code - 0xac00) % 28 === 0 ? '를' : '을'
}

/** Why a row started on or off (A.6 `by`). The default store is set per kind, so that sentence names the kind. */
export function whyOn(row: StoreRow, kind: Kind): string {
  switch (row.by) {
    case 'agent':
      return 'AI 모델이 골라서 켜 두었습니다.'
    case 'history':
      return '전에 이 입력 페이지로 같은 이름의 값을 저장할 때 쓴 저장 위치라 켜 두었습니다.'
    case 'default':
      return `${KIND_NAME[kind]}${objectParticle(KIND_NAME[kind])} 기본으로 저장하는 곳이라 켜 두었습니다.`
    default:
      return '처음에는 꺼져 있었습니다.'
  }
}

// The keychain is the login keychain of the user account that runs Hermes, not one shared by the whole computer
// (N-5). The row's use and readers lines already say "Hermes가 도는 컴퓨터에서", so this line names only the keychain.
export function scopeText(row: StoreRow, profile: string): string {
  return row.scope === 'mac'
    ? '프로필과 상관없이, Hermes를 돌리는 사용자 계정의 로그인 키체인에 저장합니다.'
    : `${profile} 프로필만 씁니다. 다른 프로필의 Hermes는 이 값을 읽지 않습니다.`
}

/** What the store is for (row item 2 of plan 4.1). */
export function storeUse(store: StoreName, open: OpenResponse): string {
  switch (store) {
    case 'env':
      return 'Hermes가 이 키를 쓰는 서비스를 호출할 때 이 값을 읽습니다.'
    case 'hermes_vault':
      return `Hermes가 앞으로 ${open.target.origin ?? ''}에 로그인할 때마다 이 로그인 정보를 로그인 화면에 자동으로 입력합니다.`
    case 'keychain':
      return 'Hermes가 도는 컴퓨터에서 이 항목 이름과 키체인 계정 이름으로 읽게 되어 있는 프로그램이 있으면, 그 프로그램이 이 값을 읽어 씁니다.'
  }
}

/** Who can read the value once it is there (row item 9 of plan 4.1; plan 6.1). */
export function storeReaders(store: StoreName): string[] {
  switch (store) {
    case 'env':
      return ['이 파일은 암호화되지 않습니다.', 'Hermes가 도는 컴퓨터에서 Hermes를 돌리는 사용자 계정만 읽을 수 있게 저장하고, Hermes 안의 AI 모델도 그 계정으로 명령을 실행하면 이 파일을 읽을 수 있습니다.']
    case 'hermes_vault':
      // The id is item metadata Hermes lists to the AI model (hermes-agent tools/browser_vault_tool.py, list).
      return [
        '암호화해 저장합니다.',
        'Hermes가 도는 컴퓨터에서 Hermes를 돌리는 사용자 계정의 프로그램은 풀어 읽을 수 있습니다.',
        'Hermes 안의 AI 모델은 비밀번호와 인증 앱 설정 키를 건네받지 않지만, 그 계정으로 명령을 실행하면 풀어 읽을 수 있습니다. 이메일, 사용자 이름, 전화번호 중 어느 것을 넣든 그 값은 저장한 뒤 AI 모델이 볼 수 있습니다.',
      ]
    case 'keychain':
      return ['Hermes가 도는 컴퓨터에서 Hermes를 돌리는 사용자 계정의 프로그램만 이 값을 읽을 수 있고, Hermes 안의 AI 모델도 그 계정으로 명령을 실행하면 이 값을 읽을 수 있습니다.']
  }
}

/** Sentences that hold for the whole request, shown above the storage list. */
export function pageNotes(open: OpenResponse): string[] {
  const agent = open.requester.type === 'agent'
  switch (open.kind) {
    case 'api_key':
      return [
        '이 페이지는 키 값을 Hermes 안의 AI 모델에게 보내지 않습니다.',
        // A user command's result goes back to the user, never to the AI model, so only a Hermes request says this.
        ...(agent ? ['AI 모델은 저장 위치마다 저장했는지를 받고, 사용자가 처음 상태에서 바꿔 끄거나 켠 저장 위치도 받습니다.'] : []),
      ]
    case 'secret':
      return [
        '이 페이지는 비밀번호를 Hermes 안의 AI 모델에게 보내지 않습니다.',
        // Security review 3 R3-5: an allow-list item's account stays on this page; the plugin's own fixed one does not.
        ...(agent
          ? [
              open.target.keychain?.listed === true
                ? 'AI 모델은 저장 결과와 키체인 항목 이름만 받습니다. 키체인 계정 이름은 받지 않습니다.'
                : 'AI 모델은 저장 결과와 키체인 항목 이름, 이 플러그인이 정한 키체인 계정 이름만 받습니다.',
            ]
          : []),
      ]
    default:
      return []
  }
}

export type Destination = {
  /** Short title of the last route step. */
  title: string
  /** The literal name the user should recognise, set large. Null for one-time codes. */
  ident: string | null
  identCaption: string | null
  /** Sentences shown right under the caption (what happens to an entry that already exists). */
  identNotes: string[]
  /** How Hermes will use the value. */
  use: string
  /** Sentences shown under `use`: how the value is kept and where it never appears. */
  notes: string[]
}

/** The last route step for a one-time code (unchanged since protocol 1: a code is never stored). */
export function destination(open: OpenResponse): Destination {
  const t = open.target
  return {
    title: `${t.site ?? ''} 로그인 화면에 한 번 입력`,
    ident: null,
    identCaption: null,
    identNotes: [],
    use: `Hermes가 지금 진행 중인 ${t.site ?? ''} 로그인 화면에 한 번 입력하고 버립니다.`,
    notes: ['이 페이지는 코드를 Hermes 안의 AI 모델에게 보내지 않습니다.'],
  }
}

export const NOT_STORED = '일회용 코드는 어디에도 저장하지 않습니다.'

export const ROUTE = {
  heading: '보낸 값이 가는 길',
  encrypt: {
    title: '이 기기에서 암호화',
    body: ['보내기 전에 이 기기에서 값을 암호화합니다.', 'Hermes가 도는 컴퓨터만 풀 수 있습니다.'],
  },
  transfer: {
    title: 'Hermes가 도는 컴퓨터로 바로 전송',
    body: ['값은 Slack을 거치지 않습니다.'],
  },
  /** One-time codes are not stored, so their Slack line says delivered, not saved. */
  slackNote: (kind: Kind) =>
    kind === 'otp_code' ? 'Slack 대화에는 전달 결과만 표시됩니다.' : 'Slack 대화에는 저장 결과만 표시됩니다.',
}

export const FORM = {
  heading: '입력',
  profileLabel: '저장할 프로필',
  /**
   * What a profile is. Which profile each store reaches, and that the Mac keychain is shared by the whole
   * Mac, is said once, on the store's own row (scopeText), and that row follows this select.
   */
  profileHelp: ['프로필은 Hermes 안에서 설정과 저장소를 따로 쓰는 작업 공간입니다.'],
  /**
   * Shown under the profile select only when the chosen profile is not the requester's. One fact per sentence.
   * `agent` is true when Hermes asked during a task: that tool call then gets back only a saved result naming
   * the chosen profile (secure_input/plugin.py, result()). A user command has no task waiting on the value.
   */
  profileMismatch: (requested: string, chosen: string, agent: boolean): string | null =>
    requested && chosen && requested !== chosen
      ? [
          `요청한 쪽은 ${requested} 프로필입니다.`,
          `${chosen} 프로필에 저장하면 ${requested} 프로필의 Hermes는 이 값을 쓰지 못합니다.`,
          agent
            ? `요청한 작업에 쓰려면 ${requested} 프로필을 고르세요.`
            : `${requested} 프로필에서 쓰려면 ${requested} 프로필을 고르세요.`,
          ...(agent ? [`그대로 보내면 요청한 AI 모델은 ${chosen} 프로필에 저장했다는 결과만 받습니다.`] : []),
        ].join(' ')
      : null,
  profileFixed: (p: string) => `${p} (이 요청에서는 바꿀 수 없습니다)`,
  apiKeyLabel: 'API 키',
  apiKeyHelp: '서비스 관리 화면에서 발급받은 키를 그대로 붙여 넣으세요. 예: 3f9a0c2e71b44d0e9a58c1d27b6e0f4a',
  idTypeLegend: '아이디 종류',
  idTypeHelp: '로그인할 때 쓰는 아이디의 형태를 고르세요. 아래 칸의 이름과 예시만 바뀌고, 자동 입력 방식은 같습니다.',
  idTypes: { email: '이메일', username: '사용자 이름', phone: '전화번호' },
  idLabel: { email: '이메일 주소', username: '사용자 이름', phone: '전화번호' },
  idHelp: {
    email: '예: admin@example.com',
    username: '예: shop_admin',
    phone: '예: 010-1234-5678',
  },
  passwordLabel: '비밀번호',
  passwordHelp: '입력한 그대로 저장합니다. 앞뒤 공백도 지우지 않습니다.',
  secretLabel: '비밀번호',
  secretHelp: '영문 대소문자, 숫자, 영문 자판의 기호와 공백으로 된 1,024자 이하만 받습니다. 맨 앞이나 맨 뒤에 공백이 있으면 보낼 수 없습니다.',
  secretConfirmLabel: '비밀번호 다시 입력',
  secretConfirmHelp: '이 값은 보낸 뒤에 맞게 입력했는지 확인할 방법이 없어서, 같은 값을 한 번 더 받아 두 칸을 비교합니다.',
  otpSecretToggle: '인증 앱 설정 키 추가(선택)',
  otpSecretLabel: '인증 앱 설정 키(선택)',
  otpSecretWhat: '인증 앱에 계정을 등록할 때 사이트가 보여 주는 영문 키입니다. 예: JBSWY3DPEHPK3PXP',
  // With a saved key, Hermes' enter_code mints the code itself and asks nobody
  // (hermes-agent tools/browser_vault_tool.py browser_vault_enter_code, tools/browser_vault_context.py write_backend_code).
  otpSecretUse: ['로그인 때 사이트가 6자리 코드를 물으면 Hermes가 이 키로 코드를 만들어 입력합니다.', '그때는 코드 입력 요청이 따로 오지 않습니다.'],
  /**
   * Fix 2 of the last reader test: shown next to the toggle whether or not the section is open, because the
   * older item is removed whole, its setup key included, even when this section is never opened
   * (secure_input/storage.py add_login).
   */
  otpSecretLoss: [
    '저장할 프로필에 같은 사이트 주소와 이번과 같은 이메일 주소, 사용자 이름 또는 전화번호로 저장해 둔 로그인이 있으면, 이번에 설정 키를 넣지 않고 보내도 그 로그인의 인증 앱 설정 키가 함께 지워집니다.',
    '그 설정 키를 계속 쓰려면 위의 인증 앱 설정 키 추가(선택)를 눌러 이번에도 넣으세요.',
  ],
  otpLabel: '일회용 코드',
  otpHelp: '문자나 인증 앱에 표시된 코드를 입력하세요. 예: 123456',
  otpHelpExpiry: '코드는 사이트에서 금방 만료되니 받은 즉시 보내세요.',
  show: '보이기',
  hide: '가리기',
  submit: '암호화해서 보내기',
  sending: '암호화해서 보내는 중…',
  /** Button text while a saved kind is being stored (the A.12 line is shown above the button). */
  saving: '저장 중…',
  savingNext: '남은 시간은 저장 중에도 줄지만, 다 지나도 저장은 멈추지 않고 끝나면 이 화면이 결과로 바뀝니다.',
  afterSubmit: '이 링크는 한 번만 열립니다. 이 창을 닫거나 새로 고치면 다시 열 수 없습니다.',
  timeoutNote: '남은 시간이 끝나면 입력한 값을 지우고, 이 링크는 더 쓸 수 없게 됩니다.',
  cancel: '요청 취소',
  cancelConfirm: '요청을 취소할까요? 이 링크는 다시 열 수 없습니다.',
  cancelYes: '요청 취소하기',
  cancelNo: '계속 입력하기',
  retryable: '다시 보낼 수 있습니다.',
  networkError: 'Hermes 컴퓨터에 연결하지 못했습니다. 연결을 확인하고 다시 보내세요.',
  genericError: '보내지 못했습니다.',
}

/** Text of the alert after a retryable store failure (A.8). Each line names a store and says why. */
export type StoreAlert = { title: string; lines: string[]; next: string[] }

/** The last line of both retryable alerts: about the fields of this form, not about a store. */
const VALUE_KEPT = '입력한 값은 입력 칸에 그대로 있습니다.'

/** 422 store_unavailable: nothing was written anywhere (plan 5.2). */
export function storeUnavailableAlert(open: OpenResponse, stores: UnavailableStore[]): StoreAlert {
  const fixed = (s: StoreName) => open.target.stores.find((r) => r.store === s)?.fixed ?? false
  const allFixed = stores.length > 0 && stores.every((s) => fixed(s.store))
  return {
    title: '아무 데도 저장하지 않았습니다',
    lines: [
      '켠 저장 위치 가운데 지금 쓸 수 없는 곳이 있어서, 어디에도 쓰지 않았습니다.',
      ...stores.map((s) => `${STORE_NAME[s.store]}: ${plainText(reasonText(s.reason))}`),
    ],
    next: allFixed
      ? ['지금은 저장할 수 없습니다.', '원인을 고친 뒤 다시 보내세요.', VALUE_KEPT]
      : ['그 저장 위치를 끄고 이 화면에서 다시 보내면 나머지 저장 위치에만 저장합니다.', VALUE_KEPT],
  }
}

/** A keychain line whose main item was written before the save failed (A.13, main_touched). */
export const MAIN_TOUCHED = '이 항목에 새 값을 쓰기 시작했으므로, 있던 예전 값이 바뀌었을 수 있습니다.'

/** A keychain line whose main write ran on an item that was not there before, and the save failed (RC-1, main_created). */
export const MAIN_CREATED = '이 이름의 키체인 항목이 새로 만들어졌고, 이번에 넣은 값이 들어 있을 수 있습니다.'

/** A keychain line that did not save but whose main write ran: main_created (RC-1). */
export function mainCreated(r: StoreResult): boolean {
  return r.store === 'keychain' && r.saved === false && r.main_created === true
}

/**
 * A temporary keychain item may still hold the value sent (R3-3): the store left it behind (`tmp_left`), or it
 * stopped at its time limit or without a result, which can be during the temporary step. Same words as the Slack message.
 */
export const TMP_LEFT =
  "임시 키체인 항목에 이번에 넣은 값이 남아 있을 수 있습니다. Hermes가 도는 컴퓨터에서 README의 '남은 임시 키체인 항목' 절의 명령으로 확인해 지우세요."

export function tmpMayBeLeft(r: StoreResult): boolean {
  return r.store === 'keychain' && (r.tmp_left === true || r.error === 'store_timeout' || r.error === 'no_result')
}

/**
 * 422 storage_failed with result_unknown false: no store saved, and the page knows it (A.8). Right under a keychain
 * line, in the order of the Slack message: its item was written before the failure (R3-2), the write made the item
 * (RC-1), a temporary item may hold the value (RC-3). The last line is about the fields of this form, not about the
 * keychain item, and says so.
 */
export function storageFailedAlert(stores: StoreResult[], serverMessage?: string): StoreAlert {
  return {
    title: '값을 저장하지 못했습니다',
    lines: stores.length
      ? stores.flatMap((s) => [
          `${STORE_NAME[s.store]}: ${plainText(reasonText(s.error))}`,
          ...(s.main_touched === true ? [MAIN_TOUCHED] : []),
          ...(mainCreated(s) ? [MAIN_CREATED] : []),
          ...(tmpMayBeLeft(s) ? [TMP_LEFT] : []),
        ])
      : serverMessage
        ? [serverMessage]
        : [],
    next: [FORM.retryable, VALUE_KEPT],
  }
}

export const TIMER = {
  label: '남은 시간',
  spoken: (m: number, s: number) => `남은 시간 ${m}분 ${s}초`,
  oneMinute: '남은 시간이 1분입니다.',
}

/** One store's line on the done screen. */
export type DoneStore = {
  store: StoreName
  name: string
  status: 'saved' | 'failed' | 'unknown'
  statusText: string
  idents: { term: string; value: string }[]
  notes: string[]
}

export type DoneText = {
  heading: string
  rows: { term: string; value: string; ident?: boolean }[]
  /** Per-store results (protocol 2). Empty for one-time codes. */
  stores?: DoneStore[]
  /** True when some turned-on store did not save (A.8 `partial`). */
  partial?: boolean
  lines: string[]
}

function doneStore(r: StoreResult, open: OpenResponse, chosenProfile: string): DoneStore {
  const name = STORE_NAME[r.store]
  const status = r.saved === true ? 'saved' : r.saved === false ? 'failed' : 'unknown'
  // A keychain item that held a value before the send keeps it when no write reached it
  // (main_touched false: secure_input/stores/keychain.py sets it just before the main write).
  const keptOld =
    r.store === 'keychain' &&
    r.main_touched === false &&
    open.target.stores.some((row) => row.store === 'keychain' && row.exists === true)
  const statusText =
    status === 'saved'
      ? r.replaced
        ? '예전 값을 바꿔 저장했습니다.'
        : '저장했습니다.'
      : status === 'failed'
        ? keptOld
          ? '저장하지 못했고, 예전 값은 그대로입니다.'
          : '저장하지 못했습니다.'
        : '저장했는지 확인하지 못했습니다.'
  const profile = r.profile || chosenProfile
  const idents: DoneStore['idents'] = []
  const notes: string[] = []
  if (r.store === 'env') {
    idents.push({ term: '프로필', value: profile })
    idents.push({ term: '변수 이름', value: r.env_var || open.target.env_var || '' })
  } else if (r.store === 'hermes_vault') {
    idents.push({ term: '프로필', value: profile })
    idents.push({ term: '사이트 주소', value: r.origin || open.target.origin || '' })
  } else {
    const kc = open.target.keychain
    idents.push({ term: '키체인 항목 이름', value: r.service || kc?.service || '' })
    idents.push({ term: '키체인 계정 이름', value: r.account || kc?.account || '' })
    if (status === 'saved' && r.new_item) notes.push(A12.newItem)
    // The item may hold a new value although the read-back failed (A.4 keychain_verify_failed, A.13).
    if (status !== 'saved' && r.main_touched) notes.push(MAIN_TOUCHED)
    if (mainCreated(r)) notes.push(MAIN_CREATED)
    if (tmpMayBeLeft(r)) notes.push(TMP_LEFT)
  }
  // keychain_write_failed only repeats the status line ("저장하지 못했습니다."), so it gets no cause line.
  if (status !== 'saved' && r.error !== 'keychain_write_failed') notes.unshift(plainText(reasonText(r.error)))
  return { store: r.store, name, status, statusText, idents, notes }
}

/**
 * RC2-1: what an earlier answer of this page said a failed save left in the keychain, on the done screen. A keychain
 * line of this answer that saved drops the old value and the made item (the item now holds the value reported as
 * saved; the server does the same, secure_input/server.py `_note_keychain_left`). A fact a store line of this answer
 * already says is not said twice.
 */
function doneLeftLines(rows: StoreResult[], f: EndFacts, storedInKeychain: boolean): string[] {
  const kc = rows.filter((r) => r.store === 'keychain')
  const kcSaved = storedInKeychain || kc.some((r) => r.saved === true)
  return keychainLeftLines(
    {
      touched: f.touched && !kcSaved && !kc.some((r) => r.saved !== true && r.main_touched === true),
      created: f.created && !kcSaved && !kc.some(mainCreated),
      tmpLeft: f.tmpLeft && !kc.some(tmpMayBeLeft),
    },
    RESULT_MESSAGE,
  )
}

/**
 * `withOtpSecret` says whether the user sent an authenticator setup key with a login. The done screen
 * keeps only that yes or no, never the key. `facts`: what the earlier answers of this page said about the keychain
 * (`touched`, `created`, `tmpLeft`, RC2-1).
 */
export function doneText(open: OpenResponse, result: SubmitResult, chosenProfile: string, withOtpSecret = false, facts: EndFacts = {}): DoneText {
  const s = result.storage
  const label = result.label || open.label
  const profile = s.profile || chosenProfile
  const left = open.kind === 'otp_code' ? [] : doneLeftLines(result.stores ?? [], facts, s.type === 'keychain')
  if (result.stores && result.stores.length && open.kind !== 'otp_code') {
    const stores = result.stores.map((r) => doneStore(r, open, chosenProfile))
    const partial = result.partial === true || stores.some((x) => x.status !== 'saved')
    const envSaved = stores.some((x) => x.store === 'env' && x.status === 'saved')
    const keychainSaved = stores.some((x) => x.store === 'keychain' && x.status === 'saved')
    const lines: string[] = []
    if (open.kind === 'login') {
      lines.push('아이디와 비밀번호를 한 항목으로 저장했습니다.')
      if (withOtpSecret) lines.push('인증 앱 설정 키도 같은 항목에 저장했습니다.')
      lines.push('비밀번호는 화면에 다시 보여 주지 않습니다.')
    } else {
      lines.push(open.kind === 'secret' ? '비밀번호는 화면에 다시 보여 주지 않습니다.' : '값은 화면에 다시 보여 주지 않습니다.')
    }
    if (open.kind === 'api_key' && !envSaved && keychainSaved) {
      lines.push('Hermes는 이 키를 .env에서 읽습니다. 이번에는 .env에 저장하지 않았으므로 Hermes가 이번에 넣은 키를 쓰지 못합니다.')
    }
    if (partial) {
      lines.push(`저장하지 못한 곳에만 다시 넣으려면 ${newLink(open.requester)}`)
    }
    return {
      heading: partial ? '일부만 저장했습니다' : '저장했습니다',
      rows: [{ term: '입력한 항목', value: label }],
      stores,
      partial,
      lines: [...lines, ...left, ...doneCommon(open.kind, open.requester)],
    }
  }
  if (s.type === 'env') {
    return {
      heading: '저장했습니다',
      rows: [
        { term: '저장한 항목', value: label },
        { term: '저장한 곳', value: `${profile} 프로필의 ${ENV_FILE}` },
        { term: '변수 이름', value: s.env_var || open.target.env_var || '', ident: true },
      ],
      lines: ['값은 화면에 다시 보여 주지 않습니다.', ...left, ...doneCommon(open.kind, open.requester)],
    }
  }
  if (s.type === 'vault') {
    return {
      heading: '저장했습니다',
      rows: [
        { term: '저장한 항목', value: label },
        { term: '저장한 곳', value: `${profile} 프로필의 ${VAULT}` },
        { term: '사이트 주소', value: s.origin || open.target.origin || '', ident: true },
      ],
      lines: [
        '아이디와 비밀번호를 한 항목으로 저장했습니다.',
        ...(withOtpSecret ? ['인증 앱 설정 키도 같은 항목에 저장했습니다.'] : []),
        '비밀번호는 화면에 다시 보여 주지 않습니다.',
        ...left,
        ...doneCommon(open.kind, open.requester),
      ],
    }
  }
  if (s.type === 'keychain') {
    return {
      heading: '저장했습니다',
      rows: [
        { term: '저장한 항목', value: label },
        { term: '저장한 곳', value: KEYCHAIN },
        { term: '키체인 항목 이름', value: s.service || open.target.keychain?.service || '', ident: true },
      ],
      lines: ['값은 화면에 다시 보여 주지 않습니다.', ...left, ...doneCommon(open.kind, open.requester)],
    }
  }
  return {
    heading: '전달했습니다',
    rows: [
      { term: '전달한 항목', value: label },
      { term: '전달한 곳', value: `${open.target.site || s.origin || ''} 로그인 화면` },
    ],
    lines: [
      '코드를 Hermes에 넘겼습니다.',
      'Hermes가 곧바로 로그인 화면에 입력합니다.',
      '로그인이 됐는지, 코드가 틀렸는지는 이 화면에 나오지 않습니다. Slack 대화에서 확인하세요.',
      NOT_STORED,
      ...doneCommon(open.kind, open.requester),
    ],
  }
}

/** `r` is the requester: a Hermes request's tool call gets the save result back (secure_input/plugin.py, result()). */
export function doneCommon(kind: Kind, r?: Requester): string[] {
  return [
    '입력한 값은 이 브라우저 화면에서 지웠습니다.',
    kind === 'otp_code'
      ? 'Slack 대화에도 전달 결과가 표시됩니다.'
      : r?.type === 'agent'
        ? '저장 결과는 Hermes 안의 AI 모델과 Slack 대화에도 전달됩니다.'
        : 'Slack 대화에도 저장 결과가 표시됩니다.',
    '이 창을 닫아도 됩니다.',
  ]
}

/**
 * How to get a new link. A screen that knows who asked (the page had opened the request) uses
 * newLink(requester); a screen reached without an opened request uses NEW_LINK.
 */
export const NEW_LINK = '링크를 받은 Slack 대화에서 다시 요청하세요.'
export const NEW_LINK_AGENT = '링크를 받은 Slack 대화에서 Hermes에게 다시 요청하세요.'
export const NEW_LINK_USER = '링크를 띄울 때 보낸 명령을 같은 대화에 다시 보내세요.'

export function newLink(r?: Requester): string {
  if (!r) return NEW_LINK
  return r.type === 'agent' ? NEW_LINK_AGENT : NEW_LINK_USER
}

export const END_HEADING: Record<EndReason, string> = {
  already_opened: '이미 열린 링크입니다',
  expired: '열 수 있는 시간이 지났습니다',
  deadline_passed: '제출 시간이 지났습니다',
  cancelled: '요청을 취소했습니다',
  too_many_attempts: '시도 횟수를 넘었습니다',
  already_submitted: '이미 제출한 링크입니다',
  unusable: '이 링크를 더 쓸 수 없습니다',
  unreachable: 'Hermes 컴퓨터에 연결하지 못했습니다',
  identity_denied: '이 기기의 Tailscale 계정으로는 열 수 없습니다',
  result_unknown: '저장했는지 알 수 없습니다',
}

/**
 * What the page saw before it ended, for the end screens that depend on it.
 * `sent`: cancelled: a submit of this page got an answer from the server. deadline_passed: a value this page sent
 *   was refused or not saved and could be sent again (a 422 store_unavailable, masked_value, or storage_failed
 *   that is not result unknown), which is when the server ends the request `window_passed_after_failed_save`
 *   (secure_input/lifecycle.py, RC-2).
 * `touched`: one of those answers had a keychain line with `main_touched` true.
 * `created`: one of those answers had a keychain line that did not save with `main_created` true (RC-1).
 * `code`: the request is for a one-time code, which is delivered, not saved (cancelled).
 * `tmpLeft`: an answer had a keychain line for which tmpMayBeLeft holds (RC-3).
 * `touched`, `created` and `tmpLeft` show on the cancelled, deadline_passed, too_many_attempts and result_unknown
 * screens and on the done screen (doneText; RC2-1, RC2-3).
 */
export type EndFacts = { sent?: boolean; touched?: boolean; created?: boolean; code?: boolean; tmpLeft?: boolean }

/** The pointer at the Slack result message, which repeats a keychain sentence with the item's name. */
const RESULT_MESSAGE = 'Slack 대화의 결과 메시지를 확인하세요.'

/**
 * What a failed save may have left in the keychain, in the order of the Slack message (secure_input/notify.py
 * result_text). `where` names the Slack message that repeats it with the item's name: the server keeps the same
 * three facts for the whole request and puts them in that message (RC2-1, `keychain_left`).
 */
function keychainLeftLines(f: EndFacts, where: string): string[] {
  return [
    ...(f.touched ? [`보낸 값을 키체인 항목에 쓰기 시작했으므로, 그 항목에 있던 예전 값이 바뀌었을 수 있습니다. ${where}`] : []),
    ...(f.created ? [`보낸 값을 쓰려던 키체인 항목이 새로 만들어졌고, 이번에 넣은 값이 들어 있을 수 있습니다. ${where}`] : []),
    ...(f.tmpLeft ? [TMP_LEFT] : []),
  ]
}

/**
 * The first lines of the cancelled screen (R3-2). The Slack cancel message says something about the value only
 * when a keychain item was touched or made (secure_input/notify.py result_text, _touched), so only then does this
 * point there.
 */
function cancelledLines(f: EndFacts): string[] {
  if (!f.sent && !f.touched) return ['아무 값도 보내지 않았습니다.']
  if (f.code) return ['보낸 코드는 로그인 화면에 전달하지 못했습니다.']
  return ['보낸 값은 저장하지 못했습니다.', ...keychainLeftLines(f, 'Slack 대화의 취소 결과 메시지를 확인하세요.')]
}

/** The first lines of the submit time passed screen (RC-2): what happened to a value the page had sent. */
function deadlineLines(f: EndFacts): string[] {
  if (!f.sent) return ['값은 링크를 연 뒤 5분 안에 보내야 합니다.', '입력한 값은 지웠고 보내지 않았습니다.']
  return [
    '앞서 보낸 값은 저장하지 못했고, 다시 보내지 않은 채 제출 시간이 지났습니다.',
    '입력 칸에 남아 있던 값은 지웠습니다.',
    ...keychainLeftLines(f, RESULT_MESSAGE),
  ]
}

/**
 * Heading and lines of an end screen. `r` is the requester when the page had opened the request before
 * it ended. Already opened, expired and unreachable are reached without an opened request, so they
 * always use NEW_LINK.
 */
export function endText(reason: EndReason, r?: Requester, facts: EndFacts = {}): { heading: string; lines: string[] } {
  const heading = END_HEADING[reason]
  switch (reason) {
    case 'already_opened':
      return {
        heading,
        lines: [
          '이 링크는 한 번만 열 수 있고, 이미 한 번 열렸습니다.',
          '지금 이 창에서는 값을 넣을 수 없습니다.',
          '먼저 연 창이 남아 있으면 그 창에서 계속 입력하세요.',
          `그 창을 닫았거나 새로 고쳤다면 새 링크가 필요합니다. ${NEW_LINK}`,
          `직접 연 적이 없다면 다른 사람이 열었을 수 있습니다. 이 경우 값을 넣지 말고, ${NEW_LINK}`,
        ],
      }
    case 'expired':
      return { heading, lines: ['링크는 만든 뒤 60초 안에 열어야 합니다.', NEW_LINK] }
    case 'deadline_passed':
      return {
        heading,
        lines: [
          ...deadlineLines(facts),
          // The Slack link message is edited to the expiry result (secure_input/plugin.py finish(),
          // secure_input/notify.py result_text()).
          'Slack 대화에도 시간이 지났다는 결과가 표시됩니다.',
          // The requesting tool call returns status "expired" (secure_input/plugin.py, result()).
          ...(r?.type === 'agent' ? ['요청한 AI 모델에도 시간이 지났다고 전달됩니다.'] : []),
          newLink(r),
        ],
      }
    case 'cancelled':
      return {
        heading,
        lines: [
          ...cancelledLines(facts),
          'Slack 대화에도 취소 결과가 표시됩니다.',
          // The requesting tool call returns status "cancelled" (secure_input/plugin.py, result()).
          ...(r?.type === 'agent' ? ['요청한 AI 모델에도 취소했다고 전달됩니다.'] : []),
          `나중에 다시 넣으려면 ${newLink(r)}`,
          '이 창을 닫아도 됩니다.',
        ],
      }
    case 'too_many_attempts':
      return {
        heading,
        // RC2-3: what the failed sends left in the keychain; the Slack failure message says it too (RC2-1).
        lines: ['보안을 위해 이 링크를 닫았습니다.', '입력한 값은 지웠습니다.', ...keychainLeftLines(facts, RESULT_MESSAGE), newLink(r)],
      }
    case 'already_submitted':
      return { heading, lines: ['이 링크로는 더 보낼 수 없습니다.', '저장 결과는 Slack 대화에서 확인하세요.'] }
    case 'unusable':
      return { heading, lines: ['입력한 값은 지웠습니다.', newLink(r)] }
    case 'unreachable':
      return { heading, lines: ['Tailscale 연결을 확인하세요.', '연결한 뒤에도 안 되면 새 링크가 필요합니다.', NEW_LINK] }
    // api/open answered 403 identity_required or identity_not_allowed. The identity check runs before the
    // link is consumed, so the link stays unused and its 60 s open window keeps running (secure_input/server.py).
    // After those 60 s the link expires (state expired, detail open_window_passed) and only a new link works.
    case 'identity_denied':
      return {
        heading,
        lines: [
          '이 링크는 Hermes 컴퓨터에 허용된 Tailscale 계정으로 로그인한 기기에서만 열 수 있습니다.',
          '이 기기에서 열려고 한 것은 링크를 연 것으로 치지 않았습니다. 그래서 이 링크는 아직 한 번 열 수 있습니다.',
          '허용된 계정의 기기에서 링크를 만든 뒤 60초 안에 여세요. 60초가 지나면 링크가 만료되고, 그때는 링크를 받은 Slack 대화에서 새 링크를 요청해야 합니다.',
          '본인 기기에서 이 화면이 나왔다면 이 기기의 Tailscale 앱이 어느 계정으로 로그인되어 있는지 확인하세요.',
        ],
      }
    // Saving had started (the button was pressed) and the page lost the answer, or the server said
    // result_unknown (A.8). The page offers no resubmit: the server may still be writing.
    case 'result_unknown':
      return {
        heading,
        lines: [
          A12.resultUnknown,
          '값이 저장됐을 수도 있고 저장되지 않았을 수도 있습니다.',
          // Only a 422 storage_failed with result_unknown carries store lines; a lost reply or 410 has none. The
          // facts are also those of the earlier answers of this page (RC2-1); the temporary item sentence comes once.
          ...keychainLeftLines(facts, RESULT_MESSAGE),
          '이 화면에서는 다시 보낼 수 없습니다.',
          '입력한 값은 이 브라우저 화면에서 지웠습니다.',
          `저장되지 않았다고 나오면 ${newLink(r)}`,
        ],
      }
  }
}

export const OPENING = '요청 내용을 불러오는 중…'

/** Text under the form after a retryable or unknown submit error: the server's own sentence when it
 * sent one (e.g. `masked_value`), otherwise the generic line (with the code only for unknown codes). */
export function formErrorText(code: string, serverMessage?: string): string {
  if (serverMessage) return serverMessage
  return RETRYABLE.has(code) ? FORM.genericError : `${FORM.genericError} (${code})`
}

export function endReasonFor(code: string): EndReason {
  switch (code) {
    case 'already_opened':
    case 'expired':
    case 'deadline_passed':
    case 'too_many_attempts':
    case 'already_submitted':
      return code
    case 'identity_required':
    case 'identity_not_allowed':
      return 'identity_denied'
    // A second submit or a cancel while the first submit is still being saved (A.3): this page has
    // lost track of that first submit, so it cannot say how it ended.
    case 'saving_in_progress':
      return 'result_unknown'
    default:
      return 'unusable'
  }
}
