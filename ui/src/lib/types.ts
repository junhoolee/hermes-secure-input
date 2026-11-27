// Shapes from protocol version 2 (docs/plans/storage-targets-plan.md, appendix A.6-A.8).
// Field names must match the server exactly.

export type Kind = 'api_key' | 'login' | 'otp_code' | 'secret'
export type IdentifierType = 'email' | 'username' | 'phone'

/** Store names in STORE_NAMES order (A.1): the row order on screen and the order the server writes in. */
export const STORE_NAMES = ['env', 'hermes_vault', 'keychain'] as const
export type StoreName = (typeof STORE_NAMES)[number]

/** One row of target.stores in api/open (A.6). */
export type StoreRow = {
  store: StoreName
  selected: boolean
  fixed: boolean
  by: 'agent' | 'history' | 'default' | null
  reason: string | null
  needed: boolean
  scope: 'profile' | 'mac'
  ident: string | null
  available: boolean
  unavailable_reason: string | null
  exists: boolean | null
}

/** target.keychain in api/open (A.6). Present only when target.stores has a keychain row. */
export type KeychainTarget = {
  id: string | null
  service: string | null
  account: string | null
  listed: boolean
  new_item: boolean
  label: string | null
  used_by: string | null
}

export type OpenResponse = {
  v: 2
  request_id: string
  kind: Kind
  purpose: string
  label: string
  requester: { type: 'agent' | 'user'; profile: string }
  target: {
    profile: string
    profiles: string[]
    profile_editable: boolean
    env_var: string | null
    origin: string | null
    site: string | null
    /** Every store the kind can use, in STORE_NAMES order. Empty for otp_code. */
    stores: StoreRow[]
    keychain?: KeychainTarget
  }
  server_public_key: string
  sid: string
  submit_deadline_s: number
  opened_at: string
}

/** One store result line (A.8). Fields beyond the common four depend on the store. */
export type StoreResult = {
  store: StoreName
  saved: boolean | null
  replaced: boolean | null
  error: string | null
  env_var?: string
  profile?: string
  origin?: string
  item_id?: string
  service?: string
  account?: string
  listed?: boolean
  new_item?: boolean
  tmp_left?: boolean | null
  main_touched?: boolean | null
  /** Keychain: the main write ran on an item that was not there before (RC-1). */
  main_created?: boolean | null
}

export type SubmitResult = {
  status: 'saved' | 'delivered'
  /** Saved kinds only (A.8): true when at least one store saved and another did not. */
  partial?: boolean
  /** Saved kinds only (A.8): the stores turned on for this submit, in STORE_NAMES order. */
  stores?: StoreResult[]
  storage: {
    type: 'vault' | 'env' | 'keychain' | 'browser_page'
    profile?: string
    origin?: string
    env_var?: string
    item_id?: string | null
    service?: string
    account?: string
  }
  label: string
}

export type Plaintext =
  | { kind: 'api_key'; target_profile: string; value: string; stores: StoreName[] }
  | {
      kind: 'login'
      target_profile: string
      identifier_type: IdentifierType
      identifier: string
      password: string
      otp_secret: string
      stores: StoreName[]
    }
  | { kind: 'secret'; target_profile: string; value: string; stores: StoreName[] }
  | { kind: 'otp_code'; code: string }

/** Error codes after which the same page may submit again (new key pair, new iv). */
export const RETRYABLE = new Set(['decrypt_failed', 'invalid_payload', 'storage_failed', 'masked_value', 'store_unavailable'])

/** One entry of the 422 store_unavailable reply (A.8). */
export type UnavailableStore = { store: StoreName; reason: string }

export type EndReason =
  | 'already_opened'
  | 'expired'
  | 'deadline_passed'
  | 'cancelled'
  | 'too_many_attempts'
  | 'already_submitted'
  | 'unusable'
  | 'unreachable'
  | 'identity_denied'
  /** Saving started but the page cannot tell how it ended: the reply was lost, or the server said result_unknown. */
  | 'result_unknown'
