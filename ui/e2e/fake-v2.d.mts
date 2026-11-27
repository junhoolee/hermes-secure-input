// Types for fake-v2.mjs (the module is plain JavaScript so e2e/server.mjs can run it under node).

export type ScenarioBody = {
  kind: 'api_key' | 'login' | 'otp_code' | 'secret'
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
    stores: {
      store: 'env' | 'hermes_vault' | 'keychain'
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
    }[]
    keychain?: {
      id: string | null
      service: string | null
      account: string | null
      listed: boolean
      new_item: boolean
      label: string | null
      used_by: string | null
    }
  }
}

export type ScenarioName = 'A' | 'A2' | 'B' | 'C' | 'D' | 'D2' | 'D3'
export const SCENARIOS: Record<ScenarioName, ScenarioBody>
export function savedLine(s: ScenarioBody, store: string, profile: string): Record<string, unknown>
export function storageFor(s: ScenarioBody, lines: Record<string, unknown>[]): Record<string, unknown>
export function successFor(
  s: ScenarioBody,
  stores: string[],
  profile: string,
  lines?: Record<string, Record<string, unknown>>,
): { ok: true; result: Record<string, unknown> }
