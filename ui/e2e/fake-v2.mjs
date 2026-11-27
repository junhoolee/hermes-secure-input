// Protocol 2 reply shapes for the fake servers (plan appendix A.6 and A.8), shared by the screen-test
// mock (e2e/harness.ts) and the static test server (e2e/server.mjs). Scenario bodies live in fixtures.json.

import { readFileSync } from 'node:fs'

export const SCENARIOS = JSON.parse(readFileSync(new URL('./fixtures.json', import.meta.url), 'utf8'))

const ORDER = ['env', 'hermes_vault', 'keychain']

/** One store result line (A.8) for a store that saved. */
export function savedLine(s, store, profile) {
  const t = s.target
  const row = t.stores.find((r) => r.store === store)
  if (store === 'env') {
    return { store, saved: true, replaced: row?.exists === true, error: null, env_var: t.env_var, profile }
  }
  if (store === 'hermes_vault') {
    return { store, saved: true, replaced: false, error: null, origin: t.origin, item_id: 'item_01', profile }
  }
  return {
    store,
    saved: true,
    replaced: row?.exists === true,
    error: null,
    service: t.keychain?.service ?? null,
    account: t.keychain?.account ?? null,
    listed: t.keychain?.listed ?? false,
    new_item: t.keychain?.new_item ?? false,
    tmp_left: false,
    main_touched: true,
  }
}

/** The `storage` object (A.8, plan 5.3): the first saved store in env, hermes_vault, keychain order. */
export function storageFor(s, lines) {
  const first = ORDER.map((n) => lines.find((l) => l.store === n && l.saved === true)).find(Boolean)
  if (!first) return { type: 'env' }
  if (first.store === 'env') return { type: 'env', env_var: first.env_var, profile: first.profile, origin: null, item_id: null }
  if (first.store === 'hermes_vault') return { type: 'vault', profile: first.profile, origin: first.origin, item_id: first.item_id }
  return { type: 'keychain', service: first.service, account: first.account, origin: null, item_id: null }
}

/**
 * The 200 reply of api/submit for a scenario (A.8). `stores` are the names the page turned on; `lines`
 * may replace individual result lines (for a partial save).
 */
export function successFor(s, stores, profile, lines = {}) {
  if (s.kind === 'otp_code') {
    return { ok: true, result: { status: 'delivered', storage: { type: 'browser_page', origin: 'https://accounts.example.com' }, label: s.label } }
  }
  const out = ORDER.filter((n) => stores.includes(n)).map((n) => ({ ...savedLine(s, n, profile), ...(lines[n] ?? {}) }))
  const saved = out.filter((l) => l.saved === true).length
  return {
    ok: true,
    result: { status: 'saved', partial: saved > 0 && saved < out.length, stores: out, storage: storageFor(s, out), label: s.label },
  }
}
