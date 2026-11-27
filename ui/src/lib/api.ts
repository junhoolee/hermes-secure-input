// Calls to the one-time page server. Every URL is relative to the page
// (https://<host>/<token>/), so './api/open' resolves under the token path.

import type { SubmitBody } from './crypto'
import type { OpenResponse, SubmitResult } from './types'

export class ApiError extends Error {
  readonly status: number
  readonly code: string
  readonly serverMessage?: string
  /** The whole error reply, for the fields a code carries (A.8: `stores`, `result_unknown`). */
  readonly data: Record<string, unknown> | null

  constructor(status: number, code: string, serverMessage?: string, data: Record<string, unknown> | null = null) {
    super(code)
    this.status = status
    this.code = code
    this.serverMessage = serverMessage
    this.data = data
  }
}

async function post(path: string, body: unknown): Promise<{ status: number; data: Record<string, unknown> | null }> {
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    cache: 'no-store',
    credentials: 'same-origin',
    referrerPolicy: 'no-referrer',
  })
  let data: Record<string, unknown> | null = null
  try {
    data = (await res.json()) as Record<string, unknown>
  } catch {
    data = null
  }
  return { status: res.status, data }
}

function toError(status: number, data: Record<string, unknown> | null): ApiError {
  const code = typeof data?.error_code === 'string' ? data.error_code : `http_${status}`
  const message = typeof data?.message === 'string' ? data.message : undefined
  return new ApiError(status, code, message, data)
}

function isOpenResponse(d: unknown): d is OpenResponse {
  if (!d || typeof d !== 'object') return false
  const o = d as Record<string, unknown>
  const t = o.target as Record<string, unknown> | undefined
  const r = o.requester as Record<string, unknown> | undefined
  return (
    o.v === 2 &&
    typeof o.request_id === 'string' &&
    (o.kind === 'api_key' || o.kind === 'login' || o.kind === 'otp_code' || o.kind === 'secret') &&
    typeof o.purpose === 'string' &&
    typeof o.label === 'string' &&
    !!r &&
    (r.type === 'agent' || r.type === 'user') &&
    typeof r.profile === 'string' &&
    !!t &&
    typeof t.profile === 'string' &&
    Array.isArray(t.profiles) &&
    Array.isArray(t.stores) &&
    typeof o.server_public_key === 'string' &&
    typeof o.sid === 'string' &&
    typeof o.submit_deadline_s === 'number'
  )
}

let openOnce: Promise<OpenResponse> | null = null

/**
 * POST ./api/open. The server answers 200 exactly once, so the call is
 * memoised for the lifetime of the page (React StrictMode runs effects twice).
 */
export function openRequest(): Promise<OpenResponse> {
  openOnce ??= (async () => {
    const { status, data } = await post('./api/open', {})
    if (status !== 200) throw toError(status, data)
    if (!isOpenResponse(data)) throw new ApiError(status, 'bad_open_response')
    return data
  })()
  return openOnce
}

export async function submitRequest(body: SubmitBody): Promise<SubmitResult> {
  const { status, data } = await post('./api/submit', body)
  if (status === 200 && data?.ok === true && data.result && typeof data.result === 'object') {
    return data.result as SubmitResult
  }
  throw toError(status, data)
}

export async function cancelRequest(sid: string): Promise<void> {
  try {
    await post('./api/cancel', { sid })
  } catch {
    // The page closes either way; the server also expires the link on its own.
  }
}
