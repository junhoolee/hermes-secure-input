import { useId } from 'react'
import { AlertCircle, AlertTriangle, Info, Lock } from 'lucide-react'

import { Literal } from '@/components/form-parts'
import { Checkbox } from '@/components/ui/checkbox'
import { A12, scopeText, STORE_NAME, STORES, storeReaders, storeUse, whyOn, reasonText } from '@/lib/copy'
import type { OpenResponse, StoreName, StoreRow } from '@/lib/types'
import { cn } from '@/lib/utils'

export type StoreSelection = Record<StoreName, boolean>

/** Initial on/off state of every row: what the server pre-selected; a fixed row is always on (A.6). */
export function initialSelection(open: OpenResponse): StoreSelection {
  const sel: StoreSelection = { env: false, hermes_vault: false, keychain: false }
  for (const r of open.target.stores) sel[r.store] = r.fixed || r.selected
  return sel
}

/** Turned-on store names in the server's row order (A.7 `stores`). */
export function chosenStores(open: OpenResponse, sel: StoreSelection): StoreName[] {
  return open.target.stores.filter((r) => r.fixed || sel[r.store]).map((r) => r.store)
}

/** True when some turned-on store keeps the value per profile, so the profile choice matters (plan 2.5). */
export function profileMatters(open: OpenResponse, sel: StoreSelection): boolean {
  return open.target.stores.some((r) => r.scope === 'profile' && (r.fixed || sel[r.store]))
}

/**
 * The warning for a row that is off (plan 2.4, A.12): api_key's .env has the fixed A.12 sentence whether
 * the agent left it off or the user turned it off; any other store the agent marked `needed` gets the
 * needed-store sentence.
 */
export function offWarning(open: OpenResponse, row: StoreRow, on: boolean): string | null {
  if (on || row.fixed) return null
  if (open.kind === 'api_key' && row.store === 'env') return A12.envOff
  if (row.needed) return STORES.neededOff(row.store)
  return null
}

/**
 * The storage list (plan 4.1). It hangs off the last stop of the route: the route line runs down past
 * every row, and each row joins it with a short branch, solid when the row is on and dashed when off.
 */
export function StoreList({
  open,
  profile,
  selection,
  onToggle,
  disabled,
  noneError,
  failed,
  labelledBy,
}: {
  open: OpenResponse
  profile: string
  selection: StoreSelection
  onToggle: (store: StoreName, on: boolean) => void
  /** True while saving: nothing can change. */
  disabled: boolean
  /** True when the user tried to send with every row off. */
  noneError: boolean
  /** Stores the last submit found unusable (422 store_unavailable), with the A.4 word. */
  failed: Partial<Record<StoreName, string>>
  labelledBy: string
}) {
  const errId = useId()
  const rows = open.target.stores
  const anyOn = rows.some((r) => r.fixed || selection[r.store])
  // The profile select is hidden when no turned-on store is per profile (App.tsx, profileMatters).
  const profileShown = profileMatters(open, selection)
  return (
    <div
      role="group"
      aria-labelledby={labelledBy}
      aria-describedby={noneError && !anyOn ? errId : undefined}
      className="mt-3 flex flex-col gap-3"
      data-testid="store-list"
    >
      {/* Above the rows: the last row must end the step, where the route line stops. */}
      {noneError && !anyOn && (
        <p id={errId} role="alert" className="flex items-start gap-1.5 text-sm font-medium text-seal" data-testid="stores-none">
          <AlertCircle aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
          <span>{STORES.noneOn}</span>
        </p>
      )}
      <ul className="flex flex-col gap-3">
        {rows.map((row, i) => (
          <StoreRowItem
            key={row.store}
            open={open}
            row={row}
            profile={profile}
            on={row.fixed || selection[row.store]}
            last={i === rows.length - 1}
            disabled={disabled}
            profileShown={profileShown}
            failedReason={failed[row.store]}
            onToggle={onToggle}
          />
        ))}
      </ul>
    </div>
  )
}

function StoreRowItem({
  open,
  row,
  profile,
  on,
  last,
  disabled,
  profileShown,
  failedReason,
  onToggle,
}: {
  open: OpenResponse
  row: StoreRow
  profile: string
  on: boolean
  last: boolean
  disabled: boolean
  profileShown: boolean
  failedReason?: string
  onToggle: (store: StoreName, on: boolean) => void
}) {
  const id = useId()
  const warnId = `${id}-warn`
  const stateId = `${id}-state`
  const byId = `${id}-by`
  const warning = offWarning(open, row, on)
  // A row the server left off and nobody marked: "처음에는 꺼져 있었습니다" only repeats the empty box and "꺼짐".
  const showBy = row.fixed || row.by !== null
  // An off .env row's profile scope says nothing about this send while the profile select is hidden.
  const showScope = !(row.store === 'env' && !on && !profileShown)
  // A fixed box is a disabled checkbox; its state line and the sentence saying why it cannot be turned off
  // are its description, so a screen reader hears why it is dimmed, not just that it is.
  const describedBy = [row.fixed ? stateId : null, row.fixed ? byId : null, warning ? warnId : null].filter(Boolean).join(' ') || undefined
  const kc = row.store === 'keychain' ? open.target.keychain : undefined
  const ident = row.store === 'keychain' ? (kc?.service ?? row.ident) : row.ident
  const unavailable = failedReason ?? (row.available ? null : row.unavailable_reason)

  return (
    <li className="relative" data-testid={`store-${row.store}`} data-on={on} data-fixed={row.fixed}>
      {/* The branch from the route line (left of the content column, at the route stop's centre) to this row. */}
      <span
        aria-hidden="true"
        className={cn(
          'absolute top-[1.375rem] -left-[1.625rem] w-[1.625rem]',
          on ? 'h-0.5 bg-route' : 'h-0 border-t-2 border-dashed border-ink-muted/60',
        )}
      />
      {/* Below the last branch, hide the route line that runs down the step. */}
      {last && <span aria-hidden="true" className="absolute top-[1.5rem] -bottom-px -left-[1.75rem] w-1.5 bg-sheet" />}
      <div
        className={cn(
          'flex flex-col gap-2.5 rounded-md border bg-sheet p-3.5',
          on ? 'border-route' : 'border-dashed border-ink-muted/60',
        )}
      >
        <div className="flex items-start gap-3">
          {/* The box is 20px. This text-less label pads it to a 44px hit area that runs up to the name label
              (no dead zone); Chromium does not hit-test the overflow of a <button>, so the box's own ::after cannot. */}
          <label htmlFor={id} className={cn('-m-3 flex shrink-0 p-3', !row.fixed && !disabled && 'cursor-pointer')}>
            <Checkbox
              id={id}
              checked={on}
              disabled={row.fixed || disabled}
              aria-describedby={describedBy}
              onCheckedChange={(v) => onToggle(row.store, v === true)}
              className={cn(
                'mt-1 size-5 rounded-[5px] border-2 border-input bg-sheet enabled:hover:border-route [&_svg]:size-4',
                row.fixed && 'disabled:cursor-default disabled:opacity-100',
              )}
            />
          </label>
          <div className="flex min-w-0 flex-1 flex-wrap items-baseline justify-between gap-x-3 gap-y-0.5">
            <label htmlFor={id} className={cn('text-base font-semibold text-ink', !row.fixed && !disabled && 'cursor-pointer')}>
              {STORE_NAME[row.store]}
            </label>
            <span id={stateId} className="flex items-center gap-1 text-sm text-ink-muted" data-testid="store-switch">
              {row.fixed && <Lock aria-hidden="true" className="size-3.5" />}
              {row.fixed ? '끌 수 없음' : on ? '켜짐' : '꺼짐'}
            </span>
          </div>
        </div>

        <p className="text-sm text-ink">
          <Literal text={storeUse(row.store, open)} />
        </p>

        <div className="flex flex-col gap-0.5">
          <span className="text-sm text-ink-muted">{STORES.identCaption[row.store]}</span>
          {ident ? (
            <span translate="no" className="ident text-lg font-semibold text-route" data-testid="store-ident">
              {ident}
            </span>
          ) : (
            <span className="text-sm font-medium text-ink">{STORES.keychainNameMissing}</span>
          )}
          {kc?.account && ident && (
            <span className="text-sm text-ink">
              {STORES.accountTerm}{' '}
              <span translate="no" className="ident">
                {kc.account}
              </span>
            </span>
          )}
          {kc?.listed && kc.label && (
            <span className="text-sm text-ink" data-testid="keychain-listed-label">
              {STORES.listedLabel(kc.label, row.exists)}
            </span>
          )}
          {kc?.listed && kc.used_by && <span className="text-sm text-ink">{STORES.usedBy(kc.used_by)}</span>}
          {row.store === 'hermes_vault' &&
            STORES.vaultReplace.map((s) => (
              <span key={s} className="text-sm text-ink-muted">
                {s}
              </span>
            ))}
        </div>

        {/* Overwrite and new-item notes: plugin facts, shown only while the store is on (plan 4.1). */}
        {on && row.store === 'keychain' && ident && row.exists === true && (
          <Note tone="seal" testId="keychain-overwrite">
            {A12.overwrite}
          </Note>
        )}
        {on && row.store === 'keychain' && ident && kc?.new_item && row.exists !== true && (
          <Note tone="route" testId="keychain-new">
            {A12.newItem}
          </Note>
        )}
        {/* A listed name the keychain does not have: the send creates it, so a typo in the allow-list shows here (R3-4). */}
        {on && row.store === 'keychain' && ident && kc?.listed && row.exists === false && (
          <Note tone="seal" testId="keychain-listed-missing">
            {STORES.listedMissing}
          </Note>
        )}
        {on && row.store === 'env' && row.exists === true && (
          <Note tone="seal" testId="env-exists">
            {STORES.envExists}
          </Note>
        )}

        <dl className="grid grid-cols-1 gap-x-3 gap-y-0.5 text-sm sm:grid-cols-[auto_minmax(0,1fr)] sm:gap-y-1.5">
          {showScope && (
            <>
              <dt className="text-ink-muted">{STORES.scopeTerm}</dt>
              <dd className="mb-1 text-ink sm:mb-0">{scopeText(row, profile)}</dd>
            </>
          )}
          {showBy && (
            <>
              <dt className="text-ink-muted">{STORES.whyOnTerm}</dt>
              <dd id={byId} className="mb-1 text-ink sm:mb-0" data-testid="store-by">
                {/* A fixed row says only why it cannot be turned off: why it started on adds nothing (reader round 4, U1). */}
                {row.fixed ? STORES.fixed : `${whyOn(row, open.kind)} ${STORES.switchable}`}
              </dd>
            </>
          )}
          {/* A row that cannot be written now says only why (its unavailable line), not who could read a value there (reader round 5, V1). */}
          {!unavailable && (
            <>
              <dt className="text-ink-muted">{STORES.readTerm}</dt>
              <dd className="text-ink">{storeReaders(row.store).join(' ')}</dd>
            </>
          )}
        </dl>

        {row.reason && (
          // The agent's own words: only ever in this quote shape, captioned, never mixed with plugin sentences (plan 3.3).
          <figure className="flex flex-col gap-1" data-testid="store-reason">
            <figcaption className="text-sm text-ink-muted">{STORES.reasonCaption}</figcaption>
            <blockquote className="border-l-[3px] border-route pl-3 text-base text-ink">“{row.reason}”</blockquote>
          </figure>
        )}

        {unavailable && (
          <div className="flex items-start gap-1.5 text-sm text-seal" data-testid="store-unavailable">
            <AlertCircle aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
            <p className="flex flex-col">
              <span className="font-semibold">{STORES.unavailable(row.store)}</span>
              <span className="text-ink">
                <Literal text={reasonText(unavailable)} />
              </span>
              {/* After a refused submit the alert by the send button already says what to do next (storeUnavailableAlert). */}
              {!failedReason && <span className="text-ink">{STORES.unavailableNext(row.fixed, row.store)}</span>}
            </p>
          </div>
        )}

        {/* Always rendered so a screen reader announces the warning when the row is switched off. */}
        <p id={warnId} aria-live="polite" className="empty:hidden" data-testid={`store-warning-${row.store}`}>
          {warning && (
            <span className="flex items-start gap-1.5 text-sm font-medium text-seal">
              <AlertTriangle aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
              <span>
                <Literal text={warning} />
              </span>
            </span>
          )}
        </p>
      </div>
    </li>
  )
}

function Note({ tone, testId, children }: { tone: 'seal' | 'route'; testId: string; children: React.ReactNode }) {
  const Icon = tone === 'seal' ? AlertTriangle : Info
  return (
    <p
      className={cn(
        'flex items-start gap-2 rounded-md border px-3 py-2 text-sm font-medium text-ink',
        tone === 'seal' ? 'border-seal bg-seal-soft' : 'border-route bg-route-soft',
      )}
      data-testid={testId}
    >
      <Icon aria-hidden="true" className={cn('mt-0.5 size-4 shrink-0', tone === 'seal' ? 'text-seal' : 'text-route')} />
      <span>{children}</span>
    </p>
  )
}
