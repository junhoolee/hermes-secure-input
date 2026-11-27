import { useId } from 'react'

import { StoreList, type StoreSelection } from '@/components/StoreList'
import { destination, NOT_STORED, pageNotes, requesterText, ROUTE, STORES } from '@/lib/copy'
import type { OpenResponse, StoreName } from '@/lib/types'

export type StoreControls = {
  selection: StoreSelection
  onToggle: (store: StoreName, on: boolean) => void
  disabled: boolean
  noneError: boolean
  failed: Partial<Record<StoreName, string>>
}

/** What is being asked for, why, and the path the value takes (contract 5 a-e). */
export function RequestSummary({ open, profile, stores }: { open: OpenResponse; profile: string; stores: StoreControls }) {
  const storesHeadingId = useId()

  return (
    <div className="flex flex-col gap-7">
      <div className="flex flex-col gap-4">
        <h1 className="text-3xl font-bold tracking-tight text-balance text-ink">{open.label}</h1>
        <figure className="flex flex-col gap-2">
          <blockquote className="border-l-[3px] border-route pl-4 text-xl font-medium text-ink">
            {open.purpose}
          </blockquote>
          <figcaption className="pl-[1.1875rem] text-sm text-ink-muted" data-testid="requester">
            {requesterText(open.requester)}
          </figcaption>
        </figure>
      </div>

      <section aria-labelledby="route-heading" className="flex flex-col gap-4">
        <h2 id="route-heading" className="text-sm font-semibold text-ink">
          {ROUTE.heading}
        </h2>
        <ol className="route flex flex-col" data-testid="route">
          <RouteStep n={1} title={ROUTE.encrypt.title} body={ROUTE.encrypt.body} />
          <RouteStep n={2} title={ROUTE.transfer.title} body={ROUTE.transfer.body} />
          {open.kind === 'otp_code' ? <OtpStop open={open} /> : <StoresStop open={open} profile={profile} stores={stores} headingId={storesHeadingId} />}
        </ol>
        <p className="text-sm text-ink-muted">{ROUTE.slackNote(open.kind)}</p>
      </section>
    </div>
  )
}

/** A one-time code is never stored: the last stop is the login screen it is typed into (unchanged). */
function OtpStop({ open }: { open: OpenResponse }) {
  const dest = destination(open)
  return (
    <RouteStep n={3} title={dest.title} last>
      <p className="mt-2 text-sm text-ink">{dest.use}</p>
      {dest.notes.length > 0 && (
        <ul className="mt-1 flex flex-col gap-0.5 text-sm text-ink" data-testid="destination-notes">
          {dest.notes.map((n) => (
            <li key={n}>{n}</li>
          ))}
        </ul>
      )}
      <p className="mt-1 text-sm text-ink">{NOT_STORED}</p>
    </RouteStep>
  )
}

/** The last stop branches into one row per store the kind can use (plan 4.1). */
function StoresStop({
  open,
  profile,
  stores,
  headingId,
}: {
  open: OpenResponse
  profile: string
  stores: StoreControls
  headingId: string
}) {
  const single = open.target.stores.every((r) => r.fixed)
  const notes = pageNotes(open)
  return (
    <RouteStep n={3} title={STORES.heading} titleId={headingId} last branch>
      {!single && <p className="mt-0.5 text-sm text-ink-muted">{STORES.choose}</p>}
      {notes.length > 0 && (
        <ul className="mt-1 flex flex-col gap-0.5 text-sm text-ink" data-testid="destination-notes">
          {notes.map((n) => (
            <li key={n}>{n}</li>
          ))}
        </ul>
      )}
      <StoreList
        open={open}
        profile={profile}
        selection={stores.selection}
        onToggle={stores.onToggle}
        disabled={stores.disabled}
        noneError={stores.noneError}
        failed={stores.failed}
        labelledBy={headingId}
      />
    </RouteStep>
  )
}

function RouteStep({
  n,
  title,
  titleId,
  body,
  last,
  branch,
  children,
}: {
  n: number
  title: string
  titleId?: string
  body?: string[]
  last?: boolean
  /** The route line keeps running down this stop so the rows below can branch off it. */
  branch?: boolean
  children?: React.ReactNode
}) {
  return (
    <li className="relative grid grid-cols-[1.75rem_minmax(0,1fr)] gap-x-3">
      {/* The route line: a solid rule joining each stop to the next. */}
      {(!last || branch) && <span aria-hidden="true" className="absolute top-7 bottom-0 left-[0.8125rem] w-0.5 bg-route" />}
      <span
        aria-hidden="true"
        className={
          last
            ? 'relative z-10 flex size-7 items-center justify-center rounded-full bg-route text-xs font-bold text-primary-foreground'
            : 'relative z-10 flex size-7 items-center justify-center rounded-full border-2 border-route bg-sheet text-xs font-bold text-route'
        }
      >
        {n}
      </span>
      <div className={last ? 'pb-0' : 'pb-5'}>
        <p id={titleId} className="pt-0.5 font-semibold text-ink">
          {title}
        </p>
        {body?.map((b) => (
          <p key={b} className="mt-0.5 text-sm text-ink-muted">
            {b}
          </p>
        ))}
        {children}
      </div>
    </li>
  )
}
