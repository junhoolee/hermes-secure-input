import { useEffect, useRef } from 'react'
import { CircleAlert, CircleCheck, CircleHelp, CircleSlash, CircleX } from 'lucide-react'

import { endText, type DoneText, type EndFacts, type Requester } from '@/lib/copy'
import type { EndReason } from '@/lib/types'
import { cn } from '@/lib/utils'

/** Move focus to a screen's heading when it replaces the form, so the change is announced in order. */
function useFocusHeading() {
  const ref = useRef<HTMLHeadingElement>(null)
  useEffect(() => {
    ref.current?.focus()
  }, [])
  return ref
}

export function DoneScreen({ text }: { text: DoneText }) {
  const h = useFocusHeading()
  return (
    <section className="flex flex-col gap-5" data-testid="done-screen" aria-labelledby="done-heading">
      <div className="flex items-center gap-3">
        {text.partial ? (
          <CircleAlert aria-hidden="true" className="size-9 shrink-0 text-seal" />
        ) : (
          <CircleCheck aria-hidden="true" className="size-9 shrink-0 text-done" />
        )}
        <h1 id="done-heading" ref={h} tabIndex={-1} className="text-3xl font-bold text-balance text-ink outline-none">
          {text.heading}
        </h1>
      </div>
      <dl className="grid grid-cols-1 gap-x-5 gap-y-1 rounded-md border border-done bg-done-soft p-4 sm:grid-cols-[auto_minmax(0,1fr)] sm:gap-y-3">
        {text.rows.map((r, i) => (
          <div key={r.term} className="contents">
            <dt className={cn('text-sm text-ink-muted', i > 0 && 'mt-2 sm:mt-0')}>{r.term}</dt>
            <dd translate={r.ident ? 'no' : undefined} className={cn('font-semibold text-ink', r.ident && 'ident')}>
              {r.value}
            </dd>
          </div>
        ))}
      </dl>
      {text.stores && text.stores.length > 0 && (
        <ul className="flex flex-col gap-3" data-testid="done-stores">
          {text.stores.map((s) => (
            <li
              key={s.store}
              data-testid={`done-store-${s.store}`}
              data-status={s.status}
              className={cn(
                'flex flex-col gap-1.5 rounded-md border p-3.5',
                s.status === 'saved' ? 'border-done' : 'border-seal bg-seal-soft',
              )}
            >
              <p className="flex items-start gap-2">
                {s.status === 'saved' ? (
                  <CircleCheck aria-hidden="true" className="mt-0.5 size-5 shrink-0 text-done" />
                ) : s.status === 'failed' ? (
                  <CircleX aria-hidden="true" className="mt-0.5 size-5 shrink-0 text-seal" />
                ) : (
                  <CircleHelp aria-hidden="true" className="mt-0.5 size-5 shrink-0 text-seal" />
                )}
                <span className="flex flex-col">
                  <span className="font-semibold text-ink">{s.name}</span>
                  <span className="text-ink">{s.statusText}</span>
                </span>
              </p>
              <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-0.5 pl-7 text-sm">
                {s.idents.map((d) => (
                  <div key={d.term} className="contents">
                    <dt className="text-ink-muted">{d.term}</dt>
                    <dd translate="no" className="ident font-semibold text-ink">
                      {d.value}
                    </dd>
                  </div>
                ))}
              </dl>
              {s.notes.map((n) => (
                <p key={n} className="pl-7 text-sm text-ink">
                  {n}
                </p>
              ))}
            </li>
          ))}
        </ul>
      )}
      <ul className="flex flex-col gap-1 text-base text-ink">
        {text.lines.map((l) => (
          <li key={l}>{l}</li>
        ))}
      </ul>
    </section>
  )
}

/** `requester` is known only when the page had opened the request before it ended; `facts` is what it saw (EndFacts). */
export function EndScreen({
  reason,
  message,
  requester,
  facts,
}: {
  reason: EndReason
  message?: string
  requester?: Requester
  facts?: EndFacts
}) {
  const h = useFocusHeading()
  const t = endText(reason, requester, facts)
  return (
    <section className="flex flex-col gap-5" data-testid="end-screen" data-reason={reason} aria-labelledby="end-heading">
      <div className="flex items-center gap-3">
        <CircleSlash aria-hidden="true" className="size-9 shrink-0 text-seal" />
        <h1 id="end-heading" ref={h} tabIndex={-1} className="text-3xl font-bold text-balance text-ink outline-none">
          {t.heading}
        </h1>
      </div>
      <ul className="flex flex-col gap-1 text-base text-ink">
        {t.lines.map((l) => (
          <li key={l}>{l}</li>
        ))}
      </ul>
      {message && <p className="text-sm text-ink-muted">Hermes 컴퓨터의 안내: {message}</p>}
    </section>
  )
}
