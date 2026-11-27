import { useEffect, useState } from 'react'
import { Clock } from 'lucide-react'

import { TIMER } from '@/lib/copy'
import { cn } from '@/lib/utils'

/** Seconds left until `deadline` (ms since epoch), refreshed four times a second. */
export function useSecondsLeft(deadline: number | null, totalSeconds: number): number | null {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    if (deadline === null) return
    setNow(Date.now())
    const id = window.setInterval(() => setNow(Date.now()), 250)
    return () => window.clearInterval(id)
  }, [deadline])
  if (deadline === null) return null
  // `now` can predate the deadline by a render; never show more than the full allowance.
  return Math.min(totalSeconds, Math.max(0, Math.ceil((deadline - now) / 1000)))
}

export function Countdown({ seconds }: { seconds: number }) {
  const m = Math.floor(seconds / 60)
  const s = seconds % 60
  const urgent = seconds <= 60
  return (
    <p
      className={cn(
        'flex items-center gap-1.5 rounded-md px-2.5 py-1 text-sm font-semibold tabular-nums',
        urgent ? 'bg-seal text-sheet' : 'bg-sheet text-ink',
      )}
      data-testid="countdown"
    >
      <Clock aria-hidden="true" className="size-4" />
      {/* The ticking digits are hidden from screen readers; a spoken form is given instead. */}
      <span aria-hidden="true">
        {TIMER.label} {m}:{String(s).padStart(2, '0')}
      </span>
      <span className="sr-only">{TIMER.spoken(m, s)}</span>
    </p>
  )
}
