import { useCallback, useEffect, useRef, useState } from 'react'
import { ShieldCheck } from 'lucide-react'

import { Countdown, useSecondsLeft } from '@/components/Countdown'
import { ApiKeyForm, LoginForm, OtpForm, SecretForm, type FormProps } from '@/components/CredentialForms'
import { RequestSummary } from '@/components/RequestSummary'
import { DoneScreen, EndScreen } from '@/components/Screens'
import { chosenStores, initialSelection, profileMatters, type StoreSelection } from '@/components/StoreList'
import { ApiError, cancelRequest, openRequest, submitRequest } from '@/lib/api'
import {
  doneText,
  END_HEADING,
  endReasonFor,
  FORM,
  formErrorText,
  mainCreated,
  OPENING,
  requestBand,
  storageFailedAlert,
  storeUnavailableAlert,
  TIMER,
  tmpMayBeLeft,
  type DoneText,
  type EndFacts,
  type StoreAlert,
} from '@/lib/copy'
import { encryptSubmission } from '@/lib/crypto'
import type { EndReason, OpenResponse, Plaintext, StoreName, StoreResult, UnavailableStore } from '@/lib/types'

type Phase =
  | { t: 'opening' }
  | { t: 'form'; open: OpenResponse; deadline: number }
  | { t: 'done'; open: OpenResponse; text: DoneText }
  | { t: 'end'; reason: EndReason; message?: string; open?: OpenResponse; facts?: EndFacts }

const FORMS: Record<OpenResponse['kind'], (p: FormProps) => React.JSX.Element> = {
  api_key: ApiKeyForm,
  login: LoginForm,
  secret: SecretForm,
  otp_code: OtpForm,
}

/** Server error codes that close the page (everything except the retryable ones, types.ts RETRYABLE). */
const TERMINAL = new Set(['bad_sid', 'replayed', 'deadline_passed', 'too_many_attempts', 'already_submitted', 'saving_in_progress'])

const NO_SELECTION: StoreSelection = { env: false, hermes_vault: false, keychain: false }

export default function App() {
  const [phase, setPhase] = useState<Phase>({ t: 'opening' })
  const [sending, setSending] = useState(false)
  const [formError, setFormError] = useState<string | null>(null)
  const [storeAlert, setStoreAlert] = useState<StoreAlert | null>(null)
  const [selection, setSelection] = useState<StoreSelection>(NO_SELECTION)
  const [noneError, setNoneError] = useState(false)
  const [failed, setFailed] = useState<Partial<Record<StoreName, string>>>({})
  const [profile, setProfile] = useState('')
  const [announce, setAnnounce] = useState('')
  const warned = useRef(false)
  // For the cancelled and submit time passed screens (R3-2, RC-1 to RC-3): whether the server answered a submit of
  // this page (sent), whether a value sent was refused or not saved and could be sent again (failedSave:
  // store_unavailable, masked_value or a storage_failed that is not result unknown, the answers on which the server
  // ends window_passed_after_failed_save, secure_input/lifecycle.py), and what those answers' keychain lines said: the
  // item was written (main_touched), made (main_created) or a temporary item may be left (tmpMayBeLeft). Once true,
  // each stays true.
  const answered = useRef({ sent: false, failedSave: false, touched: false, created: false, tmpLeft: false })
  // RC2-1, RC2-3: the keychain facts for every end screen and the done screen a page that sent a value can reach. The
  // server keeps the same facts for the request and says them in the Slack result message (keychain_left).
  const keychainFacts = useCallback((): EndFacts => {
    const { touched, created, tmpLeft } = answered.current
    return { touched, created, tmpLeft }
  }, [])

  const end = useCallback((reason: EndReason, message?: string, open?: OpenResponse, facts?: EndFacts) => {
    setSending(false)
    setFormError(null)
    setStoreAlert(null)
    setPhase({ t: 'end', reason, message, open, facts })
    setAnnounce(END_HEADING[reason])
  }, [])

  useEffect(() => {
    let live = true
    openRequest().then(
      (open) => {
        if (!live) return
        setProfile(open.target.profile)
        setSelection(initialSelection(open))
        setPhase({ t: 'form', open, deadline: Date.now() + open.submit_deadline_s * 1000 })
      },
      (e: unknown) => {
        if (!live) return
        end(e instanceof ApiError ? endReasonFor(e.code) : 'unreachable')
      },
    )
    return () => {
      live = false
    }
  }, [end])

  // The link opens only once: reloading or leaving the form ends the request for good, so the browser
  // asks before it unloads a form that is still open (and while a value is being saved).
  const formOpen = phase.t === 'form'
  useEffect(() => {
    if (!formOpen) return
    const guard = (e: BeforeUnloadEvent) => {
      e.preventDefault()
      e.returnValue = ''
    }
    window.addEventListener('beforeunload', guard)
    return () => window.removeEventListener('beforeunload', guard)
  }, [formOpen])

  const seconds = useSecondsLeft(
    phase.t === 'form' ? phase.deadline : null,
    phase.t === 'form' ? phase.open.submit_deadline_s : 0,
  )

  // Kinds that are stored go through "saving" on the server (plan 5.7); a one-time code does not.
  const saving = sending && phase.t === 'form' && phase.open.kind !== 'otp_code'

  // Deadline: drop the form (and with it every typed value) and close the page. While a value is being
  // sent the server decides; after a retryable failure the original deadline applies again, so a deadline
  // that passed while saving closes the page right away (plan 4.1).
  useEffect(() => {
    if (phase.t !== 'form' || seconds === null) return
    if (seconds <= 60 && seconds > 0 && !warned.current) {
      warned.current = true
      setAnnounce(TIMER.oneMinute)
    }
    if (seconds === 0 && !sending) {
      const { failedSave, touched, created, tmpLeft } = answered.current
      end('deadline_passed', undefined, phase.open, { sent: failedSave, touched, created, tmpLeft })
    }
  }, [seconds, phase, sending, end])

  const onSend = useCallback(
    async (pt: Plaintext): Promise<boolean> => {
      if (phase.t !== 'form') return false
      const open = phase.open
      const saves = open.kind !== 'otp_code'
      setSending(true)
      setFormError(null)
      setStoreAlert(null)
      setNoneError(false)
      try {
        // A new key pair and iv for every attempt (contract 4.3, steps 1 and 4).
        const body = await encryptSubmission(open, pt)
        const result = await submitRequest(body)
        // Only whether a setup key was sent is passed on, never the key itself.
        const withOtpSecret = pt.kind === 'login' && !!pt.otp_secret
        const text = doneText(open, result, pt.kind === 'otp_code' ? '' : pt.target_profile, withOtpSecret, keychainFacts())
        setSending(false)
        setPhase({ t: 'done', open, text })
        setAnnounce(text.heading)
        return true
      } catch (e) {
        setSending(false)
        const rows = (e instanceof ApiError && Array.isArray(e.data?.stores) ? e.data.stores : []) as StoreResult[]
        // A 5xx may come from a proxy in front of the server, so only a 4xx counts as the server's answer.
        if (e instanceof ApiError && e.status < 500) {
          const a = answered.current
          a.sent = true
          // The answers on which the server marks a failed save (secure_input/server.py: _apply_save after
          // end_saving "retry", and _checked_submit's masked_value and profile error answers, which call
          // Lifecycle.note_failed_save): a value was sent and not saved. invalid_payload, decrypt_failed, bad_sid
          // and replayed are not: no usable value reached the server.
          if (e.code === 'store_unavailable' || e.code === 'masked_value' || (e.code === 'storage_failed' && e.data?.result_unknown !== true)) {
            a.failedSave = true
          }
          if (rows.some((r) => r.store === 'keychain' && r.main_touched === true)) a.touched = true
          if (rows.some(mainCreated)) a.created = true
          if (rows.some(tmpMayBeLeft)) a.tmpLeft = true
        }
        if (saves && e instanceof ApiError && e.code === 'deadline_passed') {
          // The value reached the server: the submit window passed during the save and the save ended in a
          // retryable result, so the request ended (secure_input/server.py _apply_save). A keychain item may
          // have changed (main_touched), so the page cannot say the value was not sent (A.12, reader round 6, X1).
          end('result_unknown', undefined, open, keychainFacts())
        } else if (e instanceof ApiError && TERMINAL.has(e.code)) {
          end(endReasonFor(e.code), e.serverMessage, open, keychainFacts())
        } else if (e instanceof ApiError && e.code === 'storage_failed' && e.data?.result_unknown === true) {
          // This answer carries the store lines, so the page can say a temporary keychain item may be left (R3-3);
          // they are already in keychainFacts, with those of the earlier answers (RC2-1).
          end('result_unknown', undefined, open, keychainFacts())
        } else if (e instanceof ApiError && e.code === 'store_unavailable') {
          const list = (Array.isArray(e.data?.stores) ? e.data.stores : []) as UnavailableStore[]
          setFailed(Object.fromEntries(list.map((s) => [s.store, s.reason])))
          const alert = storeUnavailableAlert(open, list)
          setStoreAlert(alert)
          setAnnounce(alert.title)
        } else if (e instanceof ApiError && e.code === 'storage_failed') {
          const list = (Array.isArray(e.data?.stores) ? e.data.stores : []) as StoreResult[]
          const alert = storageFailedAlert(list, e.serverMessage)
          setStoreAlert(alert)
          setAnnounce(alert.title)
        } else if (saves && (!(e instanceof ApiError) || e.status >= 500)) {
          // The reply was lost (or a proxy answered) while the server may still be saving (plan 4.1, A.12).
          end('result_unknown', undefined, open, keychainFacts())
        } else if (e instanceof ApiError) {
          setFormError(formErrorText(e.code, e.serverMessage))
        } else {
          setFormError(FORM.networkError)
        }
        return false
      }
    },
    [phase, end, keychainFacts],
  )

  const onCancel = useCallback(async () => {
    if (phase.t !== 'form' || sending) return
    await cancelRequest(phase.open.sid)
    end('cancelled', undefined, phase.open, { ...answered.current, code: phase.open.kind === 'otp_code' })
  }, [phase, sending, end])

  const onToggle = useCallback((store: StoreName, on: boolean) => {
    setSelection((s) => ({ ...s, [store]: on }))
    if (on) setNoneError(false)
  }, [])

  const onNoStores = useCallback(() => {
    setNoneError(true)
    // Bring the list into view at its first switch, so the reason the page did not send is where focus is.
    const first = document.querySelector<HTMLElement>('[data-testid="store-list"] button[role="checkbox"]:not([disabled])')
    first?.focus()
  }, [])

  const open = phase.t === 'opening' ? undefined : phase.open
  const Form = phase.t === 'form' ? FORMS[phase.open.kind] : null

  return (
    // viewport-fit=cover lets the page run under the notch in landscape; the safe-area padding keeps text clear of it.
    <div className="min-h-dvh bg-sheet pt-[env(safe-area-inset-top)] pr-[env(safe-area-inset-right)] pb-[env(safe-area-inset-bottom)] pl-[env(safe-area-inset-left)] lg:envelope-tint lg:py-10">
      <div className="mx-auto flex min-h-dvh w-full max-w-[66rem] flex-col bg-sheet lg:min-h-0 lg:rounded-md lg:border lg:border-line">
        <header className="bg-ground lg:rounded-t-md">
          <div className="flex min-h-14 flex-wrap items-center justify-between gap-x-3 gap-y-1 px-5 py-2 lg:px-10">
            <p className="flex items-center gap-2 text-sm font-semibold text-ink" data-testid="kind-band">
              <ShieldCheck aria-hidden="true" className="size-5 text-route" />
              {open ? requestBand(open.kind) : 'Hermes 일회용 입력 페이지'}
            </p>
            {/* The time left stays in view while saving too, so the saving line's "남은 시간은 저장 중에도 줄지만" points at it (plan 4.1, reader round 5, V3). */}
            {phase.t === 'form' && seconds !== null && <Countdown seconds={seconds} />}
          </div>
          <div aria-hidden="true" className="envelope-tint h-3 border-b border-line" />
        </header>

        <main className="flex-1 px-5 pt-7 pb-12 lg:px-10 lg:pt-10">
          {phase.t === 'opening' && (
            <p className="text-base text-ink-muted" data-testid="opening">
              {OPENING}
            </p>
          )}

          {phase.t === 'form' && Form && (
            <div className="grid gap-9 lg:grid-cols-[minmax(0,1.1fr)_minmax(0,1fr)] lg:gap-12">
              <RequestSummary
                open={phase.open}
                profile={profile || phase.open.target.profile}
                stores={{ selection, onToggle, disabled: sending, noneError, failed }}
              />
              <div className="border-t border-line pt-7 lg:border-t-0 lg:border-l lg:pt-0 lg:pl-12">
                <Form
                  open={phase.open}
                  sending={sending}
                  formError={formError}
                  onSend={onSend}
                  onCancel={onCancel}
                  onProfileChange={setProfile}
                  stores={chosenStores(phase.open, selection)}
                  showProfile={profileMatters(phase.open, selection)}
                  onNoStores={onNoStores}
                  saving={saving}
                  storeAlert={storeAlert}
                />
              </div>
            </div>
          )}

          {phase.t === 'done' && (
            <div className="max-w-[36rem]">
              <DoneScreen text={phase.text} />
            </div>
          )}

          {phase.t === 'end' && (
            <div className="max-w-[36rem]">
              <EndScreen reason={phase.reason} message={phase.message} requester={phase.open?.requester} facts={phase.facts} />
            </div>
          )}
        </main>
      </div>

      <p role="status" aria-live="polite" className="sr-only" data-testid="live">
        {announce}
      </p>
    </div>
  )
}
