import { useId, useState } from 'react'
import { AlertCircle, Eye, EyeOff, LoaderCircle, LockKeyhole } from 'lucide-react'
import type { UseFormRegisterReturn } from 'react-hook-form'

import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Field, FieldDescription, FieldError, FieldLabel } from '@/components/ui/field'
import { Input } from '@/components/ui/input'
import { NativeSelect, NativeSelectOption } from '@/components/ui/native-select'
import { A12, FORM, type StoreAlert } from '@/lib/copy'
import { cn } from '@/lib/utils'

/** Shared attributes for anything secret: no autofill guesses, no spell check, no capitalising. */
export const SECRET_ATTRS = {
  autoComplete: 'off',
  autoCapitalize: 'none',
  autoCorrect: 'off',
  spellCheck: false,
} as const

// read-only: the fields are read-only only while saving. They are dimmed by a ground-coloured fill and a light
// border, not by opacity: opacity-50 text failed axe colour contrast (reader round 1, P9).
export const inputClass = 'h-12 rounded-md border-input bg-sheet px-3 text-base md:text-base read-only:border-line read-only:bg-ground'

/** A copy sentence where `name` between backticks is a literal (file, command): drawn in the code face. A literal
 * is a short command or file name, so it never breaks inside (a longer sentence once broke `security` mid-word). */
export function Literal({ text }: { text: string }) {
  const parts = text.split('`')
  return (
    <>
      {parts.map((p, i) =>
        i % 2 === 1 ? (
          <code key={i} translate="no" className="ident rounded-sm bg-route-soft px-1 text-[0.95em] whitespace-nowrap">
            {p}
          </code>
        ) : (
          p
        ),
      )}
    </>
  )
}

/** Text input with a visible label, help text, inline error and an optional show/hide toggle. */
export function TextField({
  label,
  help,
  error,
  reg,
  secret,
  inputProps,
  children,
}: {
  label: string
  help?: React.ReactNode
  error?: string
  reg: UseFormRegisterReturn
  secret?: boolean
  inputProps?: React.ComponentProps<'input'>
  children?: React.ReactNode
}) {
  const id = useId()
  const helpId = `${id}-help`
  const errId = `${id}-err`
  const [shown, setShown] = useState(false)
  const describedBy = [help ? helpId : null, error ? errId : null].filter(Boolean).join(' ') || undefined

  return (
    <Field data-invalid={!!error}>
      <FieldLabel htmlFor={id} className="text-base font-semibold text-ink">
        {label}
      </FieldLabel>
      <div className="flex gap-2">
        <Input
          id={id}
          {...inputProps}
          type={secret && !shown ? 'password' : (inputProps?.type ?? 'text')}
          aria-invalid={!!error}
          aria-describedby={describedBy}
          className={cn(inputClass, secret && 'font-mono tracking-normal', inputProps?.className)}
          {...reg}
        />
        {secret && (
          <Button
            type="button"
            variant="outline"
            className="h-12 min-w-[4.75rem] shrink-0 gap-1.5 rounded-md border-input bg-sheet px-3 text-sm text-ink"
            aria-pressed={shown}
            aria-controls={id}
            onClick={() => setShown((v) => !v)}
          >
            {shown ? <EyeOff aria-hidden="true" /> : <Eye aria-hidden="true" />}
            {shown ? FORM.hide : FORM.show}
          </Button>
        )}
      </div>
      {help && (
        <FieldDescription id={helpId} className="text-sm text-ink-muted">
          {help}
        </FieldDescription>
      )}
      {error && (
        <FieldError id={errId} className="flex items-start gap-1.5 text-sm font-medium text-seal">
          <AlertCircle aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
          <span>{error}</span>
        </FieldError>
      )}
      {children}
    </Field>
  )
}

/** Wrap each profile name inside a sentence in translate="no", so browser translation keeps the names intact. */
function noTranslateNames(sentence: string, names: string[]): React.ReactNode[] {
  const escaped = [...new Set(names.filter(Boolean))].map((n) => n.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
  if (!escaped.length) return [sentence]
  return sentence.split(new RegExp(`(${escaped.join('|')})`)).map((part, i) =>
    i % 2 === 1 ? (
      <span key={i} translate="no">
        {part}
      </span>
    ) : (
      part
    ),
  )
}

/** Target profile: a select when the server allows a choice, otherwise plain text. */
export function ProfileField({
  profiles,
  editable,
  fixedValue,
  reg,
  selected,
  requesterProfile,
  agentRequest,
}: {
  profiles: string[]
  editable: boolean
  fixedValue: string
  reg: UseFormRegisterReturn
  /** The profile chosen right now. */
  selected: string
  /** The profile of whoever asked (open.requester.profile). */
  requesterProfile: string
  /** True when Hermes asked during a task (open.requester.type === 'agent'). */
  agentRequest: boolean
}) {
  const id = useId()
  const mismatch = FORM.profileMismatch(requesterProfile, selected, agentRequest)
  if (!editable || profiles.length < 2) {
    return (
      <div className="flex flex-col gap-1" data-testid="profile-fixed">
        <p className="text-base font-semibold text-ink">{FORM.profileLabel}</p>
        <p className="text-base text-ink">
          <span translate="no" className="ident">
            {fixedValue}
          </span>
          <span className="text-sm text-ink-muted"> (이 요청에서는 바꿀 수 없습니다)</span>
        </p>
        <input type="hidden" value={fixedValue} {...reg} />
      </div>
    )
  }
  return (
    <Field>
      <FieldLabel htmlFor={id} className="text-base font-semibold text-ink">
        {FORM.profileLabel}
      </FieldLabel>
      <NativeSelect
        id={id}
        className="w-full [&_select]:h-12 [&_select]:rounded-md [&_select]:border-input [&_select]:bg-sheet [&_select]:pl-3 [&_select]:text-base [&_select]:text-ink"
        aria-describedby={`${id}-help`}
        translate="no"
        {...reg}
      >
        {profiles.map((p) => (
          <NativeSelectOption key={p} value={p}>
            {p}
          </NativeSelectOption>
        ))}
      </NativeSelect>
      <FieldDescription id={`${id}-help`} className="text-sm text-ink-muted">
        {FORM.profileHelp.map((l) => (
          <span key={l} className="block">
            {l}
          </span>
        ))}
        {/* Always rendered (empty when the profiles match) so screen readers announce the line when it appears. */}
        <span aria-live="polite" className="block" data-testid="profile-mismatch">
          {mismatch && (
            <span className="mt-1.5 flex items-start gap-1.5 font-medium text-seal">
              <AlertCircle aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
              <span>{noTranslateNames(mismatch, [requesterProfile, selected])}</span>
            </span>
          )}
        </span>
      </FieldDescription>
    </Field>
  )
}

/** Submit, cancel (with a confirm step), retryable error and the what-happens-next notes. */
export function FormActions({
  sending,
  formError,
  onCancel,
  saving = false,
  storeAlert = null,
}: {
  sending: boolean
  formError: string | null
  onCancel: () => void
  /** True while a value of a saved kind is being stored (plan 5.7): the A.12 line replaces the time left. */
  saving?: boolean
  /** A retryable store failure (A.8 store_unavailable or storage_failed), shown store by store. */
  storeAlert?: StoreAlert | null
}) {
  const [confirming, setConfirming] = useState(false)
  return (
    <div className="flex flex-col gap-4">
      {saving && (
        <div
          role="status"
          className="flex items-start gap-2.5 rounded-md border-2 border-route bg-route-soft px-3 py-3"
          data-testid="saving"
        >
          <LoaderCircle aria-hidden="true" className="mt-0.5 size-5 shrink-0 text-route motion-safe:animate-spin" />
          <p className="flex flex-col gap-0.5">
            <span className="text-base font-semibold text-ink">{A12.saving}</span>
            <span className="text-sm text-ink">{FORM.savingNext}</span>
          </p>
        </div>
      )}
      {storeAlert && !saving && (
        <Alert variant="destructive" className="rounded-md border-seal bg-seal-soft px-3 py-3 text-seal" data-testid="store-alert">
          <AlertCircle aria-hidden="true" />
          <AlertTitle className="text-base font-semibold">{storeAlert.title}</AlertTitle>
          <AlertDescription className="text-sm text-ink">
            <ul className="flex flex-col gap-0.5">
              {storeAlert.lines.map((l) => (
                <li key={l}>{l}</li>
              ))}
            </ul>
            {storeAlert.next.map((l) => (
              <p key={l}>{l}</p>
            ))}
          </AlertDescription>
        </Alert>
      )}
      {formError && (
        <Alert variant="destructive" className="rounded-md border-seal bg-seal-soft px-3 py-3 text-seal">
          <AlertCircle aria-hidden="true" />
          <AlertTitle className="text-base font-semibold">{FORM.genericError}</AlertTitle>
          <AlertDescription className="text-sm text-ink">
            <p>{formError}</p>
            <p>{FORM.retryable}</p>
          </AlertDescription>
        </Alert>
      )}
      <Button
        type="submit"
        disabled={sending}
        className="h-12 w-full gap-2 rounded-md text-base font-semibold hover:bg-route-strong"
        data-testid="submit"
      >
        {sending ? (
          <LoaderCircle aria-hidden="true" className="size-5 motion-safe:animate-spin" />
        ) : (
          <LockKeyhole aria-hidden="true" className="size-5" />
        )}
        {saving ? FORM.saving : sending ? FORM.sending : FORM.submit}
      </Button>
      <ul className="flex flex-col gap-1 text-sm text-ink-muted">
        <li>{FORM.afterSubmit}</li>
        {/* While saving the server decides and the time left is hidden, so the deadline line is hidden too (App.tsx). */}
        {!saving && <li data-testid="timeout-note">{FORM.timeoutNote}</li>}
      </ul>
      <div className="border-t border-line pt-3">
        {!confirming ? (
          <Button
            type="button"
            variant="ghost"
            disabled={sending}
            className="h-11 px-2 text-sm text-ink-muted underline underline-offset-4 hover:text-ink"
            onClick={() => setConfirming(true)}
          >
            {FORM.cancel}
          </Button>
        ) : (
          <div className="flex flex-col gap-3" role="group" aria-label={FORM.cancel}>
            <p className="text-sm text-ink">{FORM.cancelConfirm}</p>
            <div className="flex flex-wrap gap-2">
              <Button
                type="button"
                variant="outline"
                disabled={sending}
                className="h-11 rounded-md border-seal bg-sheet px-4 text-sm font-semibold text-seal hover:bg-seal-soft"
                onClick={onCancel}
              >
                {FORM.cancelYes}
              </Button>
              <Button
                type="button"
                variant="ghost"
                className="h-11 rounded-md px-4 text-sm text-ink"
                onClick={() => setConfirming(false)}
              >
                {FORM.cancelNo}
              </Button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
