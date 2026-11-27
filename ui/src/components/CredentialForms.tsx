import { useEffect, useId, useState } from 'react'
import { zodResolver } from '@hookform/resolvers/zod'
import { AlertTriangle, ChevronDown } from 'lucide-react'
import { useForm } from 'react-hook-form'

import { FormActions, ProfileField, SECRET_ATTRS, TextField } from '@/components/form-parts'
import { FieldLegend, FieldSet } from '@/components/ui/field'
import { FORM, type StoreAlert } from '@/lib/copy'
import {
  apiKeySchema,
  loginSchema,
  otpSchema,
  secretSchema,
  type ApiKeyInput,
  type ApiKeyOutput,
  type LoginInput,
  type LoginOutput,
  type OtpInput,
  type OtpOutput,
  type SecretInput,
  type SecretOutput,
} from '@/lib/schemas'
import type { IdentifierType, OpenResponse, Plaintext, StoreName } from '@/lib/types'
import { cn } from '@/lib/utils'

export type FormProps = {
  open: OpenResponse
  sending: boolean
  formError: string | null
  /** Encrypts and submits. Resolves true when the server saved the value. */
  onSend: (pt: Plaintext) => Promise<boolean>
  onCancel: () => void
  onProfileChange: (p: string) => void
  /** Stores turned on in the storage list, in row order (A.7 `stores`). Empty for one-time codes. */
  stores: StoreName[]
  /** False when no turned-on store is kept per profile, so the profile choice would change nothing (plan 2.5). */
  showProfile: boolean
  /** Called instead of sending when every store is off. */
  onNoStores: () => void
  /** True while a saved kind is being stored (plan 5.7). */
  saving: boolean
  storeAlert: StoreAlert | null
}

function defaultProfile(open: OpenResponse) {
  return open.target.profiles.includes(open.target.profile) ? open.target.profile : (open.target.profiles[0] ?? open.target.profile)
}

function FormFrame({ children, onSubmit }: { children: React.ReactNode; onSubmit: React.FormEventHandler }) {
  return (
    <form noValidate onSubmit={onSubmit} className="flex flex-col gap-6" aria-labelledby="form-heading" data-testid="credential-form">
      <h2 id="form-heading" className="sr-only">
        {FORM.heading}
      </h2>
      {children}
    </form>
  )
}

function Actions(p: FormProps) {
  return (
    <FormActions sending={p.sending} formError={p.formError} onCancel={p.onCancel} saving={p.saving} storeAlert={p.storeAlert} />
  )
}

export function ApiKeyForm(p: FormProps) {
  const blank: ApiKeyInput = { target_profile: defaultProfile(p.open), value: '' }
  const form = useForm<ApiKeyInput, unknown, ApiKeyOutput>({ resolver: zodResolver(apiKeySchema), defaultValues: blank })
  const profile = form.watch('target_profile')
  useEffect(() => p.onProfileChange(profile), [profile]) // eslint-disable-line react-hooks/exhaustive-deps

  const submit = form.handleSubmit(async (v) => {
    if (!p.stores.length) return p.onNoStores()
    const ok = await p.onSend({ kind: 'api_key', target_profile: v.target_profile, value: v.value, stores: p.stores })
    if (ok) form.reset({ ...blank, value: '' })
  })

  return (
    <FormFrame onSubmit={submit}>
      {/* Hidden, not removed, when only the keychain is on: the choice comes back if .env is turned on again. */}
      <div hidden={!p.showProfile}>
        <ProfileField
          profiles={p.open.target.profiles}
          editable={p.open.target.profile_editable}
          fixedValue={blank.target_profile}
          reg={form.register('target_profile')}
          selected={profile}
          requesterProfile={p.open.requester.profile}
          agentRequest={p.open.requester.type === 'agent'}
        />
      </div>
      <TextField
        label={FORM.apiKeyLabel}
        help={FORM.apiKeyHelp}
        error={form.formState.errors.value?.message}
        reg={form.register('value')}
        secret
        inputProps={{ ...SECRET_ATTRS, 'aria-required': true, readOnly: p.saving }}
      />
      <Actions {...p} />
    </FormFrame>
  )
}

/** A password kept only in the Mac keychain (kind `secret`, plan 3.1): typed twice and compared here. */
export function SecretForm(p: FormProps) {
  const blank: SecretInput = { value: '', confirm: '' }
  const form = useForm<SecretInput, unknown, SecretOutput>({ resolver: zodResolver(secretSchema), defaultValues: blank })
  const errors = form.formState.errors

  const submit = form.handleSubmit(async (v) => {
    if (!p.stores.length) return p.onNoStores()
    // No profile choice on this screen: the requested profile only names the log (A.7).
    const ok = await p.onSend({ kind: 'secret', target_profile: p.open.target.profile, value: v.value, stores: p.stores })
    if (ok) form.reset(blank)
  })

  return (
    <FormFrame onSubmit={submit}>
      <TextField
        label={FORM.secretLabel}
        help={FORM.secretHelp}
        error={errors.value?.message}
        reg={form.register('value')}
        secret
        inputProps={{ ...SECRET_ATTRS, 'aria-required': true, maxLength: 1024, readOnly: p.saving }}
      />
      <TextField
        label={FORM.secretConfirmLabel}
        help={FORM.secretConfirmHelp}
        error={errors.confirm?.message}
        reg={form.register('confirm')}
        secret
        inputProps={{ ...SECRET_ATTRS, 'aria-required': true, maxLength: 1024, readOnly: p.saving }}
      />
      <Actions {...p} />
    </FormFrame>
  )
}

const ID_TYPES: IdentifierType[] = ['email', 'username', 'phone']
const ID_INPUT: Record<IdentifierType, React.ComponentProps<'input'>> = {
  email: { type: 'email', inputMode: 'email' },
  username: { type: 'text' },
  phone: { type: 'tel', inputMode: 'tel' },
}

export function LoginForm(p: FormProps) {
  const blank: LoginInput = {
    target_profile: defaultProfile(p.open),
    identifier_type: 'email',
    identifier: '',
    password: '',
    otp_secret: '',
  }
  const form = useForm<LoginInput, unknown, LoginOutput>({ resolver: zodResolver(loginSchema), defaultValues: blank })
  const profile = form.watch('target_profile')
  const idType = form.watch('identifier_type')
  useEffect(() => p.onProfileChange(profile), [profile]) // eslint-disable-line react-hooks/exhaustive-deps

  const errors = form.formState.errors
  const [otpOpen, setOtpOpen] = useState(false)
  const otpRegionId = useId()
  const otpLossId = useId()
  const idTypeHelpId = useId()
  // An error inside the folded section must be visible so focus can land on it.
  useEffect(() => {
    if (errors.otp_secret) setOtpOpen(true)
  }, [errors.otp_secret])

  const submit = form.handleSubmit(async (v) => {
    if (!p.stores.length) return p.onNoStores()
    const ok = await p.onSend({
      kind: 'login',
      target_profile: v.target_profile,
      identifier_type: v.identifier_type,
      identifier: v.identifier,
      password: v.password,
      otp_secret: v.otp_secret,
      stores: p.stores,
    })
    if (ok) form.reset(blank)
  })

  return (
    <FormFrame onSubmit={submit}>
      <ProfileField
        profiles={p.open.target.profiles}
        editable={p.open.target.profile_editable}
        fixedValue={blank.target_profile}
        reg={form.register('target_profile')}
        selected={profile}
        requesterProfile={p.open.requester.profile}
        agentRequest={p.open.requester.type === 'agent'}
      />

      <FieldSet className="gap-2" aria-describedby={idTypeHelpId}>
        <FieldLegend className="mb-1 text-base font-semibold text-ink">{FORM.idTypeLegend}</FieldLegend>
        <p id={idTypeHelpId} className="text-sm text-ink-muted">
          {FORM.idTypeHelp}
        </p>
        <div className="grid grid-cols-3 gap-0 overflow-hidden rounded-md border border-input">
          {ID_TYPES.map((t, i) => (
            <label
              key={t}
              className={cn(
                'relative flex min-h-12 cursor-pointer items-center justify-center px-2 text-sm font-medium text-ink',
                'hover:not-has-checked:bg-route-soft has-checked:bg-route has-checked:text-primary-foreground',
                'has-focus-visible:outline-3 has-focus-visible:-outline-offset-3 has-focus-visible:outline-ring',
                i > 0 && 'border-l border-input',
              )}
            >
              <input type="radio" value={t} className="sr-only" {...form.register('identifier_type')} />
              {FORM.idTypes[t]}
            </label>
          ))}
        </div>
      </FieldSet>

      <TextField
        label={FORM.idLabel[idType]}
        help={FORM.idHelp[idType]}
        error={errors.identifier?.message}
        reg={form.register('identifier')}
        inputProps={{ ...ID_INPUT[idType], autoComplete: 'off', autoCapitalize: 'none', autoCorrect: 'off', spellCheck: false, 'aria-required': true, readOnly: p.saving }}
      />

      <TextField
        label={FORM.passwordLabel}
        help={FORM.passwordHelp}
        error={errors.password?.message}
        reg={form.register('password')}
        secret
        inputProps={{ ...SECRET_ATTRS, 'aria-required': true, readOnly: p.saving }}
      />

      <div className="flex flex-col gap-3">
        <button
          type="button"
          aria-expanded={otpOpen}
          aria-controls={otpRegionId}
          aria-describedby={otpLossId}
          onClick={() => setOtpOpen((v) => !v)}
          className="flex min-h-11 items-center gap-2 self-start rounded-md text-left text-base font-semibold text-route underline-offset-4 hover:underline focus-visible:outline-3 focus-visible:outline-ring"
        >
          <ChevronDown aria-hidden="true" className={cn('size-5 shrink-0 transition-transform', otpOpen && 'rotate-180')} />
          {FORM.otpSecretToggle}
        </button>
        {/* Outside the folded section on purpose: the older key goes even if this section is never opened. */}
        <p id={otpLossId} className="flex items-start gap-1.5 text-sm text-ink" data-testid="otp-secret-loss">
          <AlertTriangle aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-seal" />
          <span>
            {FORM.otpSecretLoss.map((l) => (
              <span key={l} className="block">
                {l}
              </span>
            ))}
          </span>
        </p>
        <div id={otpRegionId} hidden={!otpOpen} className="flex flex-col gap-3 border-l-2 border-line pl-4">
          <p className="text-sm text-ink">
            {FORM.otpSecretUse.map((l) => (
              <span key={l} className="block">
                {l}
              </span>
            ))}
          </p>
          <TextField
            label={FORM.otpSecretLabel}
            help={FORM.otpSecretWhat}
            error={errors.otp_secret?.message}
            reg={form.register('otp_secret')}
            secret
            inputProps={{ ...SECRET_ATTRS, readOnly: p.saving }}
          />
        </div>
      </div>

      <Actions {...p} />
    </FormFrame>
  )
}

export function OtpForm(p: FormProps) {
  const blank: OtpInput = { code: '' }
  const form = useForm<OtpInput, unknown, OtpOutput>({ resolver: zodResolver(otpSchema), defaultValues: blank })
  const submit = form.handleSubmit(async (v) => {
    const ok = await p.onSend({ kind: 'otp_code', code: v.code })
    if (ok) form.reset(blank)
  })
  return (
    <FormFrame onSubmit={submit}>
      <TextField
        label={FORM.otpLabel}
        help={
          <>
            <span className="block">{FORM.otpHelp}</span>
            <span className="block">{FORM.otpHelpExpiry}</span>
          </>
        }
        error={form.formState.errors.code?.message}
        reg={form.register('code')}
        inputProps={{
          type: 'text',
          inputMode: 'numeric',
          autoComplete: 'one-time-code',
          autoCapitalize: 'none',
          autoCorrect: 'off',
          spellCheck: false,
          maxLength: 24,
          'aria-required': true,
          className: 'tracking-[0.2em]',
        }}
      />
      <FormActions sending={p.sending} formError={p.formError} onCancel={p.onCancel} />
    </FormFrame>
  )
}
