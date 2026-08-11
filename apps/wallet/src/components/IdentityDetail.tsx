import {
  AlertTriangle,
  ArrowRightLeft,
  Fingerprint,
  Globe2,
  KeySquare,
  Link2,
  Loader2,
  ShieldCheck,
  Trash2,
  X,
} from 'lucide-react';
import { motion } from 'motion/react';
import type { LocalIdentitySummary } from '@nexus/wallet-core';

import {
  canUseRegisteredIdentityActions,
  needsRegistrationRecovery,
} from '../lib/identity-capabilities';

interface IdentityDetailProps {
  identity: LocalIdentitySummary;
  onClose: () => void;
  onRotate: () => void;
  onDispose: () => void;
  onContinuity: () => void;
  retryingRegistration: boolean;
  onRetryRegistration: () => void;
}

export function IdentityDetail({
  identity,
  onClose,
  onRotate,
  onDispose,
  onContinuity,
  retryingRegistration,
  onRetryRegistration,
}: IdentityDetailProps) {
  const active = identity.localState === 'active';
  const registeredActions = canUseRegisteredIdentityActions(identity);

  return (
    <motion.section
      initial={{ opacity: 0, height: 0 }}
      animate={{ opacity: 1, height: 'auto' }}
      exit={{ opacity: 0, height: 0 }}
      aria-labelledby="identity-details-title"
      className="overflow-hidden rounded-3xl border border-slate-200 bg-white shadow-sm"
    >
      <div className="p-6 sm:p-8">
        <div className="flex items-start justify-between gap-4">
          <div className="flex min-w-0 items-start gap-3">
            <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl bg-indigo-100 text-indigo-600">
              <Fingerprint className="h-6 w-6" aria-hidden="true" />
            </div>
            <div className="min-w-0">
              <p className="text-xs font-semibold uppercase tracking-wider text-indigo-600">
                Local identity
              </p>
              <h2
                id="identity-details-title"
                className="mt-0.5 truncate text-xl font-bold text-slate-900"
              >
                {identity.label ?? 'Untitled identity'}
              </h2>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg p-1.5 text-slate-400 transition-colors hover:bg-slate-100 hover:text-slate-600"
            aria-label="Close identity details"
          >
            <X className="h-4 w-4" aria-hidden="true" />
          </button>
        </div>

        <dl className="mt-6 grid gap-3 sm:grid-cols-2">
          <div className="rounded-xl border border-slate-200 bg-slate-50 p-4 sm:col-span-2">
            <dt className="flex items-center gap-1.5 text-xs font-medium uppercase tracking-wide text-slate-500">
              <KeySquare className="h-3.5 w-3.5" aria-hidden="true" /> Subject
            </dt>
            <dd className="mt-2 break-all font-mono text-sm text-slate-800">{identity.subject}</dd>
          </div>
          <div className="rounded-xl border border-slate-200 p-4">
            <dt className="text-xs font-medium uppercase tracking-wide text-slate-500">
              Registry state
            </dt>
            <dd className="mt-2 flex items-center gap-2 text-sm font-semibold text-slate-900">
              <ShieldCheck className="h-4 w-4 text-indigo-600" aria-hidden="true" />
              {active && identity.registered
                ? 'Active and registered'
                : active
                  ? 'Not registered'
                  : 'Revoked forever'}
            </dd>
          </div>
          <div className="rounded-xl border border-slate-200 p-4">
            <dt className="text-xs font-medium uppercase tracking-wide text-slate-500">
              Key suite
            </dt>
            <dd className="mt-2 text-sm font-semibold text-slate-900">
              Ed25519{identity.hasAgreementKey ? ' + X25519' : ''}
            </dd>
          </div>
        </dl>

        {needsRegistrationRecovery(identity) && (
          <div className="mt-5 rounded-2xl border border-amber-200 bg-amber-50 p-4 text-amber-950">
            <div className="flex items-start gap-3">
              <AlertTriangle
                className="mt-0.5 h-5 w-5 shrink-0 text-amber-600"
                aria-hidden="true"
              />
              <div className="min-w-0 flex-1">
                <h3 className="text-sm font-semibold">Finish registration safely</h3>
                <p className="mt-1 text-xs leading-relaxed text-amber-800">
                  The wallet kept this identity because the registry response may have been lost.
                  Retrying uses the same subject and is idempotent. Nexus will not delete local keys
                  until an irreversible revocation is confirmed.
                </p>
                <button
                  type="button"
                  onClick={onRetryRegistration}
                  disabled={retryingRegistration}
                  className="mt-3 inline-flex items-center gap-2 rounded-xl bg-amber-600 px-4 py-2.5 text-sm font-medium text-white shadow-sm transition-colors hover:bg-amber-700 disabled:cursor-not-allowed disabled:bg-amber-300"
                >
                  {retryingRegistration && <Loader2 className="h-4 w-4 animate-spin" />}
                  {retryingRegistration ? 'Retrying registration…' : 'Retry registration'}
                </button>
              </div>
            </div>
          </div>
        )}

        <div className="mt-6">
          <div className="mb-3 flex items-center gap-2">
            <Globe2 className="h-4 w-4 text-indigo-600" aria-hidden="true" />
            <h3 className="text-sm font-semibold text-slate-900">Locally remembered app scopes</h3>
          </div>
          {identity.localScopes.length === 0 ? (
            <div className="rounded-xl border border-dashed border-slate-300 bg-slate-50 p-4 text-sm text-slate-500">
              This identity has not been approved for an app origin. A scope is added only after you
              approve a cross-scope proof request.
            </div>
          ) : (
            <ul className="space-y-2">
              {identity.localScopes.map((origin) => (
                <li
                  key={origin}
                  className="flex items-center gap-2 rounded-xl border border-slate-200 px-3 py-2.5"
                >
                  <span className="h-2 w-2 shrink-0 rounded-full bg-emerald-500" />
                  <code className="min-w-0 truncate text-xs text-slate-700" title={origin}>
                    {origin}
                  </code>
                </li>
              ))}
            </ul>
          )}
          <p className="mt-2 text-xs leading-relaxed text-slate-400">
            Scope mappings stay in this wallet and are never stored in the Nexus registry.
          </p>
        </div>

        {registeredActions && (
          <div className="mt-6 grid gap-3 border-t border-slate-100 pt-6 sm:grid-cols-3">
            <button
              type="button"
              onClick={onRotate}
              className="flex items-center justify-center gap-2 rounded-xl border border-slate-200 px-4 py-2.5 text-sm font-medium text-slate-700 transition-all hover:border-indigo-300 hover:bg-indigo-50 hover:text-indigo-700"
            >
              <ArrowRightLeft className="h-4 w-4" /> Rotate
            </button>
            <button
              type="button"
              onClick={onContinuity}
              className="flex items-center justify-center gap-2 rounded-xl border border-slate-200 px-4 py-2.5 text-sm font-medium text-slate-700 transition-all hover:border-amber-300 hover:bg-amber-50 hover:text-amber-800"
            >
              <Link2 className="h-4 w-4" /> Link
            </button>
            <button
              type="button"
              onClick={onDispose}
              className="flex items-center justify-center gap-2 rounded-xl border border-rose-200 px-4 py-2.5 text-sm font-medium text-rose-700 transition-colors hover:bg-rose-50"
            >
              <Trash2 className="h-4 w-4" /> Dispose
            </button>
          </div>
        )}
      </div>
    </motion.section>
  );
}
