import { useState } from 'react';
import {
  AlertTriangle,
  ArrowRightLeft,
  Clock3,
  Fingerprint,
  Globe2,
  History,
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
  clearingHistory: boolean;
  onClearHistory: () => Promise<void>;
}

export function IdentityDetail({
  identity,
  onClose,
  onRotate,
  onDispose,
  onContinuity,
  retryingRegistration,
  onRetryRegistration,
  clearingHistory,
  onClearHistory,
}: IdentityDetailProps) {
  const active = identity.localState === 'active';
  const registeredActions = canUseRegisteredIdentityActions(identity);
  const [confirmClearHistory, setConfirmClearHistory] = useState(false);

  const clearHistory = async () => {
    if (!confirmClearHistory) {
      setConfirmClearHistory(true);
      return;
    }
    await onClearHistory();
    setConfirmClearHistory(false);
  };

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

        <div className="mt-6 border-t border-slate-100 pt-6">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <History className="h-4 w-4 text-indigo-600" aria-hidden="true" />
              <h3 className="text-sm font-semibold text-slate-900">Authorization history</h3>
              {identity.authorizationHistory.length > 0 && (
                <span className="rounded-full bg-indigo-50 px-2 py-0.5 text-xs font-semibold text-indigo-700">
                  {String(identity.authorizationHistory.length)}
                </span>
              )}
            </div>
            {identity.authorizationHistory.length > 0 && (
              <button
                type="button"
                onClick={() => void clearHistory()}
                disabled={clearingHistory}
                className={`rounded-lg px-3 py-1.5 text-xs font-semibold transition-colors disabled:cursor-not-allowed disabled:opacity-60 ${
                  confirmClearHistory
                    ? 'bg-rose-600 text-white hover:bg-rose-700'
                    : 'text-slate-500 hover:bg-slate-100 hover:text-slate-700'
                }`}
              >
                {clearingHistory
                  ? 'Clearing…'
                  : confirmClearHistory
                    ? 'Confirm clear'
                    : 'Clear history'}
              </button>
            )}
          </div>

          {identity.authorizationHistory.length === 0 ? (
            <div className="rounded-xl border border-dashed border-slate-300 bg-slate-50 p-4 text-sm text-slate-500">
              No proof authorizations have been recorded for this identity in this browser.
            </div>
          ) : (
            <ol className="max-h-96 space-y-2 overflow-y-auto pr-1">
              {identity.authorizationHistory.map((entry) => {
                const approvedAt = new Date(entry.approvedAt * 1_000);
                return (
                  <li
                    key={entry.authorizationId}
                    className="rounded-xl border border-slate-200 p-3.5"
                  >
                    <div className="flex flex-wrap items-start justify-between gap-2">
                      <code
                        className="min-w-0 truncate text-xs font-semibold text-indigo-700"
                        title={entry.audience}
                      >
                        {entry.audience}
                      </code>
                      <time
                        dateTime={approvedAt.toISOString()}
                        className="inline-flex shrink-0 items-center gap-1 text-xs text-slate-400"
                      >
                        <Clock3 className="h-3 w-3" aria-hidden="true" />
                        {approvedAt.toLocaleString()}
                      </time>
                    </div>
                    <div className="mt-2 grid gap-1.5 text-xs sm:grid-cols-[auto_1fr]">
                      <span className="font-medium text-slate-500">Action</span>
                      <code className="break-all text-slate-800">{entry.action}</code>
                      <span className="font-medium text-slate-500">Resource</span>
                      <code className="break-all text-slate-800">{entry.resource}</code>
                    </div>
                    {(entry.introducedScope || entry.contextBound) && (
                      <div className="mt-2 flex flex-wrap gap-1.5">
                        {entry.introducedScope && (
                          <span className="rounded-full bg-amber-50 px-2 py-0.5 text-[11px] font-medium text-amber-800">
                            New app scope
                          </span>
                        )}
                        {entry.contextBound && (
                          <span className="rounded-full bg-emerald-50 px-2 py-0.5 text-[11px] font-medium text-emerald-800">
                            Context-bound
                          </span>
                        )}
                      </div>
                    )}
                  </li>
                );
              })}
            </ol>
          )}
          <p className="mt-2 text-xs leading-relaxed text-slate-400">
            Stored only in this browser, up to 200 entries per identity. It contains no proofs,
            signatures, nonces, or key material. Actions covered by an app's own session are not
            visible to the wallet.
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
