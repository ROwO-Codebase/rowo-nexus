import { useState } from 'react';
import {
  AlertTriangle,
  Check,
  Copy,
  History,
  KeyRound,
  Loader2,
  LockKeyhole,
  Unplug,
} from 'lucide-react';
import { motion } from 'motion/react';
import type { LocalIdentitySummary } from '@nexus/wallet-core';

import { needsRegistrationRecovery } from '../lib/identity-capabilities';

interface IdentityCardProps {
  identity: LocalIdentitySummary;
  selected: boolean;
  onSelect: () => void;
  retryingRegistration: boolean;
  onRetryRegistration: () => void;
}

export function IdentityCard({
  identity,
  selected,
  onSelect,
  retryingRegistration,
  onRetryRegistration,
}: IdentityCardProps) {
  const [copied, setCopied] = useState(false);
  const active = identity.localState === 'active';
  const deviceState = identity.device?.localState;
  const deviceRevoked = deviceState === 'revoked' || identity.device?.registryState === 'revoked';
  const deviceExpired =
    identity.device !== undefined &&
    (identity.device.registryState === 'expired' ||
      Math.floor(Date.now() / 1_000) >= identity.device.expiresAt);
  const terminal = !active || deviceRevoked;
  const statusLabel = deviceRevoked
    ? 'Revoked device'
    : deviceExpired
      ? 'Expired device'
      : deviceState === 'pending-activation'
        ? 'Pending activation'
        : deviceState === 'active'
          ? 'Active device'
          : active
            ? identity.registered
              ? 'Active'
              : 'Unregistered'
            : 'Disposed';
  const ready = identity.proofReady;

  const copySubject = async () => {
    await navigator.clipboard.writeText(identity.subject);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1_500);
  };

  return (
    <motion.article
      layout
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      {...(!terminal ? { whileHover: { y: -2 } } : {})}
      className={`overflow-hidden rounded-2xl border bg-white transition-all ${
        selected
          ? 'border-indigo-300 ring-2 ring-indigo-100'
          : 'border-slate-200 hover:border-indigo-200 hover:shadow-sm'
      }`}
    >
      <div className="p-5">
        <div className="flex items-start gap-3">
          <div
            className={`flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl ${
              !terminal ? 'bg-indigo-100 text-indigo-600' : 'bg-slate-100 text-slate-500'
            }`}
          >
            {!terminal ? (
              <KeyRound className="h-5 w-5" aria-hidden="true" />
            ) : (
              <Unplug className="h-5 w-5" aria-hidden="true" />
            )}
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <h2 className="truncate font-semibold text-slate-900">
                {identity.label ?? 'Untitled identity'}
              </h2>
              <span
                className={`inline-flex items-center gap-1 rounded-full px-2.5 py-1 text-xs font-medium ${
                  !terminal
                    ? ready
                      ? 'bg-emerald-100 text-emerald-800'
                      : 'bg-amber-100 text-amber-800'
                    : 'bg-rose-100 text-rose-800'
                }`}
              >
                <span
                  className={`h-1.5 w-1.5 rounded-full ${
                    !terminal ? (ready ? 'bg-emerald-500' : 'bg-amber-500') : 'bg-rose-500'
                  }`}
                />
                {statusLabel}
              </span>
            </div>
            <div className="mt-1 flex items-center gap-1.5">
              <code className="min-w-0 truncate text-xs text-slate-500" title={identity.subject}>
                {identity.subject}
              </code>
              <button
                type="button"
                onClick={() => void copySubject()}
                className="shrink-0 rounded p-1 text-slate-400 transition-colors hover:bg-slate-100 hover:text-slate-700"
                aria-label={copied ? 'Subject copied' : 'Copy subject'}
              >
                {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
              </button>
            </div>
          </div>
        </div>

        {needsRegistrationRecovery(identity) && (
          <div className="mt-4 rounded-xl border border-amber-200 bg-amber-50 p-3 text-amber-950">
            <div className="flex items-start gap-2">
              <AlertTriangle
                className="mt-0.5 h-4 w-4 shrink-0 text-amber-600"
                aria-hidden="true"
              />
              <div className="min-w-0 flex-1">
                <div className="text-sm font-semibold">Registration response was not retained</div>
                <p className="mt-1 text-xs leading-relaxed text-amber-800">
                  Your local keys are safe. Retry the same idempotent registration before using this
                  identity.
                </p>
                <button
                  type="button"
                  onClick={onRetryRegistration}
                  disabled={retryingRegistration}
                  className="mt-3 inline-flex items-center gap-2 rounded-lg bg-amber-600 px-3 py-2 text-xs font-semibold text-white transition-colors hover:bg-amber-700 disabled:cursor-not-allowed disabled:bg-amber-300"
                >
                  {retryingRegistration && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
                  {retryingRegistration ? 'Retrying…' : 'Retry registration'}
                </button>
              </div>
            </div>
          </div>
        )}

        <div className="mt-5 flex items-center justify-between border-t border-slate-100 pt-4">
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-slate-500">
            <span className="inline-flex items-center gap-1.5">
              <LockKeyhole className="h-3.5 w-3.5" aria-hidden="true" />
              {identity.localScopes.length === 0
                ? 'No app scopes'
                : `${String(identity.localScopes.length)} app ${identity.localScopes.length === 1 ? 'scope' : 'scopes'}`}
            </span>
            <span className="inline-flex items-center gap-1.5">
              <History className="h-3.5 w-3.5" aria-hidden="true" />
              {identity.authorizationHistory.length === 0
                ? 'No history'
                : `${String(identity.authorizationHistory.length)} ${identity.authorizationHistory.length === 1 ? 'authorization' : 'authorizations'}`}
            </span>
          </div>
          <button
            type="button"
            onClick={onSelect}
            className="rounded-lg px-3 py-1.5 text-sm font-medium text-indigo-600 transition-colors hover:bg-indigo-50 hover:text-indigo-700"
          >
            {selected ? 'Hide details' : 'View details'}
          </button>
        </div>
      </div>
    </motion.article>
  );
}
