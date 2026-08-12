import { useEffect, useMemo, useState } from 'react';
import type { LocalIdentitySummary } from '@nexus/wallet-core';
import {
  AlertTriangle,
  ArrowRight,
  Braces,
  Clock3,
  FileKey2,
  Globe2,
  KeyRound,
  Loader2,
  LockKeyhole,
  ShieldCheck,
  X,
} from 'lucide-react';
import { motion } from 'motion/react';

import {
  selectProofProtocol,
  type NexusOwnershipProofProtocol,
  type PendingProofRequest,
} from '../lib/popup-protocol';
import { canCreateProof } from '../lib/identity-capabilities';
import { Brand } from './Brand';

interface ProofConsentScreenProps {
  pending: PendingProofRequest;
  identities: LocalIdentitySummary[];
  onApprove: (
    localId: string,
    rememberScope: boolean,
    proofProtocol: NexusOwnershipProofProtocol,
  ) => Promise<void>;
  onCancel: () => void;
}

export function identityProofProtocols(
  identity: LocalIdentitySummary,
): readonly NexusOwnershipProofProtocol[] {
  if (identity.device !== undefined) {
    return identity.device.localState === 'active' ? ['nexus.ownership-proof.v2'] : [];
  }
  return ['nexus.ownership-proof.v1'];
}

export function resolveConsentIdentityId(
  identities: readonly LocalIdentitySummary[],
  selectedId: string,
): string {
  const eligible = identities.filter(canCreateProof);
  if (eligible.some((identity) => identity.localId === selectedId)) return selectedId;
  return (
    eligible.find(
      (identity) => identity.device !== undefined && identity.device.localState === 'active',
    )?.localId ??
    eligible[0]?.localId ??
    ''
  );
}

export function requiresLegacyRootConfirmation(
  identity: LocalIdentitySummary | undefined,
  proofProtocol: NexusOwnershipProofProtocol | undefined,
): boolean {
  return identity?.device === undefined && proofProtocol === 'nexus.ownership-proof.v1';
}

export function ProofConsentScreen({
  pending,
  identities,
  onApprove,
  onCancel,
}: ProofConsentScreenProps) {
  const eligible = useMemo(
    () =>
      identities.filter(
        (identity) =>
          canCreateProof(identity) &&
          selectProofProtocol(pending.acceptedProofProtocols, identityProofProtocols(identity)) !==
            undefined,
      ),
    [identities, pending.acceptedProofProtocols],
  );
  const [selectedId, setSelectedId] = useState(() => resolveConsentIdentityId(eligible, ''));
  const [now, setNow] = useState(() => Math.floor(Date.now() / 1000));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [legacyRootConfirmed, setLegacyRootConfirmed] = useState(false);
  const selected = eligible.find((identity) => identity.localId === selectedId);
  const selectedProofProtocol =
    selected === undefined
      ? undefined
      : selectProofProtocol(pending.acceptedProofProtocols, identityProofProtocols(selected));
  const crossScope = selected !== undefined && !selected.localScopes.includes(pending.origin);
  const secondsRemaining = Math.max(0, pending.request.expiresAt - now);
  const expired = secondsRemaining === 0;
  const legacyRootProof = requiresLegacyRootConfirmation(selected, selectedProofProtocol);

  useEffect(() => {
    const handle = window.setInterval(() => setNow(Math.floor(Date.now() / 1000)), 250);
    return () => window.clearInterval(handle);
  }, []);

  useEffect(() => {
    setSelectedId((current) => resolveConsentIdentityId(eligible, current));
  }, [eligible]);

  useEffect(() => {
    setLegacyRootConfirmed(false);
  }, [selectedId]);

  const approve = async () => {
    if (
      selected === undefined ||
      selectedProofProtocol === undefined ||
      expired ||
      (legacyRootProof && !legacyRootConfirmed)
    )
      return;
    setBusy(true);
    setError(undefined);
    try {
      await onApprove(selected.localId, crossScope, selectedProofProtocol);
    } catch (cause) {
      setBusy(false);
      setError(cause instanceof Error ? cause.message : 'The wallet could not create this proof.');
    }
  };

  return (
    <div className="min-h-screen bg-slate-50 px-4 py-5 text-slate-900 sm:px-6 sm:py-8">
      <main className="mx-auto w-full max-w-lg">
        <div className="mb-5 flex items-center justify-between">
          <Brand compact />
          <div
            className={`flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium ${
              expired ? 'bg-red-100 text-red-800' : 'bg-slate-100 text-slate-600'
            }`}
          >
            <Clock3 className="h-3.5 w-3.5" aria-hidden="true" />
            {expired ? 'Expired' : `${String(secondsRemaining)}s`}
          </div>
        </div>

        <motion.section
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          aria-labelledby="consent-title"
          className="rounded-3xl border border-slate-200 bg-white p-6 shadow-sm sm:p-8"
        >
          <div className="flex flex-col items-center text-center">
            <div
              className="mb-5 flex items-center justify-center gap-3 sm:gap-4"
              aria-hidden="true"
            >
              <div className="flex h-14 w-14 shrink-0 items-center justify-center overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
                <img src="/logo.png" alt="" className="h-full w-full object-cover" />
              </div>
              <div className="relative h-6 w-20 shrink-0">
                <div className="absolute left-0 right-0 top-1/2 h-px -translate-y-px bg-gradient-to-r from-slate-200 via-indigo-200 to-slate-200" />
                {[0, 1, 2].map((index) => (
                  <motion.span
                    key={index}
                    className="absolute h-1.5 w-1.5 rounded-full bg-indigo-500 shadow-[0_0_8px_rgba(99,102,241,0.6)]"
                    style={{ top: 'calc(50% - 3px)' }}
                    animate={{ x: [0, 74], opacity: [0, 1, 1, 0] }}
                    transition={{
                      duration: 1.6,
                      repeat: Infinity,
                      delay: index * 0.55,
                      ease: 'linear',
                    }}
                  />
                ))}
              </div>
              <div className="flex h-14 w-14 shrink-0 items-center justify-center rounded-2xl border border-slate-200 bg-indigo-100 text-indigo-600 shadow-sm">
                <Globe2 className="h-7 w-7" />
              </div>
            </div>
            <h1 id="consent-title" className="text-2xl font-bold tracking-tight text-slate-900">
              Allow a bound proof?
            </h1>
            <p className="mt-2 max-w-sm text-sm leading-relaxed text-slate-500">
              Review every value. Your signature will be valid only for this exact origin, action,
              resource, and challenge.
            </p>
          </div>

          <div className="mt-6 rounded-2xl border border-indigo-200 bg-indigo-50 p-4">
            <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-indigo-700">
              <LockKeyhole className="h-4 w-4" aria-hidden="true" /> Exact requesting origin
            </div>
            <code className="mt-2 block break-all text-sm font-semibold text-indigo-950">
              {pending.origin}
            </code>
            <p className="mt-2 text-xs leading-relaxed text-indigo-700">
              Captured from the browser MessageEvent—not from request JSON or a URL parameter.
            </p>
          </div>

          <dl className="mt-4 grid gap-3">
            <BindingRow
              icon={<ShieldCheck className="h-4 w-4" />}
              label="Action"
              value={pending.request.action}
            />
            <BindingRow
              icon={<FileKey2 className="h-4 w-4" />}
              label="Resource"
              value={pending.request.resource}
            />
            <BindingRow
              icon={<Braces className="h-4 w-4" />}
              label="Context binding"
              value={pending.request.contextHash ?? 'Not supplied by this app'}
              muted={pending.request.contextHash === undefined}
            />
            <BindingRow
              icon={<KeyRound className="h-4 w-4" />}
              label="Single-use nonce"
              value={pending.request.nonce}
              compact
            />
          </dl>

          <div className="mt-5">
            <label
              htmlFor="proof-identity"
              className="ml-1 block text-sm font-medium text-slate-700"
            >
              Sign with identity
            </label>
            {eligible.length === 0 ? (
              <div className="mt-1.5 rounded-xl border border-amber-200 bg-amber-50 p-4 text-sm text-amber-900">
                No active, registered identity is available. Close this window, create one in your
                wallet, then try again.
              </div>
            ) : (
              <select
                id="proof-identity"
                value={selectedId}
                onChange={(event) => setSelectedId(event.target.value)}
                disabled={busy}
                className="mt-1.5 block w-full rounded-xl border border-slate-300 bg-white px-4 py-3 text-sm shadow-sm focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500"
              >
                {eligible.map((identity) => (
                  <option key={identity.localId} value={identity.localId}>
                    {identity.label ?? identity.subject}
                    {identity.device === undefined
                      ? ' — root key (legacy v1)'
                      : ' — device key (v2)'}
                  </option>
                ))}
              </select>
            )}
            {selected !== undefined && (
              <code
                className="ml-1 mt-2 block truncate text-xs text-slate-400"
                title={selected.subject}
              >
                {selected.subject}
              </code>
            )}
          </div>

          {crossScope && (
            <div
              role="alert"
              className="mt-4 flex items-start gap-3 rounded-xl border border-amber-200 bg-amber-50 p-4 text-sm text-amber-900"
            >
              <AlertTriangle
                className="mt-0.5 h-5 w-5 shrink-0 text-amber-600"
                aria-hidden="true"
              />
              <div>
                <div className="font-semibold">New app scope</div>
                <p className="mt-1 text-xs leading-relaxed">
                  This identity has not been used with <strong>{pending.origin}</strong>. Approving
                  will remember this origin locally and may make activity at this app linkable to
                  the same identity.
                </p>
              </div>
            </div>
          )}

          {legacyRootProof && (
            <div
              role="alert"
              className="mt-4 rounded-xl border border-rose-200 bg-rose-50 p-4 text-sm text-rose-950"
            >
              <div className="flex items-start gap-3">
                <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-rose-600" />
                <div>
                  <div className="font-semibold">Legacy root-key proof</div>
                  <p className="mt-1 text-xs leading-relaxed">
                    This signs directly with the identity's root key because this app accepts v1.
                    Prefer an active device key when possible; root compromise affects the whole
                    identity.
                  </p>
                </div>
              </div>
              <label className="mt-3 flex items-start gap-2 rounded-lg border border-rose-200 bg-white/70 p-3">
                <input
                  type="checkbox"
                  checked={legacyRootConfirmed}
                  onChange={(event) => setLegacyRootConfirmed(event.target.checked)}
                  disabled={busy}
                  className="mt-0.5 accent-rose-600"
                />
                <span className="text-xs font-semibold leading-relaxed">
                  Use this root key for this legacy v1 proof.
                </span>
              </label>
            </div>
          )}

          {expired && (
            <div
              role="alert"
              className="mt-4 flex items-start gap-2 rounded-xl border border-red-100 bg-red-50 p-3 text-sm text-red-700"
            >
              <X className="mt-0.5 h-4 w-4 shrink-0" /> The challenge expired. Return to the app and
              request a new one.
            </div>
          )}
          {error !== undefined && (
            <div
              role="alert"
              className="mt-4 flex items-start gap-2 rounded-xl border border-red-100 bg-red-50 p-3 text-sm text-red-700"
            >
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" /> {error}
            </div>
          )}

          <div className="mt-6 flex gap-2">
            <button
              type="button"
              onClick={onCancel}
              disabled={busy}
              className="flex flex-1 items-center justify-center rounded-xl border border-slate-200 bg-white px-4 py-3 text-sm font-medium text-slate-700 transition-colors hover:bg-slate-50 disabled:opacity-50"
            >
              Deny
            </button>
            <button
              type="button"
              onClick={() => void approve()}
              disabled={
                busy ||
                expired ||
                selectedProofProtocol === undefined ||
                (legacyRootProof && !legacyRootConfirmed)
              }
              className="flex flex-[1.4] items-center justify-center gap-2 rounded-xl bg-indigo-600 px-4 py-3 text-sm font-medium text-white shadow-sm transition-colors hover:bg-indigo-700 disabled:cursor-not-allowed disabled:bg-indigo-400"
            >
              {busy ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <ArrowRight className="h-4 w-4" />
              )}
              {busy ? 'Signing…' : crossScope ? 'Approve new scope' : 'Approve and sign'}
            </button>
          </div>
        </motion.section>

        <p className="mt-4 text-center text-xs leading-relaxed text-slate-500">
          The response is pinned to <code>{pending.origin}</code>. ROwO Nexus never broadcasts
          proofs.
        </p>
      </main>
    </div>
  );
}

interface BindingRowProps {
  icon: React.ReactNode;
  label: string;
  value: string;
  muted?: boolean;
  compact?: boolean;
}

function BindingRow({ icon, label, value, muted = false, compact = false }: BindingRowProps) {
  return (
    <div className="rounded-xl border border-slate-200 p-3.5">
      <dt className="flex items-center gap-2 text-xs font-medium uppercase tracking-wide text-slate-500">
        <span className="text-indigo-600">{icon}</span> {label}
      </dt>
      <dd
        className={`mt-1.5 break-all font-mono text-sm ${muted ? 'italic text-slate-400' : 'text-slate-900'} ${
          compact ? 'line-clamp-2 text-xs' : ''
        }`}
        title={value}
      >
        {value}
      </dd>
    </div>
  );
}
