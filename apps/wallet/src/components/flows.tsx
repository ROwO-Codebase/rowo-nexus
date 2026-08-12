import { useMemo, useState, type FormEvent } from 'react';
import type { ContinuityLinkV1 } from '@nexus/protocol';
import type { LocalIdentitySummary } from '@nexus/wallet-core';
import {
  AlertTriangle,
  ArrowRightLeft,
  CheckCircle2,
  Download,
  KeyRound,
  Link2,
  Loader2,
  ShieldAlert,
  Sparkles,
  Trash2,
} from 'lucide-react';

import type { CreateIdentityInput, RotateIdentityInput } from '../lib/wallet-adapter';
import { ModalShell } from './ModalShell';

interface AsyncFormState {
  busy: boolean;
  error?: string;
}

const idle: AsyncFormState = { busy: false };

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'The wallet could not complete this operation.';
}

interface CreateIdentityModalProps {
  onClose: () => void;
  onCreate: (input: CreateIdentityInput) => Promise<void>;
}

export function CreateIdentityModal({ onClose, onCreate }: CreateIdentityModalProps) {
  const [label, setLabel] = useState('');
  const [withAgreementKey, setWithAgreementKey] = useState(false);
  const [state, setState] = useState<AsyncFormState>(idle);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setState({ busy: true });
    try {
      const normalized = label.trim();
      await onCreate({
        ...(normalized === '' ? {} : { label: normalized }),
        withAgreementKey,
      });
    } catch (error) {
      setState({ busy: false, error: errorMessage(error) });
    }
  };

  return (
    <ModalShell
      title="Create an identity"
      description="Generate an independent identity with new random key material."
      icon={<Sparkles className="h-5 w-5" aria-hidden="true" />}
      onClose={onClose}
      closeDisabled={state.busy}
    >
      <form onSubmit={(event) => void submit(event)} className="space-y-5">
        <div>
          <label htmlFor="identity-label" className="ml-1 block text-sm font-medium text-slate-700">
            Local nickname <span className="font-normal text-slate-400">(optional)</span>
          </label>
          <input
            id="identity-label"
            value={label}
            onChange={(event) => setLabel(event.target.value)}
            maxLength={48}
            autoComplete="off"
            placeholder="e.g. Campus forum"
            className="mt-1.5 block w-full rounded-xl border border-slate-300 px-4 py-3 text-sm shadow-sm transition-colors placeholder:text-slate-400 focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500"
          />
          <p className="ml-1 mt-1.5 text-xs text-slate-500">
            Labels stay on this device and are never sent to the registry or an app.
          </p>
        </div>

        <label className="flex items-start gap-3 rounded-xl border border-slate-200 p-4 transition-colors hover:border-indigo-300">
          <input
            type="checkbox"
            checked={withAgreementKey}
            onChange={(event) => setWithAgreementKey(event.target.checked)}
            className="mt-1 accent-indigo-600"
          />
          <span>
            <span className="block text-sm font-medium text-slate-900">Add an encryption key</span>
            <span className="mt-1 block text-xs leading-relaxed text-slate-500">
              Also generate an X25519 agreement key for apps that support encrypted collaboration.
            </span>
          </span>
        </label>

        <div className="rounded-xl border border-indigo-100 bg-indigo-50 p-4 text-sm leading-relaxed text-indigo-900">
          <div className="mb-1 flex items-center gap-2 font-semibold">
            <KeyRound className="h-4 w-4" aria-hidden="true" /> Independent by design
          </div>
          This identity is not derived from another identity or a reusable master seed. Its private
          key stays in this browser.
        </div>

        {state.error !== undefined && <ErrorNotice message={state.error} />}

        <div className="flex gap-2 pt-1">
          <button type="button" onClick={onClose} disabled={state.busy} className={secondaryButton}>
            Cancel
          </button>
          <button type="submit" disabled={state.busy} className={primaryButton}>
            {state.busy && <Loader2 className="h-4 w-4 animate-spin" />}
            {state.busy ? 'Creating…' : 'Create identity'}
          </button>
        </div>
      </form>
    </ModalShell>
  );
}

interface DisposeIdentityModalProps {
  identity: LocalIdentitySummary;
  onClose: () => void;
  onDispose: () => Promise<void>;
}

export function DisposeIdentityModal({ identity, onClose, onDispose }: DisposeIdentityModalProps) {
  const confirmation = identity.label ?? 'DISPOSE';
  const [typed, setTyped] = useState('');
  const [state, setState] = useState<AsyncFormState>(idle);
  const confirmed = typed === confirmation;

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!confirmed) return;
    setState({ busy: true });
    try {
      await onDispose();
    } catch (error) {
      setState({ busy: false, error: errorMessage(error) });
    }
  };

  return (
    <ModalShell
      title="Dispose identity forever"
      description="This is a terminal registry action and cannot be undone."
      icon={<Trash2 className="h-5 w-5" aria-hidden="true" />}
      onClose={onClose}
      closeDisabled={state.busy}
    >
      <form onSubmit={(event) => void submit(event)} className="space-y-5">
        <div className="rounded-xl border border-rose-200 bg-rose-50 p-4 text-sm leading-relaxed text-rose-900">
          <div className="mb-2 flex items-center gap-2 font-semibold">
            <ShieldAlert className="h-4 w-4" aria-hidden="true" /> Cryptographically disabled
          </div>
          Nexus will publish an irreversible revocation and wait for a valid receipt. After that,
          this wallet erases its active key references. The identity will be cryptographically
          disabled for future control—even if an old copy of the key survives elsewhere.
        </div>
        <p className="text-sm leading-relaxed text-slate-600">
          Browser and operating-system storage cannot promise physical secure erasure. Nexus does
          not claim that this action physically destroys every possible copy.
        </p>
        <div>
          <label
            htmlFor="dispose-confirmation"
            className="ml-1 block text-sm font-medium text-slate-700"
          >
            Type <strong className="font-mono text-slate-900">{confirmation}</strong> to confirm
          </label>
          <input
            id="dispose-confirmation"
            value={typed}
            onChange={(event) => setTyped(event.target.value)}
            autoComplete="off"
            spellCheck={false}
            className="mt-1.5 block w-full rounded-xl border border-slate-300 px-4 py-3 text-sm shadow-sm focus:border-rose-500 focus:ring-2 focus:ring-rose-500"
          />
        </div>
        {state.error !== undefined && <ErrorNotice message={state.error} />}
        <div className="flex gap-2">
          <button type="button" onClick={onClose} disabled={state.busy} className={secondaryButton}>
            Keep identity
          </button>
          <button
            type="submit"
            disabled={state.busy || !confirmed}
            className="flex flex-1 items-center justify-center gap-2 rounded-xl bg-rose-600 px-4 py-2.5 text-sm font-medium text-white shadow-sm transition-colors hover:bg-rose-700 disabled:cursor-not-allowed disabled:bg-rose-300"
          >
            {state.busy && <Loader2 className="h-4 w-4 animate-spin" />}
            {state.busy ? 'Revoking…' : 'Dispose forever'}
          </button>
        </div>
      </form>
    </ModalShell>
  );
}

interface RotateIdentityModalProps {
  identity: LocalIdentitySummary;
  onClose: () => void;
  onRotate: (input: RotateIdentityInput) => Promise<void>;
}

export function RotateIdentityModal({ identity, onClose, onRotate }: RotateIdentityModalProps) {
  const [label, setLabel] = useState(identity.label === undefined ? '' : `${identity.label} · new`);
  const [revokeOld, setRevokeOld] = useState(false);
  const [state, setState] = useState<AsyncFormState>(idle);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setState({ busy: true });
    try {
      const normalized = label.trim();
      await onRotate({
        ...(normalized === '' ? {} : { label: normalized }),
        withAgreementKey: identity.hasAgreementKey,
        revokeOld,
      });
    } catch (error) {
      setState({ busy: false, error: errorMessage(error) });
    }
  };

  return (
    <ModalShell
      title="Rotate privately"
      description="Create a new, unrelated identity without publishing an old/new relationship."
      icon={<ArrowRightLeft className="h-5 w-5" aria-hidden="true" />}
      onClose={onClose}
      closeDisabled={state.busy}
    >
      <form onSubmit={(event) => void submit(event)} className="space-y-5">
        <div className="rounded-xl border border-emerald-100 bg-emerald-50 p-4 text-sm leading-relaxed text-emerald-900">
          <div className="mb-1 flex items-center gap-2 font-semibold">
            <CheckCircle2 className="h-4 w-4" aria-hidden="true" /> Unlinkable by default
          </div>
          Rotation generates independent random keys and registers a new subject. Nexus sends no
          rotation event and stores no relation between the two identities.
        </div>
        <div>
          <label htmlFor="rotated-label" className="ml-1 block text-sm font-medium text-slate-700">
            New local nickname
          </label>
          <input
            id="rotated-label"
            value={label}
            onChange={(event) => setLabel(event.target.value)}
            maxLength={48}
            autoComplete="off"
            className="mt-1.5 block w-full rounded-xl border border-slate-300 px-4 py-3 text-sm shadow-sm focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500"
          />
        </div>
        <label className="flex items-start gap-3 rounded-xl border border-slate-200 p-4">
          <input
            type="checkbox"
            checked={revokeOld}
            onChange={(event) => setRevokeOld(event.target.checked)}
            className="mt-1 accent-indigo-600"
          />
          <span>
            <span className="block text-sm font-medium text-slate-900">
              Dispose the old identity afterward
            </span>
            <span className="mt-1 block text-xs leading-relaxed text-slate-500">
              The new identity is created first. Then the old identity is terminally revoked and its
              active key references are erased.
            </span>
          </span>
        </label>
        {state.error !== undefined && <ErrorNotice message={state.error} />}
        <div className="flex gap-2">
          <button type="button" onClick={onClose} disabled={state.busy} className={secondaryButton}>
            Cancel
          </button>
          <button type="submit" disabled={state.busy} className={primaryButton}>
            {state.busy && <Loader2 className="h-4 w-4 animate-spin" />}
            {state.busy ? 'Rotating…' : 'Create unrelated identity'}
          </button>
        </div>
      </form>
    </ModalShell>
  );
}

interface ContinuityLinkModalProps {
  identity: LocalIdentitySummary;
  identities: LocalIdentitySummary[];
  onClose: () => void;
  onLink: (otherLocalId: string, scope?: string) => Promise<ContinuityLinkV1>;
}

export function ContinuityLinkModal({
  identity,
  identities,
  onClose,
  onLink,
}: ContinuityLinkModalProps) {
  const candidates = useMemo(
    () =>
      identities.filter(
        (candidate) =>
          candidate.localId !== identity.localId &&
          candidate.localState === 'active' &&
          candidate.registered,
      ),
    [identities, identity.localId],
  );
  const [otherId, setOtherId] = useState(candidates[0]?.localId ?? '');
  const [scope, setScope] = useState('');
  const [understood, setUnderstood] = useState(false);
  const [state, setState] = useState<AsyncFormState>(idle);
  const [certificate, setCertificate] = useState<ContinuityLinkV1>();

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!understood || otherId === '') return;
    setState({ busy: true });
    try {
      const normalized = scope.trim();
      setCertificate(await onLink(otherId, normalized === '' ? undefined : normalized));
      setState({ busy: false });
    } catch (error) {
      setState({ busy: false, error: errorMessage(error) });
    }
  };

  const download = () => {
    if (certificate === undefined) return;
    const url = URL.createObjectURL(
      new Blob([`${JSON.stringify(certificate, null, 2)}\n`], { type: 'application/nexus+json' }),
    );
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = 'nexus-continuity-link.json';
    anchor.click();
    URL.revokeObjectURL(url);
  };

  return (
    <ModalShell
      title="Advanced: link identities"
      description="Publishable proof that two otherwise independent subjects belong to the same controller."
      icon={<Link2 className="h-5 w-5" aria-hidden="true" />}
      onClose={onClose}
      closeDisabled={state.busy}
      maxWidth="lg"
    >
      {certificate === undefined ? (
        <form onSubmit={(event) => void submit(event)} className="space-y-5">
          <div className="rounded-xl border border-amber-200 bg-amber-50 p-4 text-sm leading-relaxed text-amber-950">
            <div className="mb-2 flex items-center gap-2 font-semibold">
              <AlertTriangle className="h-4 w-4" aria-hidden="true" /> This defeats unlinkability
            </div>
            A continuity certificate permanently makes the two subjects linkable anywhere the
            certificate is shared. Rotation does not need this. Use it only when public continuity
            is more important than privacy.
          </div>
          {candidates.length === 0 ? (
            <div className="rounded-xl border border-dashed border-slate-300 bg-slate-50 p-4 text-sm text-slate-600">
              Create and register another active identity before making a continuity link.
            </div>
          ) : (
            <>
              <div>
                <label
                  htmlFor="continuity-target"
                  className="ml-1 block text-sm font-medium text-slate-700"
                >
                  Link with
                </label>
                <select
                  id="continuity-target"
                  value={otherId}
                  onChange={(event) => setOtherId(event.target.value)}
                  className="mt-1.5 block w-full rounded-xl border border-slate-300 bg-white px-4 py-3 text-sm shadow-sm focus:border-amber-500 focus:ring-2 focus:ring-amber-500"
                >
                  {candidates.map((candidate) => (
                    <option key={candidate.localId} value={candidate.localId}>
                      {candidate.label ?? candidate.subject}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label
                  htmlFor="continuity-scope"
                  className="ml-1 block text-sm font-medium text-slate-700"
                >
                  Public scope <span className="font-normal text-slate-400">(optional)</span>
                </label>
                <input
                  id="continuity-scope"
                  value={scope}
                  onChange={(event) => setScope(event.target.value)}
                  maxLength={120}
                  placeholder="e.g. project:example"
                  className="mt-1.5 block w-full rounded-xl border border-slate-300 px-4 py-3 text-sm shadow-sm focus:border-amber-500 focus:ring-2 focus:ring-amber-500"
                />
              </div>
              <label className="flex items-start gap-3 rounded-xl border border-amber-200 p-4">
                <input
                  type="checkbox"
                  checked={understood}
                  onChange={(event) => setUnderstood(event.target.checked)}
                  className="mt-1 accent-amber-600"
                />
                <span className="text-sm font-medium leading-relaxed text-slate-800">
                  I understand this creates a portable, permanent cryptographic link between both
                  identities.
                </span>
              </label>
            </>
          )}
          {state.error !== undefined && <ErrorNotice message={state.error} />}
          <div className="flex gap-2">
            <button
              type="button"
              onClick={onClose}
              disabled={state.busy}
              className={secondaryButton}
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={state.busy || !understood || otherId === ''}
              className="flex flex-1 items-center justify-center gap-2 rounded-xl bg-amber-600 px-4 py-2.5 text-sm font-medium text-white shadow-sm transition-colors hover:bg-amber-700 disabled:cursor-not-allowed disabled:bg-amber-300"
            >
              {state.busy && <Loader2 className="h-4 w-4 animate-spin" />}
              Create public link
            </button>
          </div>
        </form>
      ) : (
        <div className="space-y-5">
          <div className="rounded-xl border border-emerald-200 bg-emerald-50 p-4 text-sm text-emerald-900">
            <div className="flex items-center gap-2 font-semibold">
              <CheckCircle2 className="h-4 w-4" /> Continuity certificate created
            </div>
            <p className="mt-1 leading-relaxed">
              It has two signatures and is ready to share. Nexus does not publish it automatically.
            </p>
          </div>
          <button type="button" onClick={download} className={primaryButton}>
            <Download className="h-4 w-4" /> Download certificate
          </button>
          <button type="button" onClick={onClose} className={secondaryButton}>
            Done
          </button>
        </div>
      )}
    </ModalShell>
  );
}

function ErrorNotice({ message }: { message: string }) {
  return (
    <div
      role="alert"
      className="flex items-start gap-2 rounded-xl border border-red-100 bg-red-50 p-3 text-sm text-red-700"
    >
      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
      <span>{message}</span>
    </div>
  );
}

const secondaryButton =
  'flex flex-1 items-center justify-center gap-2 rounded-xl border border-slate-200 bg-white px-4 py-2.5 text-sm font-medium text-slate-700 transition-colors hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-50';
const primaryButton =
  'flex flex-1 items-center justify-center gap-2 rounded-xl bg-indigo-600 px-4 py-2.5 text-sm font-medium text-white shadow-sm transition-colors hover:bg-indigo-700 disabled:cursor-not-allowed disabled:bg-indigo-400';
