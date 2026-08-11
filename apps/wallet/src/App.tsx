import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { LocalIdentitySummary } from '@nexus/wallet-core';
import {
  AlertTriangle,
  Fingerprint,
  KeyRound,
  Loader2,
  LockKeyhole,
  Plus,
  ShieldCheck,
  Sparkles,
} from 'lucide-react';
import { AnimatePresence, motion } from 'motion/react';

import { IdentityCard } from './components/IdentityCard';
import { IdentityDetail } from './components/IdentityDetail';
import { ProofConsentScreen } from './components/ProofConsentScreen';
import { WalletLayout } from './components/WalletLayout';
import {
  ContinuityLinkModal,
  CreateIdentityModal,
  DisposeIdentityModal,
  RotateIdentityModal,
} from './components/flows';
import {
  announceWalletReady,
  parseProofRequestMessage,
  postProofError,
  postProofResult,
  type PendingProofRequest,
} from './lib/popup-protocol';
import {
  walletAdapter,
  type CreateIdentityInput,
  type RotateIdentityInput,
} from './lib/wallet-adapter';

type Flow =
  | { type: 'create' }
  | { type: 'dispose'; identity: LocalIdentitySummary }
  | { type: 'rotate'; identity: LocalIdentitySummary }
  | { type: 'continuity'; identity: LocalIdentitySummary };

interface Notice {
  kind: 'success' | 'error';
  message: string;
}

function App() {
  const [identities, setIdentities] = useState<LocalIdentitySummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string>();
  const [selectedId, setSelectedId] = useState<string>();
  const [flow, setFlow] = useState<Flow>();
  const [notice, setNotice] = useState<Notice>();
  const [pending, setPending] = useState<PendingProofRequest>();
  const [retryingRegistrationId, setRetryingRegistrationId] = useState<string>();
  const pendingRef = useRef<PendingProofRequest | undefined>(undefined);

  const refresh = useCallback(async () => {
    try {
      const next = await walletAdapter.listIdentities();
      setIdentities(next);
      setLoadError(undefined);
    } catch (error) {
      setLoadError(
        error instanceof Error ? error.message : 'The wallet storage could not be opened.',
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(() => {
    const opener = window.opener as Window | null;
    if (opener === null) return;
    const onMessage = (event: MessageEvent<unknown>) => {
      if (pendingRef.current !== undefined) return;
      const request = parseProofRequestMessage(event, opener);
      if (request === undefined) return;
      pendingRef.current = request;
      setPending(request);
    };
    window.addEventListener('message', onMessage);
    announceWalletReady(opener);
    return () => window.removeEventListener('message', onMessage);
  }, []);

  useEffect(() => {
    if (notice === undefined) return;
    const handle = window.setTimeout(() => setNotice(undefined), 5_000);
    return () => window.clearTimeout(handle);
  }, [notice]);

  const selectedIdentity = useMemo(
    () => identities.find((identity) => identity.localId === selectedId),
    [identities, selectedId],
  );
  const activeCount = identities.filter((identity) => identity.localState === 'active').length;
  const scopedCount = identities.filter((identity) => identity.localScopes.length > 0).length;

  const createIdentity = async (input: CreateIdentityInput) => {
    const created = await walletAdapter.createIdentity(input);
    await refresh();
    setSelectedId(created.localId);
    setFlow(undefined);
    setNotice({ kind: 'success', message: 'Independent identity created and registered.' });
  };

  const retryRegistration = async (identity: LocalIdentitySummary) => {
    if (retryingRegistrationId !== undefined) return;
    setRetryingRegistrationId(identity.localId);
    try {
      await walletAdapter.retryRegistration(identity.localId);
      await refresh();
      setNotice({ kind: 'success', message: 'Identity registration recovered successfully.' });
    } catch (error) {
      setNotice({
        kind: 'error',
        message:
          error instanceof Error ? error.message : 'The wallet could not retry registration.',
      });
    } finally {
      setRetryingRegistrationId(undefined);
    }
  };

  const disposeIdentity = async (identity: LocalIdentitySummary) => {
    await walletAdapter.dispose(identity.localId);
    await refresh();
    setFlow(undefined);
    setNotice({
      kind: 'success',
      message: 'Identity revoked. It is cryptographically disabled for future control.',
    });
  };

  const rotateIdentity = async (identity: LocalIdentitySummary, input: RotateIdentityInput) => {
    const created = await walletAdapter.rotate(identity.localId, input);
    await refresh();
    setSelectedId(created.localId);
    setFlow(undefined);
    setNotice({
      kind: 'success',
      message: input.revokeOld
        ? 'Unrelated identity created; the old identity was disposed.'
        : 'Unrelated identity created. No old/new link was published.',
    });
  };

  const approveProof = async (localId: string, rememberScope: boolean) => {
    if (pending === undefined) return;
    const proof = await walletAdapter.prove(
      localId,
      pending.boundary,
      pending.request,
      rememberScope,
    );
    postProofResult(pending, proof);
    window.close();
    pendingRef.current = undefined;
    setPending(undefined);
  };

  const cancelProof = () => {
    if (pending === undefined) return;
    postProofError(
      pending,
      pending.request.expiresAt <= Math.floor(Date.now() / 1000)
        ? 'CHALLENGE_EXPIRED'
        : 'USER_CANCELLED',
    );
    window.close();
    pendingRef.current = undefined;
    setPending(undefined);
  };

  if (pending !== undefined) {
    return (
      <ProofConsentScreen
        pending={pending}
        identities={identities}
        onApprove={approveProof}
        onCancel={cancelProof}
      />
    );
  }

  return (
    <WalletLayout>
      <div aria-live="polite" className="fixed right-4 top-20 z-40 max-w-sm sm:right-6">
        <AnimatePresence>
          {notice !== undefined && (
            <motion.div
              initial={{ opacity: 0, y: -8, scale: 0.98 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: -8, scale: 0.98 }}
              role="status"
              className={`flex items-start gap-2 rounded-xl border p-3 text-sm shadow-lg ${
                notice.kind === 'success'
                  ? 'border-emerald-200 bg-emerald-50 text-emerald-800'
                  : 'border-red-200 bg-red-50 text-red-700'
              }`}
            >
              {notice.kind === 'success' ? (
                <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0" />
              ) : (
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
              )}
              {notice.message}
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      <motion.section
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        className="relative overflow-hidden rounded-3xl bg-gradient-to-br from-indigo-600 via-violet-600 to-cyan-600 p-6 text-white shadow-lg shadow-indigo-200/60 sm:p-8"
      >
        <div
          className="absolute -right-12 -top-16 h-40 w-40 rounded-full bg-white/10 blur-2xl"
          aria-hidden="true"
        />
        <div className="relative flex flex-col gap-6 sm:flex-row sm:items-end sm:justify-between">
          <div className="max-w-2xl">
            <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-2xl bg-white/15 ring-1 ring-white/25">
              <Fingerprint className="h-6 w-6" aria-hidden="true" />
            </div>
            <p className="text-sm font-medium text-indigo-100">Your private identity wallet</p>
            <h1 className="mt-1 text-3xl font-bold tracking-tight sm:text-4xl">
              Choose who you are, each time.
            </h1>
            <p className="mt-3 max-w-xl text-sm leading-relaxed text-indigo-50 sm:text-base">
              Create independent cryptographic identities, prove control without an account, and
              dispose of any identity permanently.
            </p>
          </div>
          <button
            type="button"
            onClick={() => setFlow({ type: 'create' })}
            className="inline-flex shrink-0 items-center justify-center gap-2 rounded-xl bg-white px-5 py-3 text-sm font-bold text-indigo-600 shadow-sm transition-all hover:-translate-y-0.5 hover:bg-indigo-50"
          >
            <Plus className="h-4 w-4" aria-hidden="true" /> New identity
          </button>
        </div>
      </motion.section>

      <section aria-labelledby="wallet-overview-title" className="mt-8">
        <div className="mb-5 flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <h2
              id="wallet-overview-title"
              className="text-2xl font-bold tracking-tight text-slate-900"
            >
              Identity wallet
            </h2>
            <p className="mt-1 text-sm text-slate-500">
              Local labels and app scopes never leave this wallet.
            </p>
          </div>
          <div className="flex gap-2 text-xs font-medium text-slate-600">
            <span className="rounded-full bg-emerald-100 px-2.5 py-1">
              {String(activeCount)} active
            </span>
            <span className="rounded-full bg-indigo-100 px-2.5 py-1">
              {String(scopedCount)} scoped
            </span>
          </div>
        </div>

        {loading ? (
          <div className="flex items-center justify-center gap-2 rounded-3xl border border-slate-200 bg-white py-20 text-sm text-slate-500 shadow-sm">
            <Loader2 className="h-5 w-5 animate-spin text-indigo-600" aria-hidden="true" /> Opening
            local wallet…
          </div>
        ) : loadError !== undefined ? (
          <div
            role="alert"
            className="rounded-3xl border border-red-200 bg-red-50 p-6 text-red-800"
          >
            <div className="flex items-center gap-2 font-semibold">
              <AlertTriangle className="h-5 w-5" /> Wallet unavailable
            </div>
            <p className="mt-2 text-sm">{loadError}</p>
            <button
              type="button"
              onClick={() => void refresh()}
              className="mt-4 rounded-xl bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-700"
            >
              Try again
            </button>
          </div>
        ) : identities.length === 0 ? (
          <motion.div
            initial={{ opacity: 0, scale: 0.98 }}
            animate={{ opacity: 1, scale: 1 }}
            className="rounded-3xl border border-dashed border-slate-300 bg-white px-6 py-14 text-center"
          >
            <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-indigo-100 text-indigo-600">
              <KeyRound className="h-7 w-7" aria-hidden="true" />
            </div>
            <h3 className="mt-4 text-xl font-bold text-slate-900">
              Start with an independent identity
            </h3>
            <p className="mx-auto mt-2 max-w-md text-sm leading-relaxed text-slate-500">
              Nexus generates fresh random keys in your browser. There is no username, global
              profile, or reusable master identifier.
            </p>
            <button
              type="button"
              onClick={() => setFlow({ type: 'create' })}
              className="mt-6 inline-flex items-center gap-2 rounded-xl bg-indigo-600 px-5 py-3 text-sm font-medium text-white shadow-sm transition-colors hover:bg-indigo-700"
            >
              <Sparkles className="h-4 w-4" /> Create first identity
            </button>
          </motion.div>
        ) : (
          <div className="grid gap-4 md:grid-cols-2">
            {identities.map((identity) => (
              <IdentityCard
                key={identity.localId}
                identity={identity}
                selected={selectedId === identity.localId}
                retryingRegistration={retryingRegistrationId === identity.localId}
                onSelect={() =>
                  setSelectedId((current) =>
                    current === identity.localId ? undefined : identity.localId,
                  )
                }
                onRetryRegistration={() => void retryRegistration(identity)}
              />
            ))}
          </div>
        )}
      </section>

      <AnimatePresence initial={false}>
        {selectedIdentity !== undefined && (
          <div className="mt-6">
            <IdentityDetail
              identity={selectedIdentity}
              onClose={() => setSelectedId(undefined)}
              onRotate={() => setFlow({ type: 'rotate', identity: selectedIdentity })}
              onDispose={() => setFlow({ type: 'dispose', identity: selectedIdentity })}
              onContinuity={() => setFlow({ type: 'continuity', identity: selectedIdentity })}
              retryingRegistration={retryingRegistrationId === selectedIdentity.localId}
              onRetryRegistration={() => void retryRegistration(selectedIdentity)}
            />
          </div>
        )}
      </AnimatePresence>

      <section className="mt-8 grid gap-4 sm:grid-cols-3" aria-label="Wallet privacy guarantees">
        <Assurance
          icon={<LockKeyhole className="h-5 w-5" />}
          title="Private keys stay local"
          body="Non-extractable signing keys are held in this browser's IndexedDB-backed key vault."
        />
        <Assurance
          icon={<Fingerprint className="h-5 w-5" />}
          title="No global account"
          body="Apps receive only the identity you explicitly select for a proof request."
        />
        <Assurance
          icon={<ShieldCheck className="h-5 w-5" />}
          title="Proofs are tightly bound"
          body="Audience, action, resource, nonce, expiry, and optional context are signed together."
        />
      </section>

      <AnimatePresence>
        {flow?.type === 'create' && (
          <CreateIdentityModal onClose={() => setFlow(undefined)} onCreate={createIdentity} />
        )}
        {flow?.type === 'dispose' && (
          <DisposeIdentityModal
            identity={flow.identity}
            onClose={() => setFlow(undefined)}
            onDispose={() => disposeIdentity(flow.identity)}
          />
        )}
        {flow?.type === 'rotate' && (
          <RotateIdentityModal
            identity={flow.identity}
            onClose={() => setFlow(undefined)}
            onRotate={(input) => rotateIdentity(flow.identity, input)}
          />
        )}
        {flow?.type === 'continuity' && (
          <ContinuityLinkModal
            identity={flow.identity}
            identities={identities}
            onClose={() => setFlow(undefined)}
            onLink={(otherId, scope) =>
              walletAdapter.createContinuityLink(flow.identity.localId, otherId, scope)
            }
          />
        )}
      </AnimatePresence>
    </WalletLayout>
  );
}

function Assurance({ icon, title, body }: { icon: React.ReactNode; title: string; body: string }) {
  return (
    <div className="rounded-2xl border border-slate-200 bg-white p-5">
      <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-indigo-100 text-indigo-600">
        {icon}
      </div>
      <h3 className="mt-3 text-sm font-semibold text-slate-900">{title}</h3>
      <p className="mt-1 text-xs leading-relaxed text-slate-500">{body}</p>
    </div>
  );
}

export default App;
