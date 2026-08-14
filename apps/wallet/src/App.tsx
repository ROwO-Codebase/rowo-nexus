import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type {
  DeviceTransferEnvelopeV2,
  IssueDeviceTransferOptions,
  IssuedDeviceTransferV2,
  LocalIdentitySummary,
} from '@nexus/wallet-core';
import {
  AlertTriangle,
  Fingerprint,
  KeyRound,
  Loader2,
  LockKeyhole,
  Plus,
  ShieldCheck,
  Sparkles,
  Upload,
} from 'lucide-react';
import { AnimatePresence, motion } from 'motion/react';

import { IdentityCard } from './components/IdentityCard';
import {
  InstallDeviceModal,
  IssueDeviceModal,
  RevokeDeviceModal,
} from './components/DeviceManagement';
import { IdentityDetail } from './components/IdentityDetail';
import { ProofConsentScreen } from './components/ProofConsentScreen';
import { WalletLayout } from './components/WalletLayout';
import {
  ContinuityLinkModal,
  CreateIdentityModal,
  DisposeIdentityModal,
  RemoveLocalIdentityModal,
  RotateIdentityModal,
} from './components/flows';
import {
  announceWalletReady,
  announceWalletReadyV2,
  parseProofRequestMessage,
  postProofError,
  postProofResult,
  type PendingProofRequest,
  type NexusOwnershipProofProtocol,
} from './lib/popup-protocol';
import {
  deviceStatusRefreshTargets,
  installAndActivateDevice,
  type DeviceInstallResult,
} from './lib/device-management';
import { createIdentityWithOptionalLocalDevice } from './lib/create-identity';
import {
  walletAdapter,
  type CreateIdentityInput,
  type RotateIdentityInput,
} from './lib/wallet-adapter';

type Flow =
  | { type: 'create' }
  | { type: 'install-device' }
  | { type: 'issue-device'; identity: LocalIdentitySummary }
  | { type: 'self-revoke-device'; identity: LocalIdentitySummary }
  | {
      type: 'root-revoke-device';
      identity: LocalIdentitySummary;
      device: LocalIdentitySummary['issuedDevices'][number];
    }
  | { type: 'dispose'; identity: LocalIdentitySummary }
  | { type: 'remove-local'; identity: LocalIdentitySummary }
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
  const [clearingHistoryId, setClearingHistoryId] = useState<string>();
  const [deviceActionId, setDeviceActionId] = useState<string>();
  const [refreshingIdentityId, setRefreshingIdentityId] = useState<string>();
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
    announceWalletReadyV2(opener);
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
  const rootKeys = identities.filter((identity) => identity.device === undefined);
  const deviceKeys = identities.filter((identity) => identity.device !== undefined);
  const activeCount = identities.filter((identity) => identity.localState === 'active').length;
  const scopedCount = identities.filter((identity) => identity.localScopes.length > 0).length;

  const createIdentity = async (input: CreateIdentityInput) => {
    const created = await createIdentityWithOptionalLocalDevice(walletAdapter, input);
    await refresh();
    setSelectedId(created.device?.localId ?? created.root.localId);
    setFlow(undefined);
    if (created.deviceState === 'active' && created.deviceError === undefined) {
      setNotice({
        kind: 'success',
        message: 'Identity created. Its separate device key is active on this device.',
      });
      return;
    }
    if (created.device !== undefined) {
      setNotice({
        kind: 'error',
        message:
          created.deviceState === 'pending-activation'
            ? `Identity created and the device key was installed safely, but activation is pending. Open it and retry. ${created.deviceError ?? ''}`.trim()
            : `Identity and device key created. ${created.deviceError ?? 'The local device setup needs attention.'}`,
      });
      return;
    }
    if (created.deviceError !== undefined) {
      setNotice({
        kind: 'error',
        message: `Identity created and registered, but its device key could not be installed. You can add one from the identity details. ${created.deviceError}`,
      });
      return;
    }
    setNotice({ kind: 'success', message: 'Independent root identity created and registered.' });
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

  const removeLocalIdentity = async (identity: LocalIdentitySummary) => {
    await walletAdapter.removeLocalIdentity(identity.localId);
    setSelectedId(undefined);
    await refresh();
    setFlow(undefined);
    setNotice({ kind: 'success', message: 'Identity removed from this wallet.' });
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

  const clearAuthorizationHistory = async (identity: LocalIdentitySummary) => {
    if (clearingHistoryId !== undefined) return;
    setClearingHistoryId(identity.localId);
    try {
      await walletAdapter.clearAuthorizationHistory(identity.localId);
      await refresh();
      setNotice({ kind: 'success', message: 'Local authorization history cleared.' });
    } catch (error) {
      setNotice({
        kind: 'error',
        message:
          error instanceof Error ? error.message : 'The wallet could not clear local history.',
      });
    } finally {
      setClearingHistoryId(undefined);
    }
  };

  const renameIdentity = async (identity: LocalIdentitySummary, nickname?: string) => {
    await walletAdapter.setLabel(identity.localId, nickname);
    await refresh();
    setNotice({
      kind: 'success',
      message:
        nickname === undefined
          ? 'Local identity nickname removed.'
          : `Local identity nickname changed to “${nickname}”.`,
    });
  };

  const issueDevice = async (
    identity: LocalIdentitySummary,
    options: IssueDeviceTransferOptions,
  ): Promise<IssuedDeviceTransferV2> => {
    const issued = await walletAdapter.issueDeviceTransfer(identity.localId, options);
    await refresh();
    return issued;
  };

  const installDevice = async (
    bundle: DeviceTransferEnvelopeV2,
    transferKey: Uint8Array,
  ): Promise<DeviceInstallResult> => {
    const result = await installAndActivateDevice(walletAdapter, bundle, transferKey);
    await refresh();
    setSelectedId(result.imported.localId);
    setFlow(undefined);
    setNotice(
      result.state === 'active'
        ? { kind: 'success', message: 'Device installed and activated for this identity.' }
        : {
            kind: 'error',
            message: `Device installed safely, but activation is still pending. Open it and retry. ${result.activationError}`,
          },
    );
    return result;
  };

  const activateDevice = async (identity: LocalIdentitySummary) => {
    if (deviceActionId !== undefined) return;
    setDeviceActionId(identity.localId);
    try {
      await walletAdapter.activateDevice(identity.localId);
      await refresh();
      setNotice({ kind: 'success', message: 'Device activation confirmed by the registry.' });
    } catch (error) {
      setNotice({
        kind: 'error',
        message:
          error instanceof Error
            ? error.message
            : 'Activation failed. The installed device key was retained for retry.',
      });
    } finally {
      setDeviceActionId(undefined);
    }
  };

  const selfRevokeDevice = async (identity: LocalIdentitySummary) => {
    setDeviceActionId(identity.localId);
    try {
      await walletAdapter.revokeDeviceSelf(identity.localId);
      await refresh();
      setFlow(undefined);
      setNotice({ kind: 'success', message: 'This device was removed from the identity.' });
    } finally {
      setDeviceActionId(undefined);
    }
  };

  const rootRevokeDevice = async (
    identity: LocalIdentitySummary,
    device: LocalIdentitySummary['issuedDevices'][number],
  ) => {
    setDeviceActionId(device.deviceId);
    try {
      await walletAdapter.revokeDeviceRoot(identity.localId, device.deviceId);
      await refresh();
      setFlow(undefined);
      setNotice({ kind: 'success', message: 'The root identity removed that device.' });
    } finally {
      setDeviceActionId(undefined);
    }
  };

  const refreshDeviceStatuses = async (identity: LocalIdentitySummary) => {
    const targets = deviceStatusRefreshTargets(identity);
    if (targets.length === 0 || refreshingIdentityId !== undefined) return;
    setRefreshingIdentityId(identity.localId);
    try {
      const results: PromiseSettledResult<
        Awaited<ReturnType<typeof walletAdapter.refreshDeviceStatus>>
      >[] = [];
      for (let index = 0; index < targets.length; index += 10) {
        results.push(
          ...(await Promise.allSettled(
            targets
              .slice(index, index + 10)
              .map((deviceId) => walletAdapter.refreshDeviceStatus(identity.localId, deviceId)),
          )),
        );
      }
      await refresh();
      const statuses = results.flatMap((result) =>
        result.status === 'fulfilled' ? [result.value] : [],
      );
      const failed = results.length - statuses.length;
      if (statuses.length === 0) {
        const firstFailure = results.find((result) => result.status === 'rejected');
        if (firstFailure?.status === 'rejected' && firstFailure.reason instanceof Error) {
          throw firstFailure.reason;
        }
        throw new Error('Device statuses could not be refreshed.');
      }
      const stateCounts = new Map<string, number>();
      for (const status of statuses) {
        stateCounts.set(status.deviceState, (stateCounts.get(status.deviceState) ?? 0) + 1);
      }
      const stateSummary = [...stateCounts]
        .map(([state, count]) => `${String(count)} ${state}`)
        .join(', ');
      setNotice({
        kind:
          failed === 0 && statuses.every((status) => status.deviceState === 'active')
            ? 'success'
            : 'error',
        message:
          failed === 0
            ? statuses.length === 1
              ? `Registry device status: ${statuses[0]?.deviceState ?? 'unknown'}.`
              : `Refreshed ${String(statuses.length)} device statuses: ${stateSummary}.`
            : `Refreshed ${String(statuses.length)} of ${String(results.length)} device statuses; ${String(failed)} could not be checked.`,
      });
    } catch (error) {
      setNotice({
        kind: 'error',
        message: error instanceof Error ? error.message : 'Device statuses could not be refreshed.',
      });
    } finally {
      setRefreshingIdentityId(undefined);
    }
  };

  const approveProof = async (
    localId: string,
    rememberScope: boolean,
    proofProtocol: NexusOwnershipProofProtocol,
  ) => {
    if (pending === undefined) return;
    const proof = await walletAdapter.proveForProtocol(
      localId,
      pending.boundary,
      pending.request,
      rememberScope,
      proofProtocol,
    );
    postProofResult(pending, { proofProtocol, proof } as Parameters<typeof postProofResult>[1]);
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
          <div className="flex shrink-0 flex-col gap-2 sm:flex-row">
            <button
              type="button"
              onClick={() => setFlow({ type: 'install-device' })}
              className="inline-flex items-center justify-center gap-2 rounded-xl border border-white/30 bg-white/10 px-5 py-3 text-sm font-bold text-white transition-all hover:-translate-y-0.5 hover:bg-white/20"
            >
              <Upload className="h-4 w-4" aria-hidden="true" /> Install device
            </button>
            <button
              type="button"
              onClick={() => setFlow({ type: 'create' })}
              className="inline-flex items-center justify-center gap-2 rounded-xl bg-white px-5 py-3 text-sm font-bold text-indigo-600 shadow-sm transition-all hover:-translate-y-0.5 hover:bg-indigo-50"
            >
              <Plus className="h-4 w-4" aria-hidden="true" /> New identity
            </button>
          </div>
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
              Local nicknames and app scopes never leave this wallet.
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
          <div className="space-y-8">
            <KeySection
              id="root-keys-title"
              title="Root keys"
              description="Identity-level keys that authorize devices and control the identity lifecycle."
              emptyMessage="No root keys are stored in this wallet."
              identities={rootKeys}
              selectedId={selectedId}
              retryingRegistrationId={retryingRegistrationId}
              onSelect={(localId) =>
                setSelectedId((current) => (current === localId ? undefined : localId))
              }
              onRetryRegistration={(identity) => void retryRegistration(identity)}
            />
            <KeySection
              id="device-keys-title"
              title="Device keys"
              description="Root-authorized keys for everyday proofs on this wallet."
              emptyMessage="No device keys are installed in this wallet."
              identities={deviceKeys}
              selectedId={selectedId}
              retryingRegistrationId={retryingRegistrationId}
              onSelect={(localId) =>
                setSelectedId((current) => (current === localId ? undefined : localId))
              }
              onRetryRegistration={(identity) => void retryRegistration(identity)}
            />
          </div>
        )}
      </section>

      <AnimatePresence initial={false}>
        {selectedIdentity !== undefined && (
          <div className="mt-6">
            <IdentityDetail
              key={selectedIdentity.localId}
              identity={selectedIdentity}
              onClose={() => setSelectedId(undefined)}
              onRotate={() => setFlow({ type: 'rotate', identity: selectedIdentity })}
              onDispose={() => setFlow({ type: 'dispose', identity: selectedIdentity })}
              onRemoveLocal={() => setFlow({ type: 'remove-local', identity: selectedIdentity })}
              onContinuity={() => setFlow({ type: 'continuity', identity: selectedIdentity })}
              retryingRegistration={retryingRegistrationId === selectedIdentity.localId}
              onRetryRegistration={() => void retryRegistration(selectedIdentity)}
              clearingHistory={clearingHistoryId === selectedIdentity.localId}
              onClearHistory={() => clearAuthorizationHistory(selectedIdentity)}
              onRename={(nickname) => renameIdentity(selectedIdentity, nickname)}
              onAddDevice={() => setFlow({ type: 'issue-device', identity: selectedIdentity })}
              onActivateDevice={() => activateDevice(selectedIdentity)}
              onSelfRevokeDevice={() =>
                setFlow({ type: 'self-revoke-device', identity: selectedIdentity })
              }
              onRootRevokeDevice={(device) =>
                setFlow({ type: 'root-revoke-device', identity: selectedIdentity, device })
              }
              onRefreshDevices={() => refreshDeviceStatuses(selectedIdentity)}
              refreshingDevices={refreshingIdentityId === selectedIdentity.localId}
              deviceActionBusy={deviceActionId !== undefined}
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
        {flow?.type === 'install-device' && (
          <InstallDeviceModal onClose={() => setFlow(undefined)} onInstall={installDevice} />
        )}
        {flow?.type === 'issue-device' && (
          <IssueDeviceModal
            identity={flow.identity}
            onClose={() => setFlow(undefined)}
            onIssue={(options) => issueDevice(flow.identity, options)}
          />
        )}
        {flow?.type === 'self-revoke-device' && (
          <RevokeDeviceModal
            role="device"
            {...(flow.identity.label === undefined ? {} : { deviceLabel: flow.identity.label })}
            onClose={() => setFlow(undefined)}
            onRevoke={() => selfRevokeDevice(flow.identity)}
          />
        )}
        {flow?.type === 'root-revoke-device' && (
          <RevokeDeviceModal
            role="root"
            {...(flow.device.label === undefined ? {} : { deviceLabel: flow.device.label })}
            onClose={() => setFlow(undefined)}
            onRevoke={() => rootRevokeDevice(flow.identity, flow.device)}
          />
        )}
        {flow?.type === 'dispose' && (
          <DisposeIdentityModal
            identity={flow.identity}
            onClose={() => setFlow(undefined)}
            onDispose={() => disposeIdentity(flow.identity)}
          />
        )}
        {flow?.type === 'remove-local' && (
          <RemoveLocalIdentityModal
            identity={flow.identity}
            onClose={() => setFlow(undefined)}
            onRemove={() => removeLocalIdentity(flow.identity)}
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

interface KeySectionProps {
  id: string;
  title: string;
  description: string;
  emptyMessage: string;
  identities: readonly LocalIdentitySummary[];
  selectedId: string | undefined;
  retryingRegistrationId: string | undefined;
  onSelect: (localId: string) => void;
  onRetryRegistration: (identity: LocalIdentitySummary) => void;
}

function KeySection({
  id,
  title,
  description,
  emptyMessage,
  identities,
  selectedId,
  retryingRegistrationId,
  onSelect,
  onRetryRegistration,
}: KeySectionProps) {
  return (
    <section aria-labelledby={id}>
      <div className="mb-4 flex items-end justify-between gap-4">
        <div>
          <h3 id={id} className="text-lg font-bold text-slate-900">
            {title}
          </h3>
          <p className="mt-1 text-sm text-slate-500">{description}</p>
        </div>
        <span className="shrink-0 rounded-full bg-slate-100 px-2.5 py-1 text-xs font-medium text-slate-600">
          {String(identities.length)} {identities.length === 1 ? 'key' : 'keys'}
        </span>
      </div>

      {identities.length === 0 ? (
        <p className="rounded-2xl border border-dashed border-slate-300 bg-white px-5 py-8 text-center text-sm text-slate-500">
          {emptyMessage}
        </p>
      ) : (
        <div className="grid gap-4 md:grid-cols-2">
          {identities.map((identity) => (
            <IdentityCard
              key={identity.localId}
              identity={identity}
              selected={selectedId === identity.localId}
              retryingRegistration={retryingRegistrationId === identity.localId}
              onSelect={() => onSelect(identity.localId)}
              onRetryRegistration={() => onRetryRegistration(identity)}
            />
          ))}
        </div>
      )}
    </section>
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
