import { useEffect, useState } from 'react';
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
  Pencil,
  Plus,
  RefreshCw,
  ShieldCheck,
  ShieldOff,
  Smartphone,
  Trash2,
  X,
} from 'lucide-react';
import { motion } from 'motion/react';
import type { LocalIdentitySummary } from '@nexus/wallet-core';

import {
  canUseRegisteredIdentityActions,
  needsRegistrationRecovery,
} from '../lib/identity-capabilities';
import { deviceManagementCapabilities } from '../lib/device-management';

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
  onRename: (nickname?: string) => Promise<void>;
  onAddDevice: () => void;
  onActivateDevice: () => Promise<void>;
  onSelfRevokeDevice: () => void;
  onRootRevokeDevice: (device: LocalIdentitySummary['issuedDevices'][number]) => void;
  onRefreshDevices: () => Promise<void>;
  refreshingDevices: boolean;
  deviceActionBusy: boolean;
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
  onRename,
  onAddDevice,
  onActivateDevice,
  onSelfRevokeDevice,
  onRootRevokeDevice,
  onRefreshDevices,
  refreshingDevices,
  deviceActionBusy,
}: IdentityDetailProps) {
  const active = identity.localState === 'active';
  const registeredActions = canUseRegisteredIdentityActions(identity);
  const [confirmClearHistory, setConfirmClearHistory] = useState(false);
  const [editingNickname, setEditingNickname] = useState(false);
  const [nickname, setNickname] = useState(identity.label ?? '');
  const [renaming, setRenaming] = useState(false);
  const [renameError, setRenameError] = useState<string>();
  const [now, setNow] = useState(() => Math.floor(Date.now() / 1_000));
  const deviceCapabilities = deviceManagementCapabilities(identity, now);
  const installedRegistryState = identity.device?.registryState;
  const hasDeviceStatuses = identity.device !== undefined || identity.issuedDevices.length > 0;

  useEffect(() => {
    if (identity.device?.localState !== 'pending-activation') return;
    const cutoff = Math.min(identity.device.activationDeadline, identity.device.expiresAt);
    if (now >= cutoff) return;
    const delay = Math.min((cutoff - now) * 1_000 + 25, 2_147_483_647);
    const handle = window.setTimeout(() => setNow(Math.floor(Date.now() / 1_000)), delay);
    return () => window.clearTimeout(handle);
  }, [identity.device, now]);

  useEffect(() => {
    if (!editingNickname) setNickname(identity.label ?? '');
  }, [editingNickname, identity.label]);

  const saveNickname = async () => {
    const normalized = nickname.trim();
    if (normalized.length > 128) {
      setRenameError('The nickname cannot exceed 128 characters.');
      return;
    }
    setRenaming(true);
    setRenameError(undefined);
    try {
      await onRename(normalized === '' ? undefined : normalized);
      setEditingNickname(false);
    } catch (error) {
      setRenameError(error instanceof Error ? error.message : 'The nickname could not be saved.');
    } finally {
      setRenaming(false);
    }
  };

  const cancelNickname = () => {
    setNickname(identity.label ?? '');
    setRenameError(undefined);
    setEditingNickname(false);
  };

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
              <div className="mt-0.5 flex items-center gap-2">
                <h2
                  id="identity-details-title"
                  className="truncate text-xl font-bold text-slate-900"
                >
                  {identity.label ?? 'Untitled identity'}
                </h2>
                {!editingNickname && (
                  <button
                    type="button"
                    onClick={() => setEditingNickname(true)}
                    className="shrink-0 rounded-lg p-1.5 text-slate-400 transition-colors hover:bg-indigo-50 hover:text-indigo-700"
                    aria-label="Edit identity nickname"
                  >
                    <Pencil className="h-3.5 w-3.5" aria-hidden="true" />
                  </button>
                )}
              </div>
              {editingNickname && (
                <form
                  className="mt-3"
                  onSubmit={(event) => {
                    event.preventDefault();
                    void saveNickname();
                  }}
                >
                  <label htmlFor="identity-nickname" className="sr-only">
                    Identity nickname
                  </label>
                  <div className="flex flex-wrap gap-2">
                    <input
                      id="identity-nickname"
                      autoFocus
                      value={nickname}
                      onChange={(event) => setNickname(event.target.value)}
                      maxLength={128}
                      autoComplete="off"
                      placeholder="Nickname on this wallet"
                      disabled={renaming}
                      className="min-w-48 flex-1 rounded-lg border border-slate-300 px-3 py-2 text-sm font-medium text-slate-900 shadow-sm focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500"
                    />
                    <button type="submit" disabled={renaming} className={smallPrimaryButton}>
                      {renaming && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
                      {renaming ? 'Saving…' : 'Save'}
                    </button>
                    <button
                      type="button"
                      onClick={cancelNickname}
                      disabled={renaming}
                      className="rounded-lg border border-slate-200 px-3 py-2 text-xs font-semibold text-slate-600 hover:bg-slate-50 disabled:opacity-50"
                    >
                      Cancel
                    </button>
                  </div>
                  <p className="mt-1.5 text-xs leading-relaxed text-slate-400">
                    Stored only in this wallet. It does not change your identity or appear in
                    proofs.
                  </p>
                  {renameError !== undefined && (
                    <p role="alert" className="mt-1.5 text-xs font-medium text-rose-700">
                      {renameError}
                    </p>
                  )}
                </form>
              )}
            </div>
          </div>
          <div className="flex shrink-0 items-center gap-2">
            {hasDeviceStatuses && (
              <button
                type="button"
                onClick={() => void onRefreshDevices()}
                disabled={refreshingDevices || deviceActionBusy}
                className={smallSecondaryButton}
              >
                {refreshingDevices ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <RefreshCw className="h-3.5 w-3.5" />
                )}
                {refreshingDevices ? 'Checking…' : 'Refresh status'}
              </button>
            )}
            <button
              type="button"
              onClick={onClose}
              className="rounded-lg p-1.5 text-slate-400 transition-colors hover:bg-slate-100 hover:text-slate-600"
              aria-label="Close identity details"
            >
              <X className="h-4 w-4" aria-hidden="true" />
            </button>
          </div>
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
              {identity.device !== undefined
                ? identity.device.localState === 'active'
                  ? 'Active delegated device'
                  : identity.device.localState === 'pending-activation'
                    ? 'Delegated device pending activation'
                    : 'Delegated device revoked'
                : active && identity.registered
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

        {(identity.device !== undefined || registeredActions) && (
          <div className="mt-6 border-t border-slate-100 pt-6">
            <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <Smartphone className="h-4 w-4 text-indigo-600" aria-hidden="true" />
                <h3 className="text-sm font-semibold text-slate-900">
                  {identity.device === undefined ? 'Authorized devices' : 'This device'}
                </h3>
              </div>
              {deviceCapabilities.issueDevice && (
                <button
                  type="button"
                  onClick={onAddDevice}
                  disabled={deviceActionBusy || refreshingDevices}
                  className={smallPrimaryButton}
                >
                  <Plus className="h-3.5 w-3.5" /> Add device
                </button>
              )}
            </div>

            {identity.device !== undefined ? (
              <div className="rounded-xl border border-slate-200 p-4">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="min-w-0">
                    <p className="text-sm font-semibold text-slate-900">
                      {installedRegistryState === 'revoked'
                        ? 'Revoked delegated key'
                        : installedRegistryState === 'expired'
                          ? 'Expired delegated key'
                          : installedRegistryState === 'unknown'
                            ? 'Not active at registry'
                            : identity.device.localState === 'pending-activation'
                              ? 'Pending activation'
                              : identity.device.localState === 'active'
                                ? 'Active delegated key'
                                : 'Revoked delegated key'}
                    </p>
                    <code
                      className="mt-1 block truncate text-xs text-slate-400"
                      title={identity.device.deviceId}
                    >
                      {identity.device.deviceId}
                    </code>
                    <p className="mt-2 text-xs leading-relaxed text-slate-500">
                      Authorized until{' '}
                      {new Date(identity.device.expiresAt * 1_000).toLocaleString()}. This key
                      cannot add or remove other devices.
                    </p>
                    {identity.device.statusCheckedAt !== undefined && (
                      <p className="mt-1 text-xs text-slate-400">
                        Registry checked{' '}
                        {new Date(identity.device.statusCheckedAt * 1_000).toLocaleString()}
                      </p>
                    )}
                  </div>
                  {deviceCapabilities.activateDevice && (
                    <button
                      type="button"
                      onClick={() => void onActivateDevice()}
                      disabled={deviceActionBusy}
                      className={smallPrimaryButton}
                    >
                      {deviceActionBusy ? (
                        <Loader2 className="h-3.5 w-3.5 animate-spin" />
                      ) : (
                        <RefreshCw className="h-3.5 w-3.5" />
                      )}
                      {deviceActionBusy ? 'Activating…' : 'Retry activation'}
                    </button>
                  )}
                  {deviceCapabilities.selfRevokeDevice && (
                    <button
                      type="button"
                      onClick={onSelfRevokeDevice}
                      disabled={deviceActionBusy}
                      className={smallDangerButton}
                    >
                      <ShieldOff className="h-3.5 w-3.5" />{' '}
                      {identity.device.localState === 'pending-activation'
                        ? 'Cancel installed device'
                        : 'Remove this device'}
                    </button>
                  )}
                </div>
                {identity.device.localState === 'pending-activation' && (
                  <div className="mt-3 rounded-lg border border-amber-200 bg-amber-50 p-3 text-xs leading-relaxed text-amber-900">
                    {deviceCapabilities.activateDevice
                      ? 'The signing key is installed but cannot create proofs yet. Retry activation before the authorization deadline.'
                      : 'The activation window has closed. This installation cannot create proofs; cancel it to invalidate the device authorization.'}
                  </div>
                )}
              </div>
            ) : identity.issuedDevices.length === 0 ? (
              <div className="rounded-xl border border-dashed border-slate-300 bg-slate-50 p-4 text-sm text-slate-500">
                No device keys have been issued by this root identity. Adding one exports only a
                separately authorized device key—not this identity key.
              </div>
            ) : (
              <ul className="space-y-2">
                {identity.issuedDevices.map((device) => (
                  <li
                    key={device.authorizationId}
                    className="rounded-xl border border-slate-200 p-4"
                  >
                    <div className="flex flex-wrap items-start justify-between gap-3">
                      <div className="min-w-0">
                        <div className="flex flex-wrap items-center gap-2">
                          <p className="text-sm font-semibold text-slate-900">
                            {device.label ?? 'Authorized device'}
                          </p>
                          <span
                            className={`rounded-full px-2 py-0.5 text-[11px] font-semibold ${
                              device.localState === 'revoked' || device.registryState === 'revoked'
                                ? 'bg-rose-100 text-rose-800'
                                : device.registryState === 'active'
                                  ? 'bg-emerald-100 text-emerald-800'
                                  : 'bg-amber-100 text-amber-800'
                            }`}
                          >
                            {device.localState === 'revoked' || device.registryState === 'revoked'
                              ? 'Revoked'
                              : device.registryState === 'active'
                                ? 'Active'
                                : device.registryState === 'expired'
                                  ? 'Expired'
                                  : device.registryState === 'unknown'
                                    ? 'Not activated'
                                    : 'Not checked'}
                          </span>
                        </div>
                        <code
                          className="mt-1 block truncate text-xs text-slate-400"
                          title={device.deviceId}
                        >
                          {device.deviceId}
                        </code>
                        <p className="mt-1 text-xs text-slate-500">
                          Expires {new Date(device.expiresAt * 1_000).toLocaleString()}
                        </p>
                        {device.statusCheckedAt !== undefined && (
                          <p className="mt-1 text-xs text-slate-400">
                            Registry checked{' '}
                            {new Date(device.statusCheckedAt * 1_000).toLocaleString()}
                          </p>
                        )}
                      </div>
                      <div className="flex flex-wrap gap-2">
                        {device.localState !== 'revoked' &&
                          device.registryState !== 'revoked' &&
                          deviceCapabilities.rootRevokeDevice && (
                            <button
                              type="button"
                              onClick={() => onRootRevokeDevice(device)}
                              disabled={deviceActionBusy || refreshingDevices}
                              className={smallDangerButton}
                            >
                              <ShieldOff className="h-3.5 w-3.5" /> Remove
                            </button>
                          )}
                      </div>
                    </div>
                  </li>
                ))}
              </ul>
            )}
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

const smallPrimaryButton =
  'inline-flex shrink-0 items-center justify-center gap-2 rounded-lg bg-indigo-600 px-3 py-2 text-xs font-semibold text-white hover:bg-indigo-700 disabled:cursor-not-allowed disabled:bg-indigo-300';
const smallDangerButton =
  'inline-flex shrink-0 items-center justify-center gap-2 rounded-lg border border-rose-200 bg-white px-3 py-2 text-xs font-semibold text-rose-700 hover:bg-rose-50 disabled:cursor-not-allowed disabled:opacity-50';
const smallSecondaryButton =
  'inline-flex shrink-0 items-center justify-center gap-2 rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs font-semibold text-slate-600 hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-50';
