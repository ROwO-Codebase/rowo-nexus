import { useCallback, useEffect, useRef, useState, type ChangeEvent, type FormEvent } from 'react';
import jsQR from 'jsqr';
import { QRCodeSVG } from 'qrcode.react';
import type { DeviceInstallResult } from '../lib/device-management';
import type {
  DeviceTransferEnvelopeV2,
  IssueDeviceTransferOptions,
  IssuedDeviceTransferV2,
  LocalIdentitySummary,
} from '@nexus/wallet-core';
import {
  AlertTriangle,
  Camera,
  Check,
  Copy,
  Download,
  FileKey2,
  KeyRound,
  Loader2,
  QrCode,
  ShieldOff,
  Smartphone,
  Upload,
} from 'lucide-react';

import {
  decodeDeviceTransferKey,
  encodeDeviceTransferKey,
  MAX_DEVICE_TRANSFER_FILE_BYTES,
  parseDeviceTransferQr,
  parseDeviceTransferBundleJson,
  serializeDeviceTransferQr,
  serializeDeviceTransferBundle,
} from '../lib/device-management';
import { ModalShell } from './ModalShell';

interface AsyncState {
  busy: boolean;
  error?: string;
}

const idle: AsyncState = { busy: false };

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'The wallet could not complete this operation.';
}

function downloadJson(contents: string, filename: string): void {
  const url = URL.createObjectURL(
    new Blob([contents], { type: 'application/nexus+json;charset=utf-8' }),
  );
  try {
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = filename;
    anchor.rel = 'noopener';
    anchor.click();
  } finally {
    URL.revokeObjectURL(url);
  }
}

interface IssueDeviceModalProps {
  identity: LocalIdentitySummary;
  onClose: () => void;
  onIssue: (options: IssueDeviceTransferOptions) => Promise<IssuedDeviceTransferV2>;
}

export function IssueDeviceModal({ identity, onClose, onIssue }: IssueDeviceModalProps) {
  const [method, setMethod] = useState<'qr' | 'file'>('file');
  const [label, setLabel] = useState('');
  const [understood, setUnderstood] = useState(false);
  const [state, setState] = useState<AsyncState>(idle);
  const [issued, setIssued] = useState<{
    bundle: DeviceTransferEnvelopeV2;
    transferKey: string;
    deviceId: string;
    qrPayload?: string;
  }>();
  const [copied, setCopied] = useState(false);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!understood) return;
    setState({ busy: true });
    try {
      const normalized = label.trim();
      const result = await onIssue(normalized === '' ? {} : { label: normalized });
      let transferKey = '';
      try {
        transferKey = encodeDeviceTransferKey(result.transferKey);
      } finally {
        result.transferKey.fill(0);
      }
      let qrPayload: string | undefined;
      try {
        qrPayload = serializeDeviceTransferQr(result.bundle, transferKey);
      } catch (error) {
        setMethod('file');
        setState({
          busy: false,
          error: `${errorMessage(error)} The encrypted JSON transfer is still available.`,
        });
      }
      setIssued({
        bundle: result.bundle,
        transferKey,
        deviceId: result.authorization.payload.deviceId,
        ...(qrPayload === undefined ? {} : { qrPayload }),
      });
      if (qrPayload !== undefined) setState({ busy: false });
    } catch (error) {
      setState({ busy: false, error: errorMessage(error) });
    }
  };

  const close = () => {
    setIssued(undefined);
    setCopied(false);
    setState(idle);
    onClose();
  };

  const copyKey = async () => {
    if (issued === undefined) return;
    try {
      await navigator.clipboard.writeText(issued.transferKey);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1_500);
    } catch (error) {
      setState({ busy: false, error: errorMessage(error) });
    }
  };

  return (
    <ModalShell
      title="Add a device"
      description={`Create a separate signing key authorized by ${identity.label ?? 'this identity'}.`}
      icon={<Smartphone className="h-5 w-5" aria-hidden="true" />}
      onClose={close}
      closeDisabled={state.busy}
      maxWidth="lg"
    >
      {issued === undefined ? (
        <form onSubmit={(event) => void submit(event)} className="space-y-5">
          <TransferMethodSelector method={method} onChange={setMethod} disabled={state.busy} />
          <div>
            <label htmlFor="device-label" className="ml-1 block text-sm font-medium text-slate-700">
              Device label <span className="font-normal text-slate-400">(local only)</span>
            </label>
            <input
              id="device-label"
              value={label}
              onChange={(event) => setLabel(event.target.value)}
              maxLength={128}
              autoComplete="off"
              placeholder="e.g. Travel laptop"
              className="mt-1.5 block w-full rounded-xl border border-slate-300 px-4 py-3 text-sm shadow-sm focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500"
            />
          </div>
          <div className="rounded-xl border border-indigo-100 bg-indigo-50 p-4 text-sm leading-relaxed text-indigo-950">
            <div className="mb-1 flex items-center gap-2 font-semibold">
              <KeyRound className="h-4 w-4" /> Root key stays here
            </div>
            The identity key is never exported. Nexus creates an independent device key and puts it
            only inside the encrypted device transfer.
          </div>
          <div className="rounded-xl border border-amber-200 bg-amber-50 p-4 text-sm leading-relaxed text-amber-950">
            <div className="mb-1 flex items-center gap-2 font-semibold">
              <AlertTriangle className="h-4 w-4" /> One installation intended
            </div>
            {method === 'qr'
              ? 'The QR contains everything needed to install this device key. Anyone who scans or photographs it can create an indistinguishable clone.'
              : 'Copies of the file and key can create indistinguishable clones of this device. Keep them separate, install once, then remove both transfer copies.'}
          </div>
          <label className="flex items-start gap-3 rounded-xl border border-amber-200 p-4">
            <input
              type="checkbox"
              checked={understood}
              onChange={(event) => setUnderstood(event.target.checked)}
              className="mt-1 accent-amber-600"
            />
            <span className="text-sm font-medium leading-relaxed text-slate-800">
              {method === 'qr'
                ? 'I will show the QR only to the intended device and close it immediately after installation.'
                : 'I will send the transfer file and transfer key through separate channels.'}
            </span>
          </label>
          {state.error !== undefined && <ErrorNotice message={state.error} />}
          <div className="flex gap-2">
            <button type="button" onClick={close} disabled={state.busy} className={secondaryButton}>
              Cancel
            </button>
            <button type="submit" disabled={state.busy || !understood} className={primaryButton}>
              {state.busy && <Loader2 className="h-4 w-4 animate-spin" />}
              {state.busy ? 'Creating…' : 'Create device transfer'}
            </button>
          </div>
        </form>
      ) : (
        <div className="space-y-5">
          <div className="rounded-xl border border-emerald-200 bg-emerald-50 p-4 text-sm leading-relaxed text-emerald-950">
            <div className="mb-1 flex items-center gap-2 font-semibold">
              <Check className="h-4 w-4" /> Device authorized
            </div>
            Choose one offline method to install the authorized device key.
          </div>
          <TransferMethodSelector
            method={method}
            onChange={setMethod}
            disabled={issued.qrPayload === undefined}
          />
          {method === 'qr' && issued.qrPayload !== undefined ? (
            <div className="space-y-4">
              <div className="rounded-xl border border-amber-200 bg-amber-50 p-4 text-sm leading-relaxed text-amber-950">
                This QR contains the encrypted bundle and its transfer key. It never contacts an
                online service, but anyone who captures it can install a clone until the device is
                revoked.
              </div>
              <div className="flex justify-center rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
                <QRCodeSVG
                  value={issued.qrPayload}
                  size={360}
                  level="M"
                  marginSize={4}
                  title="Offline Nexus device transfer"
                  className="h-auto w-full max-w-[360px]"
                />
              </div>
              <p className="text-center text-xs leading-relaxed text-slate-500">
                On the target device, choose Install device → Scan QR code. Keep both devices nearby
                until activation finishes.
              </p>
            </div>
          ) : (
            <div className="space-y-4">
              <div className="rounded-xl border border-indigo-100 bg-indigo-50 p-4 text-sm leading-relaxed text-indigo-950">
                Download the encrypted file, then copy the key separately. The key is not in the
                file.
              </div>
              <button
                type="button"
                onClick={() =>
                  downloadJson(
                    serializeDeviceTransferBundle(issued.bundle),
                    `nexus-device-${issued.deviceId.slice(0, 16)}.json`,
                  )
                }
                className={primaryButton}
              >
                <Download className="h-4 w-4" /> Download encrypted transfer file
              </button>
              <div>
                <label
                  htmlFor="issued-transfer-key"
                  className="ml-1 block text-sm font-medium text-slate-700"
                >
                  Transfer key — share separately
                </label>
                <div className="mt-1.5 flex gap-2">
                  <input
                    id="issued-transfer-key"
                    readOnly
                    value={issued.transferKey}
                    spellCheck={false}
                    className="min-w-0 flex-1 rounded-xl border border-slate-300 bg-slate-50 px-3 py-3 font-mono text-xs text-slate-900"
                  />
                  <button type="button" onClick={() => void copyKey()} className={compactButton}>
                    {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
                    {copied ? 'Copied' : 'Copy'}
                  </button>
                </div>
              </div>
            </div>
          )}
          {state.error !== undefined && <ErrorNotice message={state.error} />}
          <button type="button" onClick={close} className={secondaryButton}>
            Done
          </button>
        </div>
      )}
    </ModalShell>
  );
}

interface InstallDeviceModalProps {
  onClose: () => void;
  onInstall: (
    bundle: DeviceTransferEnvelopeV2,
    transferKey: Uint8Array,
  ) => Promise<DeviceInstallResult>;
}

export function InstallDeviceModal({ onClose, onInstall }: InstallDeviceModalProps) {
  const [method, setMethod] = useState<'qr' | 'file'>('file');
  const [bundle, setBundle] = useState<DeviceTransferEnvelopeV2>();
  const [fileName, setFileName] = useState('');
  const [transferKey, setTransferKey] = useState('');
  const [state, setState] = useState<AsyncState>(idle);

  const selectMethod = (nextMethod: 'qr' | 'file') => {
    setMethod(nextMethod);
    setBundle(undefined);
    setFileName('');
    setTransferKey('');
    setState(idle);
  };

  const acceptQrPayload = useCallback((payload: string) => {
    const decoded = parseDeviceTransferQr(payload);
    setBundle(decoded.bundle);
    setTransferKey(decoded.transferKey);
    setFileName('Offline QR code');
    setState(idle);
  }, []);

  const selectFile = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    setBundle(undefined);
    setFileName('');
    setState(idle);
    if (file === undefined) return;
    if (file.size > MAX_DEVICE_TRANSFER_FILE_BYTES) {
      setState({ busy: false, error: 'The device transfer file is larger than 96 KiB.' });
      event.target.value = '';
      return;
    }
    try {
      setBundle(parseDeviceTransferBundleJson(await file.text(), file.size));
      setFileName(file.name);
    } catch (error) {
      setState({ busy: false, error: errorMessage(error) });
      event.target.value = '';
    }
  };

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (bundle === undefined) return;
    let keyBytes: Uint8Array;
    try {
      keyBytes = decodeDeviceTransferKey(transferKey);
    } catch (error) {
      setState({ busy: false, error: errorMessage(error) });
      return;
    }
    setState({ busy: true });
    try {
      await onInstall(bundle, keyBytes);
      setTransferKey('');
    } catch (error) {
      // Keep both user inputs available for a corrected retry when import itself failed.
      setState({ busy: false, error: errorMessage(error) });
    } finally {
      keyBytes.fill(0);
    }
  };

  return (
    <ModalShell
      title="Install a device"
      description="Import an encrypted device key and activate it with the registry."
      icon={<Upload className="h-5 w-5" aria-hidden="true" />}
      onClose={onClose}
      closeDisabled={state.busy}
      maxWidth="lg"
    >
      <form onSubmit={(event) => void submit(event)} className="space-y-5">
        <TransferMethodSelector method={method} onChange={selectMethod} disabled={state.busy} />
        <div className="rounded-xl border border-amber-200 bg-amber-50 p-4 text-sm leading-relaxed text-amber-950">
          {method === 'qr'
            ? 'Scan only a QR shown by the root wallet you trust. The QR is a complete bearer credential; a photo or second scan can create a clone.'
            : 'The file and its 43-character key must have arrived separately. A copied bundle can create a clone, so remove transfer copies after a successful installation.'}
        </div>
        {method === 'qr' ? (
          <DeviceTransferQrScanner
            onScan={acceptQrPayload}
            scanned={bundle !== undefined}
            disabled={state.busy}
          />
        ) : (
          <>
            <div>
              <label
                htmlFor="device-transfer-file"
                className="ml-1 block text-sm font-medium text-slate-700"
              >
                Encrypted transfer file
              </label>
              <label
                htmlFor="device-transfer-file"
                className="mt-1.5 flex cursor-pointer items-center gap-3 rounded-xl border border-dashed border-slate-300 bg-slate-50 p-4 text-sm text-slate-700 hover:border-indigo-400 hover:bg-indigo-50"
              >
                <FileKey2 className="h-5 w-5 shrink-0 text-indigo-600" />
                <span className="min-w-0 truncate">
                  {fileName === '' ? 'Choose JSON file (up to 96 KiB)' : fileName}
                </span>
              </label>
              <input
                id="device-transfer-file"
                type="file"
                accept="application/json,application/nexus+json,.json"
                onChange={(event) => void selectFile(event)}
                disabled={state.busy}
                className="sr-only"
              />
            </div>
            <div>
              <label
                htmlFor="device-transfer-key"
                className="ml-1 block text-sm font-medium text-slate-700"
              >
                Transfer key
              </label>
              <input
                id="device-transfer-key"
                value={transferKey}
                onChange={(event) => setTransferKey(event.target.value.trim())}
                minLength={43}
                maxLength={43}
                autoComplete="off"
                autoCapitalize="none"
                spellCheck={false}
                placeholder="43-character base64url key"
                className="mt-1.5 block w-full rounded-xl border border-slate-300 px-4 py-3 font-mono text-sm shadow-sm focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500"
              />
            </div>
          </>
        )}
        {state.error !== undefined && <ErrorNotice message={state.error} />}
        <div className="flex gap-2">
          <button type="button" onClick={onClose} disabled={state.busy} className={secondaryButton}>
            Cancel
          </button>
          <button
            type="submit"
            disabled={state.busy || bundle === undefined || transferKey.length !== 43}
            className={primaryButton}
          >
            {state.busy && <Loader2 className="h-4 w-4 animate-spin" />}
            {state.busy ? 'Installing…' : 'Install and activate'}
          </button>
        </div>
      </form>
    </ModalShell>
  );
}

interface TransferMethodSelectorProps {
  method: 'qr' | 'file';
  onChange: (method: 'qr' | 'file') => void;
  disabled: boolean;
}

function TransferMethodSelector({ method, onChange, disabled }: TransferMethodSelectorProps) {
  return (
    <div className="grid grid-cols-2 gap-2" role="group" aria-label="Device transfer method">
      <button
        type="button"
        onClick={() => onChange('qr')}
        disabled={disabled}
        aria-pressed={method === 'qr'}
        className={method === 'qr' ? selectedMethodButton : methodButton}
      >
        <QrCode className="h-4 w-4" /> QR code
      </button>
      <button
        type="button"
        onClick={() => onChange('file')}
        disabled={disabled}
        aria-pressed={method === 'file'}
        className={method === 'file' ? selectedMethodButton : methodButton}
      >
        <FileKey2 className="h-4 w-4" /> JSON bundle
      </button>
    </div>
  );
}

interface DeviceTransferQrScannerProps {
  onScan: (payload: string) => void;
  scanned: boolean;
  disabled: boolean;
}

function DeviceTransferQrScanner({ onScan, scanned, disabled }: DeviceTransferQrScannerProps) {
  const videoRef = useRef<HTMLVideoElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const streamRef = useRef<MediaStream | undefined>(undefined);
  const frameRef = useRef<number | undefined>(undefined);
  const lastScanAtRef = useRef(0);
  const lastPayloadRef = useRef('');
  const onScanRef = useRef(onScan);
  const [starting, setStarting] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string>();
  onScanRef.current = onScan;

  const stopCamera = useCallback(() => {
    if (frameRef.current !== undefined) cancelAnimationFrame(frameRef.current);
    frameRef.current = undefined;
    streamRef.current?.getTracks().forEach((track) => track.stop());
    streamRef.current = undefined;
    if (videoRef.current !== null) videoRef.current.srcObject = null;
    const canvas = canvasRef.current;
    if (canvas !== null) {
      canvas.getContext('2d')?.clearRect(0, 0, canvas.width, canvas.height);
      canvas.width = 1;
      canvas.height = 1;
    }
    lastPayloadRef.current = '';
    setStarting(false);
    setScanning(false);
  }, []);

  const scanFrame = useCallback(
    (time: number) => {
      const video = videoRef.current;
      const canvas = canvasRef.current;
      if (video === null || canvas === null || streamRef.current === undefined) return;

      if (
        time - lastScanAtRef.current >= 120 &&
        video.readyState >= HTMLMediaElement.HAVE_CURRENT_DATA &&
        video.videoWidth > 0 &&
        video.videoHeight > 0
      ) {
        lastScanAtRef.current = time;
        const scale = Math.min(1, 960 / Math.max(video.videoWidth, video.videoHeight));
        canvas.width = Math.max(1, Math.round(video.videoWidth * scale));
        canvas.height = Math.max(1, Math.round(video.videoHeight * scale));
        const context = canvas.getContext('2d', { willReadFrequently: true });
        if (context !== null) {
          context.drawImage(video, 0, 0, canvas.width, canvas.height);
          const image = context.getImageData(0, 0, canvas.width, canvas.height);
          const result = jsQR(image.data, image.width, image.height, {
            inversionAttempts: 'attemptBoth',
          });
          if (result !== null && result.data !== lastPayloadRef.current) {
            lastPayloadRef.current = result.data;
            try {
              setError(undefined);
              onScanRef.current(result.data);
              stopCamera();
              return;
            } catch (scanError) {
              setError(errorMessage(scanError));
            }
          }
        }
      }
      frameRef.current = requestAnimationFrame(scanFrame);
    },
    [stopCamera],
  );

  const startCamera = async () => {
    if (starting || scanning) return;
    setStarting(true);
    setError(undefined);
    lastPayloadRef.current = '';
    if (!globalThis.isSecureContext || navigator.mediaDevices?.getUserMedia === undefined) {
      setError('Camera scanning requires HTTPS or localhost and a browser with camera access.');
      setStarting(false);
      return;
    }
    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        audio: false,
        video: { facingMode: { ideal: 'environment' } },
      });
      streamRef.current = stream;
      const video = videoRef.current;
      if (video === null) {
        stopCamera();
        return;
      }
      video.srcObject = stream;
      await video.play();
      setStarting(false);
      setScanning(true);
      frameRef.current = requestAnimationFrame(scanFrame);
    } catch (cameraError) {
      stopCamera();
      setError(
        cameraError instanceof DOMException && cameraError.name === 'NotAllowedError'
          ? 'Camera access was denied. Allow camera access, then try again.'
          : errorMessage(cameraError),
      );
    }
  };

  useEffect(() => {
    return stopCamera;
  }, [stopCamera]);

  return (
    <div className="space-y-3">
      <div className="relative overflow-hidden rounded-2xl border border-slate-200 bg-slate-950">
        <video
          ref={videoRef}
          muted
          playsInline
          aria-label="Camera preview for scanning the device transfer QR code"
          className={`aspect-square w-full object-cover ${scanning ? 'block' : 'hidden'}`}
        />
        {!scanning && (
          <div className="flex aspect-square flex-col items-center justify-center gap-3 p-8 text-center text-slate-300">
            {scanned ? (
              <>
                <Check className="h-12 w-12 text-emerald-400" />
                <span className="font-medium text-white">Device transfer scanned</span>
                <span className="text-sm">
                  Ready to install without contacting an online service.
                </span>
              </>
            ) : (
              <>
                <QrCode className="h-12 w-12" />
                <span className="text-sm">The camera feed stays on this device.</span>
              </>
            )}
          </div>
        )}
        <canvas ref={canvasRef} className="hidden" aria-hidden="true" />
      </div>
      {!scanned && (
        <button
          type="button"
          onClick={() => (scanning ? stopCamera() : void startCamera())}
          disabled={disabled || starting}
          className={scanning ? secondaryButton : primaryButton}
        >
          {starting ? <Loader2 className="h-4 w-4 animate-spin" /> : <Camera className="h-4 w-4" />}{' '}
          {starting ? 'Starting camera…' : scanning ? 'Stop camera' : 'Scan QR code'}
        </button>
      )}
      {error !== undefined && <ErrorNotice message={error} />}
    </div>
  );
}

interface RevokeDeviceModalProps {
  role: 'root' | 'device';
  deviceLabel?: string;
  onClose: () => void;
  onRevoke: () => Promise<void>;
}

export function RevokeDeviceModal({
  role,
  deviceLabel,
  onClose,
  onRevoke,
}: RevokeDeviceModalProps) {
  const [confirmed, setConfirmed] = useState(false);
  const [state, setState] = useState<AsyncState>(idle);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!confirmed) return;
    setState({ busy: true });
    try {
      await onRevoke();
    } catch (error) {
      // A failed or unverifiable response leaves the local signing key/catalogue intact for retry.
      setState({ busy: false, error: errorMessage(error) });
    }
  };

  return (
    <ModalShell
      title={role === 'root' ? 'Remove authorized device' : 'Remove this device'}
      description={
        role === 'root'
          ? `Use the root identity to invalidate ${deviceLabel ?? 'this device'}.`
          : 'Use this device key to invalidate only this installation.'
      }
      icon={<ShieldOff className="h-5 w-5" aria-hidden="true" />}
      onClose={onClose}
      closeDisabled={state.busy}
    >
      <form onSubmit={(event) => void submit(event)} className="space-y-5">
        <div className="rounded-xl border border-rose-200 bg-rose-50 p-4 text-sm leading-relaxed text-rose-950">
          This device will no longer be accepted for identity proofs. Local signing material is
          removed only after the wallet verifies the registry receipt.
        </div>
        <label className="flex items-start gap-3 rounded-xl border border-rose-200 p-4">
          <input
            type="checkbox"
            checked={confirmed}
            onChange={(event) => setConfirmed(event.target.checked)}
            className="mt-1 accent-rose-600"
          />
          <span className="text-sm font-medium leading-relaxed text-slate-800">
            I understand this device authorization cannot be restored.
          </span>
        </label>
        {state.error !== undefined && <ErrorNotice message={state.error} />}
        <div className="flex gap-2">
          <button type="button" onClick={onClose} disabled={state.busy} className={secondaryButton}>
            Keep device
          </button>
          <button
            type="submit"
            disabled={state.busy || !confirmed}
            className="flex flex-1 items-center justify-center gap-2 rounded-xl bg-rose-600 px-4 py-2.5 text-sm font-medium text-white shadow-sm hover:bg-rose-700 disabled:cursor-not-allowed disabled:bg-rose-300"
          >
            {state.busy && <Loader2 className="h-4 w-4 animate-spin" />}
            {state.busy ? 'Removing…' : 'Remove device'}
          </button>
        </div>
      </form>
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
const compactButton =
  'inline-flex shrink-0 items-center justify-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50';
const methodButton =
  'flex items-center justify-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2.5 text-sm font-medium text-slate-600 transition-colors hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-50';
const selectedMethodButton =
  'flex items-center justify-center gap-2 rounded-xl border border-indigo-500 bg-indigo-50 px-3 py-2.5 text-sm font-semibold text-indigo-700 ring-1 ring-indigo-200 disabled:cursor-not-allowed disabled:opacity-50';
