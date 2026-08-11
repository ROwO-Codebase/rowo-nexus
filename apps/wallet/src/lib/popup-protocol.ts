import {
  base64Url32Schema,
  base64UrlAtLeast16Schema,
  proofRequestSchema,
  type OwnershipProofV1,
  type ProofRequest,
} from '@nexus/protocol';
import { captureWalletEventBoundary, type TrustedWalletEventBoundary } from '@nexus/wallet-core';

export const NEXUS_POPUP_CHANNEL = 'nexus.popup.v1' as const;

export interface PendingProofRequest {
  requestId: string;
  request: ProofRequest;
  origin: string;
  boundary: TrustedWalletEventBoundary;
  source: Window;
}

export type WalletProofErrorCode =
  | 'USER_CANCELLED'
  | 'INVALID_REQUEST'
  | 'CHALLENGE_EXPIRED'
  | 'NO_ACTIVE_IDENTITY'
  | 'REGISTRATION_FAILED'
  | 'INTERNAL_ERROR';

const MESSAGE_KEYS = ['channel', 'request', 'requestId', 'type'] as const;
const REQUEST_KEYS = ['action', 'contextHash', 'expiresAt', 'nonce', 'resource'] as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hasOnlyKeys(value: Record<string, unknown>, allowed: readonly string[]): boolean {
  return Object.keys(value).every((key) => allowed.includes(key));
}

function isRequestId(value: unknown): value is string {
  return typeof value === 'string' && /^[A-Za-z0-9_-]{22,}$/u.test(value) && value.length % 4 !== 1;
}

export function parseProofRequestMessage(
  event: MessageEvent<unknown>,
  expectedSource: Window | null,
  nowSeconds = Math.floor(Date.now() / 1000),
): PendingProofRequest | undefined {
  if (expectedSource === null || event.source !== expectedSource || !isRecord(event.data)) {
    return undefined;
  }
  if (
    !hasOnlyKeys(event.data, MESSAGE_KEYS) ||
    Object.keys(event.data).length !== MESSAGE_KEYS.length
  ) {
    return undefined;
  }
  if (
    event.data.channel !== NEXUS_POPUP_CHANNEL ||
    event.data.type !== 'NEXUS_PROOF_REQUEST' ||
    !isRequestId(event.data.requestId) ||
    !isRecord(event.data.request) ||
    !hasOnlyKeys(event.data.request, REQUEST_KEYS)
  ) {
    return undefined;
  }

  const parsed = proofRequestSchema.safeParse(event.data.request);
  if (!parsed.success || parsed.data.expiresAt <= nowSeconds) return undefined;
  if (parsed.data.expiresAt > nowSeconds + 120) return undefined;
  if (!base64UrlAtLeast16Schema.safeParse(parsed.data.nonce).success) return undefined;
  if (
    parsed.data.contextHash !== undefined &&
    !base64Url32Schema.safeParse(parsed.data.contextHash).success
  ) {
    return undefined;
  }

  let boundary: TrustedWalletEventBoundary;
  try {
    boundary = captureWalletEventBoundary(event);
  } catch {
    return undefined;
  }
  return {
    requestId: event.data.requestId,
    request: parsed.data,
    origin: event.origin,
    boundary,
    source: expectedSource,
  };
}

/** NEXUS_READY contains no proof or identity data. It is the sole wildcard message. */
export function announceWalletReady(opener: Window | null): void {
  opener?.postMessage({ channel: NEXUS_POPUP_CHANNEL, type: 'NEXUS_READY' }, '*');
}

export function postProofResult(pending: PendingProofRequest, proof: OwnershipProofV1): void {
  pending.source.postMessage(
    {
      channel: NEXUS_POPUP_CHANNEL,
      type: 'NEXUS_PROOF_RESULT',
      requestId: pending.requestId,
      proof,
    },
    pending.origin,
  );
}

export function postProofError(pending: PendingProofRequest, code: WalletProofErrorCode): void {
  pending.source.postMessage(
    {
      channel: NEXUS_POPUP_CHANNEL,
      type: 'NEXUS_PROOF_ERROR',
      requestId: pending.requestId,
      error: { code },
    },
    pending.origin,
  );
}
