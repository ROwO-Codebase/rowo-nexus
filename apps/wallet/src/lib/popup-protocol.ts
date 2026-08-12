import {
  base64Url32Schema,
  base64UrlAtLeast16Schema,
  proofRequestSchema,
  type OwnershipProofV1,
  type OwnershipProofV2,
  type ProofRequest,
} from '@nexus/protocol';
import { captureWalletEventBoundary, type TrustedWalletEventBoundary } from '@nexus/wallet-core';

export const NEXUS_POPUP_CHANNEL = 'nexus.popup.v1' as const;
export const NEXUS_POPUP_CHANNEL_V2 = 'nexus.popup.v2' as const;

export const SUPPORTED_PROOF_PROTOCOLS = [
  'nexus.ownership-proof.v2',
  'nexus.ownership-proof.v1',
] as const;

export type NexusOwnershipProofProtocol = (typeof SUPPORTED_PROOF_PROTOCOLS)[number];
export type AcceptedProofProtocols = readonly [
  NexusOwnershipProofProtocol,
  ...NexusOwnershipProofProtocol[],
];

export interface PendingProofRequest {
  requestId: string;
  request: ProofRequest;
  origin: string;
  boundary: TrustedWalletEventBoundary;
  source: Window;
  popupProtocol: typeof NEXUS_POPUP_CHANNEL | typeof NEXUS_POPUP_CHANNEL_V2;
  /** Ordered policy asserted by the RP. Its backend must also bind and enforce it. */
  acceptedProofProtocols: AcceptedProofProtocols;
}

export type WalletProofErrorCode =
  | 'USER_CANCELLED'
  | 'INVALID_REQUEST'
  | 'CHALLENGE_EXPIRED'
  | 'NO_ACTIVE_IDENTITY'
  | 'REGISTRATION_FAILED'
  | 'INTERNAL_ERROR';
export type WalletProofErrorCodeV2 = WalletProofErrorCode | 'UNSUPPORTED_PROOF_PROTOCOL';

const MESSAGE_KEYS = ['channel', 'request', 'requestId', 'type'] as const;
const MESSAGE_KEYS_V2 = [
  'acceptedProofProtocols',
  'channel',
  'request',
  'requestId',
  'type',
] as const;
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
  const isV1 = event.data.channel === NEXUS_POPUP_CHANNEL;
  const isV2 = event.data.channel === NEXUS_POPUP_CHANNEL_V2;
  if (!isV1 && !isV2) return undefined;
  const expectedKeys = isV2 ? MESSAGE_KEYS_V2 : MESSAGE_KEYS;
  if (
    !hasOnlyKeys(event.data, expectedKeys) ||
    Object.keys(event.data).length !== expectedKeys.length
  ) {
    return undefined;
  }
  if (
    event.data.type !== 'NEXUS_PROOF_REQUEST' ||
    !isRequestId(event.data.requestId) ||
    !isRecord(event.data.request) ||
    !hasOnlyKeys(event.data.request, REQUEST_KEYS)
  ) {
    return undefined;
  }

  const acceptedProofProtocols = isV2
    ? parseAcceptedProofProtocols(event.data.acceptedProofProtocols)
    : (['nexus.ownership-proof.v1'] as const);
  if (acceptedProofProtocols === undefined) return undefined;

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
    popupProtocol: isV2 ? NEXUS_POPUP_CHANNEL_V2 : NEXUS_POPUP_CHANNEL,
    acceptedProofProtocols,
  };
}

/** NEXUS_READY contains no proof or identity data. It is the sole wildcard message. */
export function announceWalletReady(opener: Window | null): void {
  opener?.postMessage({ channel: NEXUS_POPUP_CHANNEL, type: 'NEXUS_READY' }, '*');
}

/** NEXUS_READY v2 advertises capabilities but contains no proof or identity data. */
export function announceWalletReadyV2(opener: Window | null): void {
  opener?.postMessage(
    {
      channel: NEXUS_POPUP_CHANNEL_V2,
      type: 'NEXUS_READY',
      supportedProofProtocols: SUPPORTED_PROOF_PROTOCOLS,
    },
    '*',
  );
}

export function postProofResult(
  pending: PendingProofRequest,
  result:
    | { proofProtocol: 'nexus.ownership-proof.v1'; proof: OwnershipProofV1 }
    | { proofProtocol: 'nexus.ownership-proof.v2'; proof: OwnershipProofV2 },
): void {
  if (!pending.acceptedProofProtocols.includes(result.proofProtocol)) {
    throw new Error('Proof protocol was not accepted by the RP request.');
  }
  if (result.proof.payload.protocol !== result.proofProtocol) {
    throw new Error('Proof payload protocol does not match the selected popup protocol.');
  }
  if (
    pending.popupProtocol === NEXUS_POPUP_CHANNEL &&
    result.proofProtocol !== 'nexus.ownership-proof.v1'
  ) {
    throw new Error('The v1 popup protocol can only return a v1 ownership proof.');
  }
  pending.source.postMessage(
    pending.popupProtocol === NEXUS_POPUP_CHANNEL
      ? {
          channel: NEXUS_POPUP_CHANNEL,
          type: 'NEXUS_PROOF_RESULT',
          requestId: pending.requestId,
          proof: result.proof,
        }
      : {
          channel: NEXUS_POPUP_CHANNEL_V2,
          type: 'NEXUS_PROOF_RESULT',
          requestId: pending.requestId,
          proofProtocol: result.proofProtocol,
          proof: result.proof,
        },
    pending.origin,
  );
}

export function postProofError(pending: PendingProofRequest, code: WalletProofErrorCodeV2): void {
  if (pending.popupProtocol === NEXUS_POPUP_CHANNEL && code === 'UNSUPPORTED_PROOF_PROTOCOL') {
    throw new Error('The v1 popup protocol does not define UNSUPPORTED_PROOF_PROTOCOL.');
  }
  pending.source.postMessage(
    {
      channel: pending.popupProtocol,
      type: 'NEXUS_PROOF_ERROR',
      requestId: pending.requestId,
      error: { code },
    },
    pending.origin,
  );
}

export function selectProofProtocol(
  accepted: AcceptedProofProtocols,
  supported: readonly NexusOwnershipProofProtocol[],
): NexusOwnershipProofProtocol | undefined {
  return accepted.find((protocol) => supported.includes(protocol));
}

function parseAcceptedProofProtocols(value: unknown): AcceptedProofProtocols | undefined {
  if (!Array.isArray(value) || value.length === 0) return undefined;
  if (
    !value.every(
      (protocol) =>
        typeof protocol === 'string' &&
        (SUPPORTED_PROOF_PROTOCOLS as readonly string[]).includes(protocol),
    ) ||
    new Set(value).size !== value.length
  ) {
    return undefined;
  }
  return value as unknown as AcceptedProofProtocols;
}
