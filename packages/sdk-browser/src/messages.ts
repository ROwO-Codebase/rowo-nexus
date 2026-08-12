import type { OwnershipProofV1, OwnershipProofV2, ProofRequest } from '@nexus/protocol';

export const NEXUS_POPUP_CHANNEL = 'nexus.popup.v1' as const;

/** Additive negotiation channel. The v1 channel and its envelopes remain unchanged. */
export const NEXUS_POPUP_CHANNEL_V2 = 'nexus.popup.v2' as const;

export const NEXUS_OWNERSHIP_PROOF_PROTOCOLS = [
  'nexus.ownership-proof.v2',
  'nexus.ownership-proof.v1',
] as const;

export type NexusOwnershipProofProtocol = (typeof NEXUS_OWNERSHIP_PROOF_PROTOCOLS)[number];
export type AcceptedProofProtocols = readonly [
  NexusOwnershipProofProtocol,
  ...NexusOwnershipProofProtocol[],
];

export interface NexusReadyMessage {
  channel: typeof NEXUS_POPUP_CHANNEL;
  type: 'NEXUS_READY';
}

export interface NexusProofRequestMessage {
  channel: typeof NEXUS_POPUP_CHANNEL;
  type: 'NEXUS_PROOF_REQUEST';
  requestId: string;
  request: ProofRequest;
}

export interface NexusProofResultMessage {
  channel: typeof NEXUS_POPUP_CHANNEL;
  type: 'NEXUS_PROOF_RESULT';
  requestId: string;
  proof: OwnershipProofV1;
}

export const WALLET_PROOF_ERROR_CODES = [
  'USER_CANCELLED',
  'POPUP_CLOSED',
  'INVALID_REQUEST',
  'CHALLENGE_EXPIRED',
  'NO_ACTIVE_IDENTITY',
  'REGISTRATION_FAILED',
  'INTERNAL_ERROR',
] as const;

export type WalletProofErrorCode = (typeof WALLET_PROOF_ERROR_CODES)[number];

export interface NexusProofErrorMessage {
  channel: typeof NEXUS_POPUP_CHANNEL;
  type: 'NEXUS_PROOF_ERROR';
  requestId: string;
  error: {
    code: WalletProofErrorCode;
  };
}

export type WalletToRpMessage =
  NexusReadyMessage | NexusProofResultMessage | NexusProofErrorMessage;

export type RpToWalletMessage = NexusProofRequestMessage;

export interface NexusReadyMessageV2 {
  channel: typeof NEXUS_POPUP_CHANNEL_V2;
  type: 'NEXUS_READY';
  supportedProofProtocols: AcceptedProofProtocols;
}

export interface NexusProofRequestMessageV2 {
  channel: typeof NEXUS_POPUP_CHANNEL_V2;
  type: 'NEXUS_PROOF_REQUEST';
  requestId: string;
  request: ProofRequest;
  /**
   * Ordered RP preference. This negotiates the popup response only; an RP backend MUST bind the
   * same policy to the challenge and independently reject a returned protocol it did not allow.
   */
  acceptedProofProtocols: AcceptedProofProtocols;
}

export type NexusNegotiatedProofResult =
  | {
      proofProtocol: 'nexus.ownership-proof.v2';
      proof: OwnershipProofV2;
    }
  | {
      proofProtocol: 'nexus.ownership-proof.v1';
      proof: OwnershipProofV1;
    };

export type NexusProofResultMessageV2 = NexusNegotiatedProofResult & {
  channel: typeof NEXUS_POPUP_CHANNEL_V2;
  type: 'NEXUS_PROOF_RESULT';
  requestId: string;
};

export type WalletProofErrorCodeV2 = WalletProofErrorCode | 'UNSUPPORTED_PROOF_PROTOCOL';

export interface NexusProofErrorMessageV2 {
  channel: typeof NEXUS_POPUP_CHANNEL_V2;
  type: 'NEXUS_PROOF_ERROR';
  requestId: string;
  error: {
    code: WalletProofErrorCodeV2;
  };
}

export type WalletToRpMessageV2 =
  NexusReadyMessageV2 | NexusProofResultMessageV2 | NexusProofErrorMessageV2;

export type RpToWalletMessageV2 = NexusProofRequestMessageV2;

const READY_KEYS = ['channel', 'type'] as const;
const RESULT_KEYS = ['channel', 'proof', 'requestId', 'type'] as const;
const ERROR_KEYS = ['channel', 'error', 'requestId', 'type'] as const;
const ERROR_BODY_KEYS = ['code'] as const;
const READY_KEYS_V2 = ['channel', 'supportedProofProtocols', 'type'] as const;
const RESULT_KEYS_V2 = ['channel', 'proof', 'proofProtocol', 'requestId', 'type'] as const;

export function parseWalletMessage(value: unknown): WalletToRpMessage | undefined {
  if (!isRecord(value) || value.channel !== NEXUS_POPUP_CHANNEL) return undefined;

  if (value.type === 'NEXUS_READY') {
    return hasExactKeys(value, READY_KEYS) ? (value as unknown as NexusReadyMessage) : undefined;
  }

  if (value.type === 'NEXUS_PROOF_RESULT') {
    if (
      !hasExactKeys(value, RESULT_KEYS) ||
      !isRequestId(value.requestId) ||
      !isRecord(value.proof)
    ) {
      return undefined;
    }

    return value as unknown as NexusProofResultMessage;
  }

  if (value.type === 'NEXUS_PROOF_ERROR') {
    if (
      !hasExactKeys(value, ERROR_KEYS) ||
      !isRequestId(value.requestId) ||
      !isRecord(value.error) ||
      !hasExactKeys(value.error, ERROR_BODY_KEYS) ||
      !isWalletProofErrorCode(value.error.code)
    ) {
      return undefined;
    }

    return value as unknown as NexusProofErrorMessage;
  }

  return undefined;
}

export function parseWalletMessageV2(value: unknown): WalletToRpMessageV2 | undefined {
  if (!isRecord(value) || value.channel !== NEXUS_POPUP_CHANNEL_V2) return undefined;

  if (value.type === 'NEXUS_READY') {
    if (
      !hasExactKeys(value, READY_KEYS_V2) ||
      !isAcceptedProofProtocols(value.supportedProofProtocols)
    ) {
      return undefined;
    }
    return value as unknown as NexusReadyMessageV2;
  }

  if (value.type === 'NEXUS_PROOF_RESULT') {
    if (
      !hasExactKeys(value, RESULT_KEYS_V2) ||
      !isRequestId(value.requestId) ||
      !isNexusOwnershipProofProtocol(value.proofProtocol) ||
      !isRecord(value.proof) ||
      !proofMatchesProtocol(value.proof, value.proofProtocol)
    ) {
      return undefined;
    }
    return value as unknown as NexusProofResultMessageV2;
  }

  if (value.type === 'NEXUS_PROOF_ERROR') {
    if (
      !hasExactKeys(value, ERROR_KEYS) ||
      !isRequestId(value.requestId) ||
      !isRecord(value.error) ||
      !hasExactKeys(value.error, ERROR_BODY_KEYS) ||
      !isWalletProofErrorCodeV2(value.error.code)
    ) {
      return undefined;
    }
    return value as unknown as NexusProofErrorMessageV2;
  }

  return undefined;
}

export function parseAcceptedProofProtocols(value: unknown): AcceptedProofProtocols | undefined {
  return isAcceptedProofProtocols(value) ? value : undefined;
}

export function isRequestId(value: unknown): value is string {
  return typeof value === 'string' && isUnpaddedBase64Url(value) && decodedByteLength(value) >= 16;
}

function isWalletProofErrorCode(value: unknown): value is WalletProofErrorCode {
  return (
    typeof value === 'string' && (WALLET_PROOF_ERROR_CODES as readonly string[]).includes(value)
  );
}

function isWalletProofErrorCodeV2(value: unknown): value is WalletProofErrorCodeV2 {
  return value === 'UNSUPPORTED_PROOF_PROTOCOL' || isWalletProofErrorCode(value);
}

function isNexusOwnershipProofProtocol(value: unknown): value is NexusOwnershipProofProtocol {
  return (
    typeof value === 'string' &&
    (NEXUS_OWNERSHIP_PROOF_PROTOCOLS as readonly string[]).includes(value)
  );
}

function isAcceptedProofProtocols(value: unknown): value is AcceptedProofProtocols {
  if (!Array.isArray(value) || value.length === 0) return false;
  if (!value.every(isNexusOwnershipProofProtocol)) return false;
  return new Set(value).size === value.length;
}

function proofMatchesProtocol(
  proof: Record<string, unknown>,
  protocol: NexusOwnershipProofProtocol,
): boolean {
  return isRecord(proof.payload) && proof.payload.protocol === protocol;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hasExactKeys<T extends readonly string[]>(
  value: Record<string, unknown>,
  expected: T,
): boolean {
  const keys = Object.keys(value).sort();
  const sortedExpected = [...expected].sort();
  return (
    keys.length === sortedExpected.length &&
    keys.every((key, index) => key === sortedExpected[index])
  );
}

function isUnpaddedBase64Url(value: string): boolean {
  return value.length > 0 && /^[A-Za-z0-9_-]+$/.test(value) && value.length % 4 !== 1;
}

function decodedByteLength(value: string): number {
  return Math.floor((value.length * 6) / 8);
}
