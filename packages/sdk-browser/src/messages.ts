import type { OwnershipProofV1, ProofRequest } from '@nexus/protocol';

export const NEXUS_POPUP_CHANNEL = 'nexus.popup.v1' as const;

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

const READY_KEYS = ['channel', 'type'] as const;
const RESULT_KEYS = ['channel', 'proof', 'requestId', 'type'] as const;
const ERROR_KEYS = ['channel', 'error', 'requestId', 'type'] as const;
const ERROR_BODY_KEYS = ['code'] as const;

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

export function isRequestId(value: unknown): value is string {
  return typeof value === 'string' && isUnpaddedBase64Url(value) && decodedByteLength(value) >= 16;
}

function isWalletProofErrorCode(value: unknown): value is WalletProofErrorCode {
  return (
    typeof value === 'string' && (WALLET_PROOF_ERROR_CODES as readonly string[]).includes(value)
  );
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
