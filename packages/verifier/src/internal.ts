import { deriveSubject, getDefaultCryptoProvider, verifyProtocolPayload } from '@nexus/crypto';
import { decodeBase64UrlExact, identityGenesisV1Schema } from '@nexus/protocol';
import type { IdentityGenesisV1, VerifiedSubject } from '@nexus/protocol';

import { verificationError } from './errors.js';

type Path = readonly (string | number)[];

interface SafeParseSuccess<T> {
  readonly success: true;
  readonly data: T;
}

interface SafeParseFailure {
  readonly success: false;
}

interface StrictSchema<T> {
  safeParse(value: unknown): SafeParseSuccess<T> | SafeParseFailure;
}

interface ExpectedField {
  readonly path: Path;
  readonly expected: string;
}

export interface ParseOptions {
  readonly protocols?: readonly ExpectedField[];
  readonly suites?: readonly ExpectedField[];
}

function isRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function readPath(value: unknown, path: Path): unknown {
  let current = value;

  for (const part of path) {
    if (typeof part === 'number') {
      if (!Array.isArray(current)) return undefined;
      current = current[part];
      continue;
    }

    if (!isRecord(current)) return undefined;
    current = current[part];
  }

  return current;
}

/**
 * Runs the strict versioned schema before classifying a protocol/suite mismatch.
 * This preserves fail-closed parsing while still exposing useful typed errors.
 */
export function parseExternal<T>(
  schema: StrictSchema<T>,
  value: unknown,
  options: ParseOptions = {},
): T {
  const result = schema.safeParse(value);
  if (result.success) return result.data;

  for (const field of options.protocols ?? []) {
    const actual = readPath(value, field.path);
    if (typeof actual === 'string' && actual !== field.expected) {
      throw verificationError('UNSUPPORTED_PROTOCOL');
    }
  }

  for (const field of options.suites ?? []) {
    const actual = readPath(value, field.path);
    if (typeof actual === 'string' && actual !== field.expected) {
      throw verificationError('UNSUPPORTED_SUITE');
    }
  }

  throw verificationError('BAD_REQUEST');
}

export function parseGenesis(
  value: unknown,
  identityProtocol: string,
  suite: string,
): IdentityGenesisV1 {
  return parseExternal(identityGenesisV1Schema, value, {
    protocols: [{ path: ['protocol'], expected: identityProtocol }],
    suites: [{ path: ['suite'], expected: suite }],
  });
}

export function assertNonNegativeInteger(value: number): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw verificationError('BAD_REQUEST');
  }
}

export function assertClockInput(now: number, maxClockSkewSeconds: number): void {
  assertNonNegativeInteger(now);
  assertNonNegativeInteger(maxClockSkewSeconds);
}

export function validateExpiringWindow(
  iat: number,
  exp: number,
  now: number,
  maxClockSkewSeconds: number,
  maxLifetimeSeconds: number,
): void {
  assertClockInput(now, maxClockSkewSeconds);
  assertNonNegativeInteger(maxLifetimeSeconds);

  if (exp - iat > maxLifetimeSeconds) {
    throw verificationError('PROOF_LIFETIME_EXCEEDED');
  }
  if (iat > now + maxClockSkewSeconds) {
    throw verificationError('PROOF_NOT_YET_VALID');
  }
  if (now > exp + maxClockSkewSeconds) {
    throw verificationError('PROOF_EXPIRED');
  }
}

export function validateIssuedAt(
  iat: number,
  now: number,
  maxClockSkewSeconds: number,
  maxAgeSeconds: number,
): void {
  assertClockInput(now, maxClockSkewSeconds);
  assertNonNegativeInteger(maxAgeSeconds);

  if (iat > now + maxClockSkewSeconds) {
    throw verificationError('PROOF_NOT_YET_VALID');
  }
  if (now > iat + maxAgeSeconds + maxClockSkewSeconds) {
    throw verificationError('PROOF_EXPIRED');
  }
}

export async function importIdentitySigningKey(genesis: IdentityGenesisV1): Promise<CryptoKey> {
  return importEd25519PublicKey(genesis.signingKey.publicKey);
}

export async function importEd25519PublicKey(encodedPublicKey: string): Promise<CryptoKey> {
  const raw = decodeBase64UrlExact(encodedPublicKey, 32);

  try {
    return await getDefaultCryptoProvider().importEd25519PublicKey(raw);
  } catch {
    throw verificationError('INVALID_KEY');
  }
}

export async function verifyPayloadSignature<T extends { protocol: string }>(
  payload: T,
  signature: string,
  publicKey: CryptoKey,
): Promise<void> {
  let valid: boolean;
  try {
    valid = await verifyProtocolPayload(payload, signature, publicKey);
  } catch {
    throw verificationError('INVALID_SIGNATURE');
  }

  if (!valid) throw verificationError('INVALID_SIGNATURE');
}

export async function verifyParsedSubject(
  genesis: IdentityGenesisV1,
  claimedSubject: string,
): Promise<VerifiedSubject> {
  const computed = await deriveSubject(genesis);
  if (computed !== claimedSubject) throw verificationError('INVALID_SUBJECT');

  const signingPublicKey = decodeBase64UrlExact(genesis.signingKey.publicKey, 32);
  const base = {
    subject: computed,
    signingPublicKey,
  };

  if (genesis.agreementKey === undefined) return base;

  return {
    ...base,
    agreementPublicKey: decodeBase64UrlExact(genesis.agreementKey.publicKey, 32),
  };
}
