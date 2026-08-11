import { deriveGenesisHash, getDefaultCryptoProvider, type CryptoProvider } from '@nexus/crypto';
import {
  base64Url32Schema,
  base64Url64Schema,
  encodeBase64Url,
  formatRegistryEventId,
  registryReceiptV1Schema,
  type NexusSubject,
  type RegistryReceiptV1,
  type RevokeBySecretRequestV1,
  type RevokeBySignatureRequestV1,
} from '@nexus/protocol';

import { WalletCoreError } from './errors.js';
import type {
  Clock,
  RegistryClient,
  RegistryIdentityStatus,
  RegistryRegisterRequest,
} from './types.js';

interface InMemoryRegistryEntry {
  request: RegistryRegisterRequest;
  status: RegistryIdentityStatus;
  registrationReceipt: RegistryReceiptV1;
  revocationReceipt?: RegistryReceiptV1;
}

export interface InMemoryRegistryClientOptions {
  crypto?: CryptoProvider;
  clock?: Clock;
  signerKid?: string;
}

const systemClock: Clock = {
  now: () => Math.floor(Date.now() / 1000),
};

/**
 * An intentionally unsigned registry state machine for wallet-core unit tests.
 * Production applications must use a real RegistryClient and receipt verifier.
 */
export class InMemoryRegistryClient implements RegistryClient {
  readonly #crypto: CryptoProvider;
  readonly #clock: Clock;
  readonly #signerKid: string;
  readonly #entries = new Map<NexusSubject, InMemoryRegistryEntry>();
  readonly #registerRequests: RegistryRegisterRequest[] = [];

  public constructor(options: InMemoryRegistryClientOptions = {}) {
    this.#crypto = options.crypto ?? getDefaultCryptoProvider();
    this.#clock = options.clock ?? systemClock;
    this.#signerKid = options.signerKid ?? 'in-memory-test-key';
  }

  public get registerRequests(): readonly RegistryRegisterRequest[] {
    return this.#registerRequests.map((request) => structuredClone(request));
  }

  public async register(request: RegistryRegisterRequest): Promise<unknown> {
    const existing = this.#entries.get(request.subject);
    if (existing !== undefined) return structuredClone(existing.registrationReceipt);

    const acceptedAt = this.#clock.now();
    const registrationReceipt = await this.#createReceipt(
      request,
      'registered',
      'active',
      0,
      acceptedAt,
    );
    const savedRequest = structuredClone(request);
    this.#registerRequests.push(savedRequest);
    this.#entries.set(request.subject, {
      request: savedRequest,
      status: {
        subject: request.subject,
        state: 'active',
        sequence: 0,
        registeredAt: acceptedAt,
      },
      registrationReceipt,
    });
    return structuredClone(registrationReceipt);
  }

  public getStatus(subject: NexusSubject): Promise<RegistryIdentityStatus> {
    const entry = this.#entries.get(subject);
    if (entry === undefined) {
      return Promise.reject(
        new WalletCoreError(
          'IDENTITY_NOT_REGISTERED',
          'The in-memory registry has no such subject.',
        ),
      );
    }
    return Promise.resolve(structuredClone(entry.status));
  }

  public async revoke(
    request: RevokeBySignatureRequestV1 | RevokeBySecretRequestV1,
  ): Promise<unknown> {
    const subject = request.payload.subject;
    const entry = this.#entries.get(subject);
    if (entry === undefined) {
      throw new WalletCoreError(
        'IDENTITY_NOT_REGISTERED',
        'The in-memory registry has no such subject.',
      );
    }
    if (entry.status.state === 'revoked') return structuredClone(entry.revocationReceipt);
    if (request.payload.expectedSequence !== entry.status.sequence) {
      throw new WalletCoreError('REGISTRY_CONFLICT', 'The in-memory registry sequence is stale.');
    }

    const acceptedAt = this.#clock.now();
    const receipt = await this.#createReceipt(entry.request, 'revoked', 'revoked', 1, acceptedAt);
    entry.revocationReceipt = receipt;
    entry.status = {
      ...entry.status,
      state: 'revoked',
      sequence: 1,
      revokedAt: acceptedAt,
      terminalReceipt: structuredClone(receipt),
    };
    return structuredClone(receipt);
  }

  async #createReceipt(
    request: RegistryRegisterRequest,
    eventType: 'registered' | 'revoked',
    state: 'active' | 'revoked',
    sequence: number,
    acceptedAt: number,
  ): Promise<RegistryReceiptV1> {
    const genesisHash = await deriveGenesisHash(request.genesis, this.#crypto);
    return registryReceiptV1Schema.parse({
      payload: {
        protocol: 'nexus.registry-receipt.v1',
        eventId: formatRegistryEventId(this.#crypto.randomBytes(32)),
        subject: request.subject,
        genesisHash: base64Url32Schema.parse(encodeBase64Url(genesisHash)),
        eventType,
        sequence,
        state,
        acceptedAt,
        signerKid: this.#signerKid,
      },
      // Deliberately not valid: tests must explicitly install the test verifier below.
      signature: base64Url64Schema.parse(encodeBase64Url(this.#crypto.randomBytes(64))),
    });
  }
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

/**
 * Test-only verifier for InMemoryRegistryClient receipts. It provides no
 * cryptographic assurance and must never be wired into a production wallet.
 */
export function acceptUnsignedInMemoryRegistryReceipt(
  receipt: unknown,
): Promise<RegistryReceiptV1> {
  if (!isObject(receipt) || !isObject(receipt.payload) || typeof receipt.signature !== 'string') {
    return Promise.reject(
      new WalletCoreError('INVALID_REGISTRY_RECEIPT', 'Malformed in-memory test receipt.'),
    );
  }
  const payload = receipt.payload;
  if (
    payload.protocol !== 'nexus.registry-receipt.v1' ||
    typeof payload.subject !== 'string' ||
    typeof payload.eventType !== 'string' ||
    typeof payload.state !== 'string' ||
    typeof payload.sequence !== 'number'
  ) {
    return Promise.reject(
      new WalletCoreError('INVALID_REGISTRY_RECEIPT', 'Malformed in-memory test payload.'),
    );
  }
  try {
    return Promise.resolve(registryReceiptV1Schema.parse(receipt));
  } catch (error) {
    return Promise.reject(
      new WalletCoreError('INVALID_REGISTRY_RECEIPT', 'Malformed in-memory test receipt.', {
        cause: error,
      }),
    );
  }
}
