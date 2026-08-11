import {
  computeRevocationCommitment,
  createProtocolSignaturePreimage,
  deriveGenesisHash,
  deriveSubject,
  getDefaultCryptoProvider,
  type CryptoProvider,
} from '@nexus/crypto';
import {
  base64Url32Schema,
  base64Url64Schema,
  base64UrlAtLeast16Schema,
  continuityLinkPayloadV1Schema,
  encodeBase64Url,
  identityGenesisV1Schema,
  ownershipProofPayloadV1Schema,
  proofRequestSchema,
  revokeBySecretRequestV1Schema,
  revokeBySignatureRequestV1Schema,
  type ContinuityLinkPayloadV1,
  type ContinuityLinkV1,
  type IdentityGenesisV1,
  type OwnershipProofPayloadV1,
  type OwnershipProofV1,
  type ProofRequest,
  type RegistryReceiptV1,
  type RevokeBySecretRequestV1,
  type RevokeBySignaturePayloadV1,
  type RevokeBySignatureRequestV1,
} from '@nexus/protocol';

import { WalletCoreError } from './errors.js';
import { requireTrustedWalletEventBoundary } from './trusted-wallet-event.js';
import type {
  Clock,
  ContinuityLinkOptions,
  CreatedLocalIdentity,
  CreateIdentityOptions,
  DisposeIdentityOptions,
  IdentityStore,
  KeyRef,
  KeyVault,
  LocalIdentityRecordV1,
  LocalIdentitySummary,
  RegistryClient,
  RegistryIdentityStatus,
  RegistryReceiptVerifier,
  RevokeIdentityOptions,
  RotateIdentityOptions,
  RotateIdentityResult,
  TrustedWalletEventBoundary,
  WalletCoreApi,
} from './types.js';

const IDENTITY_PROTOCOL = 'nexus.identity.v1' as const;
const SUITE = 'NX-25519-SHA256-JCS-v1' as const;
const OWNERSHIP_PROOF_PROTOCOL = 'nexus.ownership-proof.v1' as const;
const REVOKE_PROTOCOL = 'nexus.revoke.v1' as const;
const REVOKE_SECRET_PROTOCOL = 'nexus.revoke-secret.v1' as const;
const CONTINUITY_LINK_PROTOCOL = 'nexus.continuity-link.v1' as const;

export interface WalletCoreOptions {
  keyVault: KeyVault;
  identityStore: IdentityStore;
  registryClient: RegistryClient;
  verifyRegistryReceipt: RegistryReceiptVerifier;
  crypto?: CryptoProvider;
  clock?: Clock;
}

const systemClock: Clock = {
  now: () => Math.floor(Date.now() / 1000),
};

function validateAscii(value: string, field: string, allowEmpty = false): void {
  if ((!allowEmpty && value.length === 0) || !/^[\x20-\x7e]*$/.test(value)) {
    throw new WalletCoreError(
      'INVALID_REQUEST',
      `${field} must be a non-empty printable ASCII string.`,
    );
  }
}

function validateEpochSeconds(value: number, field: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new WalletCoreError(
      'INVALID_REQUEST',
      `${field} must be a non-negative integer epoch second.`,
    );
  }
}

function parseWalletInput<T>(parse: () => T, message: string): T {
  try {
    return parse();
  } catch (error) {
    throw new WalletCoreError('INVALID_REQUEST', message, { cause: error });
  }
}

function newLocalId(cryptoProvider: CryptoProvider): string {
  const bytes = cryptoProvider.randomBytes(16);
  if (bytes.byteLength !== 16) {
    throw new WalletCoreError('STORAGE_ERROR', 'The CSPRNG returned an invalid local identifier.');
  }
  const uuid = Uint8Array.from(bytes);
  uuid[6] = ((uuid[6] ?? 0) & 0x0f) | 0x40;
  uuid[8] = ((uuid[8] ?? 0) & 0x3f) | 0x80;
  const hex = [...uuid].map((byte) => byte.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function summarize(record: LocalIdentityRecordV1): LocalIdentitySummary {
  return {
    localId: record.localId,
    subject: record.subject,
    ...(record.label === undefined ? {} : { label: record.label }),
    localScopes: [...record.localScopes],
    localState: record.localState,
    registered: record.registrationReceipt !== undefined,
    hasAgreementKey: record.genesis.agreementKey !== undefined,
  };
}

function requireSigningRef(record: LocalIdentityRecordV1): KeyRef {
  if (record.signingPrivateKeyRef === undefined) {
    throw new WalletCoreError(
      'IDENTITY_REVOKED',
      'This identity no longer has active signing material.',
    );
  }
  return record.signingPrivateKeyRef;
}

function requireRevocationSecretRef(record: LocalIdentityRecordV1) {
  if (record.revocationSecretRef === undefined) {
    throw new WalletCoreError(
      'IDENTITY_REVOKED',
      'This identity no longer has an active revocation secret.',
    );
  }
  return record.revocationSecretRef;
}

function asCreatedIdentity(record: LocalIdentityRecordV1): CreatedLocalIdentity {
  return {
    localId: record.localId,
    subject: record.subject,
    genesis: structuredClone(record.genesis),
    ...(record.registrationReceipt === undefined
      ? {}
      : { registrationReceipt: structuredClone(record.registrationReceipt) }),
  };
}

export class WalletCore implements WalletCoreApi {
  readonly #keyVault: KeyVault;
  readonly #identityStore: IdentityStore;
  readonly #registryClient: RegistryClient;
  readonly #verifyRegistryReceipt: RegistryReceiptVerifier;
  readonly #crypto: CryptoProvider;
  readonly #clock: Clock;

  public constructor(options: WalletCoreOptions) {
    this.#keyVault = options.keyVault;
    this.#identityStore = options.identityStore;
    this.#registryClient = options.registryClient;
    this.#verifyRegistryReceipt = options.verifyRegistryReceipt;
    this.#crypto = options.crypto ?? getDefaultCryptoProvider();
    this.#clock = options.clock ?? systemClock;
  }

  public async createIdentity(options: CreateIdentityOptions = {}): Promise<CreatedLocalIdentity> {
    const signingPrivateKeyRef = await this.#keyVault.createSigningKey();
    let agreementPrivateKeyRef: KeyRef | undefined;
    let revocationSecretRef: LocalIdentityRecordV1['revocationSecretRef'];

    try {
      if (options.withAgreementKey === true) {
        agreementPrivateKeyRef = await this.#keyVault.createAgreementKey();
      }

      const revocationSecret = this.#crypto.randomBytes(32);
      if (revocationSecret.byteLength !== 32) {
        throw new WalletCoreError(
          'STORAGE_ERROR',
          'The CSPRNG returned an invalid revocation secret.',
        );
      }
      revocationSecretRef = await this.#keyVault.storeRevocationSecret(revocationSecret);

      const signingPublicKey = await this.#keyVault.readPublicKey(signingPrivateKeyRef);
      if (signingPublicKey.byteLength !== 32) {
        throw new WalletCoreError('STORAGE_ERROR', 'The Ed25519 public key must contain 32 bytes.');
      }

      const agreementPublicKey =
        agreementPrivateKeyRef === undefined
          ? undefined
          : await this.#keyVault.readPublicKey(agreementPrivateKeyRef);
      if (agreementPublicKey !== undefined && agreementPublicKey.byteLength !== 32) {
        throw new WalletCoreError('STORAGE_ERROR', 'The X25519 public key must contain 32 bytes.');
      }

      const revocationCommitment = await computeRevocationCommitment(
        revocationSecret,
        this.#crypto,
      );
      const genesis: IdentityGenesisV1 = identityGenesisV1Schema.parse({
        protocol: IDENTITY_PROTOCOL,
        suite: SUITE,
        signingKey: { alg: 'Ed25519', publicKey: encodeBase64Url(signingPublicKey) },
        ...(agreementPublicKey === undefined
          ? {}
          : {
              agreementKey: {
                alg: 'X25519' as const,
                publicKey: encodeBase64Url(agreementPublicKey),
              },
            }),
        revocationCommitment: encodeBase64Url(revocationCommitment),
      });
      const subject = await deriveSubject(genesis, this.#crypto);
      const record: LocalIdentityRecordV1 = {
        localId: newLocalId(this.#crypto),
        subject,
        genesis,
        signingPrivateKeyRef,
        ...(agreementPrivateKeyRef === undefined ? {} : { agreementPrivateKeyRef }),
        revocationSecretRef,
        localScopes: [],
        ...(options.label === undefined ? {} : { label: options.label }),
        localState: 'active',
      };
      await this.#identityStore.put(record);

      if (options.register === false) return asCreatedIdentity(record);
      const registrationReceipt = await this.registerIdentity(record.localId);
      return asCreatedIdentity({ ...record, registrationReceipt });
    } catch (error) {
      const existing = await this.#identityStore
        .list()
        .then((records) =>
          records.some((record) => record.signingPrivateKeyRef === signingPrivateKeyRef),
        )
        .catch(() => true);
      if (!existing) {
        await Promise.allSettled([
          this.#keyVault.deleteKey(signingPrivateKeyRef),
          ...(agreementPrivateKeyRef === undefined
            ? []
            : [this.#keyVault.deleteKey(agreementPrivateKeyRef)]),
          ...(revocationSecretRef === undefined
            ? []
            : [this.#keyVault.deleteSecret(revocationSecretRef)]),
        ]);
      }
      throw error;
    }
  }

  public async registerIdentity(localId: string): Promise<RegistryReceiptV1> {
    const record = await this.#getRecord(localId);
    if (record.localState !== 'active') {
      throw new WalletCoreError(
        'IDENTITY_REVOKED',
        'A revoked identity cannot be registered again.',
      );
    }
    if (record.registrationReceipt !== undefined)
      return structuredClone(record.registrationReceipt);

    const rawReceipt = await this.#registryClient.register({
      subject: record.subject,
      genesis: structuredClone(record.genesis),
    });
    const registrationReceipt = await this.#verifyReceipt(rawReceipt, {
      subject: record.subject,
      eventType: 'registered',
      state: 'active',
      sequence: 0,
      genesisHash: encodeBase64Url(await deriveGenesisHash(record.genesis, this.#crypto)),
    });
    await this.#identityStore.put({ ...record, registrationReceipt });
    return structuredClone(registrationReceipt);
  }

  public async prove(
    localId: string,
    boundary: TrustedWalletEventBoundary,
    request: ProofRequest,
  ): Promise<OwnershipProofV1> {
    const audience = requireTrustedWalletEventBoundary(boundary).audience;
    const record = await this.#getActiveRegisteredRecord(localId);
    const parsedRequest = parseWalletInput(
      () => proofRequestSchema.parse(request),
      'The ownership proof request is invalid.',
    );

    const issuedAt = this.#clock.now();
    validateEpochSeconds(issuedAt, 'clock.now()');
    if (parsedRequest.expiresAt <= issuedAt) {
      throw new WalletCoreError('INVALID_REQUEST', 'The proof challenge has expired.');
    }

    const payload: OwnershipProofPayloadV1 = ownershipProofPayloadV1Schema.parse({
      protocol: OWNERSHIP_PROOF_PROTOCOL,
      subject: record.subject,
      genesis: structuredClone(record.genesis),
      aud: audience,
      act: parsedRequest.action,
      resource: parsedRequest.resource,
      nonce: parsedRequest.nonce,
      iat: issuedAt,
      exp: parsedRequest.expiresAt,
      ...(parsedRequest.contextHash === undefined
        ? {}
        : { contextHash: parsedRequest.contextHash }),
    });
    const signature = await this.#keyVault.sign(
      requireSigningRef(record),
      createProtocolSignaturePreimage(payload),
    );
    return { payload, signature: base64Url64Schema.parse(encodeBase64Url(signature)) };
  }

  public async revoke(
    localId: string,
    options: RevokeIdentityOptions = {},
  ): Promise<RegistryReceiptV1> {
    const record = await this.#getRecord(localId);
    const terminal = await this.#reachTerminalState(record, options);
    await this.#identityStore.put({
      ...record,
      localState: 'revoked',
      revocationReceipt: terminal.receipt,
    });
    return structuredClone(terminal.receipt);
  }

  public async dispose(
    localId: string,
    options: DisposeIdentityOptions = {},
  ): Promise<RegistryReceiptV1> {
    const record = await this.#getRecord(localId);
    const terminal = await this.#reachTerminalState(record, {
      ...(options.method === undefined ? {} : { method: options.method }),
      reasonCode: options.reasonCode ?? 'dispose',
    });

    const revokedRecord: LocalIdentityRecordV1 = {
      ...record,
      localState: 'revoked',
      revocationReceipt: terminal.receipt,
    };
    await this.#identityStore.put(revokedRecord);

    const deletions = await Promise.allSettled([
      ...(record.signingPrivateKeyRef === undefined
        ? []
        : [this.#keyVault.deleteKey(record.signingPrivateKeyRef)]),
      ...(record.agreementPrivateKeyRef === undefined
        ? []
        : [this.#keyVault.deleteKey(record.agreementPrivateKeyRef)]),
      ...(record.revocationSecretRef === undefined
        ? []
        : [this.#keyVault.deleteSecret(record.revocationSecretRef)]),
    ]);
    const deletionFailure = deletions.find(
      (result): result is PromiseRejectedResult => result.status === 'rejected',
    );
    if (deletionFailure !== undefined) {
      throw new WalletCoreError(
        'STORAGE_ERROR',
        'The identity is terminally revoked, but some local private material could not be deleted.',
        { cause: deletionFailure.reason },
      );
    }

    if (options.retainPublicRecord === false) {
      await this.#identityStore.delete(localId);
    } else {
      const publicRecord = { ...revokedRecord };
      delete publicRecord.signingPrivateKeyRef;
      delete publicRecord.agreementPrivateKeyRef;
      delete publicRecord.revocationSecretRef;
      await this.#identityStore.put(publicRecord);
    }
    return structuredClone(terminal.receipt);
  }

  public async rotate(
    oldLocalId: string,
    boundary: TrustedWalletEventBoundary,
    options: RotateIdentityOptions = {},
  ): Promise<RotateIdentityResult> {
    requireTrustedWalletEventBoundary(boundary);
    const oldRecord = await this.#getActiveRegisteredRecord(oldLocalId);
    const identity = await this.createIdentity({
      ...(options.label === undefined ? {} : { label: options.label }),
      withAgreementKey: options.withAgreementKey ?? oldRecord.genesis.agreementKey !== undefined,
      register: true,
    });
    await this.addScope(identity.localId, boundary);

    const oldRevocationReceipt =
      options.revokeOld === true
        ? await this.revoke(oldLocalId, { reasonCode: 'dispose' })
        : undefined;
    return {
      oldSubject: oldRecord.subject,
      identity,
      ...(oldRevocationReceipt === undefined ? {} : { oldRevocationReceipt }),
    };
  }

  public async createContinuityLink(
    localIdA: string,
    localIdB: string,
    options: ContinuityLinkOptions,
  ): Promise<ContinuityLinkV1> {
    if (localIdA === localIdB) {
      throw new WalletCoreError('INVALID_REQUEST', 'A continuity link requires two identities.');
    }
    const [identityA, identityB] = await Promise.all([
      this.#getActiveRegisteredRecord(localIdA),
      this.#getActiveRegisteredRecord(localIdB),
    ]);
    if (options.scope !== undefined) validateAscii(options.scope, 'scope');

    const issuedAt = this.#clock.now();
    validateEpochSeconds(issuedAt, 'clock.now()');
    if (options.expiresAt !== undefined) {
      validateEpochSeconds(options.expiresAt, 'expiresAt');
      if (options.expiresAt <= issuedAt) {
        throw new WalletCoreError(
          'INVALID_REQUEST',
          'The continuity link expiry must be in the future.',
        );
      }
    }

    const payload: ContinuityLinkPayloadV1 = parseWalletInput(
      () =>
        continuityLinkPayloadV1Schema.parse({
          protocol: CONTINUITY_LINK_PROTOCOL,
          subjectA: identityA.subject,
          genesisA: structuredClone(identityA.genesis),
          subjectB: identityB.subject,
          genesisB: structuredClone(identityB.genesis),
          ...(options.scope === undefined ? {} : { scope: options.scope }),
          iat: issuedAt,
          ...(options.expiresAt === undefined ? {} : { exp: options.expiresAt }),
          nonce: options.nonce,
        }),
      'The continuity link request is invalid.',
    );
    const preimage = createProtocolSignaturePreimage(payload);
    const [signatureA, signatureB] = await Promise.all([
      this.#keyVault.sign(requireSigningRef(identityA), preimage),
      this.#keyVault.sign(requireSigningRef(identityB), preimage),
    ]);
    return {
      payload,
      signatureA: base64Url64Schema.parse(encodeBase64Url(signatureA)),
      signatureB: base64Url64Schema.parse(encodeBase64Url(signatureB)),
    };
  }

  public async listIdentitySummaries(): Promise<LocalIdentitySummary[]> {
    return (await this.#identityStore.list()).map(summarize);
  }

  public async listIdentitySummariesForBoundary(
    boundary: TrustedWalletEventBoundary,
  ): Promise<LocalIdentitySummary[]> {
    const audience = requireTrustedWalletEventBoundary(boundary).audience;
    return (await this.#identityStore.list())
      .filter((record) => record.localScopes.includes(audience))
      .map(summarize);
  }

  public async addScope(localId: string, boundary: TrustedWalletEventBoundary): Promise<void> {
    const audience = requireTrustedWalletEventBoundary(boundary).audience;
    const record = await this.#getRecord(localId);
    if (record.localScopes.includes(audience)) return;
    await this.#identityStore.put({ ...record, localScopes: [...record.localScopes, audience] });
  }

  public async removeScope(localId: string, boundary: TrustedWalletEventBoundary): Promise<void> {
    const audience = requireTrustedWalletEventBoundary(boundary).audience;
    const record = await this.#getRecord(localId);
    await this.#identityStore.put({
      ...record,
      localScopes: record.localScopes.filter((scope) => scope !== audience),
    });
  }

  public async setLabel(localId: string, label?: string): Promise<void> {
    const record = await this.#getRecord(localId);
    if (label === undefined) {
      const withoutLabel = { ...record };
      delete withoutLabel.label;
      await this.#identityStore.put(withoutLabel);
      return;
    }
    await this.#identityStore.put({ ...record, label });
  }

  async #getRecord(localId: string): Promise<LocalIdentityRecordV1> {
    const record = await this.#identityStore.get(localId);
    if (record === undefined) {
      throw new WalletCoreError('IDENTITY_NOT_FOUND', `Local identity ${localId} does not exist.`);
    }
    return record;
  }

  async #getActiveRegisteredRecord(localId: string): Promise<LocalIdentityRecordV1> {
    const record = await this.#getRecord(localId);
    if (record.localState !== 'active') {
      throw new WalletCoreError('IDENTITY_REVOKED', 'This identity is locally marked as revoked.');
    }
    if (record.registrationReceipt === undefined) {
      throw new WalletCoreError(
        'IDENTITY_NOT_REGISTERED',
        'This identity has not been registered.',
      );
    }
    requireSigningRef(record);
    return record;
  }

  async #verifyReceipt(
    rawReceipt: unknown,
    expectation: {
      subject: LocalIdentityRecordV1['subject'];
      eventType: 'registered' | 'revoked';
      state: 'active' | 'revoked';
      sequence: number;
      genesisHash: string;
    },
  ): Promise<RegistryReceiptV1> {
    let receipt: RegistryReceiptV1;
    try {
      receipt = await this.#verifyRegistryReceipt(rawReceipt);
    } catch (error) {
      throw new WalletCoreError(
        'INVALID_REGISTRY_RECEIPT',
        'The registry receipt did not pass cryptographic verification.',
        { cause: error },
      );
    }
    const payload = receipt.payload;
    if (
      payload.protocol !== 'nexus.registry-receipt.v1' ||
      payload.subject !== expectation.subject ||
      payload.eventType !== expectation.eventType ||
      payload.state !== expectation.state ||
      payload.sequence !== expectation.sequence ||
      payload.genesisHash !== expectation.genesisHash
    ) {
      throw new WalletCoreError(
        'INVALID_REGISTRY_RECEIPT',
        'The verified registry receipt does not confirm the expected lifecycle transition.',
      );
    }
    return structuredClone(receipt);
  }

  #validateStatus(
    status: RegistryIdentityStatus,
    record: LocalIdentityRecordV1,
  ): RegistryIdentityStatus {
    if (
      status.subject !== record.subject ||
      (status.state !== 'active' && status.state !== 'revoked') ||
      !Number.isSafeInteger(status.sequence) ||
      status.sequence < 0
    ) {
      throw new WalletCoreError(
        'REGISTRY_CONFLICT',
        'The authoritative registry status is inconsistent.',
      );
    }
    if (status.state === 'active' && status.sequence !== 0) {
      throw new WalletCoreError(
        'REGISTRY_CONFLICT',
        'An active v1 identity must have sequence zero.',
      );
    }
    if (status.state === 'revoked' && status.sequence !== 1) {
      throw new WalletCoreError(
        'REGISTRY_CONFLICT',
        'A revoked v1 identity must have sequence one.',
      );
    }
    return status;
  }

  async #reachTerminalState(
    record: LocalIdentityRecordV1,
    options: RevokeIdentityOptions,
  ): Promise<{ receipt: RegistryReceiptV1 }> {
    const status = this.#validateStatus(
      await this.#registryClient.getStatus(record.subject),
      record,
    );

    if (status.state === 'revoked') {
      if (status.terminalReceipt !== undefined) {
        return {
          receipt: await this.#verifyReceipt(status.terminalReceipt, {
            subject: record.subject,
            eventType: 'revoked',
            state: 'revoked',
            sequence: status.sequence,
            genesisHash: encodeBase64Url(await deriveGenesisHash(record.genesis, this.#crypto)),
          }),
        };
      }

      if (record.revocationReceipt !== undefined) {
        return {
          receipt: await this.#verifyReceipt(record.revocationReceipt, {
            subject: record.subject,
            eventType: 'revoked',
            state: 'revoked',
            sequence: status.sequence,
            genesisHash: encodeBase64Url(await deriveGenesisHash(record.genesis, this.#crypto)),
          }),
        };
      }

      // Production status responses do not carry the historical receipt. If a
      // revoke committed but its response was lost, retry the terminal action
      // with the sequence that preceded the already-observed transition. The
      // registry returns the stored terminal event receipt idempotently.
      return {
        receipt: await this.#submitRevocation(record, status.sequence - 1, options),
      };
    }

    return {
      receipt: await this.#submitRevocation(record, status.sequence, options),
    };
  }

  async #submitRevocation(
    record: LocalIdentityRecordV1,
    expectedSequence: number,
    options: RevokeIdentityOptions,
  ): Promise<RegistryReceiptV1> {
    let request: RevokeBySignatureRequestV1 | RevokeBySecretRequestV1;
    if (options.method === 'secret') {
      const secret = await this.#keyVault.readRevocationSecret(requireRevocationSecretRef(record));
      request = revokeBySecretRequestV1Schema.parse({
        mode: 'secret',
        payload: {
          protocol: REVOKE_SECRET_PROTOCOL,
          subject: record.subject,
          expectedSequence,
          revocationSecret: base64Url32Schema.parse(encodeBase64Url(secret)),
        },
      });
    } else {
      const payload: RevokeBySignaturePayloadV1 = {
        protocol: REVOKE_PROTOCOL,
        subject: record.subject,
        expectedSequence,
        nonce: base64UrlAtLeast16Schema.parse(encodeBase64Url(this.#crypto.randomBytes(16))),
        iat: this.#clock.now(),
        ...(options.reasonCode === undefined ? {} : { reasonCode: options.reasonCode }),
      };
      validateEpochSeconds(payload.iat, 'clock.now()');
      const signature = await this.#keyVault.sign(
        requireSigningRef(record),
        createProtocolSignaturePreimage(payload),
      );
      request = revokeBySignatureRequestV1Schema.parse({
        mode: 'signature',
        payload,
        signature: base64Url64Schema.parse(encodeBase64Url(signature)),
      });
    }

    const rawReceipt = await this.#registryClient.revoke(request);
    return this.#verifyReceipt(rawReceipt, {
      subject: record.subject,
      eventType: 'revoked',
      state: 'revoked',
      sequence: expectedSequence + 1,
      genesisHash: encodeBase64Url(await deriveGenesisHash(record.genesis, this.#crypto)),
    });
  }
}
