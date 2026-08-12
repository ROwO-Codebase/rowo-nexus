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
  createDeviceAuthorizationHashPreimageV2,
  createDeviceIdHashPreimageV2,
  decodeBase64UrlExact,
  deviceActivationPayloadV2Schema,
  deviceAuthorizationPayloadV2Schema,
  deviceAuthorizationV2Schema,
  deviceRegistryReceiptV2Schema,
  deviceRegistryStatusV2Schema,
  deviceRootRevokePayloadV2Schema,
  deviceSelfRevokePayloadV2Schema,
  continuityLinkPayloadV1Schema,
  encodeBase64Url,
  identityGenesisV1Schema,
  formatDeviceAuthorizationIdV2,
  formatDeviceIdV2,
  nexusDeviceIdV2Schema,
  ownershipProofPayloadV1Schema,
  ownershipProofPayloadV2Schema,
  proofRequestSchema,
  revokeBySecretRequestV1Schema,
  revokeBySignatureRequestV1Schema,
  type ContinuityLinkPayloadV1,
  type ContinuityLinkV1,
  type DeviceActivationPayloadV2,
  type DeviceActivationRequestV2,
  type DeviceAuthorizationPayloadV2,
  type DeviceAuthorizationV2,
  type DeviceRegistryReceiptV2,
  type DeviceRegistryStatusV2,
  type DeviceRootRevokePayloadV2,
  type DeviceRootRevokeRequestV2,
  type DeviceSelfRevokePayloadV2,
  type DeviceSelfRevokeRequestV2,
  type IdentityGenesisV1,
  type OwnershipProofPayloadV1,
  type OwnershipProofV1,
  type OwnershipProofPayloadV2,
  type OwnershipProofV2,
  type ProofRequest,
  type RegistryReceiptV1,
  type RevokeBySecretRequestV1,
  type RevokeBySignaturePayloadV1,
  type RevokeBySignatureRequestV1,
} from '@nexus/protocol';

import { WalletCoreError } from './errors.js';
import { getManagedKeyVaultCapabilities } from './key-vault.js';
import { requireTrustedWalletEventBoundary } from './trusted-wallet-event.js';
import type {
  AuthorizationHistoryEntry,
  Clock,
  ContinuityLinkOptions,
  CreatedLocalIdentity,
  CreateIdentityOptions,
  DisposeIdentityOptions,
  DeviceRegistryReceiptVerifier,
  DeviceRegistryStatusVerifier,
  DeviceRequestOptions,
  DeviceRevocationOptions,
  DeviceTransferEnvelopeV2,
  IdentityStore,
  ImportedDeviceV2,
  IssueDeviceTransferOptions,
  IssuedDeviceTransferV2,
  KeyRef,
  KeyVault,
  KeyVaultStorage,
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
import { decryptDeviceTransfer, encryptDeviceTransfer } from './device-transfer.js';

const IDENTITY_PROTOCOL = 'nexus.identity.v1' as const;
const SUITE = 'NX-25519-SHA256-JCS-v1' as const;
const OWNERSHIP_PROOF_PROTOCOL = 'nexus.ownership-proof.v1' as const;
const REVOKE_PROTOCOL = 'nexus.revoke.v1' as const;
const REVOKE_SECRET_PROTOCOL = 'nexus.revoke-secret.v1' as const;
const CONTINUITY_LINK_PROTOCOL = 'nexus.continuity-link.v1' as const;
const MAX_AUTHORIZATION_HISTORY_ENTRIES = 200;
const DEVICE_AUTHORIZATION_PROTOCOL = 'nexus.device-authorization.v2' as const;
const DEVICE_ACTIVATION_PROTOCOL = 'nexus.device-activation.v2' as const;
const DEVICE_SELF_REVOKE_PROTOCOL = 'nexus.device-self-revoke.v2' as const;
const DEVICE_ROOT_REVOKE_PROTOCOL = 'nexus.device-root-revoke.v2' as const;
const DEVICE_PROOF_PROTOCOL = 'nexus.ownership-proof.v2' as const;
const DEFAULT_DEVICE_ACTIVATION_WINDOW_SECONDS = 30 * 24 * 60 * 60;
const DEFAULT_DEVICE_AUTHORIZATION_LIFETIME_SECONDS = 366 * 24 * 60 * 60;
const DEFAULT_DEVICE_REQUEST_LIFETIME_SECONDS = 120;
const DEVICE_IMPORT_RECOVERY_LEASE_SECONDS = 5 * 60;

export interface WalletCoreOptions {
  keyVault: KeyVaultStorage;
  identityStore: IdentityStore;
  registryClient: RegistryClient;
  verifyRegistryReceipt: RegistryReceiptVerifier;
  crypto?: CryptoProvider;
  clock?: Clock;
  verifyDeviceRegistryReceipt?: DeviceRegistryReceiptVerifier;
  verifyDeviceRegistryStatus?: DeviceRegistryStatusVerifier;
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

function summarize(record: LocalIdentityRecordV1, now: number): LocalIdentitySummary {
  return {
    localId: record.localId,
    subject: record.subject,
    ...(record.label === undefined ? {} : { label: record.label }),
    localScopes: [...record.localScopes],
    authorizationHistory: structuredClone(record.authorizationHistory ?? []),
    localState: record.localState,
    registered: record.registrationReceipt !== undefined,
    proofReady:
      record.localState === 'active' &&
      (record.deviceV2 === undefined
        ? record.registrationReceipt !== undefined
        : record.deviceV2.localState === 'active' &&
          (record.deviceV2.registryState === undefined ||
            record.deviceV2.registryState === 'active') &&
          now >= record.deviceV2.authorization.payload.validFrom &&
          now < record.deviceV2.authorization.payload.expiresAt),
    hasAgreementKey: record.agreementPrivateKeyRef !== undefined,
    ...(record.deviceV2 === undefined
      ? {}
      : {
          device: {
            deviceId: record.deviceV2.deviceId,
            authorizationId: record.deviceV2.authorizationId,
            localState: record.deviceV2.localState,
            activationDeadline: record.deviceV2.authorization.payload.activationDeadline,
            expiresAt: record.deviceV2.authorization.payload.expiresAt,
            ...(record.deviceV2.registryState === undefined
              ? {}
              : { registryState: record.deviceV2.registryState }),
            ...(record.deviceV2.statusCheckedAt === undefined
              ? {}
              : { statusCheckedAt: record.deviceV2.statusCheckedAt }),
            ...(record.deviceV2.registryRevokedAt === undefined
              ? {}
              : { registryRevokedAt: record.deviceV2.registryRevokedAt }),
          },
        }),
    issuedDevices: (record.issuedDevicesV2 ?? []).map((device) => ({
      deviceId: device.deviceId,
      authorizationId: device.authorizationId,
      issuedAt: device.issuedAt,
      activationDeadline: device.authorization.payload.activationDeadline,
      expiresAt: device.authorization.payload.expiresAt,
      ...(device.label === undefined ? {} : { label: device.label }),
      localState: device.localState,
      ...(device.registryState === undefined ? {} : { registryState: device.registryState }),
      ...(device.statusCheckedAt === undefined ? {} : { statusCheckedAt: device.statusCheckedAt }),
      ...(device.registryRevokedAt === undefined
        ? {}
        : { registryRevokedAt: device.registryRevokedAt }),
    })),
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
  readonly #keyVault: KeyVaultStorage;
  readonly #identityStore: IdentityStore;
  readonly #registryClient: RegistryClient;
  readonly #verifyRegistryReceipt: RegistryReceiptVerifier;
  readonly #crypto: CryptoProvider;
  readonly #clock: Clock;
  readonly #verifyDeviceRegistryReceipt: DeviceRegistryReceiptVerifier | undefined;
  readonly #verifyDeviceRegistryStatus: DeviceRegistryStatusVerifier | undefined;

  public constructor(options: WalletCoreOptions) {
    this.#keyVault = options.keyVault;
    this.#identityStore = options.identityStore;
    this.#registryClient = options.registryClient;
    this.#verifyRegistryReceipt = options.verifyRegistryReceipt;
    this.#crypto = options.crypto ?? getDefaultCryptoProvider();
    this.#clock = options.clock ?? systemClock;
    this.#verifyDeviceRegistryReceipt = options.verifyDeviceRegistryReceipt;
    this.#verifyDeviceRegistryStatus = options.verifyDeviceRegistryStatus;
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
        authorizationHistory: [],
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
    await this.#updateRecord(record.localId, (latest) => ({ ...latest, registrationReceipt }));
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
    const signature = await this.#signProtocolPayload(requireSigningRef(record), payload);
    return { payload, signature: base64Url64Schema.parse(encodeBase64Url(signature)) };
  }

  public async proveAndRecordAuthorization(
    localId: string,
    boundary: TrustedWalletEventBoundary,
    request: ProofRequest,
    rememberScope: boolean,
  ): Promise<OwnershipProofV1> {
    const proof = await this.prove(localId, boundary, request);
    await this.#recordProofAuthorization(localId, boundary, request, rememberScope);
    return proof;
  }

  async #recordProofAuthorization(
    localId: string,
    boundary: TrustedWalletEventBoundary,
    request: ProofRequest,
    rememberScope: boolean,
  ): Promise<void> {
    const audience = requireTrustedWalletEventBoundary(boundary).audience;
    await this.#getActiveRegisteredRecord(localId);
    const parsedRequest = parseWalletInput(
      () => proofRequestSchema.parse(request),
      'The ownership proof request is invalid.',
    );
    const approvedAt = this.#clock.now();
    validateEpochSeconds(approvedAt, 'clock.now()');

    const entry: AuthorizationHistoryEntry = {
      authorizationId: newLocalId(this.#crypto),
      approvedAt,
      audience,
      action: parsedRequest.action,
      resource: parsedRequest.resource,
      introducedScope: false,
      contextBound: parsedRequest.contextHash !== undefined,
    };
    await this.#updateRecord(localId, (latest) => {
      const introducedScope = rememberScope && !latest.localScopes.includes(audience);
      return {
        ...latest,
        localScopes: introducedScope ? [...latest.localScopes, audience] : latest.localScopes,
        authorizationHistory: [
          { ...entry, introducedScope },
          ...(latest.authorizationHistory ?? []),
        ].slice(0, MAX_AUTHORIZATION_HISTORY_ENTRIES),
      };
    });
  }

  public async clearAuthorizationHistory(localId: string): Promise<void> {
    await this.#updateRecord(localId, (latest) => ({ ...latest, authorizationHistory: [] }));
  }

  public async revoke(
    localId: string,
    options: RevokeIdentityOptions = {},
  ): Promise<RegistryReceiptV1> {
    const record = await this.#getRecord(localId);
    const terminal = await this.#reachTerminalState(record, options);
    await this.#updateRecord(localId, (latest) => ({
      ...latest,
      localState: 'revoked',
      revocationReceipt: terminal.receipt,
    }));
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

    await this.#updateRecord(localId, (latest) => ({
      ...latest,
      localState: 'revoked',
      revocationReceipt: terminal.receipt,
    }));

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
      await this.#updateRecord(localId, (latest) => {
        const publicRecord = { ...latest };
        delete publicRecord.signingPrivateKeyRef;
        delete publicRecord.agreementPrivateKeyRef;
        delete publicRecord.revocationSecretRef;
        return publicRecord;
      });
    }
    return structuredClone(terminal.receipt);
  }

  public async removeLocalIdentity(localId: string): Promise<void> {
    const record = await this.#getRecord(localId);
    const now = this.#clock.now();
    validateEpochSeconds(now, 'clock.now()');
    const device = record.deviceV2;
    const removable =
      record.localState === 'revoked' ||
      (device !== undefined &&
        (device.localState === 'revoked' ||
          device.registryState === 'revoked' ||
          device.registryState === 'expired' ||
          now >= device.authorization.payload.expiresAt));
    if (!removable) {
      throw new WalletCoreError(
        'INVALID_REQUEST',
        'Only a revoked or expired identity can be removed from this wallet.',
      );
    }

    const keyRefs = new Set<KeyRef>();
    if (record.signingPrivateKeyRef !== undefined) keyRefs.add(record.signingPrivateKeyRef);
    if (record.agreementPrivateKeyRef !== undefined) keyRefs.add(record.agreementPrivateKeyRef);
    if (device?.signingPrivateKeyRef !== undefined) keyRefs.add(device.signingPrivateKeyRef);
    const deletions = await Promise.allSettled([
      ...[...keyRefs].map((ref) => this.#keyVault.deleteKey(ref)),
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
        'The identity remains in the wallet because some local private material could not be deleted.',
        { cause: deletionFailure.reason },
      );
    }

    await this.#updateRecord(localId, (latest) => {
      const publicRecord = { ...latest };
      delete publicRecord.signingPrivateKeyRef;
      delete publicRecord.agreementPrivateKeyRef;
      delete publicRecord.revocationSecretRef;
      if (publicRecord.deviceV2 !== undefined) {
        const publicDevice = { ...publicRecord.deviceV2 };
        delete publicDevice.signingPrivateKeyRef;
        publicRecord.deviceV2 = publicDevice;
      }
      return publicRecord;
    });
    await this.#identityStore.delete(localId);
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
    const [signatureA, signatureB] = await Promise.all([
      this.#signProtocolPayload(requireSigningRef(identityA), payload),
      this.#signProtocolPayload(requireSigningRef(identityB), payload),
    ]);
    return {
      payload,
      signatureA: base64Url64Schema.parse(encodeBase64Url(signatureA)),
      signatureB: base64Url64Schema.parse(encodeBase64Url(signatureB)),
    };
  }

  /**
   * Issues one independent device capability from an existing v1 identity root.
   * The only private-key output is an authenticated encrypted bundle.
   */
  public async issueDeviceTransfer(
    rootLocalId: string,
    options: IssueDeviceTransferOptions = {},
  ): Promise<IssuedDeviceTransferV2> {
    const root = await this.#getActiveRegisteredRecord(rootLocalId);
    if (root.deviceV2 !== undefined) {
      throw new WalletCoreError(
        'INVALID_REQUEST',
        'A delegated device cannot authorize another device.',
      );
    }
    if (
      this.#identityStore.appendIssuedDevice === undefined ||
      this.#identityStore.update === undefined
    ) {
      throw new WalletCoreError(
        'INVALID_REQUEST',
        'This identity store does not support atomic v2 device issuance and updates.',
      );
    }
    if (options.label !== undefined && options.label.length > 128) {
      throw new WalletCoreError(
        'INVALID_REQUEST',
        'A local device label cannot exceed 128 characters.',
      );
    }

    const now = this.#clock.now();
    validateEpochSeconds(now, 'clock.now()');
    const validFrom = options.validFrom ?? now;
    const activationDeadline =
      options.activationDeadline ?? now + DEFAULT_DEVICE_ACTIVATION_WINDOW_SECONDS;
    const expiresAt = options.expiresAt ?? now + DEFAULT_DEVICE_AUTHORIZATION_LIFETIME_SECONDS;
    validateEpochSeconds(validFrom, 'validFrom');
    validateEpochSeconds(activationDeadline, 'activationDeadline');
    validateEpochSeconds(expiresAt, 'expiresAt');
    if (validFrom > activationDeadline || activationDeadline > expiresAt) {
      throw new WalletCoreError(
        'INVALID_REQUEST',
        'Device validity must satisfy validFrom <= activationDeadline <= expiresAt.',
      );
    }

    const generated = await this.#crypto.generateEd25519KeyPair({
      privateKeyExtractable: true,
    });
    const [publicKey, privateKeyPkcs8] = await Promise.all([
      this.#crypto.exportEd25519PublicKey(generated.publicKey),
      this.#crypto.exportEd25519PrivateKey(generated.privateKey),
    ]);
    try {
      const signingKey = {
        alg: 'Ed25519' as const,
        publicKey: base64Url32Schema.parse(encodeBase64Url(publicKey)),
      };
      const deviceId = formatDeviceIdV2(
        await this.#crypto.sha256(
          createDeviceIdHashPreimageV2({ subject: root.subject, signingKey }),
        ),
      );
      const genesisHash = base64Url32Schema.parse(
        encodeBase64Url(await deriveGenesisHash(root.genesis, this.#crypto)),
      );
      const authorizationPayload: DeviceAuthorizationPayloadV2 =
        deviceAuthorizationPayloadV2Schema.parse({
          protocol: DEVICE_AUTHORIZATION_PROTOCOL,
          subject: root.subject,
          genesisHash,
          deviceId,
          signingKey,
          authorizationNonce: encodeBase64Url(this.#crypto.randomBytes(32)),
          validFrom,
          activationDeadline,
          expiresAt,
        });
      const rootSignature = await this.#signProtocolPayload(
        requireSigningRef(root),
        authorizationPayload,
      );
      const authorization: DeviceAuthorizationV2 = deviceAuthorizationV2Schema.parse({
        payload: authorizationPayload,
        rootSignature: encodeBase64Url(rootSignature),
      });
      const authorizationId = await this.#deriveDeviceAuthorizationId(authorizationPayload);
      const encrypted = await encryptDeviceTransfer(
        {
          subject: root.subject,
          genesis: structuredClone(root.genesis),
          authorization,
          devicePrivateKey: {
            alg: 'Ed25519',
            format: 'pkcs8',
            bytes: encodeBase64Url(privateKeyPkcs8),
          },
        },
        this.#crypto,
      );

      try {
        await this.#identityStore.appendIssuedDevice(root.localId, {
          deviceId,
          authorizationId,
          authorization,
          issuedAt: now,
          ...(options.label === undefined ? {} : { label: options.label }),
          localState: 'issued',
        });
      } catch (error) {
        encrypted.transferKey.fill(0);
        throw error;
      }
      return { authorization, ...encrypted };
    } finally {
      privateKeyPkcs8.fill(0);
    }
  }

  public async importDeviceTransfer(
    bundle: DeviceTransferEnvelopeV2,
    transferKey: Uint8Array,
  ): Promise<ImportedDeviceV2> {
    const managedKeyVault = getManagedKeyVaultCapabilities(this.#keyVault);
    if (managedKeyVault === undefined) {
      throw new WalletCoreError(
        'INVALID_REQUEST',
        'This key vault does not support crash-safe v2 device-key import.',
      );
    }
    if (
      this.#identityStore.update === undefined ||
      this.#identityStore.reserveDeviceRecord === undefined
    ) {
      throw new WalletCoreError(
        'INVALID_REQUEST',
        'This identity store does not support atomic v2 device-key reservation.',
      );
    }
    const decrypted = await decryptDeviceTransfer(bundle, transferKey, this.#crypto);
    const privateKeyPkcs8 = decrypted.devicePrivateKeyPkcs8;
    let signingPrivateKeyRef: KeyRef | undefined;
    let reservedLocalId: string | undefined;
    try {
      const genesis = parseWalletInput(
        () => identityGenesisV1Schema.parse(decrypted.genesis),
        'The transferred v1 root genesis is invalid.',
      );
      const authorization = parseWalletInput(
        () => deviceAuthorizationV2Schema.parse(decrypted.authorization),
        'The transferred device authorization is invalid.',
      );
      const subject = await deriveSubject(genesis, this.#crypto);
      if (decrypted.subject !== subject || authorization.payload.subject !== subject) {
        throw new WalletCoreError(
          'INVALID_REQUEST',
          'The transferred subject does not match its root genesis and authorization.',
        );
      }
      const genesisHash = encodeBase64Url(await deriveGenesisHash(genesis, this.#crypto));
      if (authorization.payload.genesisHash !== genesisHash) {
        throw new WalletCoreError(
          'INVALID_REQUEST',
          'The transferred authorization does not match its root genesis.',
        );
      }
      if (authorization.payload.signingKey.publicKey === genesis.signingKey.publicKey) {
        throw new WalletCoreError(
          'INVALID_REQUEST',
          'The device signing key must be independent from the root signing key.',
        );
      }
      const deviceId = formatDeviceIdV2(
        await this.#crypto.sha256(
          createDeviceIdHashPreimageV2({
            subject,
            signingKey: authorization.payload.signingKey,
          }),
        ),
      );
      if (authorization.payload.deviceId !== deviceId) {
        throw new WalletCoreError('INVALID_REQUEST', 'The transferred device ID is invalid.');
      }
      const authorizationId = await this.#deriveDeviceAuthorizationId(authorization.payload);
      const rootPublicKey = await this.#crypto.importEd25519PublicKey(
        decodeBase64UrlExact(genesis.signingKey.publicKey, 32),
      );
      const rootSignatureValid = await this.#crypto.verifyEd25519(
        rootPublicKey,
        decodeBase64UrlExact(authorization.rootSignature, 64),
        createProtocolSignaturePreimage(authorization.payload),
      );
      if (!rootSignatureValid) {
        throw new WalletCoreError(
          'INVALID_REQUEST',
          'The transferred device authorization has an invalid root signature.',
        );
      }
      const now = this.#clock.now();
      validateEpochSeconds(now, 'clock.now()');
      if (
        now > authorization.payload.activationDeadline ||
        now >= authorization.payload.expiresAt
      ) {
        throw new WalletCoreError(
          'INVALID_REQUEST',
          'The transferred device authorization can no longer be activated.',
        );
      }
      const publicKeyBytes = decodeBase64UrlExact(authorization.payload.signingKey.publicKey, 32);
      signingPrivateKeyRef = managedKeyVault.createDeviceSigningKeyRef();
      const localId = newLocalId(this.#crypto);
      await this.#identityStore.reserveDeviceRecord({
        localId,
        subject,
        genesis,
        localScopes: [],
        authorizationHistory: [],
        localState: 'active',
        deviceV2: {
          deviceId,
          authorizationId,
          authorization,
          signingPrivateKeyRef,
          localState: 'pending-import',
          importStartedAt: now,
        },
      });
      reservedLocalId = localId;
      await managedKeyVault.importDeviceSigningKeyAtRef(
        signingPrivateKeyRef,
        privateKeyPkcs8,
        publicKeyBytes,
      );
      const finalizingRef = signingPrivateKeyRef;
      await this.#identityStore.update(localId, (latest) => {
        const latestDevice = latest.deviceV2;
        if (latestDevice === undefined || latestDevice.signingPrivateKeyRef !== finalizingRef) {
          throw new WalletCoreError(
            'STORAGE_ERROR',
            'The pending device import reservation changed unexpectedly.',
          );
        }
        if (latestDevice.localState === 'pending-activation') return latest;
        if (latestDevice.localState !== 'pending-import') {
          throw new WalletCoreError(
            'STORAGE_ERROR',
            'The pending device import is no longer finalizable.',
          );
        }
        const importedDevice = { ...latestDevice };
        delete importedDevice.importStartedAt;
        return {
          ...latest,
          deviceV2: { ...importedDevice, localState: 'pending-activation' },
        };
      });
      return { localId, subject, deviceId, authorizationId, authorization };
    } catch (error) {
      if (reservedLocalId !== undefined && signingPrivateKeyRef !== undefined) {
        try {
          const ownsCleanup = await this.#claimImportedKeyCleanup(
            reservedLocalId,
            signingPrivateKeyRef,
          );
          if (ownsCleanup) {
            await this.#cancelManagedDeviceKeyRef(signingPrivateKeyRef);
            await this.#identityStore.delete(reservedLocalId);
          }
        } catch (cleanupError) {
          throw new WalletCoreError(
            'STORAGE_ERROR',
            'Device import failed and its temporary imported key could not be cleaned up.',
            { cause: cleanupError },
          );
        }
      }
      throw error;
    } finally {
      privateKeyPkcs8.fill(0);
    }
  }

  public async createDeviceActivationRequest(
    deviceLocalId: string,
    options: DeviceRequestOptions = {},
  ): Promise<DeviceActivationRequestV2> {
    const record = await this.#getDeviceRecord(deviceLocalId, true);
    const device = record.deviceV2;
    if (device.localState === 'revoked') {
      throw new WalletCoreError('IDENTITY_REVOKED', 'This device is locally revoked.');
    }
    const issuedAt = this.#clock.now();
    validateEpochSeconds(issuedAt, 'clock.now()');
    const expiresAt = options.expiresAt ?? issuedAt + DEFAULT_DEVICE_REQUEST_LIFETIME_SECONDS;
    validateEpochSeconds(expiresAt, 'expiresAt');
    if (expiresAt <= issuedAt || expiresAt > device.authorization.payload.activationDeadline) {
      throw new WalletCoreError(
        'INVALID_REQUEST',
        'The activation request expiry must be within the authorization activation window.',
      );
    }
    const payload: DeviceActivationPayloadV2 = deviceActivationPayloadV2Schema.parse({
      protocol: DEVICE_ACTIVATION_PROTOCOL,
      subject: record.subject,
      deviceId: device.deviceId,
      authorizationId: device.authorizationId,
      requestId: options.requestId ?? encodeBase64Url(this.#crypto.randomBytes(32)),
      iat: issuedAt,
      exp: expiresAt,
    });
    const signature = await this.#signProtocolPayload(
      this.#requireDeviceSigningRef(device),
      payload,
    );
    return {
      authorization: structuredClone(device.authorization),
      payload,
      deviceSignature: base64Url64Schema.parse(encodeBase64Url(signature)),
    };
  }

  public async activateDevice(
    deviceLocalId: string,
    options: DeviceRequestOptions = {},
  ): Promise<DeviceRegistryReceiptV2> {
    if (this.#registryClient.activateDevice === undefined) {
      throw new WalletCoreError('INVALID_REQUEST', 'The registry does not support v2 devices.');
    }
    const request = await this.createDeviceActivationRequest(deviceLocalId, options);
    const rawReceipt = await this.#registryClient.activateDevice(request);
    const receipt = await this.#verifyDeviceReceipt(rawReceipt, {
      subject: request.payload.subject,
      genesisHash: request.authorization.payload.genesisHash,
      deviceId: request.payload.deviceId,
      authorizationId: request.payload.authorizationId,
      authorizationExpiresAt: request.authorization.payload.expiresAt,
      eventType: 'activated',
      deviceState: 'active',
    });
    await this.#updateRecord(deviceLocalId, (latest) => {
      if (latest.deviceV2 === undefined) return latest;
      if (latest.deviceV2.localState === 'revoked') return latest;
      return {
        ...latest,
        deviceV2: { ...latest.deviceV2, localState: 'active', activationReceipt: receipt },
      };
    });
    return structuredClone(receipt);
  }

  public async proveDevice(
    deviceLocalId: string,
    boundary: TrustedWalletEventBoundary,
    request: ProofRequest,
  ): Promise<OwnershipProofV2> {
    const audience = requireTrustedWalletEventBoundary(boundary).audience;
    const record = await this.#getDeviceRecord(deviceLocalId, true);
    const device = record.deviceV2;
    if (device.registryState === 'revoked') {
      throw new WalletCoreError('IDENTITY_REVOKED', 'The registry reports this device as revoked.');
    }
    if (
      device.registryState !== undefined &&
      device.registryState !== 'active' &&
      device.localState === 'active'
    ) {
      throw new WalletCoreError(
        'IDENTITY_NOT_REGISTERED',
        `The registry reports this device as ${device.registryState}.`,
      );
    }
    if (device.localState !== 'active') {
      throw new WalletCoreError(
        'IDENTITY_NOT_REGISTERED',
        'The device must be activated before it can create ownership proofs.',
      );
    }
    const parsedRequest = parseWalletInput(
      () => proofRequestSchema.parse(request),
      'The ownership proof request is invalid.',
    );
    const issuedAt = this.#clock.now();
    validateEpochSeconds(issuedAt, 'clock.now()');
    if (
      parsedRequest.expiresAt <= issuedAt ||
      issuedAt < device.authorization.payload.validFrom ||
      parsedRequest.expiresAt > device.authorization.payload.expiresAt
    ) {
      throw new WalletCoreError(
        'INVALID_REQUEST',
        'The proof time is outside the device authorization lifetime.',
      );
    }
    const payload: OwnershipProofPayloadV2 = ownershipProofPayloadV2Schema.parse({
      protocol: DEVICE_PROOF_PROTOCOL,
      subject: record.subject,
      genesis: structuredClone(record.genesis),
      deviceId: device.deviceId,
      authorizationId: device.authorizationId,
      authorization: structuredClone(device.authorization),
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
    const signature = await this.#signProtocolPayload(
      this.#requireDeviceSigningRef(device),
      payload,
    );
    return { payload, deviceSignature: base64Url64Schema.parse(encodeBase64Url(signature)) };
  }

  public async createDeviceSelfRevokeRequest(
    deviceLocalId: string,
    options: DeviceRevocationOptions = {},
  ): Promise<DeviceSelfRevokeRequestV2> {
    const record = await this.#getDeviceRecord(deviceLocalId, true);
    const device = record.deviceV2;
    if (device.localState === 'revoked') {
      throw new WalletCoreError('IDENTITY_REVOKED', 'This device is already locally revoked.');
    }
    const issuedAt = this.#clock.now();
    validateEpochSeconds(issuedAt, 'clock.now()');
    const payload: DeviceSelfRevokePayloadV2 = deviceSelfRevokePayloadV2Schema.parse({
      protocol: DEVICE_SELF_REVOKE_PROTOCOL,
      subject: record.subject,
      genesisHash: device.authorization.payload.genesisHash,
      deviceId: device.deviceId,
      authorizationId: device.authorizationId,
      requestId: options.requestId ?? encodeBase64Url(this.#crypto.randomBytes(32)),
      issuedAt,
      ...(options.reasonCode === undefined ? {} : { reasonCode: options.reasonCode }),
    });
    const signature = await this.#signProtocolPayload(
      this.#requireDeviceSigningRef(device),
      payload,
    );
    return {
      authorization: structuredClone(device.authorization),
      payload,
      deviceSignature: base64Url64Schema.parse(encodeBase64Url(signature)),
    };
  }

  public async revokeDeviceSelf(
    deviceLocalId: string,
    options: DeviceRevocationOptions = {},
  ): Promise<DeviceRegistryReceiptV2> {
    const existing = await this.#getRecord(deviceLocalId);
    if (
      existing.deviceV2?.localState === 'revoked' &&
      existing.deviceV2.revocationReceipt !== undefined
    ) {
      const existingRef = existing.deviceV2.signingPrivateKeyRef;
      if (existingRef !== undefined) {
        await this.#keyVault.deleteKey(existingRef);
        await this.#updateRecord(deviceLocalId, (latest) => {
          if (latest.deviceV2 === undefined) return latest;
          const cleaned = { ...latest.deviceV2 };
          delete cleaned.signingPrivateKeyRef;
          return { ...latest, deviceV2: cleaned };
        });
      }
      return structuredClone(existing.deviceV2.revocationReceipt);
    }
    if (this.#registryClient.revokeDeviceSelf === undefined) {
      throw new WalletCoreError('INVALID_REQUEST', 'The registry does not support v2 devices.');
    }
    const request = await this.createDeviceSelfRevokeRequest(deviceLocalId, options);
    const rawReceipt = await this.#registryClient.revokeDeviceSelf(request);
    const receipt = await this.#verifyDeviceReceipt(rawReceipt, {
      subject: request.payload.subject,
      genesisHash: request.payload.genesisHash,
      deviceId: request.payload.deviceId,
      authorizationId: request.payload.authorizationId,
      eventType: 'revoked',
      deviceState: 'revoked',
      revokedBy: 'device',
      allowConvergedRevocation: true,
    });
    const revoked = await this.#updateRecord(deviceLocalId, (current) => {
      if (current.deviceV2 === undefined) return current;
      return {
        ...current,
        deviceV2: { ...current.deviceV2, localState: 'revoked', revocationReceipt: receipt },
      };
    });
    const signingRef = revoked.deviceV2?.signingPrivateKeyRef;
    if (signingRef !== undefined) {
      try {
        await this.#keyVault.deleteKey(signingRef);
      } catch (error) {
        throw new WalletCoreError(
          'STORAGE_ERROR',
          'The device is revoked, but its local key still needs cleanup.',
          { cause: error },
        );
      }
      await this.#updateRecord(deviceLocalId, (latest) => {
        if (latest.deviceV2 === undefined) return latest;
        const cleaned = { ...latest.deviceV2 };
        delete cleaned.signingPrivateKeyRef;
        return { ...latest, deviceV2: cleaned };
      });
    }
    return structuredClone(receipt);
  }

  public async createDeviceRootRevokeRequest(
    rootLocalId: string,
    deviceIdInput: Parameters<WalletCoreApi['createDeviceRootRevokeRequest']>[1],
    options: DeviceRevocationOptions = {},
  ): Promise<DeviceRootRevokeRequestV2> {
    const root = await this.#getActiveRegisteredRecord(rootLocalId);
    if (root.deviceV2 !== undefined) {
      throw new WalletCoreError('INVALID_REQUEST', 'A delegated device has no root authority.');
    }
    const deviceId = nexusDeviceIdV2Schema.parse(deviceIdInput);
    const issued = (root.issuedDevicesV2 ?? []).find((device) => device.deviceId === deviceId);
    if (issued === undefined) {
      throw new WalletCoreError(
        'INVALID_REQUEST',
        'This root has no local record of issuing the requested device.',
      );
    }
    const issuedAt = this.#clock.now();
    validateEpochSeconds(issuedAt, 'clock.now()');
    const payload: DeviceRootRevokePayloadV2 = deviceRootRevokePayloadV2Schema.parse({
      protocol: DEVICE_ROOT_REVOKE_PROTOCOL,
      subject: root.subject,
      genesisHash: issued.authorization.payload.genesisHash,
      deviceId,
      requestId: options.requestId ?? encodeBase64Url(this.#crypto.randomBytes(32)),
      issuedAt,
      ...(options.reasonCode === undefined ? {} : { reasonCode: options.reasonCode }),
    });
    const signature = await this.#signProtocolPayload(requireSigningRef(root), payload);
    return { payload, rootSignature: base64Url64Schema.parse(encodeBase64Url(signature)) };
  }

  public async revokeDeviceRoot(
    rootLocalId: string,
    deviceId: Parameters<WalletCoreApi['revokeDeviceRoot']>[1],
    options: DeviceRevocationOptions = {},
  ): Promise<DeviceRegistryReceiptV2> {
    if (this.#registryClient.revokeDeviceRoot === undefined) {
      throw new WalletCoreError('INVALID_REQUEST', 'The registry does not support v2 devices.');
    }
    const request = await this.createDeviceRootRevokeRequest(rootLocalId, deviceId, options);
    const rawReceipt = await this.#registryClient.revokeDeviceRoot(request);
    const rootBeforeReceipt = await this.#getRecord(rootLocalId);
    const issuedBeforeReceipt = (rootBeforeReceipt.issuedDevicesV2 ?? []).find(
      (issued) => issued.deviceId === deviceId,
    );
    if (issuedBeforeReceipt === undefined) {
      throw new WalletCoreError(
        'INVALID_REQUEST',
        'This root no longer has the requested device in its local catalogue.',
      );
    }
    const receipt = await this.#verifyDeviceReceipt(rawReceipt, {
      subject: request.payload.subject,
      genesisHash: request.payload.genesisHash,
      deviceId: request.payload.deviceId,
      authorizationId: issuedBeforeReceipt.authorizationId,
      eventType: 'revoked',
      deviceState: 'revoked',
      revokedBy: 'root',
      allowConvergedRevocation: true,
    });
    const records = await this.#identityStore.list();
    for (const record of records) {
      if (record.localId === rootLocalId) {
        await this.#updateRecord(record.localId, (latest) => ({
          ...latest,
          issuedDevicesV2: (latest.issuedDevicesV2 ?? []).map((issued) =>
            issued.deviceId === deviceId
              ? { ...issued, localState: 'revoked' as const, revocationReceipt: receipt }
              : issued,
          ),
        }));
      } else if (record.deviceV2?.deviceId === deviceId) {
        const revoked = await this.#updateRecord(record.localId, (latest) => {
          if (latest.deviceV2 === undefined) return latest;
          return {
            ...latest,
            deviceV2: { ...latest.deviceV2, localState: 'revoked', revocationReceipt: receipt },
          };
        });
        const signingRef = revoked.deviceV2?.signingPrivateKeyRef;
        if (signingRef !== undefined) {
          try {
            await this.#keyVault.deleteKey(signingRef);
          } catch (error) {
            throw new WalletCoreError(
              'STORAGE_ERROR',
              'The device is revoked, but its local key still needs cleanup.',
              { cause: error },
            );
          }
          await this.#updateRecord(record.localId, (latest) => {
            if (latest.deviceV2 === undefined) return latest;
            const cleaned = { ...latest.deviceV2 };
            delete cleaned.signingPrivateKeyRef;
            return { ...latest, deviceV2: cleaned };
          });
        }
      }
    }
    return structuredClone(receipt);
  }

  public async refreshDeviceStatus(
    localId: string,
    deviceIdInput?: Parameters<WalletCoreApi['refreshDeviceStatus']>[1],
  ): Promise<DeviceRegistryStatusV2> {
    if (
      this.#registryClient.getDeviceStatus === undefined ||
      this.#verifyDeviceRegistryStatus === undefined
    ) {
      throw new WalletCoreError(
        'INVALID_REQUEST',
        'The registry client does not support verified v2 device status polling.',
      );
    }
    const record = await this.#getRecord(localId);
    const target =
      record.deviceV2 !== undefined
        ? record.deviceV2
        : (() => {
            if (deviceIdInput === undefined) {
              throw new WalletCoreError(
                'INVALID_REQUEST',
                'A root identity must select an issued device to refresh.',
              );
            }
            const deviceId = nexusDeviceIdV2Schema.parse(deviceIdInput);
            const issued = (record.issuedDevicesV2 ?? []).find(
              (device) => device.deviceId === deviceId,
            );
            if (issued === undefined) {
              throw new WalletCoreError(
                'INVALID_REQUEST',
                'This root has no local record of issuing the requested device.',
              );
            }
            return issued;
          })();
    if (deviceIdInput !== undefined && target.deviceId !== deviceIdInput) {
      throw new WalletCoreError(
        'INVALID_REQUEST',
        'The selected device does not match this wallet.',
      );
    }
    const genesisHash = base64Url32Schema.parse(
      encodeBase64Url(await deriveGenesisHash(record.genesis, this.#crypto)),
    );
    const expectation = {
      subject: record.subject,
      genesisHash,
      deviceId: target.deviceId,
      authorizationId: target.authorizationId,
    };
    const rawStatus = await this.#registryClient.getDeviceStatus({
      subject: expectation.subject,
      deviceId: expectation.deviceId,
      authorizationId: expectation.authorizationId,
    });
    const status = parseWalletInput(
      () => deviceRegistryStatusV2Schema.parse(rawStatus),
      'The device registry status response is malformed.',
    );
    const verified = await this.#verifyDeviceRegistryStatus(status, expectation);
    const exact = deviceRegistryStatusV2Schema.parse(verified);
    if (
      exact.subject !== expectation.subject ||
      exact.genesisHash !== expectation.genesisHash ||
      exact.deviceId !== expectation.deviceId ||
      exact.authorizationId !== expectation.authorizationId
    ) {
      throw new WalletCoreError(
        'INVALID_REQUEST',
        'The verified device status does not match the requested device authorization.',
      );
    }
    const checkedAt = this.#clock.now();
    validateEpochSeconds(checkedAt, 'clock.now()');
    await this.#updateRecord(localId, (latest) => {
      if (latest.deviceV2 !== undefined) {
        if (
          latest.deviceV2.deviceId !== exact.deviceId ||
          latest.deviceV2.authorizationId !== exact.authorizationId
        ) {
          return latest;
        }
        const updated = {
          ...latest.deviceV2,
          registryState: exact.deviceState,
          statusCheckedAt: checkedAt,
        };
        if (exact.revokedAt !== null) updated.registryRevokedAt = exact.revokedAt;
        else delete updated.registryRevokedAt;
        return { ...latest, deviceV2: updated };
      }
      return {
        ...latest,
        issuedDevicesV2: (latest.issuedDevicesV2 ?? []).map((device) => {
          if (
            device.deviceId !== exact.deviceId ||
            device.authorizationId !== exact.authorizationId
          ) {
            return device;
          }
          const updated = {
            ...device,
            registryState: exact.deviceState,
            statusCheckedAt: checkedAt,
          };
          if (exact.revokedAt !== null) updated.registryRevokedAt = exact.revokedAt;
          else delete updated.registryRevokedAt;
          return updated;
        }),
      };
    });
    return structuredClone(exact);
  }

  public async listIdentitySummaries(): Promise<LocalIdentitySummary[]> {
    const now = this.#clock.now();
    validateEpochSeconds(now, 'clock.now()');
    await this.#recoverPendingDeviceImports(now);
    return (await this.#identityStore.list()).map((record) => summarize(record, now));
  }

  public async listIdentitySummariesForBoundary(
    boundary: TrustedWalletEventBoundary,
  ): Promise<LocalIdentitySummary[]> {
    const audience = requireTrustedWalletEventBoundary(boundary).audience;
    const now = this.#clock.now();
    validateEpochSeconds(now, 'clock.now()');
    await this.#recoverPendingDeviceImports(now);
    return (await this.#identityStore.list())
      .filter((record) => record.localScopes.includes(audience))
      .map((record) => summarize(record, now));
  }

  public async addScope(localId: string, boundary: TrustedWalletEventBoundary): Promise<void> {
    const audience = requireTrustedWalletEventBoundary(boundary).audience;
    await this.#updateRecord(localId, (latest) =>
      latest.localScopes.includes(audience)
        ? latest
        : { ...latest, localScopes: [...latest.localScopes, audience] },
    );
  }

  public async removeScope(localId: string, boundary: TrustedWalletEventBoundary): Promise<void> {
    const audience = requireTrustedWalletEventBoundary(boundary).audience;
    await this.#updateRecord(localId, (latest) => ({
      ...latest,
      localScopes: latest.localScopes.filter((scope) => scope !== audience),
    }));
  }

  public async setLabel(localId: string, label?: string): Promise<void> {
    if (label !== undefined && (label.length === 0 || label.length > 128)) {
      throw new WalletCoreError(
        'INVALID_REQUEST',
        'A local identity nickname must contain between 1 and 128 characters.',
      );
    }
    await this.#updateRecord(localId, (latest) => {
      if (label !== undefined) return { ...latest, label };
      const withoutLabel = { ...latest };
      delete withoutLabel.label;
      return withoutLabel;
    });
  }

  async #updateRecord(
    localId: string,
    mutate: (record: LocalIdentityRecordV1) => LocalIdentityRecordV1,
  ): Promise<LocalIdentityRecordV1> {
    if (this.#identityStore.update !== undefined) {
      return this.#identityStore.update(localId, mutate);
    }
    // Compatibility path for existing v1-only custom stores. V2 issuance
    // requires the atomic capability and never reaches this fallback.
    const current = await this.#getRecord(localId);
    const updated = mutate(current);
    if (updated.localId !== localId) {
      throw new WalletCoreError('STORAGE_ERROR', 'An identity update cannot change its local ID.');
    }
    await this.#identityStore.put(updated);
    return structuredClone(updated);
  }

  async #recoverPendingDeviceImports(now: number): Promise<void> {
    if (this.#identityStore.update === undefined) return;
    const records = await this.#identityStore.list();
    for (const record of records) {
      const device = record.deviceV2;
      if (device?.localState === 'import-cleanup-pending') {
        const ref = device.signingPrivateKeyRef;
        if (ref !== undefined) await this.#cancelManagedDeviceKeyRef(ref);
        await this.#identityStore.delete(record.localId);
        continue;
      }
      if (device?.localState !== 'pending-import') continue;
      const startedAt = device.importStartedAt ?? 0;
      if (now < startedAt + DEVICE_IMPORT_RECOVERY_LEASE_SECONDS) continue;
      const ref = device.signingPrivateKeyRef;
      if (ref !== undefined && (await this.#keyVault.hasKey(ref))) {
        await this.#identityStore.update(record.localId, (latest) => {
          if (
            latest.deviceV2?.localState !== 'pending-import' ||
            latest.deviceV2.signingPrivateKeyRef !== ref
          ) {
            return latest;
          }
          const recovered = { ...latest.deviceV2 };
          delete recovered.importStartedAt;
          return {
            ...latest,
            deviceV2: { ...recovered, localState: 'pending-activation' },
          };
        });
      } else {
        // Atomically claim the still-pending reservation before deleting it.
        // The importer may have inserted its key and promoted the record since
        // the hasKey observation; a promoted record must win and be preserved.
        const claimed = await this.#identityStore.update(record.localId, (latest) => {
          if (
            latest.deviceV2?.localState !== 'pending-import' ||
            latest.deviceV2.signingPrivateKeyRef !== ref
          ) {
            return latest;
          }
          return {
            ...latest,
            deviceV2: {
              ...latest.deviceV2,
              localState: 'import-cleanup-pending',
              importStartedAt: 0,
            },
          };
        });
        if (
          claimed.deviceV2?.localState === 'import-cleanup-pending' &&
          claimed.deviceV2.signingPrivateKeyRef === ref
        ) {
          if (ref !== undefined) await this.#cancelManagedDeviceKeyRef(ref);
          await this.#identityStore.delete(record.localId);
        }
      }
    }
  }

  async #claimImportedKeyCleanup(localId: string, ref: KeyRef): Promise<boolean> {
    if (this.#identityStore.update === undefined) return false;
    const durable = await this.#identityStore.get(localId);
    if (durable === undefined) {
      // The reference was preallocated uniquely for this import. If recovery
      // already removed the reservation before insertion, this importer alone
      // owns cleanup of anything subsequently stored under that ref.
      return true;
    }
    if (
      durable.deviceV2?.localState === 'import-cleanup-pending' &&
      durable.deviceV2.signingPrivateKeyRef === ref
    ) {
      return true;
    }
    if (
      durable.deviceV2?.localState !== 'pending-import' ||
      durable.deviceV2.signingPrivateKeyRef !== ref
    ) {
      return false;
    }
    try {
      const claimed = await this.#identityStore.update(localId, (latest) => {
        if (
          latest.deviceV2?.localState !== 'pending-import' ||
          latest.deviceV2.signingPrivateKeyRef !== ref
        ) {
          return latest;
        }
        return {
          ...latest,
          deviceV2: {
            ...latest.deviceV2,
            localState: 'import-cleanup-pending',
            importStartedAt: 0,
          },
        };
      });
      return (
        claimed.deviceV2?.localState === 'import-cleanup-pending' &&
        claimed.deviceV2.signingPrivateKeyRef === ref
      );
    } catch (error) {
      if (error instanceof WalletCoreError && error.code === 'IDENTITY_NOT_FOUND') return true;
      throw error;
    }
  }

  async #cancelManagedDeviceKeyRef(ref: KeyRef): Promise<void> {
    const managed = getManagedKeyVaultCapabilities(this.#keyVault);
    if (managed === undefined) {
      throw new WalletCoreError(
        'STORAGE_ERROR',
        'A pending v2 device import requires its managed key-vault cancellation capability.',
      );
    }
    await managed.cancelDeviceSigningKeyRef(ref);
  }

  #signProtocolPayload(ref: KeyRef, payload: { readonly protocol: string }): Promise<Uint8Array> {
    const managed = getManagedKeyVaultCapabilities(this.#keyVault);
    if (managed !== undefined) return managed.signProtocolPayload(ref, payload);
    if (
      payload.protocol !== OWNERSHIP_PROOF_PROTOCOL &&
      payload.protocol !== CONTINUITY_LINK_PROTOCOL &&
      payload.protocol !== REVOKE_PROTOCOL
    ) {
      throw new WalletCoreError(
        'INVALID_REQUEST',
        'A legacy custom key vault cannot sign v2 protocol payloads.',
      );
    }
    const legacySign = (this.#keyVault as Partial<KeyVault>).sign;
    if (legacySign === undefined) {
      throw new WalletCoreError('INVALID_REQUEST', 'This key vault cannot sign protocol payloads.');
    }
    return legacySign.call(this.#keyVault, ref, createProtocolSignaturePreimage(payload));
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

  async #getDeviceRecord(
    localId: string,
    requireSigningMaterial: boolean,
  ): Promise<LocalIdentityRecordV1 & { deviceV2: NonNullable<LocalIdentityRecordV1['deviceV2']> }> {
    const record = await this.#getRecord(localId);
    if (record.localState !== 'active') {
      throw new WalletCoreError('IDENTITY_REVOKED', 'This identity is locally marked as revoked.');
    }
    if (record.deviceV2 === undefined) {
      throw new WalletCoreError('INVALID_REQUEST', 'This local identity is not a v2 device.');
    }
    if (
      record.deviceV2.localState === 'pending-import' ||
      record.deviceV2.localState === 'import-cleanup-pending'
    ) {
      throw new WalletCoreError(
        'STORAGE_ERROR',
        'This device import is incomplete and awaits recovery.',
      );
    }
    if (requireSigningMaterial && record.deviceV2.signingPrivateKeyRef === undefined) {
      throw new WalletCoreError(
        'IDENTITY_REVOKED',
        'This device no longer has active signing material.',
      );
    }
    return { ...record, deviceV2: record.deviceV2 };
  }

  #requireDeviceSigningRef(device: NonNullable<LocalIdentityRecordV1['deviceV2']>): KeyRef {
    if (device.signingPrivateKeyRef === undefined) {
      throw new WalletCoreError(
        'IDENTITY_REVOKED',
        'This device no longer has active signing material.',
      );
    }
    return device.signingPrivateKeyRef;
  }

  async #deriveDeviceAuthorizationId(
    payload: DeviceAuthorizationPayloadV2,
  ): Promise<ReturnType<typeof formatDeviceAuthorizationIdV2>> {
    return formatDeviceAuthorizationIdV2(
      await this.#crypto.sha256(createDeviceAuthorizationHashPreimageV2(payload)),
    );
  }

  async #verifyDeviceReceipt(
    rawReceipt: unknown,
    expectation: {
      subject: LocalIdentityRecordV1['subject'];
      genesisHash: string;
      deviceId: NonNullable<LocalIdentityRecordV1['deviceV2']>['deviceId'];
      authorizationId?: NonNullable<LocalIdentityRecordV1['deviceV2']>['authorizationId'];
      authorizationExpiresAt?: number;
      eventType: 'activated' | 'revoked';
      deviceState: 'active' | 'revoked';
      revokedBy?: 'root' | 'device';
      allowConvergedRevocation?: boolean;
    },
  ): Promise<DeviceRegistryReceiptV2> {
    if (this.#verifyDeviceRegistryReceipt === undefined) {
      throw new WalletCoreError(
        'INVALID_REQUEST',
        'No v2 device registry receipt verifier is configured.',
      );
    }
    let receipt: DeviceRegistryReceiptV2;
    try {
      receipt = deviceRegistryReceiptV2Schema.parse(
        await this.#verifyDeviceRegistryReceipt(rawReceipt),
      );
    } catch (error) {
      throw new WalletCoreError(
        'INVALID_REGISTRY_RECEIPT',
        'The device registry receipt did not pass cryptographic verification.',
        { cause: error },
      );
    }
    const payload = receipt.payload;
    const isConvergedRevocation =
      expectation.allowConvergedRevocation === true &&
      expectation.eventType === 'revoked' &&
      expectation.deviceState === 'revoked' &&
      payload.eventType === 'revoked' &&
      payload.deviceState === 'revoked';
    const hasValidConvergedAuthority =
      isConvergedRevocation &&
      (payload.revokedBy === 'root' ||
        (payload.revokedBy === 'device' && payload.authorizationId !== undefined));
    const hasMatchingAuthorization =
      expectation.authorizationId === undefined ||
      payload.authorizationId === undefined ||
      payload.authorizationId === expectation.authorizationId;
    if (
      payload.subject !== expectation.subject ||
      payload.genesisHash !== expectation.genesisHash ||
      payload.identityState !== 'active' ||
      payload.identitySequence !== 0 ||
      payload.deviceId !== expectation.deviceId ||
      payload.eventType !== expectation.eventType ||
      payload.deviceState !== expectation.deviceState ||
      (expectation.authorizationExpiresAt !== undefined &&
        payload.authorizationExpiresAt !== expectation.authorizationExpiresAt) ||
      (isConvergedRevocation
        ? !hasValidConvergedAuthority || !hasMatchingAuthorization
        : payload.revokedBy !== expectation.revokedBy ||
          (expectation.authorizationId !== undefined &&
            payload.authorizationId !== expectation.authorizationId))
    ) {
      throw new WalletCoreError(
        'INVALID_REGISTRY_RECEIPT',
        'The verified device receipt does not confirm the expected transition.',
      );
    }
    return receipt;
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
      const signature = await this.#signProtocolPayload(requireSigningRef(record), payload);
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
