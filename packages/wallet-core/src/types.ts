import type {
  Base64Url32,
  ContinuityLinkV1,
  DeviceActivationRequestV2,
  DeviceAuthorizationV2,
  DeviceRegistryReceiptV2,
  DeviceRegistryStatusV2,
  DeviceRootRevokeRequestV2,
  DeviceSelfRevokeRequestV2,
  DeviceStatusRequestV2,
  DeviceStatusStateV2,
  DeviceRevocationReasonCode,
  IdentityGenesisV1,
  NexusDeviceAuthorizationIdV2,
  NexusDeviceIdV2,
  NexusSubject,
  OwnershipProofV2,
  OwnershipProofV1,
  ProofRequest,
  RegistryReceiptV1,
  RevokeBySecretRequestV1,
  RevokeBySignatureRequestV1,
} from '@nexus/protocol';

declare const keyRefBrand: unique symbol;
declare const secretRefBrand: unique symbol;
declare const trustedWalletEventBrand: unique symbol;

export type KeyRef = string & { readonly [keyRefBrand]: 'KeyRef' };
export type SecretRef = string & { readonly [secretRefBrand]: 'SecretRef' };

export interface KeyVaultStorage {
  createSigningKey(): Promise<KeyRef>;
  createAgreementKey(): Promise<KeyRef>;
  deleteKey(ref: KeyRef): Promise<void>;
  storeRevocationSecret(secret: Uint8Array): Promise<SecretRef>;
  /** @deprecated Retained for v1 compatibility. It exposes revocation material to its caller. */
  readRevocationSecret(ref: SecretRef): Promise<Uint8Array>;
  deleteSecret(ref: SecretRef): Promise<void>;
  readPublicKey(ref: KeyRef): Promise<Uint8Array>;
  hasKey(ref: KeyRef): Promise<boolean>;
  hasSecret(ref: SecretRef): Promise<boolean>;
}

/**
 * Legacy custom-vault contract. Built-in vaults use a private, protocol-bound
 * signing capability and intentionally do not expose these signing/import APIs.
 */
export interface KeyVault extends KeyVaultStorage {
  /** @deprecated Implement only when adapting an existing v1 custom vault. */
  sign(ref: KeyRef, data: Uint8Array): Promise<Uint8Array>;
}

export interface LocalIdentityRecordV1 {
  localId: string;
  subject: NexusSubject;
  genesis: IdentityGenesisV1;
  signingPrivateKeyRef?: KeyRef;
  agreementPrivateKeyRef?: KeyRef;
  revocationSecretRef?: SecretRef;
  localScopes: string[];
  /**
   * A bounded, wallet-local record of proof approvals. Older v1 records may
   * omit this field; callers must treat an absent value as an empty history.
   */
  authorizationHistory?: AuthorizationHistoryEntry[];
  label?: string;
  localState: 'active' | 'revoked';
  registrationReceipt?: RegistryReceiptV1;
  revocationReceipt?: RegistryReceiptV1;
  /** Present only on an imported v2 device installation. */
  deviceV2?: LocalDeviceRecordV2;
  /** Root-device catalogue. Labels and lifecycle hints never enter signed wire objects. */
  issuedDevicesV2?: LocalIssuedDeviceRecordV2[];
}

export interface LocalDeviceRecordV2 {
  deviceId: NexusDeviceIdV2;
  authorizationId: NexusDeviceAuthorizationIdV2;
  authorization: DeviceAuthorizationV2;
  signingPrivateKeyRef?: KeyRef;
  localState:
    'pending-import' | 'import-cleanup-pending' | 'pending-activation' | 'active' | 'revoked';
  /** Lease start used to avoid recovering an import still active in another tab. */
  importStartedAt?: number;
  activationReceipt?: DeviceRegistryReceiptV2;
  revocationReceipt?: DeviceRegistryReceiptV2;
  /** Latest manually verified registry observation; absence means this wallet has not polled. */
  registryState?: DeviceStatusStateV2;
  statusCheckedAt?: number;
  registryRevokedAt?: number;
}

export interface LocalIssuedDeviceRecordV2 {
  deviceId: NexusDeviceIdV2;
  authorizationId: NexusDeviceAuthorizationIdV2;
  authorization: DeviceAuthorizationV2;
  issuedAt: number;
  label?: string;
  localState: 'issued' | 'revoked';
  revocationReceipt?: DeviceRegistryReceiptV2;
  /** Latest manually verified registry observation; absence means this wallet has not polled. */
  registryState?: DeviceStatusStateV2;
  statusCheckedAt?: number;
  registryRevokedAt?: number;
}

export interface AuthorizationHistoryEntry {
  authorizationId: string;
  approvedAt: number;
  audience: string;
  action: string;
  resource: string;
  introducedScope: boolean;
  contextBound: boolean;
}

export interface IdentityStore {
  get(localId: string): Promise<LocalIdentityRecordV1 | undefined>;
  list(): Promise<LocalIdentityRecordV1[]>;
  put(record: LocalIdentityRecordV1): Promise<void>;
  /** Atomically transforms the latest record in one storage transaction. */
  update?(
    localId: string,
    mutate: (record: LocalIdentityRecordV1) => LocalIdentityRecordV1,
  ): Promise<LocalIdentityRecordV1>;
  /** Atomically appends to the latest root record so concurrent issuance cannot lose entries. */
  appendIssuedDevice?(localId: string, device: LocalIssuedDeviceRecordV2): Promise<void>;
  /** Atomically rejects duplicate device IDs and creates one imported-device record. */
  reserveDeviceRecord?(record: LocalIdentityRecordV1): Promise<void>;
  delete(localId: string): Promise<void>;
}

export interface RegistryRegisterRequest {
  subject: NexusSubject;
  genesis: IdentityGenesisV1;
}

export interface RegistryIdentityStatus {
  subject: NexusSubject;
  state: 'active' | 'revoked';
  sequence: number;
  registeredAt: number;
  revokedAt?: number;
  terminalReceipt?: unknown;
}

export interface RegistryClient {
  register(request: RegistryRegisterRequest): Promise<unknown>;
  getStatus(subject: NexusSubject): Promise<RegistryIdentityStatus>;
  revoke(request: RevokeBySignatureRequestV1 | RevokeBySecretRequestV1): Promise<unknown>;
  activateDevice?(request: DeviceActivationRequestV2): Promise<unknown>;
  revokeDeviceSelf?(request: DeviceSelfRevokeRequestV2): Promise<unknown>;
  revokeDeviceRoot?(request: DeviceRootRevokeRequestV2): Promise<unknown>;
  getDeviceStatus?(request: DeviceStatusRequestV2): Promise<unknown>;
}

/**
 * A trust hook supplied by the wallet application. It must strict-parse the
 * envelope and cryptographically verify its Nexus service-key signature.
 */
export type RegistryReceiptVerifier = (receipt: unknown) => Promise<RegistryReceiptV1>;

/** Verifies the service signature and strict wire shape of a v2 device receipt. */
export type DeviceRegistryReceiptVerifier = (receipt: unknown) => Promise<DeviceRegistryReceiptV2>;

export interface DeviceRegistryStatusExpectation {
  subject: NexusSubject;
  genesisHash: Base64Url32;
  deviceId: NexusDeviceIdV2;
  authorizationId: NexusDeviceAuthorizationIdV2;
}

/** Strict-parses and verifies a service-signed v2 device status response and its exact tuple. */
export type DeviceRegistryStatusVerifier = (
  status: unknown,
  expected: DeviceRegistryStatusExpectation,
) => Promise<DeviceRegistryStatusV2>;

export interface Clock {
  now(): number;
}

export interface TrustedWalletEventBoundary {
  readonly audience: string;
  readonly [trustedWalletEventBrand]: true;
}

export interface CreateIdentityOptions {
  label?: string;
  withAgreementKey?: boolean;
  register?: boolean;
}

export interface CreatedLocalIdentity {
  localId: string;
  subject: NexusSubject;
  genesis: IdentityGenesisV1;
  registrationReceipt?: RegistryReceiptV1;
}

export interface LocalIdentitySummary {
  localId: string;
  subject: NexusSubject;
  label?: string;
  localScopes: readonly string[];
  authorizationHistory: readonly AuthorizationHistoryEntry[];
  localState: 'active' | 'revoked';
  registered: boolean;
  /** Role-aware readiness: active v1 root registration or active v2 device installation. */
  proofReady: boolean;
  hasAgreementKey: boolean;
  device?: {
    deviceId: NexusDeviceIdV2;
    authorizationId: NexusDeviceAuthorizationIdV2;
    localState: LocalDeviceRecordV2['localState'];
    activationDeadline: number;
    expiresAt: number;
    registryState?: DeviceStatusStateV2;
    statusCheckedAt?: number;
    registryRevokedAt?: number;
  };
  issuedDevices: readonly {
    deviceId: NexusDeviceIdV2;
    authorizationId: NexusDeviceAuthorizationIdV2;
    issuedAt: number;
    activationDeadline: number;
    expiresAt: number;
    label?: string;
    localState: LocalIssuedDeviceRecordV2['localState'];
    registryState?: DeviceStatusStateV2;
    statusCheckedAt?: number;
    registryRevokedAt?: number;
  }[];
}

export interface IssueDeviceTransferOptions {
  /** Wallet-local only; it is never signed or included in the transfer. */
  label?: string;
  validFrom?: number;
  activationDeadline?: number;
  expiresAt?: number;
}

export interface DeviceTransferEnvelopeV2 {
  protocol: 'nexus.device-transfer.v2';
  suite: 'NX-HKDF-SHA256-AES256GCM-v2';
  bundleId: string;
  salt: string;
  iv: string;
  ciphertext: string;
}

export interface IssuedDeviceTransferV2 {
  authorization: DeviceAuthorizationV2;
  bundle: DeviceTransferEnvelopeV2;
  /** A fresh 256-bit secret. Transfer this separately from the encrypted bundle. */
  /** The caller should overwrite this byte array after transferring/encoding it. */
  transferKey: Uint8Array;
}

export interface ImportedDeviceV2 {
  localId: string;
  subject: NexusSubject;
  deviceId: NexusDeviceIdV2;
  authorizationId: NexusDeviceAuthorizationIdV2;
  authorization: DeviceAuthorizationV2;
}

export interface DeviceRequestOptions {
  requestId?: string;
  expiresAt?: number;
}

export interface DeviceRevocationOptions {
  requestId?: string;
  reasonCode?: DeviceRevocationReasonCode;
}

export interface RevokeIdentityOptions {
  method?: 'signature' | 'secret';
  reasonCode?: 'dispose' | 'key-compromise' | 'lost-device';
}

export interface DisposeIdentityOptions extends RevokeIdentityOptions {
  retainPublicRecord?: boolean;
}

export interface RotateIdentityOptions {
  label?: string;
  withAgreementKey?: boolean;
  revokeOld?: boolean;
}

export interface RotateIdentityResult {
  oldSubject: NexusSubject;
  identity: CreatedLocalIdentity;
  oldRevocationReceipt?: RegistryReceiptV1;
}

export interface ContinuityLinkOptions {
  nonce: string;
  scope?: string;
  expiresAt?: number;
}

export interface WalletCoreApi {
  createIdentity(options?: CreateIdentityOptions): Promise<CreatedLocalIdentity>;
  registerIdentity(localId: string): Promise<RegistryReceiptV1>;
  prove(
    localId: string,
    boundary: TrustedWalletEventBoundary,
    request: ProofRequest,
  ): Promise<OwnershipProofV1>;
  proveAndRecordAuthorization(
    localId: string,
    boundary: TrustedWalletEventBoundary,
    request: ProofRequest,
    rememberScope: boolean,
  ): Promise<OwnershipProofV1>;
  clearAuthorizationHistory(localId: string): Promise<void>;
  revoke(localId: string, options?: RevokeIdentityOptions): Promise<RegistryReceiptV1>;
  dispose(localId: string, options?: DisposeIdentityOptions): Promise<RegistryReceiptV1>;
  /** Deletes a terminally revoked or expired identity and its remaining material from this wallet. */
  removeLocalIdentity(localId: string): Promise<void>;
  rotate(
    oldLocalId: string,
    boundary: TrustedWalletEventBoundary,
    options?: RotateIdentityOptions,
  ): Promise<RotateIdentityResult>;
  createContinuityLink(
    localIdA: string,
    localIdB: string,
    options: ContinuityLinkOptions,
  ): Promise<ContinuityLinkV1>;
  issueDeviceTransfer(
    rootLocalId: string,
    options?: IssueDeviceTransferOptions,
  ): Promise<IssuedDeviceTransferV2>;
  importDeviceTransfer(
    bundle: DeviceTransferEnvelopeV2,
    transferKey: Uint8Array,
  ): Promise<ImportedDeviceV2>;
  createDeviceActivationRequest(
    deviceLocalId: string,
    options?: DeviceRequestOptions,
  ): Promise<DeviceActivationRequestV2>;
  activateDevice(
    deviceLocalId: string,
    options?: DeviceRequestOptions,
  ): Promise<DeviceRegistryReceiptV2>;
  proveDevice(
    deviceLocalId: string,
    boundary: TrustedWalletEventBoundary,
    request: ProofRequest,
  ): Promise<OwnershipProofV2>;
  createDeviceSelfRevokeRequest(
    deviceLocalId: string,
    options?: DeviceRevocationOptions,
  ): Promise<DeviceSelfRevokeRequestV2>;
  revokeDeviceSelf(
    deviceLocalId: string,
    options?: DeviceRevocationOptions,
  ): Promise<DeviceRegistryReceiptV2>;
  createDeviceRootRevokeRequest(
    rootLocalId: string,
    deviceId: NexusDeviceIdV2,
    options?: DeviceRevocationOptions,
  ): Promise<DeviceRootRevokeRequestV2>;
  revokeDeviceRoot(
    rootLocalId: string,
    deviceId: NexusDeviceIdV2,
    options?: DeviceRevocationOptions,
  ): Promise<DeviceRegistryReceiptV2>;
  refreshDeviceStatus(localId: string, deviceId?: NexusDeviceIdV2): Promise<DeviceRegistryStatusV2>;
}
