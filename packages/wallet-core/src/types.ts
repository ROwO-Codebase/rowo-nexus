import type {
  ContinuityLinkV1,
  IdentityGenesisV1,
  NexusSubject,
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

export interface KeyVault {
  createSigningKey(): Promise<KeyRef>;
  sign(ref: KeyRef, data: Uint8Array): Promise<Uint8Array>;
  createAgreementKey(): Promise<KeyRef>;
  deleteKey(ref: KeyRef): Promise<void>;
  storeRevocationSecret(secret: Uint8Array): Promise<SecretRef>;
  readRevocationSecret(ref: SecretRef): Promise<Uint8Array>;
  deleteSecret(ref: SecretRef): Promise<void>;
  readPublicKey(ref: KeyRef): Promise<Uint8Array>;
  hasKey(ref: KeyRef): Promise<boolean>;
  hasSecret(ref: SecretRef): Promise<boolean>;
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
}

/**
 * A trust hook supplied by the wallet application. It must strict-parse the
 * envelope and cryptographically verify its Nexus service-key signature.
 */
export type RegistryReceiptVerifier = (receipt: unknown) => Promise<RegistryReceiptV1>;

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
  hasAgreementKey: boolean;
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
}
