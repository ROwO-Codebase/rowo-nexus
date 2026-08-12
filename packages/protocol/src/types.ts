import type {
  CONTINUITY_LINK_PROTOCOL_V1,
  DEVICE_ACTIVATION_PROTOCOL_V2,
  DEVICE_AUTHORIZATION_PROTOCOL_V2,
  DEVICE_REGISTRY_EVENT_PROTOCOL_V2,
  DEVICE_REGISTRY_RECEIPT_PROTOCOL_V2,
  DEVICE_ROOT_REVOKE_PROTOCOL_V2,
  DEVICE_SELF_REVOKE_PROTOCOL_V2,
  DEVICE_STATUS_STATEMENT_PROTOCOL_V2,
  ED25519_ALGORITHM,
  EDDSA_JWK_ALGORITHM,
  IDENTITY_PROTOCOL_V1,
  NEXUS_ERROR_CODES,
  NEXUS_DEVICE_ERROR_CODES,
  NEXUS_SUITE_V1,
  OWNERSHIP_PROOF_PROTOCOL_V1,
  OWNERSHIP_PROOF_PROTOCOL_V2,
  REGISTRY_EVENT_PROTOCOL_V1,
  REGISTRY_RECEIPT_PROTOCOL_V1,
  REVOKE_PROTOCOL_V1,
  REVOKE_SECRET_PROTOCOL_V1,
  STATUS_STATEMENT_PROTOCOL_V1,
  TRANSPARENCY_CHECKPOINT_PROTOCOL_V1,
  TRANSPARENCY_GLOBAL_CHECKPOINT_PROTOCOL_V1,
  TRANSPARENCY_INCLUSION_PROOF_PROTOCOL_V1,
  X25519_ALGORITHM,
} from './constants.js';

declare const base64Url32Brand: unique symbol;
declare const base64Url64Brand: unique symbol;
declare const base64UrlAtLeast16Brand: unique symbol;

export type Base64Url32 = string & { readonly [base64Url32Brand]: true };
export type Base64Url64 = string & { readonly [base64Url64Brand]: true };
export type Base64UrlAtLeast16 = string & {
  readonly [base64UrlAtLeast16Brand]: true;
};

export type NexusSubject = `nx1_${string}`;
export type NexusEventId = `nxe1_${string}`;
export type NexusDeviceIdV2 = `nxd2_${string}`;
export type NexusDeviceAuthorizationIdV2 = `nxa2_${string}`;
export type NexusDeviceOperationIdV2 = `nxo2_${string}`;
export type NexusDeviceEventIdV2 = `nxde2_${string}`;
export type DeviceIdV2 = NexusDeviceIdV2;
export type DeviceAuthorizationIdV2 = NexusDeviceAuthorizationIdV2;
export type DeviceOperationIdV2 = NexusDeviceOperationIdV2;
export type DeviceEventIdV2 = NexusDeviceEventIdV2;
export type LifecycleState = 'active' | 'revoked';
export type RegistryEventType = 'registered' | 'revoked';
export type RevocationReasonCode = 'dispose' | 'key-compromise' | 'lost-device';
export type DeviceRevocationReasonCode = RevocationReasonCode | 'replaced';
export type DeviceRegistryEventTypeV2 = 'activated' | 'revoked';
export type DeviceRegistryStateV2 = 'active' | 'revoked';
export type DeviceStatusStateV2 = DeviceRegistryStateV2 | 'expired' | 'unknown';
export type DeviceRevokedByV2 = 'root' | 'device';
export type NexusErrorCode = (typeof NEXUS_ERROR_CODES)[number];
export type NexusDeviceErrorCode = (typeof NEXUS_DEVICE_ERROR_CODES)[number];

export type JsonPrimitive = null | boolean | number | string;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };

export interface IdentityGenesisV1 {
  protocol: typeof IDENTITY_PROTOCOL_V1;
  suite: typeof NEXUS_SUITE_V1;
  signingKey: {
    alg: typeof ED25519_ALGORITHM;
    publicKey: Base64Url32;
  };
  agreementKey?:
    | {
        alg: typeof X25519_ALGORITHM;
        publicKey: Base64Url32;
      }
    | undefined;
  revocationCommitment: Base64Url32;
}

export interface OwnershipProofPayloadV1 {
  protocol: typeof OWNERSHIP_PROOF_PROTOCOL_V1;
  subject: NexusSubject;
  genesis: IdentityGenesisV1;
  aud: string;
  act: string;
  resource: string;
  nonce: Base64UrlAtLeast16;
  iat: number;
  exp: number;
  contextHash?: Base64Url32 | undefined;
}

export interface OwnershipProofV1 {
  payload: OwnershipProofPayloadV1;
  signature: Base64Url64;
}

export interface DeviceSigningKeyV2 {
  alg: typeof ED25519_ALGORITHM;
  publicKey: Base64Url32;
}

/** Canonical input committed to by a Nexus v2 device identifier. */
export interface DeviceIdInputV2 {
  subject: NexusSubject;
  signingKey: DeviceSigningKeyV2;
}

export interface DeviceAuthorizationPayloadV2 extends DeviceIdInputV2 {
  protocol: typeof DEVICE_AUTHORIZATION_PROTOCOL_V2;
  genesisHash: Base64Url32;
  deviceId: NexusDeviceIdV2;
  authorizationNonce: Base64Url32;
  validFrom: number;
  activationDeadline: number;
  expiresAt: number;
}

export interface DeviceAuthorizationV2 {
  payload: DeviceAuthorizationPayloadV2;
  rootSignature: Base64Url64;
}

export interface DeviceActivationPayloadV2 {
  protocol: typeof DEVICE_ACTIVATION_PROTOCOL_V2;
  subject: NexusSubject;
  deviceId: NexusDeviceIdV2;
  authorizationId: NexusDeviceAuthorizationIdV2;
  requestId: Base64Url32;
  iat: number;
  exp: number;
}

export interface DeviceActivationRequestV2 {
  authorization: DeviceAuthorizationV2;
  payload: DeviceActivationPayloadV2;
  deviceSignature: Base64Url64;
}
export type DeviceActivationV2 = DeviceActivationRequestV2;

export interface DeviceSelfRevokePayloadV2 {
  protocol: typeof DEVICE_SELF_REVOKE_PROTOCOL_V2;
  subject: NexusSubject;
  genesisHash: Base64Url32;
  deviceId: NexusDeviceIdV2;
  authorizationId: NexusDeviceAuthorizationIdV2;
  requestId: Base64Url32;
  issuedAt: number;
  reasonCode?: DeviceRevocationReasonCode | undefined;
}

export interface DeviceSelfRevokeRequestV2 {
  authorization: DeviceAuthorizationV2;
  payload: DeviceSelfRevokePayloadV2;
  deviceSignature: Base64Url64;
}
export type DeviceSelfRevokeV2 = DeviceSelfRevokeRequestV2;

export interface DeviceRootRevokePayloadV2 {
  protocol: typeof DEVICE_ROOT_REVOKE_PROTOCOL_V2;
  subject: NexusSubject;
  genesisHash: Base64Url32;
  deviceId: NexusDeviceIdV2;
  requestId: Base64Url32;
  issuedAt: number;
  reasonCode?: DeviceRevocationReasonCode | undefined;
}

export interface DeviceRootRevokeRequestV2 {
  payload: DeviceRootRevokePayloadV2;
  rootSignature: Base64Url64;
}
export type DeviceRootRevokeV2 = DeviceRootRevokeRequestV2;

export type DeviceOperationPayloadV2 =
  DeviceActivationPayloadV2 | DeviceSelfRevokePayloadV2 | DeviceRootRevokePayloadV2;

export interface OwnershipProofPayloadV2 {
  protocol: typeof OWNERSHIP_PROOF_PROTOCOL_V2;
  subject: NexusSubject;
  genesis: IdentityGenesisV1;
  deviceId: NexusDeviceIdV2;
  authorizationId: NexusDeviceAuthorizationIdV2;
  authorization: DeviceAuthorizationV2;
  aud: string;
  act: string;
  resource: string;
  nonce: Base64UrlAtLeast16;
  iat: number;
  exp: number;
  contextHash?: Base64Url32 | undefined;
}

export interface OwnershipProofV2 {
  payload: OwnershipProofPayloadV2;
  deviceSignature: Base64Url64;
}

export interface DeviceRegistryEventV2 {
  protocol: typeof DEVICE_REGISTRY_EVENT_PROTOCOL_V2;
  eventId: NexusDeviceEventIdV2;
  operationId: NexusDeviceOperationIdV2;
  eventType: DeviceRegistryEventTypeV2;
  subject: NexusSubject;
  genesisHash: Base64Url32;
  identitySequence: number;
  identityState: LifecycleState;
  deviceLedgerSequence: number;
  deviceId: NexusDeviceIdV2;
  authorizationId?: NexusDeviceAuthorizationIdV2 | undefined;
  deviceState: DeviceRegistryStateV2;
  authorizationExpiresAt?: number | undefined;
  acceptedAt: number;
  actionHash: Base64Url32;
  revokedBy?: DeviceRevokedByV2 | undefined;
}

export type DeviceRegistryEventWithoutEventIdV2 = Omit<DeviceRegistryEventV2, 'eventId'>;

export interface DeviceRegistryReceiptPayloadV2 {
  protocol: typeof DEVICE_REGISTRY_RECEIPT_PROTOCOL_V2;
  eventId: NexusDeviceEventIdV2;
  operationId: NexusDeviceOperationIdV2;
  eventType: DeviceRegistryEventTypeV2;
  subject: NexusSubject;
  genesisHash: Base64Url32;
  identitySequence: number;
  identityState: LifecycleState;
  deviceLedgerSequence: number;
  deviceId: NexusDeviceIdV2;
  authorizationId?: NexusDeviceAuthorizationIdV2 | undefined;
  deviceState: DeviceRegistryStateV2;
  authorizationExpiresAt?: number | undefined;
  acceptedAt: number;
  revokedBy?: DeviceRevokedByV2 | undefined;
  signerKid: string;
}

export interface DeviceRegistryReceiptV2 {
  payload: DeviceRegistryReceiptPayloadV2;
  signature: Base64Url64;
}

export interface DeviceStatusStatementPayloadV2 {
  protocol: typeof DEVICE_STATUS_STATEMENT_PROTOCOL_V2;
  subject: NexusSubject;
  genesisHash: Base64Url32;
  identityState: LifecycleState;
  identitySequence: number;
  deviceLedgerSequence: number;
  deviceId: NexusDeviceIdV2;
  authorizationId: NexusDeviceAuthorizationIdV2;
  deviceState: DeviceStatusStateV2;
  activatedAt?: number | undefined;
  revokedAt?: number | undefined;
  authorizationExpiresAt?: number | undefined;
  iat: number;
  exp: number;
  signerKid: string;
}

export interface DeviceStatusStatementV2 {
  payload: DeviceStatusStatementPayloadV2;
  signature: Base64Url64;
}

export interface DeviceStatusRequestV2 {
  subject: NexusSubject;
  deviceId: NexusDeviceIdV2;
  authorizationId: NexusDeviceAuthorizationIdV2;
}

export interface DeviceStatusBatchRequestV2 {
  devices: DeviceStatusRequestV2[];
}

export interface DeviceRegistryStatusV2 {
  subject: NexusSubject;
  genesisHash: Base64Url32;
  identityState: LifecycleState;
  identitySequence: number;
  deviceLedgerSequence: number;
  deviceId: NexusDeviceIdV2;
  authorizationId: NexusDeviceAuthorizationIdV2;
  deviceState: DeviceStatusStateV2;
  activatedAt: number | null;
  revokedAt: number | null;
  authorizationExpiresAt: number | null;
  statusStatement: DeviceStatusStatementV2;
}

export interface DeviceStatusBatchResponseV2 {
  results: (
    | { ok: true; status: DeviceRegistryStatusV2 }
    | {
        ok: false;
        subject: NexusSubject;
        deviceId: NexusDeviceIdV2;
        authorizationId: NexusDeviceAuthorizationIdV2;
        error: NexusDeviceError['error'];
      }
  )[];
}

export interface RevokeBySignaturePayloadV1 {
  protocol: typeof REVOKE_PROTOCOL_V1;
  subject: NexusSubject;
  expectedSequence: number;
  nonce: Base64UrlAtLeast16;
  iat: number;
  reasonCode?: RevocationReasonCode | undefined;
}

export interface RevokeBySignatureRequestV1 {
  mode: 'signature';
  payload: RevokeBySignaturePayloadV1;
  signature: Base64Url64;
}

export interface RevokeBySecretV1 {
  protocol: typeof REVOKE_SECRET_PROTOCOL_V1;
  subject: NexusSubject;
  expectedSequence: number;
  revocationSecret: Base64Url32;
}

export interface RevokeBySecretRequestV1 {
  mode: 'secret';
  payload: RevokeBySecretV1;
}

export type RevokeRequestV1 = RevokeBySignatureRequestV1 | RevokeBySecretRequestV1;

export interface ContinuityLinkPayloadV1 {
  protocol: typeof CONTINUITY_LINK_PROTOCOL_V1;
  subjectA: NexusSubject;
  genesisA: IdentityGenesisV1;
  subjectB: NexusSubject;
  genesisB: IdentityGenesisV1;
  scope?: string | undefined;
  iat: number;
  exp?: number | undefined;
  nonce: Base64UrlAtLeast16;
}

export interface ContinuityLinkV1 {
  payload: ContinuityLinkPayloadV1;
  signatureA: Base64Url64;
  signatureB: Base64Url64;
}

export interface RegistryEventV1 {
  protocol: typeof REGISTRY_EVENT_PROTOCOL_V1;
  eventId: NexusEventId;
  eventType: RegistryEventType;
  subject: NexusSubject;
  genesisHash: Base64Url32;
  sequence: number;
  state: LifecycleState;
  acceptedAt: number;
  actionHash: Base64Url32;
}

export type RegistryEventWithoutEventIdV1 = Omit<RegistryEventV1, 'eventId'>;

export interface RegistryReceiptPayloadV1 {
  protocol: typeof REGISTRY_RECEIPT_PROTOCOL_V1;
  eventId: NexusEventId;
  subject: NexusSubject;
  genesisHash: Base64Url32;
  eventType: RegistryEventType;
  sequence: number;
  state: LifecycleState;
  acceptedAt: number;
  signerKid: string;
}

export interface RegistryReceiptV1 {
  payload: RegistryReceiptPayloadV1;
  signature: Base64Url64;
}

export interface StatusStatementPayloadV1 {
  protocol: typeof STATUS_STATEMENT_PROTOCOL_V1;
  subject: NexusSubject;
  state: LifecycleState;
  sequence: number;
  registeredAt: number;
  revokedAt?: number | undefined;
  iat: number;
  exp: number;
  signerKid: string;
}

export interface StatusStatementV1 {
  payload: StatusStatementPayloadV1;
  signature: Base64Url64;
}

export interface CreateIdentityResult {
  subject: NexusSubject;
  genesis: IdentityGenesisV1;
  registrationReceipt?: RegistryReceiptV1 | undefined;
}

export interface ProofRequest {
  action: string;
  resource: string;
  nonce: Base64UrlAtLeast16;
  expiresAt: number;
  contextHash?: Base64Url32 | undefined;
}

export interface VerificationExpectation {
  audience: string;
  action: string;
  resource: string;
  nonce: Base64UrlAtLeast16;
  now: number;
  maxClockSkewSeconds: number;
}

/**
 * V2 expectation with explicit context binding. A null contextHash requires
 * the proof to omit contextHash; otherwise the proof value must match exactly.
 */
export interface VerificationExpectationV2 extends VerificationExpectation {
  contextHash: Base64Url32 | null;
}

export interface VerifiedSubject {
  subject: NexusSubject;
  signingPublicKey: Uint8Array;
  agreementPublicKey?: Uint8Array | undefined;
}

export interface Ed25519PublicJwk {
  kty: 'OKP';
  crv: typeof ED25519_ALGORITHM;
  alg: typeof EDDSA_JWK_ALGORITHM;
  kid: string;
  x: Base64Url32;
  use?: 'sig' | undefined;
}

export interface ServiceKeySet {
  keys: Ed25519PublicJwk[];
}

export interface RegisterIdentityRequestV1 {
  subject: NexusSubject;
  genesis: IdentityGenesisV1;
  turnstileToken?: string | undefined;
}

export interface StatusRequestV1 {
  subject: NexusSubject;
}

export interface StatusBatchRequestV1 {
  subjects: NexusSubject[];
}

export interface RegistryStatusV1 {
  subject: NexusSubject;
  state: LifecycleState;
  sequence: number;
  registeredAt: number;
  revokedAt: number | null;
  genesis: IdentityGenesisV1;
  statusStatement: StatusStatementV1;
}

export interface NexusError {
  error: {
    code: NexusErrorCode;
    message: string;
    requestId?: string | undefined;
  };
}

export interface NexusDeviceError {
  error: {
    code: NexusDeviceErrorCode;
    message: string;
    requestId?: string | undefined;
  };
}

export interface TransparencyCheckpointPayloadV1 {
  protocol: typeof TRANSPARENCY_CHECKPOINT_PROTOCOL_V1;
  shardId: string;
  treeSize: number;
  rootHash: Base64Url32;
  checkpointedAt: number;
  signerKid: string;
}

export interface SignedTransparencyCheckpointV1 {
  payload: TransparencyCheckpointPayloadV1;
  signature: Base64Url64;
}

export interface GlobalCheckpointShardV1 {
  shardId: string;
  treeSize: number;
  rootHash: Base64Url32;
}

export interface GlobalTransparencyCheckpointPayloadV1 {
  protocol: typeof TRANSPARENCY_GLOBAL_CHECKPOINT_PROTOCOL_V1;
  checkpointedAt: number;
  shards: GlobalCheckpointShardV1[];
  signerKid: string;
}

export interface SignedGlobalTransparencyCheckpointV1 {
  payload: GlobalTransparencyCheckpointPayloadV1;
  signature: Base64Url64;
}

export interface TransparencyInclusionProofV1 {
  protocol: typeof TRANSPARENCY_INCLUSION_PROOF_PROTOCOL_V1;
  eventHash: Base64Url32;
  shardId: string;
  leafIndex: number;
  treeSize: number;
  auditPath: Base64Url32[];
  checkpoint: SignedTransparencyCheckpointV1;
}
