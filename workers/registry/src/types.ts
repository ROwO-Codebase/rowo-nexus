import type {
  Base64Url32,
  DeviceActivationRequestV2,
  DeviceRegistryEventV2,
  DeviceRootRevokeRequestV2,
  DeviceSelfRevokeRequestV2,
  IdentityGenesisV1,
  NexusDeviceAuthorizationIdV2,
  NexusDeviceIdV2,
  NexusSubject,
  RegistryEventV1,
  RevokeBySecretV1,
  RevokeBySignaturePayloadV1,
} from '@nexus/protocol';
import type { IdentityState } from './identity-state-do';

export type RegistryErrorCode =
  | 'BAD_REQUEST'
  | 'UNSUPPORTED_PROTOCOL'
  | 'UNSUPPORTED_SUITE'
  | 'INVALID_SUBJECT'
  | 'INVALID_SIGNATURE'
  | 'INVALID_REVOCATION_SECRET'
  | 'IDENTITY_NOT_FOUND'
  | 'IDENTITY_REVOKED'
  | 'DEVICE_NOT_FOUND'
  | 'DEVICE_REVOKED'
  | 'DEVICE_AUTHORIZATION_CONFLICT'
  | 'SEQUENCE_CONFLICT'
  | 'SUBJECT_GENESIS_CONFLICT'
  | 'INTERNAL_ERROR';

export interface RegistryFault {
  code: RegistryErrorCode;
  message: string;
}

export type RegistryResult<T> = { ok: true; value: T } | { ok: false; error: RegistryFault };

export interface RegisterCommand {
  subject: string;
  genesis: IdentityGenesisV1;
}

export interface RevokeBySignatureCommand {
  payload: RevokeBySignaturePayloadV1;
  signature: string;
}

export type RevokeBySecretCommand = RevokeBySecretV1;

export interface AuthoritativeStatus {
  subject: string;
  state: 'active' | 'revoked';
  sequence: number;
  registeredAt: number;
  revokedAt: number | null;
  genesis: IdentityGenesisV1;
  genesisHash: string;
  eventId: string;
  eventType: 'registered' | 'revoked';
  acceptedAt: number;
}

export interface RegistryMutation extends AuthoritativeStatus {
  event: RegistryEventV1;
}

export interface DeviceStatusCommand {
  subject: NexusSubject;
  deviceId: NexusDeviceIdV2;
  authorizationId: NexusDeviceAuthorizationIdV2;
}

export type DeviceStatusState = 'active' | 'revoked' | 'expired' | 'unknown';

export interface AuthoritativeDeviceStatusV2 {
  subject: NexusSubject;
  genesisHash: Base64Url32;
  identityState: 'active' | 'revoked';
  identitySequence: number;
  deviceLedgerSequence: number;
  deviceId: NexusDeviceIdV2;
  authorizationId: NexusDeviceAuthorizationIdV2;
  deviceState: DeviceStatusState;
  activatedAt: number | null;
  revokedAt: number | null;
  authorizationExpiresAt: number | null;
}

export interface DeviceRegistryMutationV2 {
  subject: NexusSubject;
  genesisHash: Base64Url32;
  identityState: 'active' | 'revoked';
  identitySequence: number;
  deviceLedgerSequence: number;
  deviceId: NexusDeviceIdV2;
  authorizationId: NexusDeviceAuthorizationIdV2 | null;
  deviceState: 'active' | 'revoked';
  activatedAt: number | null;
  revokedAt: number | null;
  authorizationExpiresAt: number | null;
  operationId: string;
  eventId: string;
  eventType: 'activated' | 'revoked';
  acceptedAt: number;
  event: DeviceRegistryEventV2;
}

export interface PreparedRegistration {
  subject: NexusSubject;
  genesis: IdentityGenesisV1;
  genesisJcs: string;
  genesisHash: Base64Url32;
  genesisHashBytes: Uint8Array;
  signingPublicKey: Uint8Array;
  agreementPublicKey: Uint8Array | null;
  revocationCommitment: Uint8Array;
}

export interface IdentityStateRpc {
  register(input: PreparedRegistration): Promise<RegistryResult<RegistryMutation>>;
  status(): Promise<RegistryResult<AuthoritativeStatus>>;
  revokeBySignature(input: RevokeBySignatureCommand): Promise<RegistryResult<RegistryMutation>>;
  revokeBySecret(input: RevokeBySecretCommand): Promise<RegistryResult<RegistryMutation>>;
  activateDevice(
    input: DeviceActivationRequestV2,
  ): Promise<RegistryResult<DeviceRegistryMutationV2>>;
  deviceStatus(
    input: Omit<DeviceStatusCommand, 'subject'>,
  ): Promise<RegistryResult<AuthoritativeDeviceStatusV2>>;
  revokeDeviceSelf(
    input: DeviceSelfRevokeRequestV2,
  ): Promise<RegistryResult<DeviceRegistryMutationV2>>;
  revokeDeviceRoot(
    input: DeviceRootRevokeRequestV2,
  ): Promise<RegistryResult<DeviceRegistryMutationV2>>;
}

export interface RegistryEnv {
  IDENTITY_STATE: DurableObjectNamespace<IdentityState>;
  REGISTRY_EVENTS: Pick<Queue<RegistryEventV1>, 'send'>;
  REGISTRY_DEVICE_EVENTS: Pick<Queue<DeviceRegistryEventV2>, 'send'>;
  METRICS?: AnalyticsEngineDataset;
}

export interface StoredIdentityRow {
  [key: string]: SqlStorageValue;
  subject: string;
  protocol: string;
  suite: string;
  genesis_jcs: string;
  genesis_hash: ArrayBuffer;
  signing_public_key: ArrayBuffer;
  agreement_public_key: ArrayBuffer | null;
  revocation_commitment: ArrayBuffer;
  state: 'active' | 'revoked';
  sequence: number;
  registered_at: number;
  revoked_at: number | null;
  revocation_event_id: string | null;
}

export interface StoredOutboxRow {
  [key: string]: SqlStorageValue;
  event_id: string;
  payload_jcs: string;
  created_at: number;
  published_at: number | null;
  attempt_count: number;
}

export interface StoredDeviceRow {
  [key: string]: SqlStorageValue;
  device_id: string;
  authorization_id: string | null;
  authorization_jcs: string | null;
  signing_public_key: ArrayBuffer | null;
  state: 'active' | 'revoked';
  authorization_expires_at: number | null;
  activated_at: number | null;
  revoked_at: number | null;
  revoked_by: 'root' | 'device' | null;
  activation_event_id: string | null;
  revocation_event_id: string | null;
}
