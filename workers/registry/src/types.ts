import type {
  Base64Url32,
  IdentityGenesisV1,
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
}

export interface RegistryEnv {
  IDENTITY_STATE: DurableObjectNamespace<IdentityState>;
  REGISTRY_EVENTS: Pick<Queue<RegistryEventV1>, 'send'>;
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
