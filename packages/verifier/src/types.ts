import type {
  Base64Url32,
  DeviceAuthorizationIdV2,
  DeviceRegistryReceiptPayloadV2,
  GlobalCheckpointShardV1,
  NexusDeviceIdV2,
  NexusSubject,
  RegistryReceiptPayloadV1,
} from '@nexus/protocol';
import type { OWNERSHIP_PROOF_PROTOCOL_V1, OWNERSHIP_PROOF_PROTOCOL_V2 } from '@nexus/protocol';

export const MAX_SIGNED_OBJECT_LIFETIME_SECONDS = 120;

export interface RevokeBySignatureExpectation {
  subject: NexusSubject;
  expectedSequence: number;
  nonce: string;
  now: number;
  maxClockSkewSeconds: number;
  maxAgeSeconds?: number;
}

export interface RevokeBySecretExpectation {
  subject: NexusSubject;
  expectedSequence: number;
}

export interface RegistryReceiptExpectation {
  subject?: NexusSubject;
  genesisHash?: string;
  eventType?: RegistryReceiptPayloadV1['eventType'];
  sequence?: number;
  state?: RegistryReceiptPayloadV1['state'];
}

export interface StatusStatementExpectation {
  subject?: NexusSubject;
  maxClockSkewSeconds?: number;
}

export interface TransparencyFreshnessExpectation {
  now: number;
  maxAgeSeconds: number;
  maxClockSkewSeconds: number;
  signerKid?: string;
}

export interface TransparencyCheckpointExpectation extends TransparencyFreshnessExpectation {
  shardId?: string;
  treeSize?: number;
  rootHash?: string;
}

export interface GlobalTransparencyCheckpointExpectation extends TransparencyFreshnessExpectation {
  shards?: readonly GlobalCheckpointShardV1[];
}

export interface AuthenticatedInclusionProofExpectation extends TransparencyFreshnessExpectation {
  eventHash: string;
  shardId: string;
  treeSize?: number;
  rootHash?: string;
}

export interface ContinuityLinkExpectation {
  nonce: string;
  now: number;
  maxClockSkewSeconds: number;
  subjectA?: NexusSubject;
  subjectB?: NexusSubject;
  scope?: string;
  maxLifetimeSeconds?: number;
}

export interface ChallengeRecord {
  nonce: string;
  action: string;
  resource: string;
  expiresAt: number;
  consumed: boolean;
}

export interface ChallengeStore {
  get(nonce: string): Promise<ChallengeRecord | null>;

  /** Returns true only for the single caller that atomically consumes the nonce. */
  consumeAtomically(nonce: string): Promise<boolean>;
}

export type AuthoritativeLifecycleState =
  | {
      state: 'not-found';
    }
  | {
      state: 'active' | 'revoked';
      sequence: number;
      registeredAt: number;
      revokedAt?: number;
    };

export interface LifecycleProvider {
  getAuthoritativeStatus(subject: NexusSubject): Promise<AuthoritativeLifecycleState>;
}

export interface VerifiedDeviceSubject {
  protocol: typeof OWNERSHIP_PROOF_PROTOCOL_V2;
  subject: NexusSubject;
  rootSigningPublicKey: Uint8Array;
  deviceId: NexusDeviceIdV2;
  deviceSigningPublicKey: Uint8Array;
  authorizationId: DeviceAuthorizationIdV2;
}

/** A verified v2 proof plus the authoritative combined lifecycle snapshot used to accept it. */
export interface VerifiedRpDeviceOperation extends VerifiedDeviceSubject {
  identitySequence: number;
  deviceLedgerSequence: number;
}

export interface OwnershipProofAnyOptions {
  acceptedProtocols: readonly (
    typeof OWNERSHIP_PROOF_PROTOCOL_V1 | typeof OWNERSHIP_PROOF_PROTOCOL_V2
  )[];
}

export type AuthoritativeDeviceLifecycleState =
  | { state: 'not-found' }
  | {
      state: 'active' | 'revoked' | 'expired';
      identityState: 'active' | 'revoked';
      identitySequence: number;
      deviceId: NexusDeviceIdV2;
      authorizationId: DeviceAuthorizationIdV2;
      deviceLedgerSequence: number;
      activatedAt?: number;
      revokedAt?: number;
      authorizationExpiresAt?: number;
    };

export interface DeviceLifecycleProvider {
  getAuthoritativeDeviceStatus(
    subject: NexusSubject,
    deviceId: NexusDeviceIdV2,
    authorizationId: DeviceAuthorizationIdV2,
  ): Promise<AuthoritativeDeviceLifecycleState>;
}

export interface DeviceStatusStatementExpectation {
  subject?: NexusSubject;
  genesisHash?: Base64Url32;
  deviceId?: NexusDeviceIdV2;
  authorizationId?: DeviceAuthorizationIdV2;
  identityState?: 'active' | 'revoked';
  identitySequence?: number;
  deviceLedgerSequence?: number;
  deviceState?: 'active' | 'revoked' | 'expired' | 'unknown';
  authorizationExpiresAt?: number;
  maxClockSkewSeconds?: number;
}

export interface DeviceRegistryReceiptExpectation {
  eventId?: DeviceRegistryReceiptPayloadV2['eventId'];
  operationId?: DeviceRegistryReceiptPayloadV2['operationId'];
  subject?: NexusSubject;
  genesisHash?: Base64Url32;
  eventType?: DeviceRegistryReceiptPayloadV2['eventType'];
  identityState?: DeviceRegistryReceiptPayloadV2['identityState'];
  identitySequence?: number;
  deviceLedgerSequence?: number;
  deviceId?: NexusDeviceIdV2;
  authorizationId?: DeviceAuthorizationIdV2;
  deviceState?: DeviceRegistryReceiptPayloadV2['deviceState'];
  authorizationExpiresAt?: number;
  acceptedAt?: number;
  revokedBy?: DeviceRegistryReceiptPayloadV2['revokedBy'];
}
