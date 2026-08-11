import type {
  GlobalCheckpointShardV1,
  NexusSubject,
  RegistryReceiptPayloadV1,
} from '@nexus/protocol';

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
