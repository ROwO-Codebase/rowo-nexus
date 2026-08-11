export {
  NEXUS_VERIFICATION_ERROR_CODES,
  NexusVerificationError,
  verificationError,
} from './errors.js';
export type { NexusVerificationErrorCode } from './errors.js';

export { verifySubject } from './identity.js';
export { verifyOwnershipProof } from './ownership.js';
export { verifyRevocationSecret, verifyRevokeBySignature } from './revocation.js';
export { verifyRegistryReceipt, verifyStatusStatement } from './service-statements.js';
export { verifyContinuityLink } from './continuity.js';
export { verifyRpOperation } from './orchestrate.js';
export { verifyInclusionProof, verifyTransparencyInclusionProof } from './transparency.js';
export type { HashFunction, TransparencyInclusionProofInput } from './transparency.js';
export {
  verifyAuthenticatedInclusionProof,
  verifyGlobalTransparencyCheckpoint,
  verifyTransparencyCheckpoint,
  verifyTransparencyManifest,
} from './transparency-auth.js';

export { MAX_SIGNED_OBJECT_LIFETIME_SECONDS } from './types.js';
export type {
  AuthoritativeLifecycleState,
  AuthenticatedInclusionProofExpectation,
  ChallengeRecord,
  ChallengeStore,
  ContinuityLinkExpectation,
  GlobalTransparencyCheckpointExpectation,
  LifecycleProvider,
  RegistryReceiptExpectation,
  RevokeBySecretExpectation,
  RevokeBySignatureExpectation,
  StatusStatementExpectation,
  TransparencyCheckpointExpectation,
  TransparencyFreshnessExpectation,
} from './types.js';
