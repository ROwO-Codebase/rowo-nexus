export {
  NEXUS_VERIFICATION_ERROR_CODES,
  NEXUS_VERIFICATION_ERROR_CODES_V2,
  NexusVerificationError,
  NexusVerificationErrorV2,
  verificationError,
  verificationErrorV2,
} from './errors.js';
export type { NexusVerificationErrorCode, NexusVerificationErrorCodeV2 } from './errors.js';

export { verifySubject } from './identity.js';
export { verifyOwnershipProof } from './ownership.js';
export { verifyOwnershipProofAny, verifyOwnershipProofV2 } from './ownership-v2.js';
export { verifyRevocationSecret, verifyRevokeBySignature } from './revocation.js';
export {
  verifyDeviceRegistryReceipt,
  verifyDeviceStatusStatement,
  verifyRegistryReceipt,
  verifyStatusStatement,
} from './service-statements.js';
export { verifyContinuityLink } from './continuity.js';
export { verifyRpOperation, verifyRpOperationV2 } from './orchestrate.js';
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
  AuthoritativeDeviceLifecycleState,
  AuthenticatedInclusionProofExpectation,
  ChallengeRecord,
  ChallengeStore,
  DeviceLifecycleProvider,
  DeviceRegistryReceiptExpectation,
  DeviceStatusStatementExpectation,
  ContinuityLinkExpectation,
  GlobalTransparencyCheckpointExpectation,
  LifecycleProvider,
  OwnershipProofAnyOptions,
  RegistryReceiptExpectation,
  RevokeBySecretExpectation,
  RevokeBySignatureExpectation,
  StatusStatementExpectation,
  TransparencyCheckpointExpectation,
  TransparencyFreshnessExpectation,
  VerifiedDeviceSubject,
} from './types.js';
