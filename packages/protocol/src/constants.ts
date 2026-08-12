export const NEXUS_SUITE_V1 = 'NX-25519-SHA256-JCS-v1' as const;

export const IDENTITY_PROTOCOL_V1 = 'nexus.identity.v1' as const;
export const OWNERSHIP_PROOF_PROTOCOL_V1 = 'nexus.ownership-proof.v1' as const;
export const REVOKE_PROTOCOL_V1 = 'nexus.revoke.v1' as const;
export const REVOKE_SECRET_PROTOCOL_V1 = 'nexus.revoke-secret.v1' as const;
export const CONTINUITY_LINK_PROTOCOL_V1 = 'nexus.continuity-link.v1' as const;
export const REGISTRY_EVENT_PROTOCOL_V1 = 'nexus.registry-event.v1' as const;
export const REGISTRY_RECEIPT_PROTOCOL_V1 = 'nexus.registry-receipt.v1' as const;
export const STATUS_STATEMENT_PROTOCOL_V1 = 'nexus.status-statement.v1' as const;
export const TRANSPARENCY_CHECKPOINT_PROTOCOL_V1 = 'nexus.transparency-checkpoint.v1' as const;
export const TRANSPARENCY_INCLUSION_PROOF_PROTOCOL_V1 =
  'nexus.transparency-inclusion-proof.v1' as const;
export const TRANSPARENCY_GLOBAL_CHECKPOINT_PROTOCOL_V1 =
  'nexus.transparency-global-checkpoint.v1' as const;

// Nexus v2 keeps IdentityGenesisV1 as the stable root anchor and adds
// independently revocable, root-authorized device keys.
export const DEVICE_AUTHORIZATION_PROTOCOL_V2 = 'nexus.device-authorization.v2' as const;
export const DEVICE_ACTIVATION_PROTOCOL_V2 = 'nexus.device-activation.v2' as const;
export const DEVICE_SELF_REVOKE_PROTOCOL_V2 = 'nexus.device-self-revoke.v2' as const;
export const DEVICE_ROOT_REVOKE_PROTOCOL_V2 = 'nexus.device-root-revoke.v2' as const;
export const OWNERSHIP_PROOF_PROTOCOL_V2 = 'nexus.ownership-proof.v2' as const;
export const DEVICE_REGISTRY_EVENT_PROTOCOL_V2 = 'nexus.device-registry-event.v2' as const;
export const DEVICE_REGISTRY_RECEIPT_PROTOCOL_V2 = 'nexus.device-registry-receipt.v2' as const;
export const DEVICE_STATUS_STATEMENT_PROTOCOL_V2 = 'nexus.device-status-statement.v2' as const;

// Compatibility names used by the transparency Worker before this wire
// contract moved into @nexus/protocol.
export const TRANSPARENCY_CHECKPOINT_PROTOCOL = TRANSPARENCY_CHECKPOINT_PROTOCOL_V1;
export const TRANSPARENCY_INCLUSION_PROOF_PROTOCOL = TRANSPARENCY_INCLUSION_PROOF_PROTOCOL_V1;
export const TRANSPARENCY_GLOBAL_CHECKPOINT_PROTOCOL = TRANSPARENCY_GLOBAL_CHECKPOINT_PROTOCOL_V1;

export const ED25519_ALGORITHM = 'Ed25519' as const;
export const X25519_ALGORITHM = 'X25519' as const;
export const EDDSA_JWK_ALGORITHM = 'EdDSA' as const;

export const SIGNATURE_DOMAIN = 'NEXUS-SIGNATURE\0' as const;
export const GENESIS_HASH_DOMAIN = 'NEXUS-IDENTITY-GENESIS\0v1\0' as const;
export const REVOCATION_COMMITMENT_DOMAIN = 'NEXUS-REVOCATION-COMMITMENT\0v1\0' as const;
export const REGISTRY_EVENT_HASH_DOMAIN = 'NEXUS-REGISTRY-EVENT\0v1\0' as const;
export const DEVICE_ID_HASH_DOMAIN_V2 = 'NEXUS-DEVICE-ID\0v2\0' as const;
export const DEVICE_AUTHORIZATION_HASH_DOMAIN_V2 = 'NEXUS-DEVICE-AUTHORIZATION\0v2\0' as const;
export const DEVICE_OPERATION_HASH_DOMAIN_V2 = 'NEXUS-DEVICE-OPERATION\0v2\0' as const;
export const DEVICE_REGISTRY_EVENT_HASH_DOMAIN_V2 = 'NEXUS-DEVICE-REGISTRY-EVENT\0v2\0' as const;

export const NEXUS_SUBJECT_PREFIX = 'nx1_' as const;
export const NEXUS_EVENT_ID_PREFIX = 'nxe1_' as const;
export const NEXUS_DEVICE_ID_PREFIX_V2 = 'nxd2_' as const;
export const NEXUS_DEVICE_AUTHORIZATION_ID_PREFIX_V2 = 'nxa2_' as const;
export const NEXUS_DEVICE_OPERATION_ID_PREFIX_V2 = 'nxo2_' as const;
export const NEXUS_DEVICE_EVENT_ID_PREFIX_V2 = 'nxde2_' as const;

export const SHA256_BYTE_LENGTH = 32 as const;
export const ED25519_PUBLIC_KEY_BYTE_LENGTH = 32 as const;
export const X25519_PUBLIC_KEY_BYTE_LENGTH = 32 as const;
export const ED25519_SIGNATURE_BYTE_LENGTH = 64 as const;
export const REVOCATION_SECRET_BYTE_LENGTH = 32 as const;
export const MIN_NONCE_BYTE_LENGTH = 16 as const;
export const MAX_NONCE_BYTE_LENGTH = 64 as const;
export const MAX_PROOF_LIFETIME_SECONDS = 120 as const;
export const MAX_DEVICE_ACTIVATION_WINDOW_SECONDS = 30 * 24 * 60 * 60;
export const MAX_DEVICE_AUTHORIZATION_LIFETIME_SECONDS = 366 * 24 * 60 * 60;

export const MAX_ACTION_LENGTH = 128 as const;
export const MAX_RESOURCE_LENGTH = 512 as const;
export const MAX_SCOPE_LENGTH = 256 as const;
export const MAX_AUDIENCE_LENGTH = 2048 as const;
export const MAX_SIGNER_KID_LENGTH = 128 as const;
export const MAX_TURNSTILE_TOKEN_LENGTH = 4096 as const;
export const MAX_STATUS_BATCH_SUBJECTS = 100 as const;
export const TRANSPARENCY_SHARD_COUNT = 256 as const;
export const MAX_TRANSPARENCY_AUDIT_PATH_LENGTH = 53 as const;

export const NEXUS_ERROR_CODES = [
  'BAD_REQUEST',
  'UNSUPPORTED_PROTOCOL',
  'UNSUPPORTED_SUITE',
  'INVALID_SUBJECT',
  'INVALID_SIGNATURE',
  'INVALID_REVOCATION_SECRET',
  'IDENTITY_NOT_FOUND',
  'IDENTITY_REVOKED',
  'SEQUENCE_CONFLICT',
  'SUBJECT_GENESIS_CONFLICT',
  'RATE_LIMITED',
  'TURNSTILE_REQUIRED',
  'TURNSTILE_INVALID',
  'BODY_TOO_LARGE',
  'INTERNAL_ERROR',
] as const;

export const NEXUS_DEVICE_ERROR_CODES = [
  ...NEXUS_ERROR_CODES,
  'METHOD_NOT_ALLOWED',
  'UNSUPPORTED_MEDIA_TYPE',
  'ORIGIN_NOT_ALLOWED',
  'HTTPS_REQUIRED',
  'SERVICE_UNAVAILABLE',
  'DEVICE_NOT_FOUND',
  'DEVICE_REVOKED',
  'DEVICE_AUTHORIZATION_CONFLICT',
] as const;
