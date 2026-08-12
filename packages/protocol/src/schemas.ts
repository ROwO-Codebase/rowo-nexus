import * as z from 'zod';
import type { ZodType } from 'zod';

import {
  CONTINUITY_LINK_PROTOCOL_V1,
  DEVICE_ACTIVATION_PROTOCOL_V2,
  DEVICE_AUTHORIZATION_PROTOCOL_V2,
  DEVICE_REGISTRY_EVENT_PROTOCOL_V2,
  DEVICE_REGISTRY_RECEIPT_PROTOCOL_V2,
  DEVICE_ROOT_REVOKE_PROTOCOL_V2,
  DEVICE_SELF_REVOKE_PROTOCOL_V2,
  DEVICE_STATUS_STATEMENT_PROTOCOL_V2,
  ED25519_ALGORITHM,
  ED25519_SIGNATURE_BYTE_LENGTH,
  EDDSA_JWK_ALGORITHM,
  IDENTITY_PROTOCOL_V1,
  MAX_ACTION_LENGTH,
  MAX_AUDIENCE_LENGTH,
  MAX_DEVICE_ACTIVATION_WINDOW_SECONDS,
  MAX_DEVICE_AUTHORIZATION_LIFETIME_SECONDS,
  MAX_NONCE_BYTE_LENGTH,
  MAX_RESOURCE_LENGTH,
  MAX_SCOPE_LENGTH,
  MAX_SIGNER_KID_LENGTH,
  MAX_STATUS_BATCH_SUBJECTS,
  MAX_TRANSPARENCY_AUDIT_PATH_LENGTH,
  MAX_TURNSTILE_TOKEN_LENGTH,
  MIN_NONCE_BYTE_LENGTH,
  NEXUS_ERROR_CODES,
  NEXUS_DEVICE_ERROR_CODES,
  NEXUS_DEVICE_AUTHORIZATION_ID_PREFIX_V2,
  NEXUS_DEVICE_EVENT_ID_PREFIX_V2,
  NEXUS_DEVICE_ID_PREFIX_V2,
  NEXUS_DEVICE_OPERATION_ID_PREFIX_V2,
  NEXUS_EVENT_ID_PREFIX,
  NEXUS_SUBJECT_PREFIX,
  NEXUS_SUITE_V1,
  OWNERSHIP_PROOF_PROTOCOL_V1,
  OWNERSHIP_PROOF_PROTOCOL_V2,
  REGISTRY_EVENT_PROTOCOL_V1,
  REGISTRY_RECEIPT_PROTOCOL_V1,
  REVOKE_PROTOCOL_V1,
  REVOKE_SECRET_PROTOCOL_V1,
  SHA256_BYTE_LENGTH,
  STATUS_STATEMENT_PROTOCOL_V1,
  TRANSPARENCY_CHECKPOINT_PROTOCOL_V1,
  TRANSPARENCY_GLOBAL_CHECKPOINT_PROTOCOL_V1,
  TRANSPARENCY_INCLUSION_PROOF_PROTOCOL_V1,
  TRANSPARENCY_SHARD_COUNT,
  X25519_ALGORITHM,
} from './constants.js';
import { decodeBase64Url, decodeBase64UrlExact } from './base64url.js';
import type {
  Base64Url32,
  Base64Url64,
  Base64UrlAtLeast16,
  ContinuityLinkPayloadV1,
  ContinuityLinkV1,
  CreateIdentityResult,
  DeviceActivationPayloadV2,
  DeviceActivationRequestV2,
  DeviceAuthorizationPayloadV2,
  DeviceAuthorizationV2,
  DeviceRegistryEventV2,
  DeviceRegistryEventWithoutEventIdV2,
  DeviceRegistryReceiptPayloadV2,
  DeviceRegistryReceiptV2,
  DeviceRootRevokePayloadV2,
  DeviceRootRevokeRequestV2,
  DeviceSelfRevokePayloadV2,
  DeviceSelfRevokeRequestV2,
  DeviceStatusStatementPayloadV2,
  DeviceStatusStatementV2,
  DeviceStatusBatchRequestV2,
  DeviceStatusBatchResponseV2,
  DeviceStatusRequestV2,
  DeviceRegistryStatusV2,
  Ed25519PublicJwk,
  GlobalCheckpointShardV1,
  GlobalTransparencyCheckpointPayloadV1,
  IdentityGenesisV1,
  NexusError,
  NexusDeviceError,
  NexusDeviceAuthorizationIdV2,
  NexusDeviceEventIdV2,
  NexusDeviceIdV2,
  NexusDeviceOperationIdV2,
  NexusEventId,
  NexusSubject,
  OwnershipProofPayloadV1,
  OwnershipProofV1,
  OwnershipProofPayloadV2,
  OwnershipProofV2,
  ProofRequest,
  RegisterIdentityRequestV1,
  RegistryEventV1,
  RegistryEventWithoutEventIdV1,
  RegistryReceiptPayloadV1,
  RegistryReceiptV1,
  RegistryStatusV1,
  RevokeBySecretRequestV1,
  RevokeBySecretV1,
  RevokeBySignaturePayloadV1,
  RevokeBySignatureRequestV1,
  RevokeRequestV1,
  ServiceKeySet,
  SignedGlobalTransparencyCheckpointV1,
  SignedTransparencyCheckpointV1,
  StatusBatchRequestV1,
  StatusRequestV1,
  StatusStatementPayloadV1,
  StatusStatementV1,
  TransparencyCheckpointPayloadV1,
  TransparencyInclusionProofV1,
  VerificationExpectation,
  VerificationExpectationV2,
} from './types.js';

const PRINTABLE_ASCII_PATTERN = /^[\x20-\x7e]+$/u;

function isExactBase64Url(value: unknown, bytes: number): boolean {
  if (typeof value !== 'string') return false;
  try {
    decodeBase64UrlExact(value, bytes);
    return true;
  } catch {
    return false;
  }
}

function isBoundedNonce(value: unknown): boolean {
  if (typeof value !== 'string') return false;
  try {
    const decoded = decodeBase64Url(value);
    return decoded.length >= MIN_NONCE_BYTE_LENGTH && decoded.length <= MAX_NONCE_BYTE_LENGTH;
  } catch {
    return false;
  }
}

function isSubject(value: unknown): value is NexusSubject {
  return (
    typeof value === 'string' &&
    value.startsWith(NEXUS_SUBJECT_PREFIX) &&
    isExactBase64Url(value.slice(NEXUS_SUBJECT_PREFIX.length), SHA256_BYTE_LENGTH)
  );
}

function isEventId(value: unknown): value is NexusEventId {
  return (
    typeof value === 'string' &&
    value.startsWith(NEXUS_EVENT_ID_PREFIX) &&
    isExactBase64Url(value.slice(NEXUS_EVENT_ID_PREFIX.length), SHA256_BYTE_LENGTH)
  );
}

function isPrefixedHash<Prefix extends string>(
  value: unknown,
  prefix: Prefix,
): value is `${Prefix}${string}` {
  return (
    typeof value === 'string' &&
    value.startsWith(prefix) &&
    isExactBase64Url(value.slice(prefix.length), SHA256_BYTE_LENGTH)
  );
}

function printableAscii(maximumLength: number): z.ZodString {
  return z
    .string()
    .min(1)
    .max(maximumLength)
    .regex(PRINTABLE_ASCII_PATTERN, 'Must contain printable ASCII only.');
}

function isHttpsOrigin(value: string): boolean {
  if (value.includes('*')) return false;
  try {
    const parsed = new URL(value);
    return (
      parsed.protocol === 'https:' &&
      parsed.username === '' &&
      parsed.password === '' &&
      parsed.origin === value
    );
  } catch {
    return false;
  }
}

const safeNonNegativeIntegerSchema = z.number().int().safe().nonnegative();

export const base64Url32Schema: ZodType<Base64Url32> = z.custom<Base64Url32>(
  (value) => isExactBase64Url(value, SHA256_BYTE_LENGTH),
  'Expected canonical unpadded base64url encoding of 32 bytes.',
);

export const base64Url64Schema: ZodType<Base64Url64> = z.custom<Base64Url64>(
  (value) => isExactBase64Url(value, ED25519_SIGNATURE_BYTE_LENGTH),
  'Expected canonical unpadded base64url encoding of 64 bytes.',
);

export const base64UrlAtLeast16Schema: ZodType<Base64UrlAtLeast16> = z.custom<Base64UrlAtLeast16>(
  isBoundedNonce,
  `Expected canonical unpadded base64url encoding of ${String(MIN_NONCE_BYTE_LENGTH)}-${String(MAX_NONCE_BYTE_LENGTH)} bytes.`,
);

export const nexusSubjectSchema: ZodType<NexusSubject> = z.custom<NexusSubject>(
  isSubject,
  'Expected a canonical nx1_ subject containing a 32-byte hash.',
);

export const nexusEventIdSchema: ZodType<NexusEventId> = z.custom<NexusEventId>(
  isEventId,
  'Expected a canonical nxe1_ event ID containing a 32-byte hash.',
);

export const nexusDeviceIdV2Schema: ZodType<NexusDeviceIdV2> = z.custom<NexusDeviceIdV2>(
  (value) => isPrefixedHash(value, NEXUS_DEVICE_ID_PREFIX_V2),
  'Expected a canonical nxd2_ device ID containing a 32-byte hash.',
);

export const nexusDeviceAuthorizationIdV2Schema: ZodType<NexusDeviceAuthorizationIdV2> =
  z.custom<NexusDeviceAuthorizationIdV2>(
    (value) => isPrefixedHash(value, NEXUS_DEVICE_AUTHORIZATION_ID_PREFIX_V2),
    'Expected a canonical nxa2_ device authorization ID containing a 32-byte hash.',
  );

export const nexusDeviceOperationIdV2Schema: ZodType<NexusDeviceOperationIdV2> =
  z.custom<NexusDeviceOperationIdV2>(
    (value) => isPrefixedHash(value, NEXUS_DEVICE_OPERATION_ID_PREFIX_V2),
    'Expected a canonical nxo2_ device operation ID containing a 32-byte hash.',
  );

export const nexusDeviceEventIdV2Schema: ZodType<NexusDeviceEventIdV2> =
  z.custom<NexusDeviceEventIdV2>(
    (value) => isPrefixedHash(value, NEXUS_DEVICE_EVENT_ID_PREFIX_V2),
    'Expected a canonical nxde2_ device event ID containing a 32-byte hash.',
  );

export const audienceOriginSchema: ZodType<string> = printableAscii(MAX_AUDIENCE_LENGTH).refine(
  isHttpsOrigin,
  'Audience must be a canonical HTTPS origin without path, query, fragment, credentials, or wildcard.',
);

export const actionSchema: ZodType<string> = printableAscii(MAX_ACTION_LENGTH);
export const resourceSchema: ZodType<string> = printableAscii(MAX_RESOURCE_LENGTH);
export const scopeSchema: ZodType<string> = printableAscii(MAX_SCOPE_LENGTH);
export const signerKidSchema: ZodType<string> = printableAscii(MAX_SIGNER_KID_LENGTH);

export const identityGenesisV1Schema: ZodType<IdentityGenesisV1> = z.strictObject({
  protocol: z.literal(IDENTITY_PROTOCOL_V1),
  suite: z.literal(NEXUS_SUITE_V1),
  signingKey: z.strictObject({
    alg: z.literal(ED25519_ALGORITHM),
    publicKey: base64Url32Schema,
  }),
  agreementKey: z
    .strictObject({
      alg: z.literal(X25519_ALGORITHM),
      publicKey: base64Url32Schema,
    })
    .optional(),
  revocationCommitment: base64Url32Schema,
}) satisfies z.ZodType<IdentityGenesisV1>;

export const ownershipProofPayloadV1Schema: ZodType<OwnershipProofPayloadV1> = z
  .strictObject({
    protocol: z.literal(OWNERSHIP_PROOF_PROTOCOL_V1),
    subject: nexusSubjectSchema,
    genesis: identityGenesisV1Schema,
    aud: audienceOriginSchema,
    act: actionSchema,
    resource: resourceSchema,
    nonce: base64UrlAtLeast16Schema,
    iat: safeNonNegativeIntegerSchema,
    exp: safeNonNegativeIntegerSchema,
    contextHash: base64Url32Schema.optional(),
  })
  .refine((payload) => payload.iat <= payload.exp, {
    message: 'iat must be less than or equal to exp.',
    path: ['exp'],
  }) satisfies z.ZodType<OwnershipProofPayloadV1>;

export const ownershipProofV1Schema: ZodType<OwnershipProofV1> = z.strictObject({
  payload: ownershipProofPayloadV1Schema,
  signature: base64Url64Schema,
}) satisfies z.ZodType<OwnershipProofV1>;

export const deviceSigningKeyV2Schema = z.strictObject({
  alg: z.literal(ED25519_ALGORITHM),
  publicKey: base64Url32Schema,
});

export const deviceIdInputV2Schema = z.strictObject({
  subject: nexusSubjectSchema,
  signingKey: deviceSigningKeyV2Schema,
});

export const deviceAuthorizationPayloadV2Schema: ZodType<DeviceAuthorizationPayloadV2> = z
  .strictObject({
    protocol: z.literal(DEVICE_AUTHORIZATION_PROTOCOL_V2),
    subject: nexusSubjectSchema,
    genesisHash: base64Url32Schema,
    deviceId: nexusDeviceIdV2Schema,
    signingKey: deviceSigningKeyV2Schema,
    authorizationNonce: base64Url32Schema,
    validFrom: safeNonNegativeIntegerSchema,
    activationDeadline: safeNonNegativeIntegerSchema,
    expiresAt: safeNonNegativeIntegerSchema,
  })
  .superRefine((payload, context) => {
    if (payload.validFrom > payload.activationDeadline) {
      context.addIssue({
        code: 'custom',
        message: 'validFrom must not exceed activationDeadline.',
        path: ['activationDeadline'],
      });
    }
    if (payload.activationDeadline > payload.expiresAt) {
      context.addIssue({
        code: 'custom',
        message: 'activationDeadline must not exceed expiresAt.',
        path: ['expiresAt'],
      });
    }
    if (payload.activationDeadline - payload.validFrom > MAX_DEVICE_ACTIVATION_WINDOW_SECONDS) {
      context.addIssue({
        code: 'custom',
        message: 'Device activation window must not exceed 30 days.',
        path: ['activationDeadline'],
      });
    }
    if (payload.expiresAt - payload.validFrom > MAX_DEVICE_AUTHORIZATION_LIFETIME_SECONDS) {
      context.addIssue({
        code: 'custom',
        message: 'Device authorization lifetime must not exceed 366 days.',
        path: ['expiresAt'],
      });
    }
  }) satisfies z.ZodType<DeviceAuthorizationPayloadV2>;

export const deviceAuthorizationV2Schema: ZodType<DeviceAuthorizationV2> = z.strictObject({
  payload: deviceAuthorizationPayloadV2Schema,
  rootSignature: base64Url64Schema,
}) satisfies z.ZodType<DeviceAuthorizationV2>;

export const deviceActivationPayloadV2Schema: ZodType<DeviceActivationPayloadV2> = z
  .strictObject({
    protocol: z.literal(DEVICE_ACTIVATION_PROTOCOL_V2),
    subject: nexusSubjectSchema,
    deviceId: nexusDeviceIdV2Schema,
    authorizationId: nexusDeviceAuthorizationIdV2Schema,
    requestId: base64Url32Schema,
    iat: safeNonNegativeIntegerSchema,
    exp: safeNonNegativeIntegerSchema,
  })
  .refine((payload) => payload.iat <= payload.exp, {
    message: 'iat must be less than or equal to exp.',
    path: ['exp'],
  }) satisfies z.ZodType<DeviceActivationPayloadV2>;

export const deviceActivationRequestV2Schema: ZodType<DeviceActivationRequestV2> = z
  .strictObject({
    authorization: deviceAuthorizationV2Schema,
    payload: deviceActivationPayloadV2Schema,
    deviceSignature: base64Url64Schema,
  })
  .superRefine((request, context) => {
    const authorization = request.authorization.payload;
    if (request.payload.subject !== authorization.subject) {
      context.addIssue({
        code: 'custom',
        message: 'Activation subject must match the authorization subject.',
        path: ['payload', 'subject'],
      });
    }
    if (request.payload.deviceId !== authorization.deviceId) {
      context.addIssue({
        code: 'custom',
        message: 'Activation deviceId must match the authorization deviceId.',
        path: ['payload', 'deviceId'],
      });
    }
  }) satisfies z.ZodType<DeviceActivationRequestV2>;
export const deviceActivationV2Schema = deviceActivationRequestV2Schema;

export const deviceSelfRevokePayloadV2Schema: ZodType<DeviceSelfRevokePayloadV2> = z.strictObject({
  protocol: z.literal(DEVICE_SELF_REVOKE_PROTOCOL_V2),
  subject: nexusSubjectSchema,
  genesisHash: base64Url32Schema,
  deviceId: nexusDeviceIdV2Schema,
  authorizationId: nexusDeviceAuthorizationIdV2Schema,
  requestId: base64Url32Schema,
  issuedAt: safeNonNegativeIntegerSchema,
  reasonCode: z.enum(['dispose', 'key-compromise', 'lost-device', 'replaced']).optional(),
}) satisfies z.ZodType<DeviceSelfRevokePayloadV2>;

export const deviceSelfRevokeRequestV2Schema: ZodType<DeviceSelfRevokeRequestV2> = z
  .strictObject({
    authorization: deviceAuthorizationV2Schema,
    payload: deviceSelfRevokePayloadV2Schema,
    deviceSignature: base64Url64Schema,
  })
  .superRefine((request, context) => {
    const authorization = request.authorization.payload;
    for (const key of ['subject', 'genesisHash', 'deviceId'] as const) {
      if (request.payload[key] !== authorization[key]) {
        context.addIssue({
          code: 'custom',
          message: `Self-revocation ${key} must match the authorization.`,
          path: ['payload', key],
        });
      }
    }
  }) satisfies z.ZodType<DeviceSelfRevokeRequestV2>;
export const deviceSelfRevokeV2Schema = deviceSelfRevokeRequestV2Schema;

export const deviceRootRevokePayloadV2Schema: ZodType<DeviceRootRevokePayloadV2> = z.strictObject({
  protocol: z.literal(DEVICE_ROOT_REVOKE_PROTOCOL_V2),
  subject: nexusSubjectSchema,
  genesisHash: base64Url32Schema,
  deviceId: nexusDeviceIdV2Schema,
  requestId: base64Url32Schema,
  issuedAt: safeNonNegativeIntegerSchema,
  reasonCode: z.enum(['dispose', 'key-compromise', 'lost-device', 'replaced']).optional(),
}) satisfies z.ZodType<DeviceRootRevokePayloadV2>;

export const deviceRootRevokeRequestV2Schema: ZodType<DeviceRootRevokeRequestV2> = z.strictObject({
  payload: deviceRootRevokePayloadV2Schema,
  rootSignature: base64Url64Schema,
}) satisfies z.ZodType<DeviceRootRevokeRequestV2>;
export const deviceRootRevokeV2Schema = deviceRootRevokeRequestV2Schema;

export const ownershipProofPayloadV2Schema: ZodType<OwnershipProofPayloadV2> = z
  .strictObject({
    protocol: z.literal(OWNERSHIP_PROOF_PROTOCOL_V2),
    subject: nexusSubjectSchema,
    genesis: identityGenesisV1Schema,
    deviceId: nexusDeviceIdV2Schema,
    authorizationId: nexusDeviceAuthorizationIdV2Schema,
    authorization: deviceAuthorizationV2Schema,
    aud: audienceOriginSchema,
    act: actionSchema,
    resource: resourceSchema,
    nonce: base64UrlAtLeast16Schema,
    iat: safeNonNegativeIntegerSchema,
    exp: safeNonNegativeIntegerSchema,
    contextHash: base64Url32Schema.optional(),
  })
  .superRefine((proof, context) => {
    if (proof.iat > proof.exp) {
      context.addIssue({
        code: 'custom',
        message: 'iat must be less than or equal to exp.',
        path: ['exp'],
      });
    }
    const authorization = proof.authorization.payload;
    if (proof.subject !== authorization.subject) {
      context.addIssue({
        code: 'custom',
        message: 'Proof subject must match the authorization subject.',
        path: ['subject'],
      });
    }
    if (proof.deviceId !== authorization.deviceId) {
      context.addIssue({
        code: 'custom',
        message: 'Proof deviceId must match the authorization deviceId.',
        path: ['deviceId'],
      });
    }
  }) satisfies z.ZodType<OwnershipProofPayloadV2>;

export const ownershipProofV2Schema: ZodType<OwnershipProofV2> = z.strictObject({
  payload: ownershipProofPayloadV2Schema,
  deviceSignature: base64Url64Schema,
}) satisfies z.ZodType<OwnershipProofV2>;

export const revokeBySignaturePayloadV1Schema: ZodType<RevokeBySignaturePayloadV1> = z.strictObject(
  {
    protocol: z.literal(REVOKE_PROTOCOL_V1),
    subject: nexusSubjectSchema,
    expectedSequence: safeNonNegativeIntegerSchema,
    nonce: base64UrlAtLeast16Schema,
    iat: safeNonNegativeIntegerSchema,
    reasonCode: z.enum(['dispose', 'key-compromise', 'lost-device']).optional(),
  },
) satisfies z.ZodType<RevokeBySignaturePayloadV1>;

export const revokeBySignatureRequestV1Schema: ZodType<RevokeBySignatureRequestV1> = z.strictObject(
  {
    mode: z.literal('signature'),
    payload: revokeBySignaturePayloadV1Schema,
    signature: base64Url64Schema,
  },
) satisfies z.ZodType<RevokeBySignatureRequestV1>;

export const revokeBySecretV1Schema: ZodType<RevokeBySecretV1> = z.strictObject({
  protocol: z.literal(REVOKE_SECRET_PROTOCOL_V1),
  subject: nexusSubjectSchema,
  expectedSequence: safeNonNegativeIntegerSchema,
  revocationSecret: base64Url32Schema,
}) satisfies z.ZodType<RevokeBySecretV1>;

export const revokeBySecretRequestV1Schema: ZodType<RevokeBySecretRequestV1> = z.strictObject({
  mode: z.literal('secret'),
  payload: revokeBySecretV1Schema,
}) satisfies z.ZodType<RevokeBySecretRequestV1>;

export const revokeRequestV1Schema: ZodType<RevokeRequestV1> = z.union([
  revokeBySignatureRequestV1Schema,
  revokeBySecretRequestV1Schema,
]) satisfies z.ZodType<RevokeRequestV1>;

export const continuityLinkPayloadV1Schema: ZodType<ContinuityLinkPayloadV1> = z
  .strictObject({
    protocol: z.literal(CONTINUITY_LINK_PROTOCOL_V1),
    subjectA: nexusSubjectSchema,
    genesisA: identityGenesisV1Schema,
    subjectB: nexusSubjectSchema,
    genesisB: identityGenesisV1Schema,
    scope: scopeSchema.optional(),
    iat: safeNonNegativeIntegerSchema,
    exp: safeNonNegativeIntegerSchema.optional(),
    nonce: base64UrlAtLeast16Schema,
  })
  .superRefine((payload, context) => {
    if (payload.subjectA === payload.subjectB) {
      context.addIssue({
        code: 'custom',
        message: 'Continuity links require two distinct subjects.',
        path: ['subjectB'],
      });
    }
    if (payload.exp !== undefined && payload.iat > payload.exp) {
      context.addIssue({
        code: 'custom',
        message: 'iat must be less than or equal to exp.',
        path: ['exp'],
      });
    }
  }) satisfies z.ZodType<ContinuityLinkPayloadV1>;

export const continuityLinkV1Schema: ZodType<ContinuityLinkV1> = z.strictObject({
  payload: continuityLinkPayloadV1Schema,
  signatureA: base64Url64Schema,
  signatureB: base64Url64Schema,
}) satisfies z.ZodType<ContinuityLinkV1>;

const registryEventWithoutIdBaseSchema = z.strictObject({
  protocol: z.literal(REGISTRY_EVENT_PROTOCOL_V1),
  eventType: z.enum(['registered', 'revoked']),
  subject: nexusSubjectSchema,
  genesisHash: base64Url32Schema,
  sequence: safeNonNegativeIntegerSchema,
  state: z.enum(['active', 'revoked']),
  acceptedAt: safeNonNegativeIntegerSchema,
  actionHash: base64Url32Schema,
});

function addRegistryTransitionIssues(
  value: { eventType: 'registered' | 'revoked'; state: 'active' | 'revoked'; sequence: number },
  context: z.RefinementCtx,
): void {
  if (value.eventType === 'registered' && (value.state !== 'active' || value.sequence !== 0)) {
    context.addIssue({
      code: 'custom',
      message: 'A registered event must have active state and sequence 0.',
      path: ['eventType'],
    });
  }
  if (value.eventType === 'revoked' && (value.state !== 'revoked' || value.sequence !== 1)) {
    context.addIssue({
      code: 'custom',
      message: 'A v1 revoked event must have revoked state and sequence 1.',
      path: ['eventType'],
    });
  }
}

export const registryEventWithoutEventIdV1Schema: ZodType<RegistryEventWithoutEventIdV1> =
  registryEventWithoutIdBaseSchema.superRefine(
    addRegistryTransitionIssues,
  ) satisfies z.ZodType<RegistryEventWithoutEventIdV1>;

export const registryEventV1Schema: ZodType<RegistryEventV1> = registryEventWithoutIdBaseSchema
  .extend({ eventId: nexusEventIdSchema })
  .superRefine(addRegistryTransitionIssues) satisfies z.ZodType<RegistryEventV1>;

const registryReceiptPayloadBaseSchema = z.strictObject({
  protocol: z.literal(REGISTRY_RECEIPT_PROTOCOL_V1),
  eventId: nexusEventIdSchema,
  subject: nexusSubjectSchema,
  genesisHash: base64Url32Schema,
  eventType: z.enum(['registered', 'revoked']),
  sequence: safeNonNegativeIntegerSchema,
  state: z.enum(['active', 'revoked']),
  acceptedAt: safeNonNegativeIntegerSchema,
  signerKid: signerKidSchema,
});

export const registryReceiptPayloadV1Schema: ZodType<RegistryReceiptPayloadV1> =
  registryReceiptPayloadBaseSchema.superRefine(
    addRegistryTransitionIssues,
  ) satisfies z.ZodType<RegistryReceiptPayloadV1>;

export const registryReceiptV1Schema: ZodType<RegistryReceiptV1> = z.strictObject({
  payload: registryReceiptPayloadV1Schema,
  signature: base64Url64Schema,
}) satisfies z.ZodType<RegistryReceiptV1>;

const deviceRegistryEventWithoutIdBaseV2Schema = z.strictObject({
  protocol: z.literal(DEVICE_REGISTRY_EVENT_PROTOCOL_V2),
  operationId: nexusDeviceOperationIdV2Schema,
  eventType: z.enum(['activated', 'revoked']),
  subject: nexusSubjectSchema,
  genesisHash: base64Url32Schema,
  identitySequence: safeNonNegativeIntegerSchema,
  identityState: z.enum(['active', 'revoked']),
  deviceLedgerSequence: safeNonNegativeIntegerSchema,
  deviceId: nexusDeviceIdV2Schema,
  authorizationId: nexusDeviceAuthorizationIdV2Schema.optional(),
  deviceState: z.enum(['active', 'revoked']),
  authorizationExpiresAt: safeNonNegativeIntegerSchema.optional(),
  acceptedAt: safeNonNegativeIntegerSchema,
  actionHash: base64Url32Schema,
  revokedBy: z.enum(['root', 'device']).optional(),
});

function addDeviceRegistryTransitionIssues(
  value: {
    eventType: 'activated' | 'revoked';
    identitySequence: number;
    identityState: 'active' | 'revoked';
    deviceState: 'active' | 'revoked';
    authorizationId?: NexusDeviceAuthorizationIdV2 | undefined;
    authorizationExpiresAt?: number | undefined;
    revokedBy?: 'root' | 'device' | undefined;
  },
  context: z.RefinementCtx,
): void {
  if (
    (value.identityState === 'active' && value.identitySequence !== 0) ||
    (value.identityState === 'revoked' && value.identitySequence !== 1)
  ) {
    context.addIssue({
      code: 'custom',
      message: 'identitySequence must match the v1 identity state.',
      path: ['identitySequence'],
    });
  }
  if (value.eventType === 'activated') {
    if (value.identityState !== 'active' || value.deviceState !== 'active') {
      context.addIssue({
        code: 'custom',
        message: 'An activation event requires active identity and device state.',
        path: ['eventType'],
      });
    }
    if (value.authorizationId === undefined || value.authorizationExpiresAt === undefined) {
      context.addIssue({
        code: 'custom',
        message: 'An activation event requires authorizationId and authorizationExpiresAt.',
        path: ['authorizationId'],
      });
    }
    if (value.revokedBy !== undefined) {
      context.addIssue({
        code: 'custom',
        message: 'An activation event must omit revokedBy.',
        path: ['revokedBy'],
      });
    }
  } else {
    if (value.deviceState !== 'revoked' || value.revokedBy === undefined) {
      context.addIssue({
        code: 'custom',
        message: 'A revocation event requires revoked device state and revokedBy.',
        path: ['eventType'],
      });
    }
  }
}

export const deviceRegistryEventWithoutEventIdV2Schema: ZodType<DeviceRegistryEventWithoutEventIdV2> =
  deviceRegistryEventWithoutIdBaseV2Schema.superRefine(
    addDeviceRegistryTransitionIssues,
  ) satisfies z.ZodType<DeviceRegistryEventWithoutEventIdV2>;

export const deviceRegistryEventV2Schema: ZodType<DeviceRegistryEventV2> =
  deviceRegistryEventWithoutIdBaseV2Schema
    .extend({ eventId: nexusDeviceEventIdV2Schema })
    .superRefine(addDeviceRegistryTransitionIssues) satisfies z.ZodType<DeviceRegistryEventV2>;

const deviceRegistryReceiptPayloadBaseV2Schema = z.strictObject({
  protocol: z.literal(DEVICE_REGISTRY_RECEIPT_PROTOCOL_V2),
  eventId: nexusDeviceEventIdV2Schema,
  operationId: nexusDeviceOperationIdV2Schema,
  eventType: z.enum(['activated', 'revoked']),
  subject: nexusSubjectSchema,
  genesisHash: base64Url32Schema,
  identitySequence: safeNonNegativeIntegerSchema,
  identityState: z.enum(['active', 'revoked']),
  deviceLedgerSequence: safeNonNegativeIntegerSchema,
  deviceId: nexusDeviceIdV2Schema,
  authorizationId: nexusDeviceAuthorizationIdV2Schema.optional(),
  deviceState: z.enum(['active', 'revoked']),
  authorizationExpiresAt: safeNonNegativeIntegerSchema.optional(),
  acceptedAt: safeNonNegativeIntegerSchema,
  revokedBy: z.enum(['root', 'device']).optional(),
  signerKid: signerKidSchema,
});

export const deviceRegistryReceiptPayloadV2Schema: ZodType<DeviceRegistryReceiptPayloadV2> =
  deviceRegistryReceiptPayloadBaseV2Schema.superRefine(
    addDeviceRegistryTransitionIssues,
  ) satisfies z.ZodType<DeviceRegistryReceiptPayloadV2>;

export const deviceRegistryReceiptV2Schema: ZodType<DeviceRegistryReceiptV2> = z.strictObject({
  payload: deviceRegistryReceiptPayloadV2Schema,
  signature: base64Url64Schema,
}) satisfies z.ZodType<DeviceRegistryReceiptV2>;

export const statusStatementPayloadV1Schema: ZodType<StatusStatementPayloadV1> = z
  .strictObject({
    protocol: z.literal(STATUS_STATEMENT_PROTOCOL_V1),
    subject: nexusSubjectSchema,
    state: z.enum(['active', 'revoked']),
    sequence: safeNonNegativeIntegerSchema,
    registeredAt: safeNonNegativeIntegerSchema,
    revokedAt: safeNonNegativeIntegerSchema.optional(),
    iat: safeNonNegativeIntegerSchema,
    exp: safeNonNegativeIntegerSchema,
    signerKid: signerKidSchema,
  })
  .superRefine((payload, context) => {
    if (payload.iat > payload.exp) {
      context.addIssue({ code: 'custom', message: 'iat must not exceed exp.', path: ['exp'] });
    }
    if (payload.state === 'active') {
      if ('revokedAt' in payload) {
        context.addIssue({
          code: 'custom',
          message: 'Active status must omit revokedAt.',
          path: ['revokedAt'],
        });
      }
      if (payload.sequence !== 0) {
        context.addIssue({
          code: 'custom',
          message: 'Active v1 status must have sequence 0.',
          path: ['sequence'],
        });
      }
    } else {
      if (payload.revokedAt === undefined) {
        context.addIssue({
          code: 'custom',
          message: 'Revoked status requires revokedAt.',
          path: ['revokedAt'],
        });
      } else if (payload.revokedAt < payload.registeredAt) {
        context.addIssue({
          code: 'custom',
          message: 'revokedAt must not precede registeredAt.',
          path: ['revokedAt'],
        });
      }
      if (payload.sequence !== 1) {
        context.addIssue({
          code: 'custom',
          message: 'Revoked v1 status must have sequence 1.',
          path: ['sequence'],
        });
      }
    }
  }) satisfies z.ZodType<StatusStatementPayloadV1>;

export const statusStatementV1Schema: ZodType<StatusStatementV1> = z.strictObject({
  payload: statusStatementPayloadV1Schema,
  signature: base64Url64Schema,
}) satisfies z.ZodType<StatusStatementV1>;

export const deviceStatusStatementPayloadV2Schema: ZodType<DeviceStatusStatementPayloadV2> = z
  .strictObject({
    protocol: z.literal(DEVICE_STATUS_STATEMENT_PROTOCOL_V2),
    subject: nexusSubjectSchema,
    genesisHash: base64Url32Schema,
    identityState: z.enum(['active', 'revoked']),
    identitySequence: safeNonNegativeIntegerSchema,
    deviceLedgerSequence: safeNonNegativeIntegerSchema,
    deviceId: nexusDeviceIdV2Schema,
    authorizationId: nexusDeviceAuthorizationIdV2Schema,
    deviceState: z.enum(['active', 'revoked', 'expired', 'unknown']),
    activatedAt: safeNonNegativeIntegerSchema.optional(),
    revokedAt: safeNonNegativeIntegerSchema.optional(),
    authorizationExpiresAt: safeNonNegativeIntegerSchema.optional(),
    iat: safeNonNegativeIntegerSchema,
    exp: safeNonNegativeIntegerSchema,
    signerKid: signerKidSchema,
  })
  .superRefine((status, context) => {
    if (status.iat > status.exp) {
      context.addIssue({ code: 'custom', message: 'iat must not exceed exp.', path: ['exp'] });
    }
    if (
      (status.identityState === 'active' && status.identitySequence !== 0) ||
      (status.identityState === 'revoked' && status.identitySequence !== 1)
    ) {
      context.addIssue({
        code: 'custom',
        message: 'identitySequence must match the v1 identity state.',
        path: ['identitySequence'],
      });
    }
    if (status.deviceState === 'active') {
      if (
        status.identityState !== 'active' ||
        status.activatedAt === undefined ||
        status.authorizationExpiresAt === undefined ||
        status.revokedAt !== undefined
      ) {
        context.addIssue({
          code: 'custom',
          message: 'Active device status requires an active identity, activation and expiry only.',
          path: ['deviceState'],
        });
      }
    } else if (status.deviceState === 'expired') {
      if (
        status.identityState !== 'active' ||
        status.activatedAt === undefined ||
        status.authorizationExpiresAt === undefined ||
        status.revokedAt !== undefined
      ) {
        context.addIssue({
          code: 'custom',
          message: 'Expired device status requires an active identity, activation and expiry only.',
          path: ['deviceState'],
        });
      }
    } else if (status.deviceState === 'revoked') {
      if (status.revokedAt === undefined) {
        context.addIssue({
          code: 'custom',
          message: 'Revoked device status requires revokedAt.',
          path: ['revokedAt'],
        });
      }
    } else if (
      status.activatedAt !== undefined ||
      status.revokedAt !== undefined ||
      status.authorizationExpiresAt !== undefined
    ) {
      context.addIssue({
        code: 'custom',
        message: 'Unknown device status must omit lifecycle timestamps.',
        path: ['deviceState'],
      });
    }
    if (
      status.activatedAt !== undefined &&
      status.authorizationExpiresAt !== undefined &&
      status.activatedAt > status.authorizationExpiresAt
    ) {
      context.addIssue({
        code: 'custom',
        message: 'activatedAt must not exceed authorizationExpiresAt.',
        path: ['authorizationExpiresAt'],
      });
    }
    if (
      status.activatedAt !== undefined &&
      status.revokedAt !== undefined &&
      status.activatedAt > status.revokedAt
    ) {
      context.addIssue({
        code: 'custom',
        message: 'activatedAt must not exceed revokedAt.',
        path: ['revokedAt'],
      });
    }
  }) satisfies z.ZodType<DeviceStatusStatementPayloadV2>;

export const deviceStatusStatementV2Schema: ZodType<DeviceStatusStatementV2> = z.strictObject({
  payload: deviceStatusStatementPayloadV2Schema,
  signature: base64Url64Schema,
}) satisfies z.ZodType<DeviceStatusStatementV2>;

export const deviceStatusRequestV2Schema: ZodType<DeviceStatusRequestV2> = z.strictObject({
  subject: nexusSubjectSchema,
  deviceId: nexusDeviceIdV2Schema,
  authorizationId: nexusDeviceAuthorizationIdV2Schema,
}) satisfies z.ZodType<DeviceStatusRequestV2>;

export const deviceStatusBatchRequestV2Schema: ZodType<DeviceStatusBatchRequestV2> = z
  .strictObject({
    devices: z.array(deviceStatusRequestV2Schema).min(1).max(MAX_STATUS_BATCH_SUBJECTS),
  })
  .superRefine((request, context) => {
    const seen = new Set<string>();
    request.devices.forEach((device, index) => {
      const tuple = `${device.subject}\0${device.deviceId}\0${device.authorizationId}`;
      if (seen.has(tuple)) {
        context.addIssue({
          code: 'custom',
          message: 'Device status requests must be unique.',
          path: ['devices', index],
        });
      }
      seen.add(tuple);
    });
  }) satisfies z.ZodType<DeviceStatusBatchRequestV2>;

export const deviceRegistryStatusV2Schema: ZodType<DeviceRegistryStatusV2> = z
  .strictObject({
    subject: nexusSubjectSchema,
    genesisHash: base64Url32Schema,
    identityState: z.enum(['active', 'revoked']),
    identitySequence: safeNonNegativeIntegerSchema,
    deviceLedgerSequence: safeNonNegativeIntegerSchema,
    deviceId: nexusDeviceIdV2Schema,
    authorizationId: nexusDeviceAuthorizationIdV2Schema,
    deviceState: z.enum(['active', 'revoked', 'expired', 'unknown']),
    activatedAt: safeNonNegativeIntegerSchema.nullable(),
    revokedAt: safeNonNegativeIntegerSchema.nullable(),
    authorizationExpiresAt: safeNonNegativeIntegerSchema.nullable(),
    statusStatement: deviceStatusStatementV2Schema,
  })
  .superRefine((status, context) => {
    const statement = status.statusStatement.payload;
    if (
      statement.subject !== status.subject ||
      statement.genesisHash !== status.genesisHash ||
      statement.identityState !== status.identityState ||
      statement.identitySequence !== status.identitySequence ||
      statement.deviceLedgerSequence !== status.deviceLedgerSequence ||
      statement.deviceId !== status.deviceId ||
      statement.authorizationId !== status.authorizationId ||
      statement.deviceState !== status.deviceState ||
      (statement.activatedAt ?? null) !== status.activatedAt ||
      (statement.revokedAt ?? null) !== status.revokedAt ||
      (statement.authorizationExpiresAt ?? null) !== status.authorizationExpiresAt
    ) {
      context.addIssue({
        code: 'custom',
        message: 'Status statement does not describe the enclosing device registry status.',
        path: ['statusStatement'],
      });
    }
  }) satisfies z.ZodType<DeviceRegistryStatusV2>;

export const nexusDeviceErrorBodySchema = z.strictObject({
  code: z.enum(NEXUS_DEVICE_ERROR_CODES),
  message: z.string().min(1).max(1024),
  requestId: printableAscii(128).optional(),
});

export const nexusDeviceErrorSchema: ZodType<NexusDeviceError> = z.strictObject({
  error: nexusDeviceErrorBodySchema,
}) satisfies z.ZodType<NexusDeviceError>;

const deviceStatusBatchErrorV2Schema = z.strictObject({
  ok: z.literal(false),
  subject: nexusSubjectSchema,
  deviceId: nexusDeviceIdV2Schema,
  authorizationId: nexusDeviceAuthorizationIdV2Schema,
  error: nexusDeviceErrorBodySchema,
});

export const deviceStatusBatchResponseV2Schema: ZodType<DeviceStatusBatchResponseV2> =
  z.strictObject({
    results: z
      .array(
        z.union([
          z.strictObject({ ok: z.literal(true), status: deviceRegistryStatusV2Schema }),
          deviceStatusBatchErrorV2Schema,
        ]),
      )
      .max(MAX_STATUS_BATCH_SUBJECTS),
  }) satisfies z.ZodType<DeviceStatusBatchResponseV2>;

export const proofRequestSchema: ZodType<ProofRequest> = z.strictObject({
  action: actionSchema,
  resource: resourceSchema,
  nonce: base64UrlAtLeast16Schema,
  expiresAt: safeNonNegativeIntegerSchema,
  contextHash: base64Url32Schema.optional(),
}) satisfies z.ZodType<ProofRequest>;

export const verificationExpectationSchema: ZodType<VerificationExpectation> = z.strictObject({
  audience: audienceOriginSchema,
  action: actionSchema,
  resource: resourceSchema,
  nonce: base64UrlAtLeast16Schema,
  now: safeNonNegativeIntegerSchema,
  maxClockSkewSeconds: safeNonNegativeIntegerSchema,
}) satisfies z.ZodType<VerificationExpectation>;

export const verificationExpectationV2Schema: ZodType<VerificationExpectationV2> = z.strictObject({
  audience: audienceOriginSchema,
  action: actionSchema,
  resource: resourceSchema,
  nonce: base64UrlAtLeast16Schema,
  now: safeNonNegativeIntegerSchema,
  maxClockSkewSeconds: safeNonNegativeIntegerSchema,
  contextHash: base64Url32Schema.nullable(),
}) satisfies z.ZodType<VerificationExpectationV2>;

export const ed25519PublicJwkSchema: ZodType<Ed25519PublicJwk> = z.strictObject({
  kty: z.literal('OKP'),
  crv: z.literal(ED25519_ALGORITHM),
  alg: z.literal(EDDSA_JWK_ALGORITHM),
  kid: signerKidSchema,
  x: base64Url32Schema,
  use: z.literal('sig').optional(),
}) satisfies z.ZodType<Ed25519PublicJwk>;

export const serviceKeySetSchema: ZodType<ServiceKeySet> = z
  .strictObject({
    keys: z.array(ed25519PublicJwkSchema).min(1).max(1000),
  })
  .superRefine((keyset, context) => {
    const seen = new Set<string>();
    keyset.keys.forEach((key, index) => {
      if (seen.has(key.kid)) {
        context.addIssue({
          code: 'custom',
          message: 'Service key IDs must be unique.',
          path: ['keys', index, 'kid'],
        });
      }
      seen.add(key.kid);
    });
  }) satisfies z.ZodType<ServiceKeySet>;

export const registerIdentityRequestV1Schema: ZodType<RegisterIdentityRequestV1> = z.strictObject({
  subject: nexusSubjectSchema,
  genesis: identityGenesisV1Schema,
  turnstileToken: z.string().min(1).max(MAX_TURNSTILE_TOKEN_LENGTH).optional(),
}) satisfies z.ZodType<RegisterIdentityRequestV1>;

export const statusRequestV1Schema: ZodType<StatusRequestV1> = z.strictObject({
  subject: nexusSubjectSchema,
}) satisfies z.ZodType<StatusRequestV1>;

export const statusBatchRequestV1Schema: ZodType<StatusBatchRequestV1> = z.strictObject({
  subjects: z.array(nexusSubjectSchema).min(1).max(MAX_STATUS_BATCH_SUBJECTS),
}) satisfies z.ZodType<StatusBatchRequestV1>;

export const registryStatusV1Schema: ZodType<RegistryStatusV1> = z
  .strictObject({
    subject: nexusSubjectSchema,
    state: z.enum(['active', 'revoked']),
    sequence: safeNonNegativeIntegerSchema,
    registeredAt: safeNonNegativeIntegerSchema,
    revokedAt: safeNonNegativeIntegerSchema.nullable(),
    genesis: identityGenesisV1Schema,
    statusStatement: statusStatementV1Schema,
  })
  .superRefine((status, context) => {
    if (status.state === 'active' && (status.sequence !== 0 || status.revokedAt !== null)) {
      context.addIssue({ code: 'custom', message: 'Invalid active registry status.' });
    }
    if (status.state === 'revoked' && (status.sequence !== 1 || status.revokedAt === null)) {
      context.addIssue({ code: 'custom', message: 'Invalid revoked registry status.' });
    }
    const statement = status.statusStatement.payload;
    if (
      statement.subject !== status.subject ||
      statement.state !== status.state ||
      statement.sequence !== status.sequence ||
      statement.registeredAt !== status.registeredAt ||
      (statement.revokedAt ?? null) !== status.revokedAt
    ) {
      context.addIssue({
        code: 'custom',
        message: 'Status statement does not describe the enclosing registry status.',
        path: ['statusStatement'],
      });
    }
  }) satisfies z.ZodType<RegistryStatusV1>;

export const createIdentityResultSchema: ZodType<CreateIdentityResult> = z.strictObject({
  subject: nexusSubjectSchema,
  genesis: identityGenesisV1Schema,
  registrationReceipt: registryReceiptV1Schema.optional(),
}) satisfies z.ZodType<CreateIdentityResult>;

export const nexusErrorSchema: ZodType<NexusError> = z.strictObject({
  error: z.strictObject({
    code: z.enum(NEXUS_ERROR_CODES),
    message: z.string().min(1).max(1024),
    requestId: printableAscii(128).optional(),
  }),
}) satisfies z.ZodType<NexusError>;

export const transparencyShardIdSchema: ZodType<string> = z
  .string()
  .regex(/^[0-9a-f]{2}$/u, 'Transparency shard ID must be two lowercase hex digits.');

export const transparencyCheckpointPayloadV1Schema: ZodType<TransparencyCheckpointPayloadV1> =
  z.strictObject({
    protocol: z.literal(TRANSPARENCY_CHECKPOINT_PROTOCOL_V1),
    shardId: transparencyShardIdSchema,
    treeSize: safeNonNegativeIntegerSchema,
    rootHash: base64Url32Schema,
    checkpointedAt: safeNonNegativeIntegerSchema,
    signerKid: signerKidSchema,
  }) satisfies z.ZodType<TransparencyCheckpointPayloadV1>;

export const signedTransparencyCheckpointV1Schema: ZodType<SignedTransparencyCheckpointV1> =
  z.strictObject({
    payload: transparencyCheckpointPayloadV1Schema,
    signature: base64Url64Schema,
  }) satisfies z.ZodType<SignedTransparencyCheckpointV1>;

export const globalCheckpointShardV1Schema: ZodType<GlobalCheckpointShardV1> = z.strictObject({
  shardId: transparencyShardIdSchema,
  treeSize: safeNonNegativeIntegerSchema,
  rootHash: base64Url32Schema,
}) satisfies z.ZodType<GlobalCheckpointShardV1>;

export const globalTransparencyCheckpointPayloadV1Schema: ZodType<GlobalTransparencyCheckpointPayloadV1> =
  z
    .strictObject({
      protocol: z.literal(TRANSPARENCY_GLOBAL_CHECKPOINT_PROTOCOL_V1),
      checkpointedAt: safeNonNegativeIntegerSchema,
      shards: z.array(globalCheckpointShardV1Schema).length(TRANSPARENCY_SHARD_COUNT),
      signerKid: signerKidSchema,
    })
    .superRefine((payload, context) => {
      payload.shards.forEach((shard, index) => {
        const expectedShardId = index.toString(16).padStart(2, '0');
        if (shard.shardId !== expectedShardId) {
          context.addIssue({
            code: 'custom',
            message: `Global transparency shards must be complete and ordered; expected ${expectedShardId}.`,
            path: ['shards', index, 'shardId'],
          });
        }
      });
    }) satisfies z.ZodType<GlobalTransparencyCheckpointPayloadV1>;

export const signedGlobalTransparencyCheckpointV1Schema: ZodType<SignedGlobalTransparencyCheckpointV1> =
  z.strictObject({
    payload: globalTransparencyCheckpointPayloadV1Schema,
    signature: base64Url64Schema,
  }) satisfies z.ZodType<SignedGlobalTransparencyCheckpointV1>;

export const transparencyInclusionProofV1Schema: ZodType<TransparencyInclusionProofV1> = z
  .strictObject({
    protocol: z.literal(TRANSPARENCY_INCLUSION_PROOF_PROTOCOL_V1),
    eventHash: base64Url32Schema,
    shardId: transparencyShardIdSchema,
    leafIndex: safeNonNegativeIntegerSchema,
    treeSize: safeNonNegativeIntegerSchema,
    auditPath: z.array(base64Url32Schema).max(MAX_TRANSPARENCY_AUDIT_PATH_LENGTH),
    checkpoint: signedTransparencyCheckpointV1Schema,
  })
  .superRefine((proof, context) => {
    if (proof.treeSize < 1) {
      context.addIssue({
        code: 'custom',
        message: 'An inclusion proof tree must contain at least one leaf.',
        path: ['treeSize'],
      });
    }
    if (proof.leafIndex >= proof.treeSize) {
      context.addIssue({
        code: 'custom',
        message: 'leafIndex must be less than treeSize.',
        path: ['leafIndex'],
      });
    }
    if (proof.checkpoint.payload.shardId !== proof.shardId) {
      context.addIssue({
        code: 'custom',
        message: 'The checkpoint shard must match the inclusion proof shard.',
        path: ['checkpoint', 'payload', 'shardId'],
      });
    }
    if (proof.checkpoint.payload.treeSize !== proof.treeSize) {
      context.addIssue({
        code: 'custom',
        message: 'The checkpoint tree size must match the inclusion proof tree size.',
        path: ['checkpoint', 'payload', 'treeSize'],
      });
    }
  }) satisfies z.ZodType<TransparencyInclusionProofV1>;
