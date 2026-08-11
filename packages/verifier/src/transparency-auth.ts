import {
  TRANSPARENCY_CHECKPOINT_PROTOCOL_V1,
  TRANSPARENCY_GLOBAL_CHECKPOINT_PROTOCOL_V1,
  TRANSPARENCY_INCLUSION_PROOF_PROTOCOL_V1,
  decodeBase64UrlExact,
  signedGlobalTransparencyCheckpointV1Schema,
  signedTransparencyCheckpointV1Schema,
  transparencyInclusionProofV1Schema,
} from '@nexus/protocol';
import type {
  GlobalCheckpointShardV1,
  SignedGlobalTransparencyCheckpointV1,
  SignedTransparencyCheckpointV1,
  TransparencyInclusionProofV1,
} from '@nexus/protocol';

import { verificationError } from './errors.js';
import { assertClockInput, assertNonNegativeInteger, parseExternal } from './internal.js';
import { parseServiceKeyset, verifyServiceSignature } from './service-statements.js';
import { verifyInclusionProof } from './transparency.js';
import type {
  AuthenticatedInclusionProofExpectation,
  GlobalTransparencyCheckpointExpectation,
  TransparencyCheckpointExpectation,
  TransparencyFreshnessExpectation,
} from './types.js';

function validateFreshness(
  checkpointedAt: number,
  expected: TransparencyFreshnessExpectation,
): void {
  assertClockInput(expected.now, expected.maxClockSkewSeconds);
  assertNonNegativeInteger(expected.maxAgeSeconds);

  if (checkpointedAt > expected.now + expected.maxClockSkewSeconds) {
    throw verificationError('PROOF_NOT_YET_VALID');
  }
  if (expected.now > checkpointedAt + expected.maxAgeSeconds + expected.maxClockSkewSeconds) {
    throw verificationError('PROOF_EXPIRED');
  }
}

function checkSignerKid(actual: string, expected: string | undefined): void {
  if (expected !== undefined && actual !== expected) {
    throw verificationError('KEY_NOT_FOUND');
  }
}

function checkShardExpectation(
  actual: GlobalCheckpointShardV1,
  expected: GlobalCheckpointShardV1,
): void {
  if (actual.shardId !== expected.shardId) throw verificationError('WRONG_SHARD');
  if (actual.treeSize !== expected.treeSize) {
    throw verificationError('WRONG_TREE_SIZE');
  }
  if (actual.rootHash !== expected.rootHash) throw verificationError('WRONG_ROOT');
}

export async function verifyTransparencyCheckpoint(
  checkpoint: unknown,
  keyset: unknown,
  expected: TransparencyCheckpointExpectation,
): Promise<SignedTransparencyCheckpointV1> {
  const parsed = parseExternal(signedTransparencyCheckpointV1Schema, checkpoint, {
    protocols: [
      {
        path: ['payload', 'protocol'],
        expected: TRANSPARENCY_CHECKPOINT_PROTOCOL_V1,
      },
    ],
  });
  const parsedKeyset = parseServiceKeyset(keyset);

  await verifyServiceSignature(
    parsed.payload,
    parsed.signature,
    parsed.payload.signerKid,
    parsedKeyset,
  );
  validateFreshness(parsed.payload.checkpointedAt, expected);
  checkSignerKid(parsed.payload.signerKid, expected.signerKid);

  if (expected.shardId !== undefined && parsed.payload.shardId !== expected.shardId) {
    throw verificationError('WRONG_SHARD');
  }
  if (expected.treeSize !== undefined && parsed.payload.treeSize !== expected.treeSize) {
    throw verificationError('WRONG_TREE_SIZE');
  }
  if (expected.rootHash !== undefined && parsed.payload.rootHash !== expected.rootHash) {
    throw verificationError('WRONG_ROOT');
  }

  return parsed;
}

export async function verifyGlobalTransparencyCheckpoint(
  checkpoint: unknown,
  keyset: unknown,
  expected: GlobalTransparencyCheckpointExpectation,
): Promise<SignedGlobalTransparencyCheckpointV1> {
  const parsed = parseExternal(signedGlobalTransparencyCheckpointV1Schema, checkpoint, {
    protocols: [
      {
        path: ['payload', 'protocol'],
        expected: TRANSPARENCY_GLOBAL_CHECKPOINT_PROTOCOL_V1,
      },
    ],
  });
  const parsedKeyset = parseServiceKeyset(keyset);

  await verifyServiceSignature(
    parsed.payload,
    parsed.signature,
    parsed.payload.signerKid,
    parsedKeyset,
  );
  validateFreshness(parsed.payload.checkpointedAt, expected);
  checkSignerKid(parsed.payload.signerKid, expected.signerKid);

  if (expected.shards !== undefined) {
    if (parsed.payload.shards.length !== expected.shards.length) {
      throw verificationError('WRONG_MANIFEST');
    }
    for (let index = 0; index < expected.shards.length; index += 1) {
      const actualShard = parsed.payload.shards[index];
      const expectedShard = expected.shards[index];
      if (actualShard === undefined || expectedShard === undefined) {
        throw verificationError('WRONG_MANIFEST');
      }
      checkShardExpectation(actualShard, expectedShard);
    }
  }

  return parsed;
}

export const verifyTransparencyManifest = verifyGlobalTransparencyCheckpoint;

export async function verifyAuthenticatedInclusionProof(
  proof: unknown,
  keyset: unknown,
  expected: AuthenticatedInclusionProofExpectation,
): Promise<TransparencyInclusionProofV1> {
  const parsed = parseExternal(transparencyInclusionProofV1Schema, proof, {
    protocols: [
      {
        path: ['protocol'],
        expected: TRANSPARENCY_INCLUSION_PROOF_PROTOCOL_V1,
      },
      {
        path: ['checkpoint', 'payload', 'protocol'],
        expected: TRANSPARENCY_CHECKPOINT_PROTOCOL_V1,
      },
    ],
  });

  if (parsed.eventHash !== expected.eventHash) {
    throw verificationError('WRONG_EVENT_HASH');
  }
  if (parsed.shardId !== expected.shardId) throw verificationError('WRONG_SHARD');

  await verifyTransparencyCheckpoint(parsed.checkpoint, keyset, {
    now: expected.now,
    maxAgeSeconds: expected.maxAgeSeconds,
    maxClockSkewSeconds: expected.maxClockSkewSeconds,
    ...(expected.signerKid === undefined ? {} : { signerKid: expected.signerKid }),
    shardId: expected.shardId,
    ...(expected.treeSize === undefined ? {} : { treeSize: expected.treeSize }),
    ...(expected.rootHash === undefined ? {} : { rootHash: expected.rootHash }),
  });

  const included = await verifyInclusionProof(
    decodeBase64UrlExact(parsed.eventHash, 32),
    parsed.leafIndex,
    parsed.treeSize,
    parsed.auditPath.map((node) => decodeBase64UrlExact(node, 32)),
    decodeBase64UrlExact(parsed.checkpoint.payload.rootHash, 32),
  );
  if (!included) throw verificationError('INVALID_INCLUSION_PROOF');
  return parsed;
}
