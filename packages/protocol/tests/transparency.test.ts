import { describe, expect, it } from 'vitest';

import {
  SIGNATURE_DOMAIN,
  TRANSPARENCY_CHECKPOINT_PROTOCOL,
  TRANSPARENCY_CHECKPOINT_PROTOCOL_V1,
  TRANSPARENCY_GLOBAL_CHECKPOINT_PROTOCOL,
  TRANSPARENCY_GLOBAL_CHECKPOINT_PROTOCOL_V1,
  TRANSPARENCY_INCLUSION_PROOF_PROTOCOL,
  TRANSPARENCY_INCLUSION_PROOF_PROTOCOL_V1,
  canonicalize,
  createGlobalTransparencyCheckpointSignaturePreimage,
  createSignaturePreimage,
  createTransparencyCheckpointSignaturePreimage,
  encodeBase64Url,
  globalTransparencyCheckpointPayloadV1Schema,
  signedGlobalTransparencyCheckpointV1Schema,
  signedTransparencyCheckpointV1Schema,
  transparencyCheckpointPayloadV1Schema,
  transparencyInclusionProofV1Schema,
  transparencyShardIdSchema,
} from '../src/index.js';
import type {
  Base64Url32,
  Base64Url64,
  GlobalCheckpointShardV1,
  GlobalTransparencyCheckpointPayloadV1,
  SignedTransparencyCheckpointV1,
  TransparencyCheckpointPayloadV1,
  TransparencyInclusionProofV1,
} from '../src/index.js';

const textDecoder = new TextDecoder();
const hash = encodeBase64Url(new Uint8Array(32).fill(0x42)) as Base64Url32;
const secondHash = encodeBase64Url(new Uint8Array(32).fill(0x24)) as Base64Url32;
const signature = encodeBase64Url(new Uint8Array(64).fill(0x19)) as Base64Url64;

const checkpointPayload: TransparencyCheckpointPayloadV1 = {
  protocol: TRANSPARENCY_CHECKPOINT_PROTOCOL_V1,
  shardId: '0a',
  treeSize: 3,
  rootHash: hash,
  checkpointedAt: 1_786_400_000,
  signerKid: 'transparency-2026-01',
};

const signedCheckpoint: SignedTransparencyCheckpointV1 = {
  payload: checkpointPayload,
  signature,
};

function allGlobalShards(): GlobalCheckpointShardV1[] {
  return Array.from({ length: 256 }, (_, index) => ({
    shardId: index.toString(16).padStart(2, '0'),
    treeSize: index,
    rootHash: index % 2 === 0 ? hash : secondHash,
  }));
}

const globalPayload: GlobalTransparencyCheckpointPayloadV1 = {
  protocol: TRANSPARENCY_GLOBAL_CHECKPOINT_PROTOCOL_V1,
  checkpointedAt: 1_786_400_001,
  shards: allGlobalShards(),
  signerKid: 'transparency-2026-01',
};

describe('transparency protocol constants and signature domains', () => {
  it('keeps compatibility aliases identical to the versioned constants', () => {
    expect(TRANSPARENCY_CHECKPOINT_PROTOCOL).toBe(TRANSPARENCY_CHECKPOINT_PROTOCOL_V1);
    expect(TRANSPARENCY_GLOBAL_CHECKPOINT_PROTOCOL).toBe(
      TRANSPARENCY_GLOBAL_CHECKPOINT_PROTOCOL_V1,
    );
    expect(TRANSPARENCY_INCLUSION_PROOF_PROTOCOL).toBe(TRANSPARENCY_INCLUSION_PROOF_PROTOCOL_V1);
  });

  it('builds an exact domain-separated direct-payload checkpoint preimage', () => {
    const preimage = createTransparencyCheckpointSignaturePreimage(checkpointPayload);
    expect(textDecoder.decode(preimage)).toBe(
      `${SIGNATURE_DOMAIN}${TRANSPARENCY_CHECKPOINT_PROTOCOL_V1}\0${canonicalize(checkpointPayload)}`,
    );
    expect(preimage).toEqual(
      createSignaturePreimage(TRANSPARENCY_CHECKPOINT_PROTOCOL_V1, checkpointPayload),
    );
  });

  it('uses the global protocol identifier for manifest signatures', () => {
    const globalPreimage = createGlobalTransparencyCheckpointSignaturePreimage(globalPayload);
    expect(globalPreimage).toEqual(
      createSignaturePreimage(TRANSPARENCY_GLOBAL_CHECKPOINT_PROTOCOL_V1, globalPayload),
    );
    expect(globalPreimage).not.toEqual(
      createTransparencyCheckpointSignaturePreimage(checkpointPayload),
    );
  });
});

describe('strict shard checkpoint schemas', () => {
  it('accepts a valid strict payload and signed envelope', () => {
    expect(transparencyCheckpointPayloadV1Schema.parse(checkpointPayload)).toEqual(
      checkpointPayload,
    );
    expect(signedTransparencyCheckpointV1Schema.parse(signedCheckpoint)).toEqual(signedCheckpoint);
  });

  it.each(['0a', '00', 'ff'])(`accepts the canonical shard ID %s`, (shardId) => {
    expect(transparencyShardIdSchema.safeParse(shardId).success).toBe(true);
  });

  it.each(['0A', 'a', '000', 'gg', '-1', ' 0'])(`rejects the shard ID %s`, (shardId) => {
    expect(transparencyShardIdSchema.safeParse(shardId).success).toBe(false);
  });

  it('rejects unknown keys, malformed hashes, signatures, times, sizes, and kids', () => {
    expect(
      transparencyCheckpointPayloadV1Schema.safeParse({ ...checkpointPayload, extra: true })
        .success,
    ).toBe(false);
    expect(
      transparencyCheckpointPayloadV1Schema.safeParse({
        ...checkpointPayload,
        rootHash: `${hash}=`,
      }).success,
    ).toBe(false);
    expect(
      signedTransparencyCheckpointV1Schema.safeParse({
        ...signedCheckpoint,
        signature: `${signature}=`,
      }).success,
    ).toBe(false);
    for (const checkpointedAt of [-1, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
      expect(
        transparencyCheckpointPayloadV1Schema.safeParse({
          ...checkpointPayload,
          checkpointedAt,
        }).success,
      ).toBe(false);
    }
    for (const treeSize of [-1, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
      expect(
        transparencyCheckpointPayloadV1Schema.safeParse({ ...checkpointPayload, treeSize }).success,
      ).toBe(false);
    }
    expect(
      transparencyCheckpointPayloadV1Schema.safeParse({
        ...checkpointPayload,
        signerKid: '',
      }).success,
    ).toBe(false);
    expect(
      transparencyCheckpointPayloadV1Schema.safeParse({
        ...checkpointPayload,
        signerKid: 'kid\n',
      }).success,
    ).toBe(false);
  });
});

describe('strict global transparency manifest schemas', () => {
  it('requires a complete canonical 00..ff shard manifest', () => {
    expect(globalTransparencyCheckpointPayloadV1Schema.safeParse(globalPayload).success).toBe(true);
    expect(
      signedGlobalTransparencyCheckpointV1Schema.safeParse({
        payload: globalPayload,
        signature,
      }).success,
    ).toBe(true);
  });

  it('rejects missing, duplicate, reordered, and unknown shard entries', () => {
    expect(
      globalTransparencyCheckpointPayloadV1Schema.safeParse({
        ...globalPayload,
        shards: globalPayload.shards.slice(0, -1),
      }).success,
    ).toBe(false);

    const duplicated = allGlobalShards();
    duplicated[1] = duplicated[0] as GlobalCheckpointShardV1;
    expect(
      globalTransparencyCheckpointPayloadV1Schema.safeParse({
        ...globalPayload,
        shards: duplicated,
      }).success,
    ).toBe(false);

    const reordered = allGlobalShards();
    [reordered[0], reordered[1]] = [
      reordered[1] as GlobalCheckpointShardV1,
      reordered[0] as GlobalCheckpointShardV1,
    ];
    expect(
      globalTransparencyCheckpointPayloadV1Schema.safeParse({
        ...globalPayload,
        shards: reordered,
      }).success,
    ).toBe(false);

    const unknownNested = allGlobalShards();
    unknownNested[0] = { ...unknownNested[0], extra: true } as GlobalCheckpointShardV1;
    expect(
      globalTransparencyCheckpointPayloadV1Schema.safeParse({
        ...globalPayload,
        shards: unknownNested,
      }).success,
    ).toBe(false);
  });
});

describe('strict transparency inclusion proof schema', () => {
  const proof: TransparencyInclusionProofV1 = {
    protocol: TRANSPARENCY_INCLUSION_PROOF_PROTOCOL_V1,
    eventHash: secondHash,
    shardId: '0a',
    leafIndex: 1,
    treeSize: 3,
    auditPath: [hash, secondHash],
    checkpoint: signedCheckpoint,
  };

  it('accepts a structurally consistent proof', () => {
    expect(transparencyInclusionProofV1Schema.parse(proof)).toEqual(proof);
  });

  it('rejects inconsistent tree, shard, leaf, path, and unknown fields', () => {
    expect(transparencyInclusionProofV1Schema.safeParse({ ...proof, treeSize: 0 }).success).toBe(
      false,
    );
    expect(transparencyInclusionProofV1Schema.safeParse({ ...proof, leafIndex: 3 }).success).toBe(
      false,
    );
    expect(transparencyInclusionProofV1Schema.safeParse({ ...proof, shardId: '0b' }).success).toBe(
      false,
    );
    expect(
      transparencyInclusionProofV1Schema.safeParse({
        ...proof,
        auditPath: Array.from({ length: 54 }, () => hash),
      }).success,
    ).toBe(false);
    expect(
      transparencyInclusionProofV1Schema.safeParse({ ...proof, unexpected: true }).success,
    ).toBe(false);
  });
});
