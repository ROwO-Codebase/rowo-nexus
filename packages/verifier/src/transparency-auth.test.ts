import {
  TRANSPARENCY_CHECKPOINT_PROTOCOL_V1,
  TRANSPARENCY_GLOBAL_CHECKPOINT_PROTOCOL_V1,
  TRANSPARENCY_INCLUSION_PROOF_PROTOCOL_V1,
  encodeBase64Url,
} from '@nexus/protocol';
import type {
  Base64Url32,
  Base64Url64,
  GlobalCheckpointShardV1,
  GlobalTransparencyCheckpointPayloadV1,
  ServiceKeySet,
  TransparencyCheckpointPayloadV1,
  TransparencyInclusionProofV1,
} from '@nexus/protocol';
import { getDefaultCryptoProvider, signProtocolPayload } from '@nexus/crypto';
import { describe, expect, it } from 'vitest';

import type { NexusVerificationErrorCode } from './errors.js';
import {
  verifyAuthenticatedInclusionProof,
  verifyGlobalTransparencyCheckpoint,
  verifyTransparencyCheckpoint,
} from './transparency-auth.js';

const NOW = 1_800_000_000;

function encoded32(bytes: Uint8Array): Base64Url32 {
  return encodeBase64Url(bytes) as Base64Url32;
}

function encoded64(value: string): Base64Url64 {
  return value as Base64Url64;
}

function concat(...values: readonly Uint8Array[]): Uint8Array {
  const output = new Uint8Array(values.reduce((length, value) => length + value.byteLength, 0));
  let offset = 0;
  for (const value of values) {
    output.set(value, offset);
    offset += value.byteLength;
  }
  return output;
}

async function sha256(value: Uint8Array): Promise<Uint8Array> {
  return getDefaultCryptoProvider().sha256(value);
}

async function leafHash(value: Uint8Array): Promise<Uint8Array> {
  return sha256(concat(Uint8Array.of(0), value));
}

async function nodeHash(left: Uint8Array, right: Uint8Array): Promise<Uint8Array> {
  return sha256(concat(Uint8Array.of(1), left, right));
}

async function serviceKey(seed: number) {
  const provider = getDefaultCryptoProvider();
  const pair = await provider.generateEd25519KeyPair({ privateKeyExtractable: true });
  const raw = await provider.exportEd25519PublicKey(pair.publicKey);
  const kid = `transparency-${seed}`;
  const keyset: ServiceKeySet = {
    keys: [
      {
        kty: 'OKP',
        crv: 'Ed25519',
        alg: 'EdDSA',
        kid,
        x: encoded32(raw),
        use: 'sig',
      },
    ],
  };
  return { pair, kid, keyset };
}

async function expectCode(
  operation: Promise<unknown>,
  code: NexusVerificationErrorCode,
): Promise<void> {
  await expect(operation).rejects.toMatchObject({ code });
}

async function checkpointFixture() {
  const service = await serviceKey(1);
  const first = new Uint8Array(32).fill(1);
  const second = new Uint8Array(32).fill(2);
  const firstLeaf = await leafHash(first);
  const secondLeaf = await leafHash(second);
  const root = await nodeHash(firstLeaf, secondLeaf);
  const payload: TransparencyCheckpointPayloadV1 = {
    protocol: TRANSPARENCY_CHECKPOINT_PROTOCOL_V1,
    shardId: '00',
    treeSize: 2,
    rootHash: encoded32(root),
    checkpointedAt: NOW,
    signerKid: service.kid,
  };
  const checkpoint = {
    payload,
    signature: encoded64(await signProtocolPayload(payload, service.pair.privateKey)),
  };
  const proof: TransparencyInclusionProofV1 = {
    protocol: TRANSPARENCY_INCLUSION_PROOF_PROTOCOL_V1,
    eventHash: encoded32(first),
    shardId: '00',
    leafIndex: 0,
    treeSize: 2,
    auditPath: [encoded32(secondLeaf)],
    checkpoint,
  };
  return { checkpoint, first, proof, root, secondLeaf, service };
}

const freshness = {
  now: NOW,
  maxAgeSeconds: 3_600,
  maxClockSkewSeconds: 5,
};

describe('authenticated transparency checkpoint verification', () => {
  it('verifies signature, signer, structure, expectations, and freshness', async () => {
    const fixture = await checkpointFixture();
    await expect(
      verifyTransparencyCheckpoint(fixture.checkpoint, fixture.service.keyset, {
        ...freshness,
        signerKid: fixture.service.kid,
        shardId: '00',
        treeSize: 2,
        rootHash: encoded32(fixture.root),
      }),
    ).resolves.toEqual(fixture.checkpoint);
  });

  it('rejects wrong kid, key, signature, purpose, shard, root, expiry, and malformed input', async () => {
    const fixture = await checkpointFixture();
    const other = await serviceKey(2);

    await expectCode(
      verifyTransparencyCheckpoint(fixture.checkpoint, other.keyset, freshness),
      'KEY_NOT_FOUND',
    );
    await expectCode(
      verifyTransparencyCheckpoint(
        fixture.checkpoint,
        {
          keys: other.keyset.keys.map((key) => ({ ...key, kid: fixture.service.kid })),
        },
        freshness,
      ),
      'INVALID_SIGNATURE',
    );
    await expectCode(
      verifyTransparencyCheckpoint(
        { ...fixture.checkpoint, signature: encoded64('A'.repeat(86)) },
        fixture.service.keyset,
        freshness,
      ),
      'INVALID_SIGNATURE',
    );
    await expectCode(
      verifyTransparencyCheckpoint(
        fixture.checkpoint,
        { keys: fixture.service.keyset.keys.map((key) => ({ ...key, use: 'enc' })) },
        freshness,
      ),
      'KEY_PURPOSE_MISMATCH',
    );
    await expectCode(
      verifyTransparencyCheckpoint(fixture.checkpoint, fixture.service.keyset, {
        ...freshness,
        shardId: '01',
      }),
      'WRONG_SHARD',
    );
    await expectCode(
      verifyTransparencyCheckpoint(fixture.checkpoint, fixture.service.keyset, {
        ...freshness,
        rootHash: encoded32(new Uint8Array(32).fill(9)),
      }),
      'WRONG_ROOT',
    );
    await expectCode(
      verifyTransparencyCheckpoint(fixture.checkpoint, fixture.service.keyset, {
        ...freshness,
        now: NOW + 3_606,
      }),
      'PROOF_EXPIRED',
    );
    await expectCode(
      verifyTransparencyCheckpoint(
        { ...fixture.checkpoint, unexpected: true },
        fixture.service.keyset,
        freshness,
      ),
      'BAD_REQUEST',
    );
  });
});

describe('global transparency manifest verification', () => {
  it('authenticates all 256 ordered shard roots and exact expectations', async () => {
    const service = await serviceKey(3);
    const shards: GlobalCheckpointShardV1[] = Array.from({ length: 256 }, (_, index) => ({
      shardId: index.toString(16).padStart(2, '0'),
      treeSize: index,
      rootHash: encoded32(new Uint8Array(32).fill(index)),
    }));
    const payload: GlobalTransparencyCheckpointPayloadV1 = {
      protocol: TRANSPARENCY_GLOBAL_CHECKPOINT_PROTOCOL_V1,
      checkpointedAt: NOW,
      shards,
      signerKid: service.kid,
    };
    const manifest = {
      payload,
      signature: encoded64(await signProtocolPayload(payload, service.pair.privateKey)),
    };

    await expect(
      verifyGlobalTransparencyCheckpoint(manifest, service.keyset, {
        ...freshness,
        shards,
      }),
    ).resolves.toEqual(manifest);

    const wrongExpected = shards.map((shard) => ({ ...shard }));
    wrongExpected[42] = {
      ...wrongExpected[42]!,
      rootHash: encoded32(new Uint8Array(32).fill(250)),
    };
    await expectCode(
      verifyGlobalTransparencyCheckpoint(manifest, service.keyset, {
        ...freshness,
        shards: wrongExpected,
      }),
      'WRONG_ROOT',
    );

    await expectCode(
      verifyGlobalTransparencyCheckpoint(
        { ...manifest, payload: { ...payload, shards: shards.slice().reverse() } },
        service.keyset,
        freshness,
      ),
      'BAD_REQUEST',
    );
  });
});

describe('authenticated inclusion proof composition', () => {
  it('authenticates the checkpoint then verifies RFC 6962 inclusion', async () => {
    const fixture = await checkpointFixture();
    await expect(
      verifyAuthenticatedInclusionProof(fixture.proof, fixture.service.keyset, {
        ...freshness,
        eventHash: encoded32(fixture.first),
        shardId: '00',
        treeSize: 2,
        rootHash: encoded32(fixture.root),
      }),
    ).resolves.toEqual(fixture.proof);
  });

  it('rejects wrong expectations and a malformed Merkle path under a valid checkpoint', async () => {
    const fixture = await checkpointFixture();
    await expectCode(
      verifyAuthenticatedInclusionProof(fixture.proof, fixture.service.keyset, {
        ...freshness,
        eventHash: encoded32(fixture.first),
        shardId: '01',
      }),
      'WRONG_SHARD',
    );
    await expectCode(
      verifyAuthenticatedInclusionProof(
        {
          ...fixture.proof,
          auditPath: [encoded32(new Uint8Array(32).fill(99))],
        },
        fixture.service.keyset,
        {
          ...freshness,
          eventHash: encoded32(fixture.first),
          shardId: '00',
        },
      ),
      'INVALID_INCLUSION_PROOF',
    );
  });
});
