import { env } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';

import { verifyInclusionProof } from './merkle.js';
import type { TransparencyShard } from './transparency-shard-do.js';
import type { AppendResult, StoredCheckpoint, StoredInclusionProof } from './types.js';

interface TestEnv {
  TRANSPARENCY_SHARDS: DurableObjectNamespace<TransparencyShard>;
}

function isTestEnv(value: unknown): value is TestEnv {
  return typeof value === 'object' && value !== null && 'TRANSPARENCY_SHARDS' in value;
}

function requireTestEnv(value: unknown): TestEnv {
  if (!isTestEnv(value)) {
    throw new Error('The transparency Durable Object binding is unavailable.');
  }
  return value;
}

const testEnv = requireTestEnv(env);
const sha256 = async (value: Uint8Array): Promise<Uint8Array> => {
  const owned = new Uint8Array(value.byteLength);
  owned.set(value);
  return new Uint8Array(await crypto.subtle.digest('SHA-256', owned.buffer));
};

function eventHash(fill: number): Uint8Array {
  const value = new Uint8Array(32);
  value.fill(fill);
  value[0] = 0x01;
  return value;
}

function encode(value: Uint8Array): string {
  return btoa(String.fromCharCode(...value))
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replace(/=+$/u, '');
}

function decode(value: string): Uint8Array {
  const base64 = value.replaceAll('-', '+').replaceAll('_', '/');
  const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, '=');
  return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
}

async function post<T>(
  stub: DurableObjectStub<TransparencyShard>,
  path: string,
  body: unknown,
): Promise<T> {
  const response = await stub.fetch(`https://shard.test${path}`, {
    method: 'POST',
    body: JSON.stringify(body),
  });
  expect(response.ok).toBe(true);
  return response.json<T>();
}

describe('TransparencyShard SQLite Durable Object', () => {
  it('deduplicates appends and returns a locally verifiable hash-only proof', async () => {
    const shardId = '01';
    const stub = testEnv.TRANSPARENCY_SHARDS.getByName(`test-${shardId}`);
    const hashes = [eventHash(1), eventHash(2), eventHash(3)];

    const first = await post<AppendResult>(stub, '/internal/v1/append', {
      eventId: 'nxe1_first',
      eventHash: encode(hashes[0]!),
      shardId,
    });
    const duplicate = await post<AppendResult>(stub, '/internal/v1/append', {
      eventId: 'nxe1_first',
      eventHash: encode(hashes[0]!),
      shardId,
    });
    expect(first).toMatchObject({ leafIndex: 0, treeSize: 1, duplicate: false });
    expect(duplicate).toMatchObject({ leafIndex: 0, treeSize: 1, duplicate: true });

    for (let index = 1; index < hashes.length; index += 1) {
      await post<AppendResult>(stub, '/internal/v1/append', {
        eventId: `nxe1_event_${index}`,
        eventHash: encode(hashes[index]!),
        shardId,
      });
    }

    const checkpoint = await post<StoredCheckpoint>(stub, '/internal/v1/checkpoint', {
      shardId,
      checkpointedAt: 1_786_400_000,
    });
    const targetHash = encode(hashes[1]!);
    const proof = await post<StoredInclusionProof>(
      stub,
      `/internal/v1/inclusion?eventHash=${encodeURIComponent(targetHash)}`,
      { shardId, checkpointedAt: 1_786_400_001 },
    );

    expect(checkpoint).toMatchObject({ shardId, treeSize: 3 });
    expect(proof).not.toHaveProperty('subject');
    expect(proof).not.toHaveProperty('eventId');
    await expect(
      verifyInclusionProof(
        hashes[1]!,
        proof.leafIndex,
        proof.treeSize,
        proof.auditPath.map(decode),
        decode(proof.rootHash),
        sha256,
      ),
    ).resolves.toBe(true);
  });
});
