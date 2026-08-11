import { getDefaultCryptoProvider } from '@nexus/crypto';
import { describe, expect, it } from 'vitest';

import { verifyInclusionProof, verifyTransparencyInclusionProof } from './transparency.js';

const sha256 = async (value: Uint8Array): Promise<Uint8Array> =>
  getDefaultCryptoProvider().sha256(value);

function concat(...values: readonly Uint8Array[]): Uint8Array {
  const output = new Uint8Array(values.reduce((length, value) => length + value.byteLength, 0));
  let offset = 0;
  for (const value of values) {
    output.set(value, offset);
    offset += value.byteLength;
  }
  return output;
}

async function leafHash(value: Uint8Array): Promise<Uint8Array> {
  return sha256(concat(Uint8Array.of(0), value));
}

async function nodeHash(left: Uint8Array, right: Uint8Array): Promise<Uint8Array> {
  return sha256(concat(Uint8Array.of(1), left, right));
}

describe('RFC 6962 inclusion verification', () => {
  it('verifies both leaves of a two-leaf tree with the default hash', async () => {
    const first = new Uint8Array(32).fill(1);
    const second = new Uint8Array(32).fill(2);
    const firstLeaf = await leafHash(first);
    const secondLeaf = await leafHash(second);
    const root = await nodeHash(firstLeaf, secondLeaf);

    await expect(verifyInclusionProof(first, 0, 2, [secondLeaf], root)).resolves.toBe(true);
    await expect(
      verifyTransparencyInclusionProof({
        eventHash: second,
        leafIndex: 1,
        treeSize: 2,
        auditPath: [firstLeaf],
        expectedRoot: root,
      }),
    ).resolves.toBe(true);
  });

  it('rejects changed, truncated, extended, and malformed proofs', async () => {
    const first = new Uint8Array(32).fill(3);
    const second = new Uint8Array(32).fill(4);
    const firstLeaf = await leafHash(first);
    const secondLeaf = await leafHash(second);
    const root = await nodeHash(firstLeaf, secondLeaf);
    const changed = secondLeaf.slice();
    changed[0] = (changed[0] ?? 0) ^ 0xff;

    await expect(verifyInclusionProof(first, 0, 2, [changed], root)).resolves.toBe(false);
    await expect(verifyInclusionProof(first, 0, 2, [], root)).resolves.toBe(false);
    await expect(verifyInclusionProof(first, 0, 2, [secondLeaf, secondLeaf], root)).resolves.toBe(
      false,
    );
    await expect(verifyInclusionProof(first, 2, 2, [secondLeaf], root)).resolves.toBe(false);
    await expect(
      verifyInclusionProof(first.subarray(0, 31), 0, 2, [secondLeaf], root),
    ).resolves.toBe(false);
  });
});
