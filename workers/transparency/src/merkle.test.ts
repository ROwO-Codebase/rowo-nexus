import { describe, expect, it } from 'vitest';

import {
  hashLeaf,
  hashNode,
  inclusionProof,
  treeRoot,
  verifyInclusionProof,
  type HashFunction,
  type MerkleNodeReader,
} from './merkle.js';

const sha256: HashFunction = async (value) => {
  const owned = new Uint8Array(value.byteLength);
  owned.set(value);
  return new Uint8Array(await crypto.subtle.digest('SHA-256', owned.buffer));
};

class TestTree implements MerkleNodeReader {
  readonly nodes = new Map<string, Uint8Array>();
  size = 0;

  getNode(level: number, nodeIndex: number): Uint8Array | undefined {
    return this.nodes.get(`${level}:${nodeIndex}`);
  }

  async append(eventHash: Uint8Array): Promise<void> {
    let level = 0;
    let nodeIndex = this.size;
    let node = await hashLeaf(eventHash, sha256);
    this.nodes.set(`${level}:${nodeIndex}`, node);

    while (nodeIndex % 2 === 1) {
      const left = this.getNode(level, nodeIndex - 1);
      if (left === undefined) {
        throw new Error('Test tree is corrupt.');
      }
      node = await hashNode(left, node, sha256);
      nodeIndex = Math.floor(nodeIndex / 2);
      level += 1;
      this.nodes.set(`${level}:${nodeIndex}`, node);
    }
    this.size += 1;
  }
}

function eventHash(value: number): Uint8Array {
  const output = new Uint8Array(32);
  output.fill(value);
  return output;
}

function toHex(value: Uint8Array): string {
  return [...value].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

describe('RFC 6962-style Merkle tree', () => {
  it('matches a fixed SHA-256 leaf vector', async () => {
    await expect(hashLeaf(new Uint8Array(32), sha256).then(toHex)).resolves.toBe(
      '7f9c9e31ac8256ca2f258583df262dbc7d6f68f2a03043d5c99a4ae5a7396ce9',
    );
  });

  it('uses the RFC leaf and node prefixes', async () => {
    const first = eventHash(1);
    const second = eventHash(2);
    const tree = new TestTree();
    await tree.append(first);
    await tree.append(second);

    const expected = await hashNode(
      await hashLeaf(first, sha256),
      await hashLeaf(second, sha256),
      sha256,
    );
    await expect(treeRoot(tree, 2, sha256)).resolves.toEqual(expected);
  });

  it('builds locally verifiable proofs for unbalanced trees', async () => {
    const tree = new TestTree();
    const leaves = Array.from({ length: 7 }, (_, index) => eventHash(index + 1));
    for (const leaf of leaves) {
      await tree.append(leaf);
    }
    const root = await treeRoot(tree, tree.size, sha256);

    for (const [index, leaf] of leaves.entries()) {
      const path = await inclusionProof(tree, index, tree.size, sha256);
      await expect(verifyInclusionProof(leaf, index, tree.size, path, root, sha256)).resolves.toBe(
        true,
      );
    }
  });

  it('rejects a proof whose audit path was changed', async () => {
    const tree = new TestTree();
    const leaves = [eventHash(1), eventHash(2), eventHash(3)];
    for (const leaf of leaves) {
      await tree.append(leaf);
    }
    const root = await treeRoot(tree, tree.size, sha256);
    const path = await inclusionProof(tree, 1, tree.size, sha256);
    const changedPath = path.map((node) => node.slice());
    changedPath[0]?.fill(0xff);

    await expect(
      verifyInclusionProof(leaves[1]!, 1, tree.size, changedPath, root, sha256),
    ).resolves.toBe(false);
  });
});
