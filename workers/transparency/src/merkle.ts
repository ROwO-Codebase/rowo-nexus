const LEAF_PREFIX = Uint8Array.of(0x00);
const NODE_PREFIX = Uint8Array.of(0x01);

export type HashFunction = (value: Uint8Array) => Promise<Uint8Array>;

export interface MerkleNodeReader {
  getNode(level: number, nodeIndex: number): Uint8Array | undefined;
}

export function concatBytes(...values: readonly Uint8Array[]): Uint8Array {
  const length = values.reduce((total, value) => total + value.byteLength, 0);
  const output = new Uint8Array(length);
  let offset = 0;
  for (const value of values) {
    output.set(value, offset);
    offset += value.byteLength;
  }
  return output;
}

export async function hashLeaf(eventHash: Uint8Array, hash: HashFunction): Promise<Uint8Array> {
  if (eventHash.byteLength !== 32) {
    throw new Error('A transparency event hash must be exactly 32 bytes.');
  }
  return hash(concatBytes(LEAF_PREFIX, eventHash));
}

export async function hashNode(
  left: Uint8Array,
  right: Uint8Array,
  hash: HashFunction,
): Promise<Uint8Array> {
  if (left.byteLength !== 32 || right.byteLength !== 32) {
    throw new Error('Merkle child hashes must be exactly 32 bytes.');
  }
  return hash(concatBytes(NODE_PREFIX, left, right));
}

export async function emptyRoot(hash: HashFunction): Promise<Uint8Array> {
  return hash(new Uint8Array());
}

export function largestPowerOfTwoLessThan(value: number): number {
  if (!Number.isSafeInteger(value) || value <= 1) {
    throw new Error('Value must be a safe integer greater than one.');
  }

  let power = 1;
  while (power * 2 < value) {
    power *= 2;
  }
  return power;
}

function exactLog2(value: number): number {
  const logarithm = Math.log2(value);
  if (!Number.isSafeInteger(value) || value < 1 || !Number.isInteger(logarithm)) {
    throw new Error('Value must be a positive power of two.');
  }
  return logarithm;
}

export async function subtreeRoot(
  reader: MerkleNodeReader,
  start: number,
  size: number,
  hash: HashFunction,
): Promise<Uint8Array> {
  if (!Number.isSafeInteger(start) || start < 0) {
    throw new Error('Subtree start must be a non-negative safe integer.');
  }
  if (!Number.isSafeInteger(size) || size < 1) {
    throw new Error('Subtree size must be a positive safe integer.');
  }

  if (Number.isInteger(Math.log2(size)) && start % size === 0) {
    const level = exactLog2(size);
    const stored = reader.getNode(level, start / size);
    if (stored === undefined) {
      throw new Error(`Missing Merkle node at level ${level}, index ${start / size}.`);
    }
    return stored;
  }

  const split = largestPowerOfTwoLessThan(size);
  const left = await subtreeRoot(reader, start, split, hash);
  const right = await subtreeRoot(reader, start + split, size - split, hash);
  return hashNode(left, right, hash);
}

export async function treeRoot(
  reader: MerkleNodeReader,
  treeSize: number,
  hash: HashFunction,
): Promise<Uint8Array> {
  if (!Number.isSafeInteger(treeSize) || treeSize < 0) {
    throw new Error('Tree size must be a non-negative safe integer.');
  }
  return treeSize === 0 ? emptyRoot(hash) : subtreeRoot(reader, 0, treeSize, hash);
}

export async function inclusionProof(
  reader: MerkleNodeReader,
  leafIndex: number,
  treeSize: number,
  hash: HashFunction,
): Promise<Uint8Array[]> {
  if (
    !Number.isSafeInteger(leafIndex) ||
    leafIndex < 0 ||
    !Number.isSafeInteger(treeSize) ||
    treeSize < 1 ||
    leafIndex >= treeSize
  ) {
    throw new Error('Leaf index must address an existing tree leaf.');
  }

  return inclusionProofForRange(reader, leafIndex, 0, treeSize, hash);
}

async function inclusionProofForRange(
  reader: MerkleNodeReader,
  leafIndex: number,
  start: number,
  size: number,
  hash: HashFunction,
): Promise<Uint8Array[]> {
  if (size === 1) {
    return [];
  }

  const split = largestPowerOfTwoLessThan(size);
  if (leafIndex < start + split) {
    const path = await inclusionProofForRange(reader, leafIndex, start, split, hash);
    path.push(await subtreeRoot(reader, start + split, size - split, hash));
    return path;
  }

  const path = await inclusionProofForRange(reader, leafIndex, start + split, size - split, hash);
  path.push(await subtreeRoot(reader, start, split, hash));
  return path;
}

export async function verifyInclusionProof(
  eventHash: Uint8Array,
  leafIndex: number,
  treeSize: number,
  auditPath: readonly Uint8Array[],
  expectedRoot: Uint8Array,
  hash: HashFunction,
): Promise<boolean> {
  if (
    !Number.isSafeInteger(leafIndex) ||
    leafIndex < 0 ||
    !Number.isSafeInteger(treeSize) ||
    treeSize < 1 ||
    leafIndex >= treeSize ||
    expectedRoot.byteLength !== 32
  ) {
    return false;
  }

  let node = await hashLeaf(eventHash, hash);
  let index = leafIndex;
  let last = treeSize - 1;
  let pathIndex = 0;

  while (last > 0) {
    if (pathIndex >= auditPath.length) {
      return false;
    }
    const sibling = auditPath[pathIndex];
    if (sibling === undefined || sibling.byteLength !== 32) {
      return false;
    }

    if (index % 2 === 1 || index === last) {
      node = await hashNode(sibling, node, hash);
      while (index % 2 === 0 && index !== 0) {
        index = Math.floor(index / 2);
        last = Math.floor(last / 2);
      }
    } else {
      node = await hashNode(node, sibling, hash);
    }

    index = Math.floor(index / 2);
    last = Math.floor(last / 2);
    pathIndex += 1;
  }

  return pathIndex === auditPath.length && equalBytes(node, expectedRoot);
}

export function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) {
    return false;
  }
  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return difference === 0;
}
