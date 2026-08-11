import { constantTimeEqual, getDefaultCryptoProvider } from '@nexus/crypto';

const SHA256_BYTES = 32;
const LEAF_PREFIX = Uint8Array.of(0x00);
const NODE_PREFIX = Uint8Array.of(0x01);

export type HashFunction = (value: Uint8Array) => Promise<Uint8Array>;

export interface TransparencyInclusionProofInput {
  readonly eventHash: Uint8Array;
  readonly leafIndex: number;
  readonly treeSize: number;
  readonly auditPath: readonly Uint8Array[];
  readonly expectedRoot: Uint8Array;
}

function concatBytes(...values: readonly Uint8Array[]): Uint8Array {
  const length = values.reduce((total, value) => total + value.byteLength, 0);
  const output = new Uint8Array(length);
  let offset = 0;
  for (const value of values) {
    output.set(value, offset);
    offset += value.byteLength;
  }
  return output;
}

async function hashLeaf(eventHash: Uint8Array, hash: HashFunction): Promise<Uint8Array> {
  return hash(concatBytes(LEAF_PREFIX, eventHash));
}

async function hashNode(
  left: Uint8Array,
  right: Uint8Array,
  hash: HashFunction,
): Promise<Uint8Array> {
  return hash(concatBytes(NODE_PREFIX, left, right));
}

const defaultSha256: HashFunction = async (value) => getDefaultCryptoProvider().sha256(value);

/**
 * Verifies an RFC 6962-style Merkle inclusion proof. The positional signature
 * intentionally matches the transparency Worker utility, while the hash
 * function is optional for runtime-neutral consumers.
 */
export async function verifyInclusionProof(
  eventHash: Uint8Array,
  leafIndex: number,
  treeSize: number,
  auditPath: readonly Uint8Array[],
  expectedRoot: Uint8Array,
  hash: HashFunction = defaultSha256,
): Promise<boolean> {
  if (
    eventHash.byteLength !== SHA256_BYTES ||
    !Number.isSafeInteger(leafIndex) ||
    leafIndex < 0 ||
    !Number.isSafeInteger(treeSize) ||
    treeSize < 1 ||
    leafIndex >= treeSize ||
    expectedRoot.byteLength !== SHA256_BYTES
  ) {
    return false;
  }

  try {
    let node = await hashLeaf(eventHash, hash);
    if (node.byteLength !== SHA256_BYTES) return false;

    let index = leafIndex;
    let last = treeSize - 1;
    let pathIndex = 0;

    while (last > 0) {
      if (pathIndex >= auditPath.length) return false;
      const sibling = auditPath[pathIndex];
      if (sibling === undefined || sibling.byteLength !== SHA256_BYTES) {
        return false;
      }

      if ((index & 1) === 1 || index === last) {
        node = await hashNode(sibling, node, hash);
        while ((index & 1) === 0 && index !== 0) {
          index >>= 1;
          last >>= 1;
        }
      } else {
        node = await hashNode(node, sibling, hash);
      }

      if (node.byteLength !== SHA256_BYTES) return false;
      index >>= 1;
      last >>= 1;
      pathIndex += 1;
    }

    return pathIndex === auditPath.length && constantTimeEqual(node, expectedRoot);
  } catch {
    return false;
  }
}

export function verifyTransparencyInclusionProof(
  proof: TransparencyInclusionProofInput,
  hash: HashFunction = defaultSha256,
): Promise<boolean> {
  return verifyInclusionProof(
    proof.eventHash,
    proof.leafIndex,
    proof.treeSize,
    proof.auditPath,
    proof.expectedRoot,
    hash,
  );
}
