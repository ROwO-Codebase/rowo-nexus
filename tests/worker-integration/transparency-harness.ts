import { decodeBase64UrlExact, encodeBase64Url } from '@nexus/protocol';
import type {
  AppendResult,
  StoredCheckpoint,
  StoredInclusionProof,
} from '../../workers/transparency/src/types';
import {
  hashLeaf,
  hashNode,
  inclusionProof,
  treeRoot,
  type HashFunction,
  type MerkleNodeReader,
} from '../../workers/transparency/src/merkle';
import TransparencyService from '../../workers/transparency/src/index';
import type { TransparencyShard } from '../../workers/transparency/src/transparency-shard-do';

interface StoredEvent {
  eventId: string;
  eventHash: string;
  leafIndex: number;
}

interface InternalRequest {
  eventId?: string;
  eventHash?: string;
  shardId: string;
  checkpointedAt?: number;
}

const sha256: HashFunction = async (value) => {
  const owned = new Uint8Array(value.byteLength);
  owned.set(value);
  return new Uint8Array(await crypto.subtle.digest('SHA-256', owned.buffer));
};

class MemoryTransparencyShard implements MerkleNodeReader {
  readonly #eventsById = new Map<string, StoredEvent>();
  readonly #eventsByHash = new Map<string, StoredEvent>();
  readonly #nodes = new Map<string, Uint8Array>();
  readonly #checkpoints = new Map<number, StoredCheckpoint>();
  #size = 0;

  constructor(readonly shardId: string) {}

  getNode(level: number, nodeIndex: number): Uint8Array | undefined {
    return this.#nodes.get(`${level}:${nodeIndex}`);
  }

  async fetch(requestInput: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    const request =
      requestInput instanceof Request ? requestInput : new Request(requestInput, init);
    const url = new URL(request.url);
    const input = await request.json<InternalRequest>();
    if (input.shardId !== this.shardId) return jsonError('SHARD_CONFLICT', 409);

    if (url.pathname === '/internal/v1/append') {
      if (input.eventId === undefined || input.eventHash === undefined) {
        return jsonError('BAD_REQUEST', 400);
      }
      return Response.json(await this.#append(input.eventId, input.eventHash));
    }
    if (url.pathname === '/internal/v1/checkpoint') {
      return Response.json(await this.#checkpoint(input.checkpointedAt ?? 0));
    }
    if (url.pathname === '/internal/v1/inclusion') {
      const eventHash = url.searchParams.get('eventHash');
      if (eventHash === null) return jsonError('BAD_REQUEST', 400);
      return Response.json(await this.#prove(eventHash, input.checkpointedAt ?? 0));
    }
    return jsonError('NOT_FOUND', 404);
  }

  async #append(eventId: string, eventHash: string): Promise<AppendResult> {
    const hashBytes = decodeBase64UrlExact(eventHash, 32);
    const duplicate = this.#eventsById.get(eventId);
    if (duplicate !== undefined) {
      if (duplicate.eventHash !== eventHash) throw new Error('Conflicting transparency event ID.');
      return this.#appendResult(duplicate, true);
    }
    if (this.#eventsByHash.has(eventHash)) throw new Error('Conflicting transparency event hash.');

    let level = 0;
    let nodeIndex = this.#size;
    let node = await hashLeaf(hashBytes, sha256);
    this.#nodes.set(`${level}:${nodeIndex}`, node);
    while (nodeIndex % 2 === 1) {
      const left = this.getNode(level, nodeIndex - 1);
      if (left === undefined) throw new Error('The acceptance Merkle tree is corrupt.');
      node = await hashNode(left, node, sha256);
      nodeIndex = Math.floor(nodeIndex / 2);
      level += 1;
      this.#nodes.set(`${level}:${nodeIndex}`, node);
    }

    const stored = { eventId, eventHash, leafIndex: this.#size };
    this.#eventsById.set(eventId, stored);
    this.#eventsByHash.set(eventHash, stored);
    this.#size += 1;
    return this.#appendResult(stored, false);
  }

  #appendResult(event: StoredEvent, duplicate: boolean): AppendResult {
    return {
      eventId: event.eventId,
      eventHash: event.eventHash,
      shardId: this.shardId,
      leafIndex: event.leafIndex,
      treeSize: this.#size,
      duplicate,
    };
  }

  async #checkpoint(checkpointedAt: number): Promise<StoredCheckpoint> {
    const prior = this.#checkpoints.get(this.#size);
    if (prior !== undefined) return prior;
    const checkpoint = {
      shardId: this.shardId,
      treeSize: this.#size,
      rootHash: encodeBase64Url(await treeRoot(this, this.#size, sha256)),
      checkpointedAt,
    };
    this.#checkpoints.set(this.#size, checkpoint);
    return checkpoint;
  }

  async #prove(eventHash: string, checkpointedAt: number): Promise<StoredInclusionProof> {
    const event = this.#eventsByHash.get(eventHash);
    if (event === undefined) throw new Error('Transparency event not found.');
    const checkpoint = await this.#checkpoint(checkpointedAt);
    const auditPath = await inclusionProof(this, event.leafIndex, checkpoint.treeSize, sha256);
    return {
      ...checkpoint,
      eventHash,
      leafIndex: event.leafIndex,
      auditPath: auditPath.map(encodeBase64Url),
    };
  }
}

class MemoryTransparencyNamespace {
  readonly #shards = new Map<string, MemoryTransparencyShard>();

  idFromName(name: string): DurableObjectId {
    return name as unknown as DurableObjectId;
  }

  get(id: DurableObjectId): DurableObjectStub {
    const name = id as unknown as string;
    let shard = this.#shards.get(name);
    if (shard === undefined) {
      shard = new MemoryTransparencyShard(name);
      this.#shards.set(name, shard);
    }
    return shard as unknown as DurableObjectStub;
  }
}

function jsonError(code: string, status: number): Response {
  return Response.json({ error: { code, message: code } }, { status });
}

const TEST_PRIVATE_KEY_PKCS8 = 'MC4CAQAwBQYDK2VwBCIEIMWqjfQ_n4N77bdELzHct7Fm04U1B28JS4XOOi4LRFj3'; // gitleaks:allow -- fixed test-only Ed25519 fixture
const TEST_PUBLIC_KEY = '_FHNjmIYoaONpH7QAjDwWAgW7RO6MwOsXeuRFUiQgCU';

export function createAcceptanceTransparency(context: ExecutionContext): TransparencyService {
  return new TransparencyService(context, {
    TRANSPARENCY_SHARDS:
      new MemoryTransparencyNamespace() as unknown as DurableObjectNamespace<TransparencyShard>,
    TRANSPARENCY_ARTIFACTS: {} as R2Bucket,
    TRANSPARENCY_SIGNING_KEY_PKCS8_B64URL: TEST_PRIVATE_KEY_PKCS8,
    TRANSPARENCY_SIGNING_KID: 'acceptance-transparency',
    TRANSPARENCY_PUBLIC_KEYSET_JSON: JSON.stringify({
      keys: [
        {
          kty: 'OKP',
          crv: 'Ed25519',
          alg: 'EdDSA',
          kid: 'acceptance-transparency',
          x: TEST_PUBLIC_KEY,
          use: 'sig',
        },
      ],
    }),
  });
}
