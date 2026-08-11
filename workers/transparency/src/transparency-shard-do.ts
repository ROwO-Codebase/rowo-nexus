import { DurableObject } from 'cloudflare:workers';
import { WebCryptoProvider } from '@nexus/crypto';
import { decodeBase64UrlExact, encodeBase64Url } from '@nexus/protocol';

import { badRequest, notFound, TransparencyError } from './errors.js';
import { errorResponse, jsonResponse, readSmallJson } from './http.js';
import {
  hashLeaf,
  hashNode,
  inclusionProof,
  treeRoot,
  type HashFunction,
  type MerkleNodeReader,
} from './merkle.js';
import { isShardId, resolveShardId } from './sharding.js';
import type {
  AppendResult,
  DurableAppendRequest,
  DurableCheckpointRequest,
  StoredCheckpoint,
  StoredInclusionProof,
} from './types.js';

type Env = Record<string, never>;

interface EventRow extends Record<string, SqlStorageValue> {
  event_id: string;
  event_hash: string;
  leaf_index: number;
}

interface MetaRow extends Record<string, SqlStorageValue> {
  tree_size: number;
  shard_id: string | null;
}

interface NodeRow extends Record<string, SqlStorageValue> {
  hash: ArrayBuffer;
}

interface CheckpointRow extends Record<string, SqlStorageValue> {
  tree_size: number;
  root_hash: string;
  checkpointed_at: number;
}

interface PendingNode {
  level: number;
  nodeIndex: number;
  hash: Uint8Array;
}

const INTERNAL_APPEND_PATH = '/internal/v1/append';
const INTERNAL_CHECKPOINT_PATH = '/internal/v1/checkpoint';
const INTERNAL_INCLUSION_PATH = '/internal/v1/inclusion';

export class TransparencyShard extends DurableObject<Env> implements MerkleNodeReader {
  private appendTail: Promise<void> = Promise.resolve();
  private readonly provider = new WebCryptoProvider();
  private readonly hash: HashFunction = async (value) => this.provider.sha256(value);

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    void this.ctx.blockConcurrencyWhile(() => {
      this.applySchemaMigrations();
      return Promise.resolve();
    });
  }

  override async fetch(request: Request): Promise<Response> {
    try {
      const url = new URL(request.url);
      if (request.method === 'POST' && url.pathname === INTERNAL_APPEND_PATH) {
        const input = parseDurableAppendRequest(await readSmallJson(request, 2048));
        return jsonResponse(await this.serializeAppend(() => this.append(input)));
      }
      if (request.method === 'POST' && url.pathname === INTERNAL_CHECKPOINT_PATH) {
        const input = parseDurableCheckpointRequest(await readSmallJson(request));
        return jsonResponse(await this.checkpoint(input));
      }
      if (request.method === 'POST' && url.pathname === INTERNAL_INCLUSION_PATH) {
        const input = parseDurableCheckpointRequest(await readSmallJson(request));
        const eventHash = url.searchParams.get('eventHash');
        if (eventHash === null) {
          throw badRequest('An internal event hash is required.');
        }
        return jsonResponse(await this.prove(input, eventHash));
      }
      throw new TransparencyError('NOT_FOUND', 'No such transparency operation.', 404);
    } catch (error) {
      return errorResponse(error);
    }
  }

  getNode(level: number, nodeIndex: number): Uint8Array | undefined {
    const row = this.ctx.storage.sql
      .exec<NodeRow>(
        'SELECT hash FROM transparency_nodes WHERE level = ? AND node_index = ?',
        level,
        nodeIndex,
      )
      .toArray()[0];
    return row === undefined ? undefined : new Uint8Array(row.hash);
  }

  private async serializeAppend<T>(operation: () => Promise<T>): Promise<T> {
    const previous = this.appendTail;
    let release!: () => void;
    this.appendTail = new Promise<void>((resolve) => {
      release = resolve;
    });
    await previous;
    try {
      return await operation();
    } finally {
      release();
    }
  }

  private async append(input: DurableAppendRequest): Promise<AppendResult> {
    const eventHashBytes = decodeEventHash(input.eventHash);
    if (resolveShardId(eventHashBytes) !== input.shardId) {
      throw badRequest('The event hash does not belong to the requested shard.');
    }

    const duplicate = this.findEvent(input.eventId);
    if (duplicate !== undefined) {
      if (duplicate.event_hash !== input.eventHash) {
        throw new TransparencyError(
          'EVENT_ID_CONFLICT',
          'The event ID already identifies a different hash.',
          409,
        );
      }
      return this.appendResult(duplicate, input.shardId, true);
    }

    const hashCollision = this.findEventByHash(input.eventHash);
    if (hashCollision !== undefined) {
      throw new TransparencyError(
        'EVENT_HASH_CONFLICT',
        'The event hash already identifies a different event ID.',
        409,
      );
    }

    const meta = this.readMeta();
    this.assertShard(meta.shard_id, input.shardId);
    const leafIndex = meta.tree_size;
    const pendingNodes = await this.computeAppendNodes(leafIndex, eventHashBytes);

    this.ctx.storage.transactionSync(() => {
      this.ctx.storage.sql.exec(
        `INSERT INTO transparency_events (event_id, event_hash, leaf_index)
         VALUES (?, ?, ?)`,
        input.eventId,
        input.eventHash,
        leafIndex,
      );
      for (const node of pendingNodes) {
        this.ctx.storage.sql.exec(
          `INSERT INTO transparency_nodes (level, node_index, hash)
           VALUES (?, ?, ?)`,
          node.level,
          node.nodeIndex,
          node.hash,
        );
      }
      this.ctx.storage.sql.exec(
        `UPDATE transparency_meta
         SET tree_size = ?, shard_id = COALESCE(shard_id, ?)
         WHERE singleton = 1`,
        leafIndex + 1,
        input.shardId,
      );
    });

    return {
      eventId: input.eventId,
      eventHash: input.eventHash,
      shardId: input.shardId,
      leafIndex,
      treeSize: leafIndex + 1,
      duplicate: false,
    };
  }

  private async checkpoint(input: DurableCheckpointRequest): Promise<StoredCheckpoint> {
    const meta = this.readMeta();
    this.assertShard(meta.shard_id, input.shardId);
    const existing = this.findCheckpoint(meta.tree_size);
    if (existing !== undefined) {
      return checkpointFromRow(input.shardId, existing);
    }

    const root = encodeBase64Url(await treeRoot(this, meta.tree_size, this.hash));
    this.ctx.storage.transactionSync(() => {
      this.ctx.storage.sql.exec(
        `INSERT OR IGNORE INTO transparency_checkpoints
           (tree_size, root_hash, checkpointed_at)
         VALUES (?, ?, ?)`,
        meta.tree_size,
        root,
        input.checkpointedAt,
      );
    });
    const stored = this.findCheckpoint(meta.tree_size);
    if (stored === undefined) {
      throw new Error('The checkpoint could not be stored.');
    }
    return checkpointFromRow(input.shardId, stored);
  }

  private async prove(
    input: DurableCheckpointRequest,
    eventHash: string,
  ): Promise<StoredInclusionProof> {
    decodeEventHash(eventHash);
    const event = this.findEventByHash(eventHash);
    if (event === undefined) {
      throw notFound('The event hash is not present in this transparency shard.');
    }
    const checkpoint = await this.checkpoint(input);
    const path = await inclusionProof(this, event.leaf_index, checkpoint.treeSize, this.hash);
    return {
      ...checkpoint,
      eventHash,
      leafIndex: event.leaf_index,
      auditPath: path.map(encodeBase64Url),
    };
  }

  private async computeAppendNodes(
    leafIndex: number,
    eventHash: Uint8Array,
  ): Promise<PendingNode[]> {
    const nodes: PendingNode[] = [];
    let level = 0;
    let nodeIndex = leafIndex;
    let node = await hashLeaf(eventHash, this.hash);
    nodes.push({ level, nodeIndex, hash: node });

    while (nodeIndex % 2 === 1) {
      const left = this.getNode(level, nodeIndex - 1);
      if (left === undefined) {
        throw new Error('The transparency tree is missing an append frontier node.');
      }
      node = await hashNode(left, node, this.hash);
      nodeIndex = Math.floor(nodeIndex / 2);
      level += 1;
      nodes.push({ level, nodeIndex, hash: node });
    }
    return nodes;
  }

  private appendResult(row: EventRow, shardId: string, duplicate: boolean): AppendResult {
    return {
      eventId: row.event_id,
      eventHash: row.event_hash,
      shardId,
      leafIndex: row.leaf_index,
      treeSize: this.readMeta().tree_size,
      duplicate,
    };
  }

  private findEvent(eventId: string): EventRow | undefined {
    return this.ctx.storage.sql
      .exec<EventRow>(
        `SELECT event_id, event_hash, leaf_index
         FROM transparency_events WHERE event_id = ?`,
        eventId,
      )
      .toArray()[0];
  }

  private findEventByHash(eventHash: string): EventRow | undefined {
    return this.ctx.storage.sql
      .exec<EventRow>(
        `SELECT event_id, event_hash, leaf_index
         FROM transparency_events WHERE event_hash = ?`,
        eventHash,
      )
      .toArray()[0];
  }

  private findCheckpoint(treeSize: number): CheckpointRow | undefined {
    return this.ctx.storage.sql
      .exec<CheckpointRow>(
        `SELECT tree_size, root_hash, checkpointed_at
         FROM transparency_checkpoints WHERE tree_size = ?`,
        treeSize,
      )
      .toArray()[0];
  }

  private readMeta(): MetaRow {
    const meta = this.ctx.storage.sql
      .exec<MetaRow>('SELECT tree_size, shard_id FROM transparency_meta WHERE singleton = 1')
      .toArray()[0];
    if (meta === undefined) {
      throw new Error('Transparency metadata is unavailable.');
    }
    return meta;
  }

  private assertShard(storedShardId: string | null, requestedShardId: string): void {
    if (!isShardId(requestedShardId)) {
      throw badRequest('The shard ID is not canonical.');
    }
    if (storedShardId !== null && storedShardId !== requestedShardId) {
      throw new TransparencyError(
        'SHARD_CONFLICT',
        'The Durable Object is already assigned to another shard.',
        409,
      );
    }
  }

  private applySchemaMigrations(): void {
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS _sql_schema_migrations (
        version INTEGER PRIMARY KEY,
        applied_at INTEGER NOT NULL
      );
    `);
    const current =
      this.ctx.storage.sql
        .exec<{ version: number }>(
          'SELECT version FROM _sql_schema_migrations ORDER BY version DESC LIMIT 1',
        )
        .toArray()[0]?.version ?? 0;
    if (current > 1) {
      throw new Error('The transparency schema is newer than this Worker understands.');
    }
    if (current === 1) {
      return;
    }

    this.ctx.storage.transactionSync(() => {
      this.ctx.storage.sql.exec(`
        CREATE TABLE transparency_meta (
          singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
          tree_size INTEGER NOT NULL CHECK (tree_size >= 0),
          shard_id TEXT
        );
        INSERT INTO transparency_meta (singleton, tree_size, shard_id)
        VALUES (1, 0, NULL);
        CREATE TABLE transparency_events (
          event_id TEXT PRIMARY KEY,
          event_hash TEXT NOT NULL UNIQUE,
          leaf_index INTEGER NOT NULL UNIQUE CHECK (leaf_index >= 0)
        );
        CREATE TABLE transparency_nodes (
          level INTEGER NOT NULL CHECK (level >= 0),
          node_index INTEGER NOT NULL CHECK (node_index >= 0),
          hash BLOB NOT NULL,
          PRIMARY KEY (level, node_index)
        );
        CREATE TABLE transparency_checkpoints (
          tree_size INTEGER PRIMARY KEY CHECK (tree_size >= 0),
          root_hash TEXT NOT NULL,
          checkpointed_at INTEGER NOT NULL CHECK (checkpointed_at >= 0)
        );
      `);
      this.ctx.storage.sql.exec(
        'INSERT INTO _sql_schema_migrations (version, applied_at) VALUES (1, ?)',
        Math.floor(Date.now() / 1000),
      );
    });
  }
}

function checkpointFromRow(shardId: string, row: CheckpointRow): StoredCheckpoint {
  return {
    shardId,
    treeSize: row.tree_size,
    rootHash: row.root_hash,
    checkpointedAt: row.checkpointed_at,
  };
}

function parseDurableAppendRequest(input: unknown): DurableAppendRequest {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) {
    throw badRequest('The append request must be an object.');
  }
  const value = input as Record<string, unknown>;
  const expected = ['eventHash', 'eventId', 'shardId'];
  if (
    Object.keys(value).length !== expected.length ||
    expected.some((key) => typeof value[key] !== 'string')
  ) {
    throw badRequest('The append request fields are invalid.');
  }
  return {
    eventId: value.eventId as string,
    eventHash: value.eventHash as string,
    shardId: value.shardId as string,
  };
}

function parseDurableCheckpointRequest(input: unknown): DurableCheckpointRequest {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) {
    throw badRequest('The checkpoint request must be an object.');
  }
  const value = input as Record<string, unknown>;
  if (
    Object.keys(value).length !== 2 ||
    typeof value.shardId !== 'string' ||
    !Number.isSafeInteger(value.checkpointedAt) ||
    (value.checkpointedAt as number) < 0
  ) {
    throw badRequest('The checkpoint request fields are invalid.');
  }
  return {
    shardId: value.shardId,
    checkpointedAt: value.checkpointedAt as number,
  };
}

function decodeEventHash(value: string): Uint8Array {
  try {
    return decodeBase64UrlExact(value, 32);
  } catch {
    throw badRequest('The event hash must be canonical unpadded base64url for 32 bytes.');
  }
}
