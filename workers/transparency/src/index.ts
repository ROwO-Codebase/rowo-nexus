import { WorkerEntrypoint } from 'cloudflare:workers';
import {
  decodeBase64Url,
  decodeBase64UrlExact,
  encodeBase64Url,
  globalTransparencyCheckpointPayloadV1Schema,
  registryEventV1Schema,
  signedGlobalTransparencyCheckpointV1Schema,
  signedTransparencyCheckpointV1Schema,
  TRANSPARENCY_CHECKPOINT_PROTOCOL,
  TRANSPARENCY_GLOBAL_CHECKPOINT_PROTOCOL,
  TRANSPARENCY_INCLUSION_PROOF_PROTOCOL,
  transparencyCheckpointPayloadV1Schema,
  transparencyInclusionProofV1Schema,
  type RegistryEventV1,
  type ServiceKeySet,
  type SignedGlobalTransparencyCheckpointV1,
  type SignedTransparencyCheckpointV1,
  type TransparencyInclusionProofV1,
} from '@nexus/protocol';
import { deriveRegistryEventId, signProtocolPayload, WebCryptoProvider } from '@nexus/crypto';

import { badRequest, TransparencyError } from './errors.js';
import {
  errorResponse,
  jsonResponse,
  parseExactStringObject,
  readSmallJson,
  requireNexusJson,
} from './http.js';
import {
  createTransparencyKeySetResponse,
  parseTransparencyKeySet,
  TRANSPARENCY_KEYSET_PATH,
} from './keyset.js';
import { isShardId, resolveShardId } from './sharding.js';
import { TransparencyShard } from './transparency-shard-do.js';
import { type AppendResult, type StoredCheckpoint, type StoredInclusionProof } from './types.js';

interface Env {
  TRANSPARENCY_SHARDS: DurableObjectNamespace<TransparencyShard>;
  TRANSPARENCY_ARTIFACTS: R2Bucket;
  TRANSPARENCY_SIGNING_KEY_PKCS8_B64URL: string;
  TRANSPARENCY_SIGNING_KID: string;
  TRANSPARENCY_PUBLIC_KEYSET_JSON: string;
}

interface ErrorBody {
  error?: {
    code?: unknown;
    message?: unknown;
  };
}

const CHECKPOINT_PATH = /^\/v1\/transparency\/checkpoint\/([0-9a-f]{2})$/;
const GLOBAL_CHECKPOINT_PATH = '/v1/transparency/checkpoint';
const INCLUSION_PATH = '/v1/transparency/inclusion';
const IMMUTABLE_CACHE = 'public, max-age=31536000, immutable';
const LATEST_CACHE = 'no-store';
const CHECKPOINT_BATCH_SIZE = 16;
const SHARD_COUNT = 256;

export { TransparencyShard };

export default class TransparencyService extends WorkerEntrypoint<Env> {
  private readonly provider = new WebCryptoProvider();
  private signingKeyPromise: Promise<CryptoKey> | undefined;
  private verificationKeySet: ServiceKeySet | undefined;

  /** Idempotent service-binding RPC called by the sole registry Queue consumer. */
  async append(event: RegistryEventV1): Promise<AppendResult> {
    const parsed = registryEventV1Schema.parse(event);
    const { eventId, ...eventWithoutEventId } = parsed;
    const derived = await deriveRegistryEventId(eventWithoutEventId, this.provider);
    if (derived.eventId !== eventId) {
      throw new TransparencyError(
        'INVALID_EVENT_ID',
        'The registry event ID does not match its canonical payload.',
        400,
      );
    }

    const eventHash = encodeBase64Url(derived.eventHash);
    const shardId = resolveShardId(derived.eventHash);
    return this.callShard<AppendResult>(shardId, '/internal/v1/append', {
      eventId,
      eventHash,
      shardId,
    });
  }

  /** Returns a signed, hash-only checkpoint for one shard. */
  async checkpoint(shardId: string): Promise<SignedTransparencyCheckpointV1> {
    assertShardId(shardId);
    const stored = await this.callShard<StoredCheckpoint>(
      shardId,
      '/internal/v1/checkpoint',
      checkpointRequest(shardId),
    );
    return this.signCheckpoint(stored);
  }

  /**
   * Publishes an immutable checkpoint artifact plus a mutable convenience pointer.
   * Repeating this RPC at the same tree size writes identical signed bytes.
   */
  async publishCheckpoint(shardId: string): Promise<SignedTransparencyCheckpointV1> {
    const checkpoint = await this.checkpoint(shardId);
    const body = JSON.stringify(checkpoint);
    const immutableKey =
      `checkpoints/shards/${shardId}/${checkpoint.payload.treeSize}-` +
      `${checkpoint.payload.rootHash}.json`;
    await this.env.TRANSPARENCY_ARTIFACTS.put(immutableKey, body, {
      httpMetadata: {
        contentType: 'application/nexus+json',
        cacheControl: IMMUTABLE_CACHE,
      },
    });
    await this.env.TRANSPARENCY_ARTIFACTS.put(`checkpoints/shards/${shardId}/latest.json`, body, {
      httpMetadata: {
        contentType: 'application/nexus+json',
        cacheControl: LATEST_CACHE,
      },
    });
    return checkpoint;
  }

  /** Scheduled maintenance RPC: publish one signed manifest containing all 256 shard roots. */
  async publishGlobalCheckpoint(): Promise<SignedGlobalTransparencyCheckpointV1> {
    const requestedAt = Math.floor(Date.now() / 1000);
    const checkpoints: SignedTransparencyCheckpointV1[] = [];

    // Bound concurrency to avoid creating an unbounded fan-out within one isolate.
    for (let start = 0; start < SHARD_COUNT; start += CHECKPOINT_BATCH_SIZE) {
      const shardIds = shardBatch(start);
      const batch = await Promise.all(
        shardIds.map(async (shardId) =>
          this.signCheckpoint(await this.loadStoredCheckpoint(shardId, requestedAt)),
        ),
      );
      checkpoints.push(...batch);
    }

    return this.publishGlobalManifest(checkpoints);
  }

  /** Cron entrypoint: publish every shard before its complete global manifest. */
  override async scheduled(): Promise<void> {
    const publication = this.publishScheduledArtifacts();
    this.ctx.waitUntil(publication);
    await publication;
  }

  private async publishScheduledArtifacts(): Promise<void> {
    const checkpoints: SignedTransparencyCheckpointV1[] = [];
    for (let start = 0; start < SHARD_COUNT; start += CHECKPOINT_BATCH_SIZE) {
      const batch = await Promise.all(
        shardBatch(start).map((shardId) => this.publishCheckpoint(shardId)),
      );
      checkpoints.push(...batch);
    }
    await this.publishGlobalManifest(checkpoints);
  }

  private async publishGlobalManifest(
    checkpoints: readonly SignedTransparencyCheckpointV1[],
  ): Promise<SignedGlobalTransparencyCheckpointV1> {
    if (checkpoints.length !== SHARD_COUNT) {
      throw new Error('A global transparency manifest requires all 256 shard checkpoints.');
    }
    const checkpointedAt = Math.max(
      ...checkpoints.map((checkpoint) => checkpoint.payload.checkpointedAt),
    );

    const payload = globalTransparencyCheckpointPayloadV1Schema.parse({
      protocol: TRANSPARENCY_GLOBAL_CHECKPOINT_PROTOCOL,
      checkpointedAt,
      shards: checkpoints.map(({ payload }) => ({
        shardId: payload.shardId,
        treeSize: payload.treeSize,
        rootHash: payload.rootHash,
      })),
      signerKid: this.env.TRANSPARENCY_SIGNING_KID,
    });
    const manifest = signedGlobalTransparencyCheckpointV1Schema.parse({
      payload,
      signature: await signProtocolPayload(payload, await this.getSigningKey(), this.provider),
    });
    const body = JSON.stringify(manifest);
    const manifestHash = encodeBase64Url(
      await this.provider.sha256(new TextEncoder().encode(body)),
    );
    await this.env.TRANSPARENCY_ARTIFACTS.put(
      `checkpoints/global/${checkpointedAt}-${manifestHash}.json`,
      body,
      {
        httpMetadata: {
          contentType: 'application/nexus+json',
          cacheControl: IMMUTABLE_CACHE,
        },
      },
    );
    await this.env.TRANSPARENCY_ARTIFACTS.put('checkpoints/global/latest.json', body, {
      httpMetadata: {
        contentType: 'application/nexus+json',
        cacheControl: LATEST_CACHE,
      },
    });
    return manifest;
  }

  override async fetch(request: Request): Promise<Response> {
    try {
      const url = new URL(request.url);
      if (request.method === 'GET' && url.pathname === TRANSPARENCY_KEYSET_PATH) {
        return await createTransparencyKeySetResponse(
          request,
          this.getVerificationKeySet(),
          this.provider,
        );
      }
      const checkpointMatch = CHECKPOINT_PATH.exec(url.pathname);
      if (request.method === 'GET' && checkpointMatch !== null) {
        const shardId = checkpointMatch[1];
        if (shardId === undefined) {
          throw badRequest('A canonical shard ID is required.');
        }
        return jsonResponse(await this.checkpoint(shardId));
      }

      if (request.method === 'GET' && url.pathname === GLOBAL_CHECKPOINT_PATH) {
        const latest = await this.env.TRANSPARENCY_ARTIFACTS.get('checkpoints/global/latest.json');
        if (latest === null) {
          throw new TransparencyError(
            'CHECKPOINT_NOT_AVAILABLE',
            'A global transparency checkpoint has not been published yet.',
            404,
          );
        }
        return new Response(latest.body, {
          status: 200,
          headers: {
            'cache-control': LATEST_CACHE,
            'content-security-policy':
              "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
            'content-type': 'application/nexus+json; charset=utf-8',
            'referrer-policy': 'no-referrer',
            'x-content-type-options': 'nosniff',
          },
        });
      }

      if (request.method === 'POST' && url.pathname === INCLUSION_PATH) {
        requireNexusJson(request);
        const eventHash = parseExactStringObject(await readSmallJson(request), 'eventHash');
        return jsonResponse(await this.createInclusionProof(eventHash));
      }

      throw new TransparencyError('NOT_FOUND', 'No such transparency endpoint.', 404);
    } catch (error) {
      return errorResponse(error);
    }
  }

  private async createInclusionProof(eventHash: string): Promise<TransparencyInclusionProofV1> {
    const eventHashBytes = decodeEventHash(eventHash);
    const shardId = resolveShardId(eventHashBytes);
    const query = new URLSearchParams({ eventHash });
    const proof = await this.callShard<StoredInclusionProof>(
      shardId,
      `/internal/v1/inclusion?${query.toString()}`,
      checkpointRequest(shardId),
    );
    const checkpoint = await this.signCheckpoint(proof);
    return transparencyInclusionProofV1Schema.parse({
      protocol: TRANSPARENCY_INCLUSION_PROOF_PROTOCOL,
      eventHash,
      shardId,
      leafIndex: proof.leafIndex,
      treeSize: proof.treeSize,
      auditPath: proof.auditPath,
      checkpoint,
    });
  }

  private async signCheckpoint(stored: StoredCheckpoint): Promise<SignedTransparencyCheckpointV1> {
    const payload = transparencyCheckpointPayloadV1Schema.parse({
      protocol: TRANSPARENCY_CHECKPOINT_PROTOCOL,
      shardId: stored.shardId,
      treeSize: stored.treeSize,
      rootHash: stored.rootHash,
      checkpointedAt: stored.checkpointedAt,
      signerKid: this.env.TRANSPARENCY_SIGNING_KID,
    });
    const signingKey = await this.getSigningKey();
    return signedTransparencyCheckpointV1Schema.parse({
      payload,
      signature: await signProtocolPayload(payload, signingKey, this.provider),
    });
  }

  private loadStoredCheckpoint(shardId: string, checkpointedAt: number): Promise<StoredCheckpoint> {
    assertShardId(shardId);
    return this.callShard<StoredCheckpoint>(shardId, '/internal/v1/checkpoint', {
      shardId,
      checkpointedAt,
    });
  }

  private getSigningKey(): Promise<CryptoKey> {
    this.signingKeyPromise ??= this.importSigningKey().catch((error: unknown) => {
      this.signingKeyPromise = undefined;
      throw error;
    });
    return this.signingKeyPromise;
  }

  private getVerificationKeySet(): ServiceKeySet {
    this.verificationKeySet ??= parseTransparencyKeySet(
      this.env.TRANSPARENCY_PUBLIC_KEYSET_JSON,
      this.env.TRANSPARENCY_SIGNING_KID,
    );
    return this.verificationKeySet;
  }

  private async importSigningKey(): Promise<CryptoKey> {
    const pkcs8 = decodeBase64Url(this.env.TRANSPARENCY_SIGNING_KEY_PKCS8_B64URL);
    try {
      return await this.provider.importEd25519PrivateKey(pkcs8, { extractable: false });
    } finally {
      pkcs8.fill(0);
    }
  }

  private async callShard<T>(shardId: string, path: string, body: unknown): Promise<T> {
    const id = this.env.TRANSPARENCY_SHARDS.idFromName(shardId);
    const response = await this.env.TRANSPARENCY_SHARDS.get(id).fetch(
      `https://transparency-shard.invalid${path}`,
      {
        method: 'POST',
        headers: { 'content-type': 'application/nexus+json' },
        body: JSON.stringify(body),
      },
    );
    const result = await response.json();
    if (!response.ok) {
      const error = result as ErrorBody;
      throw new TransparencyError(
        typeof error.error?.code === 'string' ? error.error.code : 'INTERNAL_ERROR',
        typeof error.error?.message === 'string'
          ? error.error.message
          : 'The transparency shard rejected the request.',
        response.status,
      );
    }
    return result as T;
  }
}

function checkpointRequest(shardId: string): {
  shardId: string;
  checkpointedAt: number;
} {
  return {
    shardId,
    checkpointedAt: Math.floor(Date.now() / 1000),
  };
}

function shardBatch(start: number): string[] {
  return Array.from({ length: Math.min(CHECKPOINT_BATCH_SIZE, SHARD_COUNT - start) }, (_, offset) =>
    (start + offset).toString(16).padStart(2, '0'),
  );
}

function assertShardId(shardId: string): void {
  if (!isShardId(shardId)) {
    throw badRequest('The shard ID must be two lowercase hexadecimal characters.');
  }
}

function decodeEventHash(value: string): Uint8Array {
  try {
    return decodeBase64UrlExact(value, 32);
  } catch {
    throw badRequest('The event hash must be canonical unpadded base64url for 32 bytes.');
  }
}
