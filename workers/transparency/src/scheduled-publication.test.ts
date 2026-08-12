import {
  deviceRegistryEventV2Schema,
  deviceRegistryEventWithoutEventIdV2Schema,
  signedGlobalTransparencyCheckpointV1Schema,
  signedTransparencyCheckpointV1Schema,
} from '@nexus/protocol';
import { deriveDeviceRegistryEventIdV2 } from '@nexus/crypto';
import { createExecutionContext, env, waitOnExecutionContext } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';

import TransparencyService from './index.js';
import type { TransparencyShard } from './transparency-shard-do.js';

interface TestEnv {
  TRANSPARENCY_SHARDS: DurableObjectNamespace<TransparencyShard>;
  TRANSPARENCY_ARTIFACTS: R2Bucket;
  TRANSPARENCY_SIGNING_KEY_PKCS8_B64URL: string;
  TRANSPARENCY_SIGNING_KID: string;
  TRANSPARENCY_PUBLIC_KEYSET_JSON: string;
}

function isTestEnv(value: unknown): value is TestEnv {
  return (
    typeof value === 'object' &&
    value !== null &&
    'TRANSPARENCY_SHARDS' in value &&
    'TRANSPARENCY_ARTIFACTS' in value &&
    'TRANSPARENCY_SIGNING_KEY_PKCS8_B64URL' in value &&
    'TRANSPARENCY_SIGNING_KID' in value &&
    'TRANSPARENCY_PUBLIC_KEYSET_JSON' in value
  );
}

function requireTestEnv(value: unknown): TestEnv {
  if (!isTestEnv(value)) {
    throw new Error('The transparency Worker test bindings are unavailable.');
  }
  return value;
}

const testEnv = requireTestEnv(env);

async function runScheduledPublication(): Promise<void> {
  const ctx = createExecutionContext();
  const worker = new TransparencyService(ctx, testEnv);
  await worker.scheduled();
  await waitOnExecutionContext(ctx);
}

async function listKeys(prefix: string): Promise<string[]> {
  const keys: string[] = [];
  let cursor: string | undefined;
  do {
    const page = await testEnv.TRANSPARENCY_ARTIFACTS.list(
      cursor === undefined ? { prefix } : { prefix, cursor },
    );
    keys.push(...page.objects.map((object) => object.key));
    cursor = page.truncated ? page.cursor : undefined;
  } while (cursor !== undefined);
  return keys.sort();
}

async function requireObject(key: string): Promise<R2ObjectBody> {
  const object = await testEnv.TRANSPARENCY_ARTIFACTS.get(key);
  if (object === null) {
    throw new Error(`Expected R2 object ${key}.`);
  }
  return object;
}

describe('scheduled transparency publication', () => {
  it('appends canonical v2 device events as idempotent hash-only leaves', async () => {
    const ctx = createExecutionContext();
    const worker = new TransparencyService(ctx, testEnv);
    const value = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
    const eventWithoutId = deviceRegistryEventWithoutEventIdV2Schema.parse({
      protocol: 'nexus.device-registry-event.v2',
      operationId: `nxo2_${value}`,
      eventType: 'activated',
      subject: `nx1_${value}`,
      genesisHash: value,
      identitySequence: 0,
      identityState: 'active',
      deviceLedgerSequence: 1,
      deviceId: `nxd2_${value}`,
      authorizationId: `nxa2_${value}`,
      deviceState: 'active',
      authorizationExpiresAt: 1_820_000_000,
      acceptedAt: 1_788_800_000,
      actionHash: value,
    });
    const { eventId } = await deriveDeviceRegistryEventIdV2(eventWithoutId);
    const event = deviceRegistryEventV2Schema.parse({ ...eventWithoutId, eventId });

    const first = await worker.appendDevice(event);
    const duplicate = await worker.appendDevice(event);

    expect(first).toMatchObject({ eventId, duplicate: false });
    expect(duplicate).toMatchObject({ eventId, duplicate: true });
    expect(first).not.toHaveProperty('subject');
    expect(first).not.toHaveProperty('deviceId');
    expect(first).not.toHaveProperty('authorizationId');

    await expect(
      worker.appendDevice({ ...event, acceptedAt: event.acceptedAt + 1 }),
    ).rejects.toMatchObject({ code: 'INVALID_EVENT_ID' });
  });

  it('serves the transparency-specific verification keyset route', async () => {
    const ctx = createExecutionContext();
    const worker = new TransparencyService(ctx, testEnv);
    const response = await worker.fetch(
      new Request('https://status.rowo.link/.well-known/nexus-transparency-keys.json'),
    );

    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe(
      'public, max-age=300, stale-while-revalidate=60',
    );
    const body = await response.text();
    expect(body).toContain(testEnv.TRANSPARENCY_SIGNING_KID);
    expect(body).not.toContain('subject');
    expect(body).not.toContain('eventId');
    expect(body).not.toContain('purpose');
  });

  it('writes immutable and latest hash-only artifacts and is idempotent', async () => {
    await runScheduledPublication();

    const firstKeys = await listKeys('checkpoints/');
    expect(firstKeys).toHaveLength(514);
    expect(firstKeys.filter((key) => key.endsWith('/latest.json'))).toHaveLength(257);
    expect(firstKeys).toContain('checkpoints/shards/00/latest.json');
    expect(firstKeys).toContain('checkpoints/shards/ff/latest.json');
    expect(firstKeys).toContain('checkpoints/global/latest.json');

    const shardBody = await (await requireObject('checkpoints/shards/00/latest.json')).text();
    const shardLatest = signedTransparencyCheckpointV1Schema.parse(
      JSON.parse(shardBody) as unknown,
    );
    expect(shardLatest.payload).toMatchObject({ shardId: '00', treeSize: 0 });
    expect(shardBody).not.toContain('subject');
    expect(shardBody).not.toContain('eventId');

    const globalObject = await requireObject('checkpoints/global/latest.json');
    const firstGlobalBody = await globalObject.text();
    const global = signedGlobalTransparencyCheckpointV1Schema.parse(
      JSON.parse(firstGlobalBody) as unknown,
    );
    expect(global.payload.shards).toHaveLength(256);
    expect(global.payload.shards[0]?.shardId).toBe('00');
    expect(global.payload.shards[255]?.shardId).toBe('ff');
    expect(firstGlobalBody).not.toContain('subject');
    expect(firstGlobalBody).not.toContain('eventId');

    await runScheduledPublication();

    expect(await listKeys('checkpoints/')).toEqual(firstKeys);
    expect(await (await requireObject('checkpoints/global/latest.json')).text()).toBe(
      firstGlobalBody,
    );
  }, 120_000);
});
