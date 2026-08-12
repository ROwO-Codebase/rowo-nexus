import type { DeviceRegistryEventV2, RegistryEventV1 } from '@nexus/protocol';

import { validateDeviceRegistryEvent } from './device-event';
import { applyDeviceRegistryEvent } from './device-projection';
import { validateRegistryEvent } from './event';
import { applyRegistryEvent } from './projection';

const REGISTRY_EVENTS_QUEUE = 'nexus-registry-events';
const REGISTRY_DEVICE_EVENTS_QUEUE = 'nexus-registry-device-events';

export interface TransparencyService {
  append(event: RegistryEventV1): Promise<unknown>;
  appendDevice(event: DeviceRegistryEventV2): Promise<unknown>;
}

export interface Env {
  INDEX_DB: D1Database;
  TRANSPARENCY_SERVICE: TransparencyService;
}

export async function projectAndAppend(rawEvent: unknown, env: Env): Promise<void> {
  const event = await validateRegistryEvent(rawEvent);
  await applyRegistryEvent(env.INDEX_DB, event);

  // This intentionally runs after the atomic D1 batch. If it fails, Queues
  // redelivers the message; event_id and the transparency service both make
  // that replay idempotent.
  await env.TRANSPARENCY_SERVICE.append(event);
}

export async function projectDeviceAndAppend(rawEvent: unknown, env: Env): Promise<void> {
  const event = await validateDeviceRegistryEvent(rawEvent);
  await applyDeviceRegistryEvent(env.INDEX_DB, event);

  // As for v1, D1 and the hash-only transparency log independently deduplicate
  // a Queue replay by canonical event ID.
  await env.TRANSPARENCY_SERVICE.appendDevice(event);
}

async function processMessage(queue: string, body: unknown, env: Env): Promise<void> {
  if (queue === REGISTRY_EVENTS_QUEUE) {
    await projectAndAppend(body, env);
    return;
  }
  if (queue === REGISTRY_DEVICE_EVENTS_QUEUE) {
    await projectDeviceAndAppend(body, env);
    return;
  }
  throw new Error('UNSUPPORTED_PROJECTOR_QUEUE');
}

export default {
  async queue(batch: MessageBatch<unknown>, env: Env): Promise<void> {
    for (const message of batch.messages) {
      try {
        await processMessage(batch.queue, message.body, env);
        message.ack();
      } catch (error: unknown) {
        const kind =
          error instanceof Error && 'code' in error
            ? String(error.code)
            : 'PROJECTOR_DELIVERY_FAILED';

        // Do not log event bodies, subjects, hashes, or exception messages.
        console.warn(
          JSON.stringify({
            event: 'projector_message_retry',
            kind,
            attempt: message.attempts,
          }),
        );
        message.retry();
      }
    }
  },
} satisfies ExportedHandler<Env>;

export type { RegistryEventV1 } from '@nexus/protocol';
export type { DeviceRegistryEventV2 } from '@nexus/protocol';
export { DeviceRegistryEventValidationError, validateDeviceRegistryEvent } from './device-event';
export {
  DeviceProjectionInvariantError,
  applyDeviceRegistryEvent,
  reconcileDeviceEventsForIdentity,
} from './device-projection';
export { RegistryEventValidationError, validateRegistryEvent } from './event';
export { ProjectionInvariantError, applyRegistryEvent } from './projection';
