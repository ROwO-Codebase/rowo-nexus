import type { RegistryEventV1 } from '@nexus/protocol';

import { validateRegistryEvent } from './event';
import { applyRegistryEvent } from './projection';

export interface TransparencyService {
  append(event: RegistryEventV1): Promise<unknown>;
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

export default {
  async queue(batch: MessageBatch<unknown>, env: Env): Promise<void> {
    for (const message of batch.messages) {
      try {
        await projectAndAppend(message.body, env);
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
export { RegistryEventValidationError, validateRegistryEvent } from './event';
export { ProjectionInvariantError, applyRegistryEvent } from './projection';
