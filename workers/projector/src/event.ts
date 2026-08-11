import { deriveRegistryEventId } from '@nexus/crypto';
import { registryEventV1Schema, type RegistryEventV1 } from '@nexus/protocol';

export class RegistryEventValidationError extends Error {
  readonly code = 'INVALID_REGISTRY_EVENT';

  constructor(reason: string) {
    super(reason);
    this.name = 'RegistryEventValidationError';
  }
}

export async function validateRegistryEvent(value: unknown): Promise<RegistryEventV1> {
  const parsed = registryEventV1Schema.safeParse(value);
  if (!parsed.success) {
    throw new RegistryEventValidationError('event does not match RegistryEventV1');
  }

  const { eventId, ...eventWithoutEventId } = parsed.data;
  const derived = await deriveRegistryEventId(eventWithoutEventId);
  if (derived.eventId !== eventId) {
    throw new RegistryEventValidationError('event id does not match the canonical event payload');
  }

  return parsed.data;
}
