import { deriveDeviceRegistryEventIdV2 } from '@nexus/crypto';
import { deviceRegistryEventV2Schema, type DeviceRegistryEventV2 } from '@nexus/protocol';

export class DeviceRegistryEventValidationError extends Error {
  readonly code = 'INVALID_DEVICE_REGISTRY_EVENT';

  constructor(reason: string) {
    super(reason);
    this.name = 'DeviceRegistryEventValidationError';
  }
}

export async function validateDeviceRegistryEvent(value: unknown): Promise<DeviceRegistryEventV2> {
  const parsed = deviceRegistryEventV2Schema.safeParse(value);
  if (!parsed.success) {
    throw new DeviceRegistryEventValidationError('event does not match DeviceRegistryEventV2');
  }

  const { eventId, ...eventWithoutEventId } = parsed.data;
  const derived = await deriveDeviceRegistryEventIdV2(eventWithoutEventId);
  if (derived.eventId !== eventId) {
    throw new DeviceRegistryEventValidationError(
      'event id does not match the canonical device event payload',
    );
  }

  return parsed.data;
}
