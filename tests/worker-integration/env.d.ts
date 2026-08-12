import type { DeviceRegistryEventV2, RegistryEventV1 } from '@nexus/protocol';
import type { D1Migration } from 'cloudflare:test';

import type { IdentityState } from '../../workers/registry/src/identity-state-do';

interface AcceptanceQueueControl<TEvent> {
  reset(): Promise<void>;
  getMessages(): Promise<TEvent[]>;
}

declare global {
  namespace Cloudflare {
    interface Env {
      IDENTITY_STATE: DurableObjectNamespace<IdentityState>;
      INDEX_DB: D1Database;
      TEST_MIGRATIONS: D1Migration[];
      TEST_QUEUE_CONTROL: AcceptanceQueueControl<RegistryEventV1>;
      TEST_DEVICE_QUEUE_CONTROL: AcceptanceQueueControl<DeviceRegistryEventV2>;
    }
  }
}

export {};
