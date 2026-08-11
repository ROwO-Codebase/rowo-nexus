import type { RegistryEventV1 } from '@nexus/protocol';
import type { D1Migration } from 'cloudflare:test';

import type { IdentityState } from '../../workers/registry/src/identity-state-do';

interface AcceptanceQueueControl {
  reset(): Promise<void>;
  getMessages(): Promise<RegistryEventV1[]>;
}

declare global {
  namespace Cloudflare {
    interface Env {
      IDENTITY_STATE: DurableObjectNamespace<IdentityState>;
      INDEX_DB: D1Database;
      TEST_MIGRATIONS: D1Migration[];
      TEST_QUEUE_CONTROL: AcceptanceQueueControl;
    }
  }
}

export {};
