import { audienceOriginSchema, registryStatusV1Schema } from '@nexus/protocol';
import type { NexusSubject } from '@nexus/protocol';
import type { AuthoritativeLifecycleState } from '@nexus/verifier';

import { RpWorkerError } from './errors';

const STATUS_PATH = '/v1/identity/status';
const STATUS_TIMEOUT_MS = 5_000;

export interface LifecycleEnv {
  readonly NEXUS_API?: Fetcher;
  readonly NEXUS_API_ORIGIN?: string;
}

export async function getAuthoritativeLifecycle(
  env: LifecycleEnv,
  subject: NexusSubject,
): Promise<AuthoritativeLifecycleState> {
  const binding = env.NEXUS_API;
  const origin = binding === undefined ? validatedOrigin(env.NEXUS_API_ORIGIN) : null;
  const endpoint = new URL(STATUS_PATH, origin ?? 'https://nexus-api.internal');

  let response: Response;
  try {
    const requestInit: RequestInit = {
      method: 'POST',
      headers: {
        Accept: 'application/nexus+json, application/json',
        'Content-Type': 'application/nexus+json',
      },
      body: JSON.stringify({ subject }),
      redirect: 'manual',
      ...(binding === undefined ? { signal: AbortSignal.timeout(STATUS_TIMEOUT_MS) } : {}),
    };
    const request = new Request(endpoint, requestInit);
    response = binding === undefined ? await fetch(request) : await binding.fetch(request);
  } catch (error) {
    console.error(
      JSON.stringify({
        event: 'reference_rp_lifecycle_fetch_failed',
        errorType: error instanceof Error ? error.name : 'UnknownError',
      }),
    );
    throw new RpWorkerError(
      'SERVICE_UNAVAILABLE',
      'Authoritative Nexus lifecycle status is unavailable.',
      503,
    );
  }

  if (response.status === 404) return { state: 'not-found' };
  if (!response.ok) {
    throw new RpWorkerError(
      'SERVICE_UNAVAILABLE',
      'Authoritative Nexus lifecycle status is unavailable.',
      503,
    );
  }

  let body: unknown;
  try {
    body = await response.json();
  } catch {
    throw new RpWorkerError(
      'SERVICE_UNAVAILABLE',
      'Authoritative Nexus lifecycle status is unreadable.',
      503,
    );
  }
  const status = registryStatusV1Schema.safeParse(body);
  if (!status.success || status.data.subject !== subject) {
    throw new RpWorkerError(
      'SERVICE_UNAVAILABLE',
      'Authoritative Nexus lifecycle status failed validation.',
      503,
    );
  }
  return {
    state: status.data.state,
    sequence: status.data.sequence,
    registeredAt: status.data.registeredAt,
    ...(status.data.revokedAt === null ? {} : { revokedAt: status.data.revokedAt }),
  };
}

function validatedOrigin(value: string | undefined): string {
  const parsed = audienceOriginSchema.safeParse(value);
  if (!parsed.success) {
    throw new RpWorkerError(
      'SERVICE_UNAVAILABLE',
      'The authoritative Nexus lifecycle service is not configured.',
      503,
    );
  }
  return parsed.data;
}
