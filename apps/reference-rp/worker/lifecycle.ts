import {
  audienceOriginSchema,
  deviceRegistryStatusV2Schema,
  registryStatusV1Schema,
  serviceKeySetSchema,
} from '@nexus/protocol';
import type {
  NexusDeviceAuthorizationIdV2,
  NexusDeviceIdV2,
  NexusSubject,
  ServiceKeySet,
} from '@nexus/protocol';
import { verifyDeviceStatusStatement } from '@nexus/verifier';
import type { AuthoritativeLifecycleState } from '@nexus/verifier';

import { RpWorkerError } from './errors';

const STATUS_PATH = '/v1/identity/status';
const DEVICE_STATUS_PATH = '/v2/device/status';
const STATUS_TIMEOUT_MS = 5_000;

export interface LifecycleEnv {
  readonly NEXUS_API?: Fetcher;
  readonly NEXUS_API_ORIGIN?: string;
  readonly SERVICE_JWKS_JSON: string;
}

let cachedServiceKeyset: { readonly raw: string; readonly value: ServiceKeySet } | undefined;

export interface AuthoritativeDeviceStatusV2 {
  readonly identityState: 'active' | 'revoked';
  readonly identitySequence: number;
  readonly deviceLedgerSequence: number;
  readonly deviceState: 'active' | 'revoked' | 'expired' | 'unknown';
  readonly authorizationExpiresAt?: number | undefined;
  readonly activatedAt?: number | undefined;
  readonly revokedAt?: number | undefined;
}

export async function getAuthoritativeDeviceStatus(
  env: LifecycleEnv,
  subject: NexusSubject,
  deviceId: NexusDeviceIdV2,
  authorizationId: NexusDeviceAuthorizationIdV2,
): Promise<AuthoritativeDeviceStatusV2> {
  const binding = env.NEXUS_API;
  const origin = binding === undefined ? validatedOrigin(env.NEXUS_API_ORIGIN) : null;
  const endpoint = new URL(DEVICE_STATUS_PATH, origin ?? 'https://nexus-api.internal');
  let response: Response;
  try {
    const request = new Request(endpoint, {
      method: 'POST',
      headers: {
        Accept: 'application/nexus+json, application/json',
        'Content-Type': 'application/nexus+json',
      },
      body: JSON.stringify({ subject, deviceId, authorizationId }),
      redirect: 'manual',
      ...(binding === undefined ? { signal: AbortSignal.timeout(STATUS_TIMEOUT_MS) } : {}),
    });
    response = binding === undefined ? await fetch(request) : await binding.fetch(request);
  } catch (error) {
    console.error(
      JSON.stringify({
        event: 'reference_rp_device_status_fetch_failed',
        errorType: error instanceof Error ? error.name : 'UnknownError',
      }),
    );
    throw deviceStatusUnavailable();
  }
  if (!response.ok) throw deviceStatusUnavailable();
  let body: unknown;
  try {
    body = await response.json();
  } catch {
    throw deviceStatusUnavailable();
  }
  const status = deviceRegistryStatusV2Schema.safeParse(body);
  if (
    !status.success ||
    status.data.subject !== subject ||
    status.data.deviceId !== deviceId ||
    status.data.authorizationId !== authorizationId
  ) {
    throw deviceStatusUnavailable();
  }
  const now = Math.floor(Date.now() / 1_000);
  try {
    await verifyDeviceStatusStatement(
      status.data.statusStatement,
      serviceKeyset(env.SERVICE_JWKS_JSON),
      now,
      {
        subject,
        genesisHash: status.data.genesisHash,
        deviceId,
        authorizationId,
        identityState: status.data.identityState,
        identitySequence: status.data.identitySequence,
        deviceLedgerSequence: status.data.deviceLedgerSequence,
        deviceState: status.data.deviceState,
        ...(status.data.authorizationExpiresAt === null
          ? {}
          : { authorizationExpiresAt: status.data.authorizationExpiresAt }),
      },
    );
  } catch {
    throw deviceStatusUnavailable();
  }
  const payload = status.data.statusStatement.payload;
  return {
    identityState: payload.identityState,
    identitySequence: payload.identitySequence,
    deviceLedgerSequence: payload.deviceLedgerSequence,
    deviceState:
      payload.deviceState === 'active' &&
      payload.authorizationExpiresAt !== undefined &&
      now >= payload.authorizationExpiresAt
        ? 'expired'
        : payload.deviceState,
    ...(payload.authorizationExpiresAt === undefined
      ? {}
      : { authorizationExpiresAt: payload.authorizationExpiresAt }),
    ...(payload.activatedAt === undefined ? {} : { activatedAt: payload.activatedAt }),
    ...(payload.revokedAt === undefined ? {} : { revokedAt: payload.revokedAt }),
  };
}

function serviceKeyset(raw: string): ServiceKeySet {
  if (cachedServiceKeyset?.raw === raw) return cachedServiceKeyset.value;
  let value: unknown;
  try {
    value = JSON.parse(raw) as unknown;
  } catch {
    throw deviceStatusUnavailable();
  }
  const parsed = serviceKeySetSchema.safeParse(value);
  if (!parsed.success) throw deviceStatusUnavailable();
  cachedServiceKeyset = { raw, value: parsed.data };
  return parsed.data;
}

function deviceStatusUnavailable(): RpWorkerError {
  return new RpWorkerError(
    'SERVICE_UNAVAILABLE',
    'Authoritative Nexus device status is unavailable.',
    503,
  );
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
