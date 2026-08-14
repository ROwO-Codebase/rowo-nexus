import {
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
import type {
  AuthoritativeDeviceLifecycleState,
  AuthoritativeLifecycleState,
  DeviceLifecycleProvider,
  LifecycleProvider,
} from '@nexus/verifier';

const STATUS_PATH = '/v1/identity/status';
const DEVICE_STATUS_PATH = '/v2/device/status';
const STATUS_TIMEOUT_MS = 5_000;

type FetchLike = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;

/** Fail-closed adapter for the edge endpoint backed by the subject Durable Object. */
export class AuthoritativeRegistryLifecycleProvider
  implements LifecycleProvider, DeviceLifecycleProvider
{
  readonly #apiOrigin: string;
  readonly #serviceKeyset: ServiceKeySet;

  public constructor(
    apiUrl: string,
    serviceKeyset: unknown,
    private readonly fetcher: FetchLike = globalThis.fetch,
    private readonly now: () => number = () => Math.floor(Date.now() / 1_000),
  ) {
    let parsed: URL;
    try {
      parsed = new URL(apiUrl);
    } catch (error) {
      throw new TypeError('Nexus API URL must be one absolute HTTPS origin.', { cause: error });
    }
    if (
      parsed.protocol !== 'https:' ||
      parsed.username !== '' ||
      parsed.password !== '' ||
      parsed.pathname !== '/' ||
      parsed.search !== '' ||
      parsed.hash !== ''
    ) {
      throw new TypeError('Nexus API URL must be one absolute HTTPS origin.');
    }
    this.#apiOrigin = parsed.origin;
    const parsedKeyset = serviceKeySetSchema.safeParse(serviceKeyset);
    if (!parsedKeyset.success) {
      throw new TypeError('Nexus service verification keyset is invalid.');
    }
    this.#serviceKeyset = parsedKeyset.data;
  }

  public async getAuthoritativeStatus(subject: NexusSubject): Promise<AuthoritativeLifecycleState> {
    let response: Response;
    try {
      response = await this.fetcher(new URL(STATUS_PATH, this.#apiOrigin), {
        method: 'POST',
        headers: {
          Accept: 'application/nexus+json, application/json',
          'Content-Type': 'application/nexus+json',
        },
        body: JSON.stringify({ subject }),
        cache: 'no-store',
        credentials: 'omit',
        redirect: 'error',
        signal: AbortSignal.timeout(STATUS_TIMEOUT_MS),
      });
    } catch (error) {
      throw new Error('Authoritative Nexus lifecycle status is unavailable.', { cause: error });
    }

    if (response.status === 404) return { state: 'not-found' };
    if (!response.ok) throw new Error('Authoritative Nexus lifecycle status was rejected.');

    let body: unknown;
    try {
      body = (await response.json()) as unknown;
    } catch (error) {
      throw new Error('Authoritative Nexus lifecycle status was unreadable.', { cause: error });
    }
    const status = registryStatusV1Schema.safeParse(body);
    if (!status.success || status.data.subject !== subject) {
      throw new Error('Authoritative Nexus lifecycle status failed strict validation.');
    }
    return {
      state: status.data.state,
      sequence: status.data.sequence,
      registeredAt: status.data.registeredAt,
      ...(status.data.revokedAt === null ? {} : { revokedAt: status.data.revokedAt }),
    };
  }

  public async getAuthoritativeDeviceStatus(
    subject: NexusSubject,
    deviceId: NexusDeviceIdV2,
    authorizationId: NexusDeviceAuthorizationIdV2,
  ): Promise<AuthoritativeDeviceLifecycleState> {
    let response: Response;
    try {
      response = await this.fetcher(new URL(DEVICE_STATUS_PATH, this.#apiOrigin), {
        method: 'POST',
        headers: {
          Accept: 'application/nexus+json, application/json',
          'Content-Type': 'application/nexus+json',
        },
        body: JSON.stringify({ subject, deviceId, authorizationId }),
        cache: 'no-store',
        credentials: 'omit',
        redirect: 'error',
        signal: AbortSignal.timeout(STATUS_TIMEOUT_MS),
      });
    } catch (error) {
      throw new Error('Authoritative Nexus device status is unavailable.', { cause: error });
    }
    if (response.status === 404) return { state: 'not-found' };
    if (!response.ok) throw new Error('Authoritative Nexus device status was rejected.');
    let body: unknown;
    try {
      body = (await response.json()) as unknown;
    } catch (error) {
      throw new Error('Authoritative Nexus device status was unreadable.', { cause: error });
    }
    const status = deviceRegistryStatusV2Schema.safeParse(body);
    if (
      !status.success ||
      status.data.subject !== subject ||
      status.data.deviceId !== deviceId ||
      status.data.authorizationId !== authorizationId
    ) {
      throw new Error('Authoritative Nexus device status failed validation.');
    }
    const now = this.now();
    try {
      await verifyDeviceStatusStatement(status.data.statusStatement, this.#serviceKeyset, now, {
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
      });
    } catch (error) {
      throw new Error('Authoritative Nexus device status signature is invalid or stale.', {
        cause: error,
      });
    }
    const payload = status.data.statusStatement.payload;
    if (payload.deviceState === 'unknown') return { state: 'not-found' };
    return {
      state:
        payload.deviceState === 'active' &&
        payload.authorizationExpiresAt !== undefined &&
        now >= payload.authorizationExpiresAt
          ? 'expired'
          : payload.deviceState,
      identityState: payload.identityState,
      identitySequence: payload.identitySequence,
      deviceId,
      authorizationId,
      deviceLedgerSequence: payload.deviceLedgerSequence,
      ...(payload.activatedAt === undefined ? {} : { activatedAt: payload.activatedAt }),
      ...(payload.revokedAt === undefined ? {} : { revokedAt: payload.revokedAt }),
      ...(payload.authorizationExpiresAt === undefined
        ? {}
        : { authorizationExpiresAt: payload.authorizationExpiresAt }),
    };
  }
}

/**
 * Explicitly unsafe local-test authority. Never wire this into a deployed RP.
 */
export class LocalLifecycleAuthority implements LifecycleProvider, DeviceLifecycleProvider {
  readonly #states = new Map<NexusSubject, AuthoritativeLifecycleState>();
  readonly #deviceStates = new Map<
    string,
    Exclude<AuthoritativeDeviceLifecycleState, { state: 'not-found' }>
  >();

  public constructor(private readonly now: () => number = () => Math.floor(Date.now() / 1000)) {}

  public getAuthoritativeStatus(subject: NexusSubject): Promise<AuthoritativeLifecycleState> {
    const existing = this.#states.get(subject);
    if (existing !== undefined) return Promise.resolve(existing);

    const active: AuthoritativeLifecycleState = {
      state: 'active',
      sequence: 0,
      registeredAt: this.now(),
    };
    this.#states.set(subject, active);
    return Promise.resolve(active);
  }

  public revoke(subject: NexusSubject): void {
    const current = this.#states.get(subject);
    const now = this.now();
    this.#states.set(subject, {
      state: 'revoked',
      sequence: current?.state === 'active' ? current.sequence + 1 : 1,
      registeredAt: current?.state === 'active' ? current.registeredAt : now,
      revokedAt: now,
    });
  }

  public set(subject: NexusSubject, state: AuthoritativeLifecycleState): void {
    this.#states.set(subject, state);
  }

  public getAuthoritativeDeviceStatus(
    subject: NexusSubject,
    deviceId: NexusDeviceIdV2,
    authorizationId: NexusDeviceAuthorizationIdV2,
  ): Promise<AuthoritativeDeviceLifecycleState> {
    const device =
      this.#deviceStates.get(deviceId) ??
      ({
        state: 'active',
        identityState: 'active',
        identitySequence: 0,
        deviceId,
        authorizationId,
        deviceLedgerSequence: 0,
      } satisfies Exclude<AuthoritativeDeviceLifecycleState, { state: 'not-found' }>);
    const identity = this.#states.get(subject);
    if (identity?.state !== 'revoked') return Promise.resolve(device);
    return Promise.resolve({
      ...device,
      state: 'revoked',
      identityState: 'revoked',
      identitySequence: identity.sequence,
      ...(identity.revokedAt === undefined ? {} : { revokedAt: identity.revokedAt }),
    });
  }

  public setDevice(
    state: Exclude<AuthoritativeDeviceLifecycleState, { state: 'not-found' }>,
  ): void {
    this.#deviceStates.set(state.deviceId, state);
  }
}
