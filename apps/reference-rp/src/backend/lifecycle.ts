import { registryStatusV1Schema } from '@nexus/protocol';
import type { NexusSubject } from '@nexus/protocol';
import type { AuthoritativeLifecycleState, LifecycleProvider } from '@nexus/verifier';

const STATUS_PATH = '/v1/identity/status';
const STATUS_TIMEOUT_MS = 5_000;

type FetchLike = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;

/** Fail-closed adapter for the edge endpoint backed by the subject Durable Object. */
export class AuthoritativeRegistryLifecycleProvider implements LifecycleProvider {
  readonly #apiOrigin: string;

  public constructor(
    apiUrl: string,
    private readonly fetcher: FetchLike = globalThis.fetch,
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
}

/**
 * Explicitly unsafe local-test authority. Never wire this into a deployed RP.
 */
export class LocalLifecycleAuthority implements LifecycleProvider {
  readonly #states = new Map<NexusSubject, AuthoritativeLifecycleState>();

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
}
