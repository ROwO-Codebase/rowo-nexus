import {
  NEXUS_BODY_LIMITS,
  NexusFault,
  assertExactRequestOrigin,
  assertHttps,
  assertMethod,
  assertNexusContentType,
  createApiHeaders,
  createCorsHeaders,
  createJsonConsoleSink,
  createNexusErrorBody,
  createRequestId,
  createWellKnownHeaders,
  emitAggregateMetric,
  faultCode,
  handleExactOriginPreflight,
  isNexusErrorCode,
  latencyBucket,
  parseExactOrigin,
  readBodyBytes,
  signRegistryReceipt,
  signStatusStatement,
  sizeBucket,
  toNexusErrorResponse,
  type AggregateMetricSink,
  type AggregateOperation,
  type ServiceSigningConfig,
} from '@nexus/cloudflare-common';
import { deriveGenesisHash, deriveSubject } from '@nexus/crypto';
import {
  IDENTITY_PROTOCOL_V1,
  NEXUS_SUITE_V1,
  REGISTRY_RECEIPT_PROTOCOL_V1,
  REVOKE_PROTOCOL_V1,
  REVOKE_SECRET_PROTOCOL_V1,
  STATUS_STATEMENT_PROTOCOL_V1,
  encodeBase64Url,
  identityGenesisV1Schema,
  nexusEventIdSchema,
  nexusSubjectSchema,
  registerIdentityRequestV1Schema,
  registryEventV1Schema,
  registryReceiptV1Schema,
  registryStatusV1Schema,
  revokeRequestV1Schema,
  serviceKeySetSchema,
  signerKidSchema,
  statusBatchRequestV1Schema,
  statusRequestV1Schema,
  statusStatementV1Schema,
  type IdentityGenesisV1,
  type NexusErrorCode,
  type NexusSubject,
  type RegistryEventV1,
  type RegistryReceiptPayloadV1,
  type RegistryReceiptV1,
  type RegistryStatusV1,
  type RevokeBySecretV1,
  type RevokeBySignaturePayloadV1,
  type StatusStatementPayloadV1,
  type StatusStatementV1,
} from '@nexus/protocol';

type RegistryErrorCode =
  | 'BAD_REQUEST'
  | 'UNSUPPORTED_PROTOCOL'
  | 'UNSUPPORTED_SUITE'
  | 'INVALID_SUBJECT'
  | 'INVALID_SIGNATURE'
  | 'INVALID_REVOCATION_SECRET'
  | 'IDENTITY_NOT_FOUND'
  | 'IDENTITY_REVOKED'
  | 'SEQUENCE_CONFLICT'
  | 'SUBJECT_GENESIS_CONFLICT'
  | 'INTERNAL_ERROR';

interface RegistryFault {
  readonly code: RegistryErrorCode;
  /** Deliberately ignored at the public boundary. */
  readonly message: string;
}

type RegistryResult<T> =
  { readonly ok: true; readonly value: T } | { readonly ok: false; readonly error: RegistryFault };

interface AuthoritativeStatus {
  readonly subject: string;
  readonly state: 'active' | 'revoked';
  readonly sequence: number;
  readonly registeredAt: number;
  readonly revokedAt: number | null;
  readonly genesis: IdentityGenesisV1;
  readonly genesisHash: string;
  readonly eventId: string;
  readonly eventType: 'registered' | 'revoked';
  readonly acceptedAt: number;
}

interface RegistryMutation extends AuthoritativeStatus {
  readonly event: RegistryEventV1;
}

/** Structural RPC contract. The edge Worker never imports the registry implementation. */
export interface RegistryService {
  register(input: {
    readonly subject: string;
    readonly genesis: IdentityGenesisV1;
  }): Promise<RegistryResult<RegistryMutation>>;
  status(subject: string): Promise<RegistryResult<AuthoritativeStatus>>;
  statusBatch(subjects: string[]): Promise<Array<RegistryResult<AuthoritativeStatus>>>;
  revokeBySignature(input: {
    readonly payload: RevokeBySignaturePayloadV1;
    readonly signature: string;
  }): Promise<RegistryResult<RegistryMutation>>;
  revokeBySecret(payload: RevokeBySecretV1): Promise<RegistryResult<RegistryMutation>>;
}

export interface PublicApiRateLimiter {
  limit(options: { readonly key: string }): Promise<{ readonly success: boolean }>;
}

export interface Env {
  readonly REGISTRY_SERVICE: RegistryService;
  readonly PUBLIC_API_RATE_LIMITER: PublicApiRateLimiter;
  /** Local development escape hatch. Production configuration must leave this unset. */
  readonly ALLOW_LOCALHOST_HTTP?: string;
  readonly PUBLIC_API_ORIGIN: string;
  readonly WALLET_ORIGIN: string;
  readonly STATUS_TTL_SECONDS?: string;
  readonly SERVICE_JWKS_JSON: string;
  readonly RECEIPT_SIGNING_KID: string;
  readonly RECEIPT_SIGNING_PRIVATE_KEY: string;
  readonly STATUS_SIGNING_KID: string;
  readonly STATUS_SIGNING_PRIVATE_KEY: string;
}

export interface EdgeDependencies {
  readonly now?: () => number;
  readonly monotonicNow?: () => number;
  readonly requestId?: () => string;
  readonly metricSink?: AggregateMetricSink | null;
  readonly rateLimitKey?: (
    request: Request,
    operation: AggregateOperation,
    now: number,
  ) => Promise<string>;
  readonly signReceipt?: (
    payload: RegistryReceiptPayloadV1,
    config: ServiceSigningConfig,
  ) => Promise<RegistryReceiptV1>;
  readonly signStatus?: (
    payload: StatusStatementPayloadV1,
    config: ServiceSigningConfig,
  ) => Promise<StatusStatementV1>;
}

interface ResolvedDependencies {
  readonly now: () => number;
  readonly monotonicNow: () => number;
  readonly requestId: () => string;
  readonly metricSink: AggregateMetricSink | null;
  readonly rateLimitKey: NonNullable<EdgeDependencies['rateLimitKey']>;
  readonly signReceipt: NonNullable<EdgeDependencies['signReceipt']>;
  readonly signStatus: NonNullable<EdgeDependencies['signStatus']>;
}

interface EdgeApi {
  fetch(request: Request, env: Env): Promise<Response>;
}

type RouteKind = 'well-known' | 'public-read' | 'mutation';

interface Route {
  readonly operation: AggregateOperation;
  readonly kind: RouteKind;
  readonly method: 'GET' | 'POST';
  readonly bodyLimit?: number;
}

const ROUTES: Readonly<Record<string, Route>> = Object.freeze({
  '/.well-known/nexus.json': {
    operation: 'discovery',
    kind: 'well-known',
    method: 'GET',
  },
  '/.well-known/jwks.json': { operation: 'jwks', kind: 'well-known', method: 'GET' },
  '/v1/identity/register': {
    operation: 'register',
    kind: 'mutation',
    method: 'POST',
    bodyLimit: NEXUS_BODY_LIMITS.register,
  },
  '/v1/identity/status': {
    operation: 'status',
    kind: 'public-read',
    method: 'POST',
    bodyLimit: NEXUS_BODY_LIMITS.status,
  },
  '/v1/identity/status-batch': {
    operation: 'status_batch',
    kind: 'public-read',
    method: 'POST',
    bodyLimit: NEXUS_BODY_LIMITS.statusBatch,
  },
  '/v1/identity/revoke': {
    operation: 'revoke',
    kind: 'mutation',
    method: 'POST',
    bodyLimit: NEXUS_BODY_LIMITS.revoke,
  },
});

const configsByEnvironment = new WeakMap<
  Env,
  {
    readonly receipt: ServiceSigningConfig;
    readonly status: ServiceSigningConfig;
  }
>();

const RATE_LIMIT_PERIOD_SECONDS = 60;
const RATE_LIMIT_KEY_DOMAIN = 'NEXUS-EDGE-RATE-LIMIT\0v1\0';
let ephemeralRateLimitSalt: { bucket: number; value: Uint8Array } | undefined;

function saltForRateLimitBucket(bucket: number): Uint8Array {
  if (ephemeralRateLimitSalt?.bucket === bucket) return ephemeralRateLimitSalt.value;
  ephemeralRateLimitSalt?.value.fill(0);
  const value = crypto.getRandomValues(new Uint8Array(32));
  ephemeralRateLimitSalt = { bucket, value };
  return value;
}

async function createEphemeralRateLimitKey(
  request: Request,
  operation: AggregateOperation,
  now: number,
): Promise<string> {
  const suppliedAddress = request.headers.get('CF-Connecting-IP')?.trim();
  const address =
    suppliedAddress !== undefined && suppliedAddress.length > 0 && suppliedAddress.length <= 64
      ? suppliedAddress
      : 'unknown';
  const bucket = Math.floor(now / RATE_LIMIT_PERIOD_SECONDS);
  const salt = saltForRateLimitBucket(bucket);
  const input = new TextEncoder().encode(
    `${RATE_LIMIT_KEY_DOMAIN}${operation}\0${String(bucket)}\0${address}`,
  );
  const preimage = new Uint8Array(salt.byteLength + input.byteLength);
  preimage.set(salt);
  preimage.set(input, salt.byteLength);
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', preimage));
  preimage.fill(0);
  input.fill(0);
  return `nexus-edge-v1:${operation}:${String(bucket)}:${encodeBase64Url(digest)}`;
}

function signingConfigs(env: Env): {
  readonly receipt: ServiceSigningConfig;
  readonly status: ServiceSigningConfig;
} {
  const cached = configsByEnvironment.get(env);
  if (cached !== undefined) return cached;

  if (
    !signerKidSchema.safeParse(env.RECEIPT_SIGNING_KID).success ||
    !signerKidSchema.safeParse(env.STATUS_SIGNING_KID).success ||
    env.RECEIPT_SIGNING_PRIVATE_KEY.length === 0 ||
    env.STATUS_SIGNING_PRIVATE_KEY.length === 0
  ) {
    throw new NexusFault('INTERNAL_ERROR');
  }

  const configs = Object.freeze({
    receipt: Object.freeze({
      signerKid: env.RECEIPT_SIGNING_KID,
      privateKeyPkcs8: env.RECEIPT_SIGNING_PRIVATE_KEY,
    }),
    status: Object.freeze({
      signerKid: env.STATUS_SIGNING_KID,
      privateKeyPkcs8: env.STATUS_SIGNING_PRIVATE_KEY,
    }),
  });
  configsByEnvironment.set(env, configs);
  return configs;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function requireHttpsOrigin(value: string): string {
  const parsed = parseExactOrigin(value);
  if (parsed === null || parsed !== value || new URL(parsed).protocol !== 'https:') {
    throw new NexusFault('INTERNAL_ERROR');
  }
  return parsed;
}

function statusTtl(env: Env): number {
  const raw = env.STATUS_TTL_SECONDS ?? '60';
  if (!/^[1-9][0-9]*$/u.test(raw)) throw new NexusFault('INTERNAL_ERROR');
  const parsed = Number(raw);
  if (!Number.isSafeInteger(parsed) || parsed > 300) throw new NexusFault('INTERNAL_ERROR');
  return parsed;
}

function epochSeconds(dependencies: ResolvedDependencies): number {
  const value = dependencies.now();
  if (!Number.isSafeInteger(value) || value < 0) throw new NexusFault('INTERNAL_ERROR');
  return value;
}

function jsonResponse(value: unknown, status: number, headers?: HeadersInit): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: createApiHeaders(headers),
  });
}

function corsHeaders(route: Route | undefined, request: Request, env: Env): Headers {
  if (route?.kind === 'public-read') {
    return createCorsHeaders(request.headers.get('Origin'), { mode: 'public' });
  }
  if (route?.kind === 'mutation') {
    return createCorsHeaders(request.headers.get('Origin'), {
      mode: 'exact',
      allowedOrigins: [requireHttpsOrigin(env.WALLET_ORIGIN)],
    });
  }
  return new Headers();
}

function parseJsonWithUniqueKeys(bytes: Uint8Array): unknown {
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw new NexusFault('BAD_REQUEST');
  }
  if (text.length === 0) throw new NexusFault('BAD_REQUEST');

  let cursor = 0;
  const isWhitespace = (character: string): boolean =>
    character === ' ' || character === '\t' || character === '\n' || character === '\r';

  const skipWhitespace = (): void => {
    while (cursor < text.length && isWhitespace(text[cursor] ?? '')) cursor += 1;
  };

  const readString = (): string => {
    const start = cursor;
    if (text[cursor] !== '"') throw new NexusFault('BAD_REQUEST');
    cursor += 1;
    let escaped = false;
    while (cursor < text.length) {
      const character = text[cursor];
      cursor += 1;
      if (escaped) {
        escaped = false;
      } else if (character === '\\') {
        escaped = true;
      } else if (character === '"') {
        try {
          return JSON.parse(text.slice(start, cursor)) as string;
        } catch {
          throw new NexusFault('BAD_REQUEST');
        }
      }
    }
    throw new NexusFault('BAD_REQUEST');
  };

  const scanValue = (): void => {
    skipWhitespace();
    const initial = text[cursor];
    if (initial === '{') {
      cursor += 1;
      skipWhitespace();
      const keys = new Set<string>();
      if (text[cursor] === '}') {
        cursor += 1;
        return;
      }
      while (true) {
        skipWhitespace();
        const key = readString();
        if (keys.has(key)) throw new NexusFault('BAD_REQUEST');
        keys.add(key);
        skipWhitespace();
        if (text[cursor] !== ':') throw new NexusFault('BAD_REQUEST');
        cursor += 1;
        scanValue();
        skipWhitespace();
        if (text[cursor] === '}') {
          cursor += 1;
          return;
        }
        if (text[cursor] !== ',') throw new NexusFault('BAD_REQUEST');
        cursor += 1;
      }
    }
    if (initial === '[') {
      cursor += 1;
      skipWhitespace();
      if (text[cursor] === ']') {
        cursor += 1;
        return;
      }
      while (true) {
        scanValue();
        skipWhitespace();
        if (text[cursor] === ']') {
          cursor += 1;
          return;
        }
        if (text[cursor] !== ',') throw new NexusFault('BAD_REQUEST');
        cursor += 1;
      }
    }
    if (initial === '"') {
      readString();
      return;
    }
    const start = cursor;
    while (
      cursor < text.length &&
      !isWhitespace(text[cursor] ?? '') &&
      text[cursor] !== ',' &&
      text[cursor] !== ']' &&
      text[cursor] !== '}'
    ) {
      cursor += 1;
    }
    if (start === cursor) throw new NexusFault('BAD_REQUEST');
  };

  scanValue();
  skipWhitespace();
  if (cursor !== text.length) throw new NexusFault('BAD_REQUEST');

  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new NexusFault('BAD_REQUEST');
  }
}

async function readStrictJson(request: Request, maximumBytes: number): Promise<unknown> {
  assertNexusContentType(request);
  return parseJsonWithUniqueKeys(await readBodyBytes(request, maximumBytes));
}

function throwProtocolHint(value: unknown): void {
  if (!isRecord(value)) return;
  const genesis = isRecord(value.genesis) ? value.genesis : null;
  const payload = isRecord(value.payload) ? value.payload : null;
  if (
    genesis !== null &&
    typeof genesis.protocol === 'string' &&
    genesis.protocol !== IDENTITY_PROTOCOL_V1
  ) {
    throw new NexusFault('UNSUPPORTED_PROTOCOL');
  }
  if (payload !== null && typeof payload.protocol === 'string') {
    const expected =
      value.mode === 'signature'
        ? REVOKE_PROTOCOL_V1
        : value.mode === 'secret'
          ? REVOKE_SECRET_PROTOCOL_V1
          : null;
    if (expected !== null && payload.protocol !== expected) {
      throw new NexusFault('UNSUPPORTED_PROTOCOL');
    }
  }
  if (genesis !== null && typeof genesis.suite === 'string' && genesis.suite !== NEXUS_SUITE_V1) {
    throw new NexusFault('UNSUPPORTED_SUITE');
  }
}

function throwInvalidSubjectHint(value: unknown): void {
  if (!isRecord(value)) return;
  const payload = isRecord(value.payload) ? value.payload : null;
  const candidate = payload?.subject ?? value.subject;
  if (candidate !== undefined && !nexusSubjectSchema.safeParse(candidate).success) {
    throw new NexusFault('INVALID_SUBJECT');
  }
}

function parseRegister(value: unknown): ReturnType<typeof registerIdentityRequestV1Schema.parse> {
  throwProtocolHint(value);
  throwInvalidSubjectHint(value);
  const result = registerIdentityRequestV1Schema.safeParse(value);
  if (!result.success) throw new NexusFault('BAD_REQUEST');
  return result.data;
}

function parseStatus(value: unknown): ReturnType<typeof statusRequestV1Schema.parse> {
  throwInvalidSubjectHint(value);
  const result = statusRequestV1Schema.safeParse(value);
  if (!result.success) throw new NexusFault('BAD_REQUEST');
  return result.data;
}

function parseStatusBatch(value: unknown): ReturnType<typeof statusBatchRequestV1Schema.parse> {
  if (isRecord(value) && Array.isArray(value.subjects)) {
    for (const subject of value.subjects) {
      if (!nexusSubjectSchema.safeParse(subject).success) throw new NexusFault('INVALID_SUBJECT');
    }
  }
  const result = statusBatchRequestV1Schema.safeParse(value);
  if (!result.success) throw new NexusFault('BAD_REQUEST');
  return result.data;
}

function parseRevoke(value: unknown): ReturnType<typeof revokeRequestV1Schema.parse> {
  throwProtocolHint(value);
  throwInvalidSubjectHint(value);
  const result = revokeRequestV1Schema.safeParse(value);
  if (!result.success) throw new NexusFault('BAD_REQUEST');
  return result.data;
}

function registryError(error: RegistryFault): NexusFault {
  return new NexusFault(isNexusErrorCode(error.code) ? error.code : 'INTERNAL_ERROR');
}

function unwrapRegistry<T>(result: RegistryResult<T>): T {
  if (!result.ok) throw registryError(result.error);
  return result.value;
}

async function callRegistry<T>(call: () => Promise<T>): Promise<T> {
  try {
    return await call();
  } catch {
    throw new NexusFault('SERVICE_UNAVAILABLE');
  }
}

async function enforceRateLimit(
  request: Request,
  env: Env,
  route: Route,
  dependencies: ResolvedDependencies,
): Promise<void> {
  const key = await dependencies.rateLimitKey(request, route.operation, epochSeconds(dependencies));
  if (!/^[!-~]{1,256}$/u.test(key)) throw new NexusFault('INTERNAL_ERROR');

  let decision: { readonly success: boolean };
  try {
    decision = await env.PUBLIC_API_RATE_LIMITER.limit({ key });
  } catch {
    throw new NexusFault('SERVICE_UNAVAILABLE');
  }
  if (typeof decision.success !== 'boolean') throw new NexusFault('INTERNAL_ERROR');
  if (!decision.success) throw new NexusFault('RATE_LIMITED');
}

async function validateAuthoritativeStatus(
  value: AuthoritativeStatus,
  expectedSubject: NexusSubject,
): Promise<AuthoritativeStatus> {
  if (
    value.subject !== expectedSubject ||
    !nexusSubjectSchema.safeParse(value.subject).success ||
    !identityGenesisV1Schema.safeParse(value.genesis).success ||
    !nexusEventIdSchema.safeParse(value.eventId).success ||
    (value.state !== 'active' && value.state !== 'revoked') ||
    (value.eventType !== 'registered' && value.eventType !== 'revoked') ||
    !Number.isSafeInteger(value.sequence) ||
    value.sequence < 0 ||
    !Number.isSafeInteger(value.registeredAt) ||
    value.registeredAt < 0 ||
    !Number.isSafeInteger(value.acceptedAt) ||
    value.acceptedAt < 0 ||
    (value.revokedAt !== null &&
      (!Number.isSafeInteger(value.revokedAt) || value.revokedAt < value.registeredAt)) ||
    (value.state === 'active' && (value.sequence !== 0 || value.revokedAt !== null)) ||
    (value.state === 'revoked' && (value.sequence !== 1 || value.revokedAt === null))
  ) {
    throw new NexusFault('INTERNAL_ERROR');
  }

  const [computedSubject, computedHash] = await Promise.all([
    deriveSubject(value.genesis),
    deriveGenesisHash(value.genesis),
  ]);
  if (
    computedSubject !== expectedSubject ||
    encodeBase64Url(computedHash) !== value.genesisHash ||
    (value.eventType === 'registered' &&
      (value.state !== 'active' ||
        value.sequence !== 0 ||
        value.acceptedAt !== value.registeredAt)) ||
    (value.eventType === 'revoked' &&
      (value.state !== 'revoked' || value.sequence !== 1 || value.acceptedAt !== value.revokedAt))
  ) {
    throw new NexusFault('INTERNAL_ERROR');
  }
  return value;
}

async function validateMutation(
  value: RegistryMutation,
  expectedSubject: NexusSubject,
): Promise<RegistryMutation> {
  await validateAuthoritativeStatus(value, expectedSubject);
  const event = registryEventV1Schema.safeParse(value.event);
  if (
    !event.success ||
    event.data.eventId !== value.eventId ||
    event.data.subject !== value.subject ||
    event.data.genesisHash !== value.genesisHash ||
    event.data.eventType !== value.eventType ||
    event.data.sequence !== value.sequence ||
    event.data.state !== value.state ||
    event.data.acceptedAt !== value.acceptedAt
  ) {
    throw new NexusFault('INTERNAL_ERROR');
  }
  return value;
}

async function signedStatus(
  status: AuthoritativeStatus,
  env: Env,
  dependencies: ResolvedDependencies,
): Promise<RegistryStatusV1> {
  const issuedAt = epochSeconds(dependencies);
  const payload: StatusStatementPayloadV1 = {
    protocol: STATUS_STATEMENT_PROTOCOL_V1,
    subject: status.subject as NexusSubject,
    state: status.state,
    sequence: status.sequence,
    registeredAt: status.registeredAt,
    ...(status.revokedAt === null ? {} : { revokedAt: status.revokedAt }),
    iat: issuedAt,
    exp: issuedAt + statusTtl(env),
    signerKid: env.STATUS_SIGNING_KID,
  };
  if (!Number.isSafeInteger(payload.exp)) throw new NexusFault('INTERNAL_ERROR');
  const statement = await dependencies.signStatus(payload, signingConfigs(env).status);
  if (!statusStatementV1Schema.safeParse(statement).success) {
    throw new NexusFault('INTERNAL_ERROR');
  }
  const response = registryStatusV1Schema.safeParse({
    subject: status.subject,
    state: status.state,
    sequence: status.sequence,
    registeredAt: status.registeredAt,
    revokedAt: status.revokedAt,
    genesis: status.genesis,
    statusStatement: statement,
  });
  if (!response.success) throw new NexusFault('INTERNAL_ERROR');
  return response.data;
}

async function signedMutation(
  mutation: RegistryMutation,
  env: Env,
  dependencies: ResolvedDependencies,
): Promise<{ readonly receipt: RegistryReceiptV1; readonly status: RegistryStatusV1 }> {
  const receiptPayload: RegistryReceiptPayloadV1 = {
    protocol: REGISTRY_RECEIPT_PROTOCOL_V1,
    eventId: mutation.event.eventId,
    subject: mutation.event.subject,
    genesisHash: mutation.event.genesisHash,
    eventType: mutation.event.eventType,
    sequence: mutation.event.sequence,
    state: mutation.event.state,
    acceptedAt: mutation.event.acceptedAt,
    signerKid: env.RECEIPT_SIGNING_KID,
  };
  const [receipt, status] = await Promise.all([
    dependencies.signReceipt(receiptPayload, signingConfigs(env).receipt),
    signedStatus(mutation, env, dependencies),
  ]);
  if (!registryReceiptV1Schema.safeParse(receipt).success) {
    throw new NexusFault('INTERNAL_ERROR');
  }
  return { receipt, status };
}

function publicPreflight(request: Request): Response {
  const origin = request.headers.get('Origin');
  const requestedMethod = request.headers.get('Access-Control-Request-Method')?.toUpperCase();
  const requestedHeaders =
    request.headers
      .get('Access-Control-Request-Headers')
      ?.split(',')
      .map((value) => value.trim().toLowerCase())
      .filter((value) => value.length > 0) ?? [];
  if (
    origin === null ||
    requestedMethod !== 'POST' ||
    requestedHeaders.some((v) => v !== 'content-type')
  ) {
    throw new NexusFault('BAD_REQUEST');
  }
  const headers = createApiHeaders(createCorsHeaders(origin, { mode: 'public' }));
  headers.set('Access-Control-Allow-Methods', 'POST');
  headers.set('Access-Control-Allow-Headers', 'content-type');
  headers.set('Access-Control-Max-Age', '300');
  headers.set('Vary', 'Access-Control-Request-Method, Access-Control-Request-Headers');
  return new Response(null, { status: 204, headers });
}

async function routeRequest(
  request: Request,
  env: Env,
  route: Route,
  dependencies: ResolvedDependencies,
  requestId: string,
): Promise<{ readonly response: Response; readonly batchSize?: number }> {
  const url = new URL(request.url);
  if (url.search.length > 0) throw new NexusFault('BAD_REQUEST');
  if (request.headers.has('Cookie')) throw new NexusFault('BAD_REQUEST');

  if (request.method.toUpperCase() === 'OPTIONS') {
    if (route.kind === 'mutation') {
      const response = handleExactOriginPreflight(request, {
        allowedOrigins: [requireHttpsOrigin(env.WALLET_ORIGIN)],
        allowedMethods: ['POST'],
        requestId,
      });
      if (response === null) throw new NexusFault('INTERNAL_ERROR');
      return { response };
    }
    if (route.kind === 'public-read') return { response: publicPreflight(request) };
  }

  assertMethod(request, [route.method]);
  if (route.kind === 'mutation') {
    assertExactRequestOrigin(request, [requireHttpsOrigin(env.WALLET_ORIGIN)]);
  }
  if (route.kind !== 'well-known') {
    await enforceRateLimit(request, env, route, dependencies);
  }

  if (url.pathname === '/.well-known/nexus.json') {
    const apiOrigin = requireHttpsOrigin(env.PUBLIC_API_ORIGIN);
    return {
      response: new Response(
        JSON.stringify({
          protocols: [IDENTITY_PROTOCOL_V1, 'nexus.ownership-proof.v1'],
          suites: [NEXUS_SUITE_V1],
          registry: `${apiOrigin}/v1`,
          jwks: `${apiOrigin}/.well-known/jwks.json`,
          wallet: requireHttpsOrigin(env.WALLET_ORIGIN),
        }),
        { status: 200, headers: createWellKnownHeaders() },
      ),
    };
  }

  if (url.pathname === '/.well-known/jwks.json') {
    let raw: unknown;
    try {
      raw = JSON.parse(env.SERVICE_JWKS_JSON) as unknown;
    } catch {
      throw new NexusFault('INTERNAL_ERROR');
    }
    const keyset = serviceKeySetSchema.safeParse(raw);
    if (
      !keyset.success ||
      !keyset.data.keys.some((key) => key.kid === env.RECEIPT_SIGNING_KID) ||
      !keyset.data.keys.some((key) => key.kid === env.STATUS_SIGNING_KID)
    ) {
      throw new NexusFault('INTERNAL_ERROR');
    }
    return {
      response: new Response(JSON.stringify(keyset.data), {
        status: 200,
        headers: createWellKnownHeaders(),
      }),
    };
  }

  if (route.bodyLimit === undefined) throw new NexusFault('INTERNAL_ERROR');
  const body = await readStrictJson(request, route.bodyLimit);

  if (url.pathname === '/v1/identity/register') {
    const parsed = parseRegister(body);
    if ((await deriveSubject(parsed.genesis)) !== parsed.subject) {
      throw new NexusFault('INVALID_SUBJECT');
    }
    const result = await callRegistry(() =>
      env.REGISTRY_SERVICE.register({ subject: parsed.subject, genesis: parsed.genesis }),
    );
    const mutation = await validateMutation(unwrapRegistry(result), parsed.subject);
    return {
      response: jsonResponse(
        await signedMutation(mutation, env, dependencies),
        200,
        corsHeaders(route, request, env),
      ),
    };
  }

  if (url.pathname === '/v1/identity/status') {
    const parsed = parseStatus(body);
    const result = await callRegistry(() => env.REGISTRY_SERVICE.status(parsed.subject));
    const status = await validateAuthoritativeStatus(unwrapRegistry(result), parsed.subject);
    return {
      response: jsonResponse(
        await signedStatus(status, env, dependencies),
        200,
        corsHeaders(route, request, env),
      ),
    };
  }

  if (url.pathname === '/v1/identity/status-batch') {
    const parsed = parseStatusBatch(body);
    const results = await callRegistry(() => env.REGISTRY_SERVICE.statusBatch(parsed.subjects));
    if (results.length !== parsed.subjects.length) throw new NexusFault('INTERNAL_ERROR');
    const publicResults = await Promise.all(
      results.map(async (result, index) => {
        if (!result.ok) {
          const code: NexusErrorCode = isNexusErrorCode(result.error.code)
            ? result.error.code
            : 'INTERNAL_ERROR';
          return { ok: false as const, error: createNexusErrorBody(code).error };
        }
        const expectedSubject = parsed.subjects[index];
        if (expectedSubject === undefined) throw new NexusFault('INTERNAL_ERROR');
        const status = await validateAuthoritativeStatus(result.value, expectedSubject);
        return { ok: true as const, status: await signedStatus(status, env, dependencies) };
      }),
    );
    return {
      response: jsonResponse({ results: publicResults }, 200, corsHeaders(route, request, env)),
      batchSize: parsed.subjects.length,
    };
  }

  if (url.pathname === '/v1/identity/revoke') {
    const parsed = parseRevoke(body);
    const result =
      parsed.mode === 'signature'
        ? await callRegistry(() =>
            env.REGISTRY_SERVICE.revokeBySignature({
              payload: parsed.payload,
              signature: parsed.signature,
            }),
          )
        : await callRegistry(() => env.REGISTRY_SERVICE.revokeBySecret(parsed.payload));
    const mutation = await validateMutation(unwrapRegistry(result), parsed.payload.subject);
    return {
      response: jsonResponse(
        await signedMutation(mutation, env, dependencies),
        200,
        corsHeaders(route, request, env),
      ),
    };
  }

  throw new NexusFault('BAD_REQUEST');
}

function resolveDependencies(overrides: EdgeDependencies): ResolvedDependencies {
  return {
    now: overrides.now ?? (() => Math.floor(Date.now() / 1_000)),
    monotonicNow: overrides.monotonicNow ?? (() => performance.now()),
    requestId: overrides.requestId ?? createRequestId,
    metricSink:
      overrides.metricSink === undefined ? createJsonConsoleSink(console) : overrides.metricSink,
    rateLimitKey: overrides.rateLimitKey ?? createEphemeralRateLimitKey,
    signReceipt: overrides.signReceipt ?? signRegistryReceipt,
    signStatus: overrides.signStatus ?? signStatusStatement,
  };
}

export function createEdgeApi(overrides: EdgeDependencies = {}): EdgeApi {
  const dependencies = resolveDependencies(overrides);
  return {
    async fetch(request, env): Promise<Response> {
      const startedAt = dependencies.monotonicNow();
      let route: Route | undefined;
      let requestId = '';
      let batchSize: number | undefined;
      try {
        requestId = dependencies.requestId();
        assertHttps(request, { allowLocalhost: env.ALLOW_LOCALHOST_HTTP === 'true' });
        route = ROUTES[new URL(request.url).pathname];
        if (route === undefined) throw new NexusFault('BAD_REQUEST');
        const routed = await routeRequest(request, env, route, dependencies, requestId);
        batchSize = routed.batchSize;
        if (dependencies.metricSink !== null) {
          emitAggregateMetric(dependencies.metricSink, {
            operation: route.operation,
            result: 'ok',
            latencyBucket: latencyBucket(dependencies.monotonicNow() - startedAt),
            ...(batchSize === undefined ? {} : { sizeBucket: sizeBucket(batchSize) }),
          });
        }
        return routed.response;
      } catch (error) {
        const code = faultCode(error);
        if (route !== undefined && dependencies.metricSink !== null) {
          emitAggregateMetric(dependencies.metricSink, {
            operation: route.operation,
            result:
              code === 'INTERNAL_ERROR' || code === 'SERVICE_UNAVAILABLE' ? 'error' : 'rejected',
            latencyBucket: latencyBucket(dependencies.monotonicNow() - startedAt),
            errorCode: code,
          });
        }
        const headers = corsHeaders(route, request, env);
        if (code === 'METHOD_NOT_ALLOWED' && route !== undefined) {
          headers.set('Allow', route.method);
        }
        if (code === 'RATE_LIMITED') {
          headers.set('Retry-After', String(RATE_LIMIT_PERIOD_SECONDS));
        }
        return toNexusErrorResponse(error, {
          requestId,
          headers,
        });
      }
    },
  };
}

export default createEdgeApi() satisfies ExportedHandler<Env>;
