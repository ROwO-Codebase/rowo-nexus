import { NexusFault, toNexusErrorResponse } from './errors.js';
import { createApiHeaders, isExactOriginAllowed, NEXUS_JSON_MEDIA_TYPE } from './headers.js';

export interface PreflightOptions {
  readonly allowedOrigins: readonly string[];
  readonly allowedMethods: readonly string[];
  readonly allowedHeaders?: readonly string[];
  readonly maxAgeSeconds?: number;
  readonly requestId?: string;
}

export const NEXUS_BODY_LIMITS = Object.freeze({
  register: 4 * 1_024,
  status: 1 * 1_024,
  statusBatch: 16 * 1_024,
  revoke: 8 * 1_024,
  notaryStamp: 1 * 1_024,
});

export function assertMethod(request: Request, allowedMethods: readonly string[]): void {
  const method = request.method.toUpperCase();
  if (!allowedMethods.some((allowed) => allowed.toUpperCase() === method)) {
    throw new NexusFault('METHOD_NOT_ALLOWED');
  }
}

export function assertHttps(
  request: Request,
  options: { readonly allowLocalhost?: boolean } = {},
): void {
  const url = new URL(request.url);
  const local =
    url.hostname === 'localhost' || url.hostname === '127.0.0.1' || url.hostname === '[::1]';
  if (url.protocol !== 'https:' && !(options.allowLocalhost === true && local)) {
    throw new NexusFault('HTTPS_REQUIRED');
  }
}

export function assertNexusContentType(request: Request): void {
  const raw = request.headers.get('Content-Type');
  if (raw === null) {
    throw new NexusFault('UNSUPPORTED_MEDIA_TYPE');
  }

  const [mediaType, ...parameters] = raw.split(';').map((part) => part.trim().toLowerCase());
  const parametersAreValid = parameters.every((parameter) => parameter === 'charset=utf-8');
  if (mediaType !== NEXUS_JSON_MEDIA_TYPE || !parametersAreValid) {
    throw new NexusFault('UNSUPPORTED_MEDIA_TYPE');
  }
}

/**
 * Enforces browser-origin policy when an Origin header is present. Requests
 * without Origin remain eligible for separately approved native/CLI policy.
 */
export function assertExactRequestOrigin(
  request: Request,
  allowedOrigins: readonly string[],
): void {
  const origin = request.headers.get('Origin');
  if (origin !== null && !isExactOriginAllowed(origin, allowedOrigins)) {
    throw new NexusFault('ORIGIN_NOT_ALLOWED');
  }
}

function declaredContentLength(request: Request): number | null {
  const value = request.headers.get('Content-Length');
  if (value === null) {
    return null;
  }
  if (!/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new NexusFault('BAD_REQUEST');
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) {
    throw new NexusFault('BODY_TOO_LARGE');
  }
  return parsed;
}

function assertBodyLimit(maxBytes: number): void {
  if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0) {
    throw new RangeError('maxBytes must be a positive safe integer');
  }
}

export async function readBodyBytes(request: Request, maxBytes: number): Promise<Uint8Array> {
  assertBodyLimit(maxBytes);
  const declared = declaredContentLength(request);
  if (declared !== null && declared > maxBytes) {
    throw new NexusFault('BODY_TOO_LARGE');
  }
  if (request.body === null) {
    throw new NexusFault('BAD_REQUEST');
  }

  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        throw new NexusFault('BODY_TOO_LARGE');
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  if (declared !== null && declared !== total) {
    throw new NexusFault('BAD_REQUEST');
  }

  const result = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return result;
}

export async function readJsonBody(request: Request, maxBytes: number): Promise<unknown> {
  assertNexusContentType(request);
  const bytes = await readBodyBytes(request, maxBytes);
  if (bytes.byteLength === 0) {
    throw new NexusFault('BAD_REQUEST');
  }

  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    return JSON.parse(text) as unknown;
  } catch (error) {
    if (error instanceof NexusFault) {
      throw error;
    }
    throw new NexusFault('BAD_REQUEST', { cause: error });
  }
}

function parseRequestedHeaders(value: string | null): readonly string[] {
  if (value === null || value.trim().length === 0) {
    return [];
  }
  return value
    .split(',')
    .map((header) => header.trim().toLowerCase())
    .filter((header) => header.length > 0);
}

export function handleExactOriginPreflight(
  request: Request,
  options: PreflightOptions,
): Response | null {
  if (request.method.toUpperCase() !== 'OPTIONS') {
    return null;
  }

  const origin = request.headers.get('Origin');
  const requestedMethod = request.headers.get('Access-Control-Request-Method')?.toUpperCase();
  if (origin === null || requestedMethod === undefined) {
    return toNexusErrorResponse(new NexusFault('BAD_REQUEST'), { requestId: options.requestId });
  }
  if (!isExactOriginAllowed(origin, options.allowedOrigins)) {
    return toNexusErrorResponse(new NexusFault('ORIGIN_NOT_ALLOWED'), {
      requestId: options.requestId,
    });
  }

  const allowedMethods = options.allowedMethods.map((method) => method.toUpperCase());
  if (!allowedMethods.includes(requestedMethod)) {
    return toNexusErrorResponse(new NexusFault('METHOD_NOT_ALLOWED'), {
      requestId: options.requestId,
    });
  }

  const allowedHeaders = (options.allowedHeaders ?? ['content-type']).map((header) =>
    header.toLowerCase(),
  );
  const requestedHeaders = parseRequestedHeaders(
    request.headers.get('Access-Control-Request-Headers'),
  );
  if (!requestedHeaders.every((header) => allowedHeaders.includes(header))) {
    return toNexusErrorResponse(new NexusFault('BAD_REQUEST'), { requestId: options.requestId });
  }

  const maxAgeSeconds = options.maxAgeSeconds ?? 300;
  if (!Number.isSafeInteger(maxAgeSeconds) || maxAgeSeconds < 0) {
    throw new RangeError('maxAgeSeconds must be a non-negative safe integer');
  }

  const headers = createApiHeaders();
  headers.set('Access-Control-Allow-Origin', origin);
  headers.set('Access-Control-Allow-Methods', allowedMethods.join(', '));
  headers.set('Access-Control-Allow-Headers', allowedHeaders.join(', '));
  headers.set('Access-Control-Max-Age', String(maxAgeSeconds));
  headers.set('Vary', 'Origin, Access-Control-Request-Method, Access-Control-Request-Headers');
  return new Response(null, { status: 204, headers });
}
