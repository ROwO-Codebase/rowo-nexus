import { TransparencyError } from './errors.js';

const NEXUS_CONTENT_TYPE = 'application/nexus+json';
const JSON_HEADERS = {
  'cache-control': 'no-store',
  'content-security-policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
  'content-type': `${NEXUS_CONTENT_TYPE}; charset=utf-8`,
  'referrer-policy': 'no-referrer',
  'x-content-type-options': 'nosniff',
} as const;

export function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: JSON_HEADERS,
  });
}

export function errorResponse(error: unknown): Response {
  if (error instanceof TransparencyError) {
    return jsonResponse({ error: { code: error.code, message: error.message } }, error.status);
  }
  return jsonResponse(
    { error: { code: 'INTERNAL_ERROR', message: 'The request could not be completed.' } },
    500,
  );
}

export function requireNexusJson(request: Request): void {
  const rawContentType = request.headers.get('content-type');
  const parts = rawContentType?.split(';').map((part) => part.trim().toLowerCase());
  const mediaType = parts?.[0];
  const parameters = parts?.slice(1) ?? [];
  if (
    mediaType !== NEXUS_CONTENT_TYPE ||
    !parameters.every((parameter) => parameter === 'charset=utf-8')
  ) {
    throw new TransparencyError('BAD_REQUEST', `Content-Type must be ${NEXUS_CONTENT_TYPE}.`, 415);
  }
}

export async function readSmallJson(request: Request, maximumBytes = 1024): Promise<unknown> {
  const declaredLength = request.headers.get('content-length');
  let parsedDeclaredLength: number | undefined;
  if (declaredLength !== null) {
    if (!/^(0|[1-9][0-9]*)$/.test(declaredLength)) {
      throw new TransparencyError('BAD_REQUEST', 'Content-Length is invalid.', 400);
    }
    parsedDeclaredLength = Number(declaredLength);
    if (
      !Number.isSafeInteger(parsedDeclaredLength) ||
      parsedDeclaredLength < 0 ||
      parsedDeclaredLength > maximumBytes
    ) {
      throw new TransparencyError('BODY_TOO_LARGE', 'The request body is too large.', 413);
    }
  }

  if (request.body === null) {
    throw new TransparencyError('BAD_REQUEST', 'A JSON request body is required.', 400);
  }
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) {
        break;
      }
      total += chunk.value.byteLength;
      if (total > maximumBytes) {
        await reader.cancel();
        throw new TransparencyError('BODY_TOO_LARGE', 'The request body is too large.', 413);
      }
      chunks.push(chunk.value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  if (parsedDeclaredLength !== undefined && parsedDeclaredLength !== bytes.byteLength) {
    throw new TransparencyError(
      'BAD_REQUEST',
      'Content-Length does not match the request body.',
      400,
    );
  }
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as unknown;
  } catch {
    throw new TransparencyError('BAD_REQUEST', 'The request body must be valid JSON.', 400);
  }
}

export function parseExactStringObject(input: unknown, field: string): string {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) {
    throw new TransparencyError('BAD_REQUEST', 'The request body must be an object.', 400);
  }
  const entries = Object.entries(input);
  if (entries.length !== 1 || entries[0]?.[0] !== field || typeof entries[0][1] !== 'string') {
    throw new TransparencyError(
      'BAD_REQUEST',
      `The request body must contain exactly one string field named ${field}.`,
      400,
    );
  }
  return entries[0][1];
}
