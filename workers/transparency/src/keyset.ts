import { encodeBase64Url, serviceKeySetSchema, type ServiceKeySet } from '@nexus/protocol';
import { WebCryptoProvider, type CryptoProvider } from '@nexus/crypto';

import { TransparencyError } from './errors.js';

export const TRANSPARENCY_KEYSET_PATH = '/.well-known/nexus-transparency-keys.json' as const;

const KEYSET_CACHE_CONTROL = 'public, max-age=300, stale-while-revalidate=60';
const KEYSET_HEADERS = {
  'access-control-allow-origin': '*',
  'cache-control': KEYSET_CACHE_CONTROL,
  'content-security-policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
  'content-type': 'application/json; charset=utf-8',
  'referrer-policy': 'no-referrer',
  'x-content-type-options': 'nosniff',
} as const;

/**
 * Parses the complete public transparency signing-key history from one strict
 * environment JSON value. The endpoint path supplies the key-purpose context;
 * custom JWK purpose members are deliberately rejected by the shared schema.
 */
export function parseTransparencyKeySet(rawJson: string, currentSignerKid: string): ServiceKeySet {
  let decoded: unknown;
  try {
    decoded = JSON.parse(rawJson) as unknown;
  } catch {
    throw invalidKeySet();
  }

  const parsed = serviceKeySetSchema.safeParse(decoded);
  if (!parsed.success) {
    throw invalidKeySet();
  }
  if (!parsed.data.keys.some((key) => key.kid === currentSignerKid)) {
    throw invalidKeySet();
  }
  return parsed.data;
}

export async function createTransparencyKeySetResponse(
  request: Request,
  keySet: ServiceKeySet,
  provider: CryptoProvider = new WebCryptoProvider(),
): Promise<Response> {
  const body = JSON.stringify(keySet);
  const etag = `"${encodeBase64Url(await provider.sha256(new TextEncoder().encode(body)))}"`;
  const headers = new Headers(KEYSET_HEADERS);
  headers.set('etag', etag);

  if (matchesEtag(request.headers.get('if-none-match'), etag)) {
    headers.delete('content-type');
    return new Response(null, { status: 304, headers });
  }
  return new Response(body, { status: 200, headers });
}

function matchesEtag(ifNoneMatch: string | null, etag: string): boolean {
  return (
    ifNoneMatch
      ?.split(',')
      .map((candidate) => candidate.trim())
      .some((candidate) => candidate === '*' || candidate === etag) ?? false
  );
}

function invalidKeySet(): TransparencyError {
  return new TransparencyError(
    'INVALID_SERVICE_CONFIGURATION',
    'The transparency verification keyset is not configured correctly.',
    500,
  );
}
