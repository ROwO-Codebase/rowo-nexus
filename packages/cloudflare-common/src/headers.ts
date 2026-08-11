export const NEXUS_JSON_MEDIA_TYPE = 'application/nexus+json';

export interface WalletHeaderOptions {
  readonly apiOrigin: string;
  readonly additionalConnectOrigins?: readonly string[];
}

export type CorsPolicy =
  | { readonly mode: 'public' }
  | { readonly mode: 'exact'; readonly allowedOrigins: readonly string[] };

function appendVary(headers: Headers, value: string): void {
  const existing = headers.get('Vary');
  const values = new Set(
    existing
      ?.split(',')
      .map((entry) => entry.trim())
      .filter((entry) => entry.length > 0),
  );
  values.add(value);
  headers.set('Vary', [...values].join(', '));
}

export function parseExactOrigin(value: string): string | null {
  try {
    const url = new URL(value);
    if (
      url.origin === 'null' ||
      (url.protocol !== 'https:' && url.protocol !== 'http:') ||
      url.username.length > 0 ||
      url.password.length > 0 ||
      url.pathname !== '/' ||
      url.search.length > 0 ||
      url.hash.length > 0
    ) {
      return null;
    }
    return url.origin;
  } catch {
    return null;
  }
}

export function isExactOriginAllowed(origin: string, allowedOrigins: readonly string[]): boolean {
  const parsedOrigin = parseExactOrigin(origin);
  if (parsedOrigin === null || parsedOrigin !== origin) {
    return false;
  }

  return allowedOrigins.some((allowed) => parseExactOrigin(allowed) === parsedOrigin);
}

export function createCorsHeaders(origin: string | null, policy: CorsPolicy): Headers {
  const headers = new Headers();
  if (policy.mode === 'public') {
    headers.set('Access-Control-Allow-Origin', '*');
    return headers;
  }

  appendVary(headers, 'Origin');
  if (origin !== null && isExactOriginAllowed(origin, policy.allowedOrigins)) {
    headers.set('Access-Control-Allow-Origin', origin);
  }
  return headers;
}

export function createApiHeaders(init?: HeadersInit): Headers {
  const headers = new Headers(init);
  headers.set('Cache-Control', 'no-store');
  headers.set('Content-Type', NEXUS_JSON_MEDIA_TYPE);
  headers.set('Referrer-Policy', 'no-referrer');
  headers.set('X-Content-Type-Options', 'nosniff');
  return headers;
}

export function createWellKnownHeaders(
  options: {
    readonly maxAgeSeconds?: number;
    readonly etag?: string;
    readonly init?: HeadersInit;
  } = {},
): Headers {
  const maxAgeSeconds = options.maxAgeSeconds ?? 300;
  if (!Number.isSafeInteger(maxAgeSeconds) || maxAgeSeconds < 0) {
    throw new RangeError('maxAgeSeconds must be a non-negative safe integer');
  }

  const headers = new Headers(options.init);
  headers.set('Cache-Control', `public, max-age=${String(maxAgeSeconds)}, must-revalidate`);
  headers.set('Access-Control-Allow-Origin', '*');
  headers.set('Content-Type', NEXUS_JSON_MEDIA_TYPE);
  headers.set('Referrer-Policy', 'no-referrer');
  headers.set('X-Content-Type-Options', 'nosniff');
  if (options.etag !== undefined) {
    headers.set('ETag', options.etag);
  }
  return headers;
}

function requireCspOrigin(value: string): string {
  const origin = parseExactOrigin(value);
  if (origin === null) {
    throw new TypeError('CSP connect origins must be valid HTTP(S) origins');
  }
  return origin;
}

export function createWalletHeaders(options: WalletHeaderOptions): Headers {
  const connectOrigins = [
    requireCspOrigin(options.apiOrigin),
    ...(options.additionalConnectOrigins ?? []).map(requireCspOrigin),
  ];
  const connectSource = [...new Set(connectOrigins)].join(' ');
  const headers = new Headers();

  headers.set('Cache-Control', 'no-store');
  headers.set(
    'Content-Security-Policy',
    [
      "default-src 'self'",
      "script-src 'self'",
      "style-src 'self'",
      "img-src 'self' data:",
      `connect-src ${connectSource}`,
      "object-src 'none'",
      "base-uri 'none'",
      "frame-ancestors 'none'",
      "form-action 'self'",
    ].join('; ') + ';',
  );
  headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
  headers.set('Referrer-Policy', 'no-referrer');
  headers.set('X-Content-Type-Options', 'nosniff');
  headers.set('X-Frame-Options', 'DENY');
  return headers;
}
