import { WorkerEntrypoint } from 'cloudflare:workers';

import type { ReferenceRpState, ReferenceRpEnv } from './reference-rp-state';

export { ReferenceRpState } from './reference-rp-state';

interface Env extends ReferenceRpEnv {
  readonly ASSETS: Fetcher;
  readonly RP_STATE: DurableObjectNamespace<ReferenceRpState>;
  readonly RP_API_RATE_LIMITER: RateLimiter;
}

interface RateLimiter {
  limit(options: { readonly key: string }): Promise<{ readonly success: boolean }>;
}

const RATE_LIMIT_PERIOD_SECONDS = 60;
const RATE_LIMIT_DOMAIN = 'NEXUS-REFERENCE-RP-RATE-LIMIT\0v1\0';
let rateLimitSalt: { bucket: number; value: Uint8Array } | undefined;

const SECURITY_HEADERS: Readonly<Record<string, string>> = Object.freeze({
  'Content-Security-Policy':
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' https://pi3.dev; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
  'Cross-Origin-Opener-Policy': 'unsafe-none',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
});

export default class ReferenceRpWorker extends WorkerEntrypoint<Env> {
  public override async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const requestId = createRequestId();
    let response: Response;
    const api = url.pathname.startsWith('/api/');

    try {
      if (isLimitedRoute(request, url)) {
        response = await rateLimitResponse(request, this.env);
        if (response.status !== 204) {
          return withSecurityHeaders(response, requestId, true);
        }
      }
      if (api) {
        const state = this.env.RP_STATE.getByName('reference-rp-primary');
        const internalUrl = new URL(request.url);
        internalUrl.protocol = 'https:';
        internalUrl.host = 'reference-rp-state.internal';
        response = await state.fetch(new Request(internalUrl, request));
      } else {
        response = await this.env.ASSETS.fetch(request);
      }
    } catch {
      response = api
        ? new Response(
            JSON.stringify({
              error: {
                code: 'SERVICE_UNAVAILABLE',
                message: 'The reference service is temporarily unavailable.',
              },
            }),
            { status: 503, headers: { 'Content-Type': 'application/json; charset=utf-8' } },
          )
        : new Response('Service unavailable.', { status: 503 });
    }

    if (response.status >= 500) {
      console.error(
        JSON.stringify({
          event: 'reference_rp_request_failed',
          requestId,
          route: api ? 'api' : 'asset',
          status: response.status,
        }),
      );
    }
    return withSecurityHeaders(response, requestId, api);
  }
}

function isLimitedRoute(request: Request, url: URL): boolean {
  return (
    request.method === 'POST' &&
    (url.pathname === '/api/challenges' ||
      url.pathname === '/api/operations' ||
      url.pathname === '/api/session-operations')
  );
}

async function rateLimitResponse(request: Request, env: Env): Promise<Response> {
  try {
    const key = await createRateLimitKey(request);
    const decision = await env.RP_API_RATE_LIMITER.limit({ key });
    if (typeof decision?.success !== 'boolean') throw new TypeError('Invalid rate-limit result.');
    if (decision.success) return new Response(null, { status: 204 });
    return new Response(
      JSON.stringify({
        error: { code: 'RATE_LIMITED', message: 'Request rate limit exceeded.' },
      }),
      {
        status: 429,
        headers: { 'Content-Type': 'application/json; charset=utf-8', 'Retry-After': '60' },
      },
    );
  } catch {
    return new Response(
      JSON.stringify({
        error: {
          code: 'SERVICE_UNAVAILABLE',
          message: 'The reference service is temporarily unavailable.',
        },
      }),
      { status: 503, headers: { 'Content-Type': 'application/json; charset=utf-8' } },
    );
  }
}

async function createRateLimitKey(request: Request): Promise<string> {
  const suppliedAddress = request.headers.get('CF-Connecting-IP')?.trim();
  const address =
    suppliedAddress !== undefined && suppliedAddress.length > 0 && suppliedAddress.length <= 64
      ? suppliedAddress
      : 'unknown';
  const bucket = Math.floor(Date.now() / 1_000 / RATE_LIMIT_PERIOD_SECONDS);
  if (rateLimitSalt?.bucket !== bucket) {
    rateLimitSalt?.value.fill(0);
    rateLimitSalt = { bucket, value: crypto.getRandomValues(new Uint8Array(32)) };
  }
  const input = new TextEncoder().encode(`${RATE_LIMIT_DOMAIN}${String(bucket)}\0${address}`);
  const preimage = new Uint8Array(rateLimitSalt.value.byteLength + input.byteLength);
  preimage.set(rateLimitSalt.value);
  preimage.set(input, rateLimitSalt.value.byteLength);
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', preimage.buffer));
  preimage.fill(0);
  input.fill(0);
  let encoded = '';
  for (const byte of digest) encoded += byte.toString(16).padStart(2, '0');
  digest.fill(0);
  return `nexus-reference-rp-v1:${String(bucket)}:${encoded}`;
}

function withSecurityHeaders(response: Response, requestId: string, api: boolean): Response {
  const headers = new Headers(response.headers);
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) headers.set(name, value);
  headers.set('X-Request-ID', requestId);
  if (api) headers.set('Cache-Control', 'no-store');
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function createRequestId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(12));
  let output = '';
  for (const byte of bytes) output += byte.toString(16).padStart(2, '0');
  return output;
}
