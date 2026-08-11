import type { IncomingMessage, ServerResponse } from 'node:http';

import type { Plugin, PreviewServer, ViteDevServer } from 'vite';

import type { ApiErrorBody } from '../shared/contracts.js';
import { RpError, toSafeApiError } from './errors.js';
import { AuthoritativeRegistryLifecycleProvider, LocalLifecycleAuthority } from './lifecycle.js';
import { ReferenceRpRepository } from './repository.js';

const MAX_BODY_BYTES = 64 * 1024;
const SESSION_TTL_SECONDS = 5 * 60;
const SESSION_COOKIE_NAME = '__Host-nexus_notes_session';
const SECURITY_HEADERS: Readonly<Record<string, string>> = {
  'Content-Security-Policy':
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' https://pi3.dev ws: wss:; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
  'Cross-Origin-Opener-Policy': 'unsafe-none',
};

export interface ReferenceRpApiPluginOptions {
  audience: string;
  nexusApiUrl: string;
  unsafeLocalLifecycle?: boolean;
}

export function createReferenceRpApiPlugin(options: ReferenceRpApiPluginOptions): Plugin {
  const lifecycle =
    options.unsafeLocalLifecycle === true
      ? new LocalLifecycleAuthority()
      : new AuthoritativeRegistryLifecycleProvider(options.nexusApiUrl);
  const repository = new ReferenceRpRepository({ audience: options.audience, lifecycle });
  const attach = (server: ViteDevServer | PreviewServer): void => {
    server.middlewares.use((request, response, next) => {
      for (const [name, value] of Object.entries(SECURITY_HEADERS)) response.setHeader(name, value);
      if (!request.url?.startsWith('/api/')) {
        next();
        return;
      }
      void routeApi(repository, request, response);
    });
  };

  return {
    name: 'nexus-reference-rp-api',
    configureServer: attach,
    configurePreviewServer: attach,
  };
}

async function routeApi(
  repository: ReferenceRpRepository,
  request: IncomingMessage,
  response: ServerResponse,
): Promise<void> {
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('Content-Type', 'application/json; charset=utf-8');

  try {
    const url = new URL(request.url ?? '/', 'https://reference-rp.invalid');
    if (request.method === 'GET' && url.pathname === '/api/health') {
      sendJson(response, 200, { ok: true });
      return;
    }
    if (request.method === 'GET' && url.pathname === '/api/notes') {
      sendJson(response, 200, { notes: await repository.listNotes(readSessionToken(request)) });
      return;
    }
    if (request.method === 'GET' && url.pathname.startsWith('/api/notes/')) {
      const id = decodeURIComponent(url.pathname.slice('/api/notes/'.length));
      sendJson(response, 200, { note: await repository.getNote(id, readSessionToken(request)) });
      return;
    }
    if (request.method === 'POST' && url.pathname === '/api/challenges') {
      const body = await readJson(request);
      sendJson(response, 201, { challenge: repository.issueChallenge(body) });
      return;
    }
    if (request.method === 'POST' && url.pathname === '/api/operations') {
      const body = await readJson(request);
      const started = await repository.startSession(body);
      response.setHeader('Set-Cookie', createSessionCookie(started.token));
      sendJson(response, 200, started.result);
      return;
    }
    if (request.method === 'POST' && url.pathname === '/api/session-operations') {
      assertSessionMutationRequest(request);
      const body = await readJson(request);
      sendJson(
        response,
        200,
        await repository.executeSessionOperation(body, readSessionToken(request)),
      );
      return;
    }
    if (request.method === 'GET' && url.pathname === '/api/session') {
      sendJson(response, 200, { session: await repository.getSession(readSessionToken(request)) });
      return;
    }
    if (request.method === 'DELETE' && url.pathname === '/api/session') {
      assertSessionMutationRequest(request);
      repository.endSession(readSessionToken(request));
      response.setHeader('Set-Cookie', clearSessionCookie());
      sendJson(response, 200, { ok: true });
      return;
    }
    sendJson(response, 404, { error: { code: 'NOT_FOUND', message: 'API route not found.' } });
  } catch (error) {
    const safe = toSafeApiError(error);
    const body: ApiErrorBody = { error: { code: safe.code, message: safe.message } };
    sendJson(response, safe.status, body);
  }
}

function readSessionToken(request: IncomingMessage): string {
  const header = request.headers.cookie;
  if (header === undefined) return '';
  for (const segment of header.split(';')) {
    const [rawName, ...rawValue] = segment.trim().split('=');
    if (rawName !== SESSION_COOKIE_NAME) continue;
    const token = rawValue.join('=');
    return /^[A-Za-z0-9_-]{43}$/u.test(token) ? token : '';
  }
  return '';
}

function createSessionCookie(token: string): string {
  return `${SESSION_COOKIE_NAME}=${token}; Path=/; Max-Age=${String(SESSION_TTL_SECONDS)}; Secure; HttpOnly; SameSite=Strict`;
}

function clearSessionCookie(): string {
  return `${SESSION_COOKIE_NAME}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict`;
}

function assertSessionMutationRequest(request: IncomingMessage): void {
  if (request.headers['x-nexus-notes-session'] !== '1') {
    throw new RpError('BAD_REQUEST', 'The session request marker is missing.', 400);
  }
}

async function readJson(request: IncomingMessage): Promise<unknown> {
  const contentType = request.headers['content-type']?.split(';', 1)[0]?.trim().toLowerCase();
  if (contentType !== 'application/json') {
    throw new Error('Requests must use application/json.');
  }
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array);
    size += buffer.byteLength;
    if (size > MAX_BODY_BYTES) throw new Error('Request body is too large.');
    chunks.push(buffer);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown;
  } catch {
    throw new Error('Request body is not valid JSON.');
  }
}

function sendJson(response: ServerResponse, status: number, value: unknown): void {
  response.statusCode = status;
  response.end(JSON.stringify(value));
}
