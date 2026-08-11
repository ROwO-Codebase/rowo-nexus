import type { IncomingMessage, ServerResponse } from 'node:http';

import type { Plugin, PreviewServer, ViteDevServer } from 'vite';

import type { ApiErrorBody } from '../shared/contracts.js';
import { toSafeApiError } from './errors.js';
import { AuthoritativeRegistryLifecycleProvider, LocalLifecycleAuthority } from './lifecycle.js';
import { ReferenceRpRepository } from './repository.js';

const MAX_BODY_BYTES = 64 * 1024;
const SECURITY_HEADERS: Readonly<Record<string, string>> = {
  'Content-Security-Policy':
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ws: wss:; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
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
      sendJson(response, 200, { notes: repository.listNotes() });
      return;
    }
    if (request.method === 'GET' && url.pathname.startsWith('/api/notes/')) {
      const id = decodeURIComponent(url.pathname.slice('/api/notes/'.length));
      sendJson(response, 200, { note: repository.getNote(id) });
      return;
    }
    if (request.method === 'POST' && url.pathname === '/api/challenges') {
      const body = await readJson(request);
      sendJson(response, 201, { challenge: repository.issueChallenge(body) });
      return;
    }
    if (request.method === 'POST' && url.pathname === '/api/operations') {
      const body = await readJson(request);
      sendJson(response, 200, await repository.submitOperation(body));
      return;
    }
    if (request.method === 'GET' && url.pathname === '/api/session') {
      const token = readSessionToken(request.headers.authorization);
      sendJson(response, 200, { session: await repository.getSession(token) });
      return;
    }
    sendJson(response, 404, { error: { code: 'NOT_FOUND', message: 'API route not found.' } });
  } catch (error) {
    const safe = toSafeApiError(error);
    const body: ApiErrorBody = { error: { code: safe.code, message: safe.message } };
    sendJson(response, safe.status, body);
  }
}

function readSessionToken(header: string | undefined): string {
  if (header === undefined || !header.startsWith('NexusSession ')) return '';
  return header.slice('NexusSession '.length);
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
