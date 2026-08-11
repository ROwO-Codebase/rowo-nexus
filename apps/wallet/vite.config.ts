import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';

import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import { defineConfig, loadEnv, type Plugin } from 'vite';

export const CANONICAL_NEXUS_API_ORIGIN = 'https://nexus.rowo.link';
export const LOCAL_NEXUS_API_ORIGIN = 'http://localhost:8787';

export function resolveNexusApiOrigin(value: string | undefined, mode: string): string {
  const production = mode === 'production';
  const raw = value?.trim() || (production ? CANONICAL_NEXUS_API_ORIGIN : LOCAL_NEXUS_API_ORIGIN);
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error('VITE_NEXUS_API_URL must be a valid absolute URL.');
  }
  const localHostname =
    url.hostname === 'localhost' || url.hostname === '127.0.0.1' || url.hostname === '[::1]';
  const allowedProtocol =
    url.protocol === 'https:' || (!production && url.protocol === 'http:' && localHostname);
  if (!allowedProtocol) {
    throw new Error(
      production
        ? 'Production VITE_NEXUS_API_URL must use HTTPS.'
        : 'Development VITE_NEXUS_API_URL must use HTTPS or loopback HTTP.',
    );
  }
  if (
    url.username !== '' ||
    url.password !== '' ||
    url.pathname !== '/' ||
    url.search !== '' ||
    url.hash !== ''
  ) {
    throw new Error(
      'VITE_NEXUS_API_URL must be an exact origin without credentials, path, query, or hash.',
    );
  }
  return url.origin;
}

export function renderWalletHeaders(apiOrigin: string): string {
  return `/*
  Cache-Control: no-store
  Content-Security-Policy: default-src 'self'; base-uri 'none'; object-src 'none'; frame-src 'none'; frame-ancestors 'none'; form-action 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'none'; connect-src 'self' ${apiOrigin}; manifest-src 'self'; worker-src 'none'
  Cross-Origin-Opener-Policy: unsafe-none
  Cross-Origin-Resource-Policy: same-origin
  Permissions-Policy: accelerometer=(), camera=(), geolocation=(), gyroscope=(), microphone=(), payment=(), usb=()
  Referrer-Policy: no-referrer
  X-Content-Type-Options: nosniff
  X-Frame-Options: DENY

/assets/*
  Cache-Control: public, max-age=31536000, immutable
`;
}

function walletHeadersPlugin(apiOrigin: string): Plugin {
  let outputFile = '';
  return {
    name: 'nexus-wallet-security-headers',
    configResolved(config) {
      outputFile = resolve(config.root, config.build.outDir, '_headers');
    },
    async closeBundle() {
      if (outputFile === '') throw new Error('The wallet header output path was not resolved.');
      await writeFile(outputFile, renderWalletHeaders(apiOrigin), 'utf8');
    },
  };
}

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, '.', 'VITE_');
  const apiOrigin = resolveNexusApiOrigin(env.VITE_NEXUS_API_URL, mode);
  return {
    plugins: [react(), tailwindcss(), walletHeadersPlugin(apiOrigin)],
    build: {
      target: 'es2022',
      sourcemap: true,
    },
    server: {
      strictPort: true,
    },
  };
});
