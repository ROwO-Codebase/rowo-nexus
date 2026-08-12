import basicSsl from '@vitejs/plugin-basic-ssl';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import { defineConfig } from 'vite';

import { createReferenceRpApiPlugin } from './src/backend/vite-plugin.js';

const DEFAULT_SERVICE_JWKS_JSON =
  '{"keys":[{"kty":"OKP","crv":"Ed25519","alg":"EdDSA","kid":"rowo-status-2026-08","x":"p_0wFlB-khNLDc_66RYGHG98JY_lrhXtzj5tNEuy4SE","use":"sig"}]}';

function serviceKeyset(): unknown {
  const raw = process.env['NEXUS_SERVICE_JWKS_JSON'] ?? DEFAULT_SERVICE_JWKS_JSON;
  try {
    return JSON.parse(raw) as unknown;
  } catch (error) {
    throw new TypeError('NEXUS_SERVICE_JWKS_JSON must contain valid JSON.', { cause: error });
  }
}

export default defineConfig(({ command }) => ({
  plugins: [
    ...(command === 'serve' ? [basicSsl()] : []),
    react(),
    tailwindcss(),
    createReferenceRpApiPlugin({
      audience: process.env['NEXUS_RP_ORIGIN'] ?? 'https://notes.rowo.link',
      nexusApiUrl:
        process.env['NEXUS_API_URL'] ??
        process.env['VITE_NEXUS_API_URL'] ??
        'https://nexus.rowo.link',
      serviceKeyset: serviceKeyset(),
      unsafeLocalLifecycle: process.env['NEXUS_LOCAL_LIFECYCLE_MODE'] === 'unsafe-local-test',
    }),
  ],
  server: {
    strictPort: true,
  },
  preview: {
    strictPort: true,
  },
  build: {
    target: 'es2022',
    sourcemap: true,
  },
}));
