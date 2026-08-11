import basicSsl from '@vitejs/plugin-basic-ssl';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import { defineConfig } from 'vite';

import { createReferenceRpApiPlugin } from './src/backend/vite-plugin.js';

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
