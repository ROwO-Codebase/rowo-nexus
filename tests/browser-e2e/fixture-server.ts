import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

import tailwindcss from '../../apps/wallet/node_modules/@tailwindcss/vite/dist/index.mjs';
import {
  createServer,
  type Plugin,
  type ViteDevServer,
} from '../../apps/wallet/node_modules/vite/dist/node/index.js';

import { createReferenceRpApiPlugin } from '../../apps/reference-rp/src/backend/vite-plugin.js';
import { REGISTRY_ORIGIN, RP_A_ORIGIN, RP_B_ORIGIN, WALLET_ORIGIN } from './origins.js';
import { startRegistryFixture } from './registry-fixture.js';

const TLS_PFX_BASE64 =
  'MIIJagIBAzCCCSYGCSqGSIb3DQEHAaCCCRcEggkTMIIJDzCCBZAGCSqGSIb3DQEHAaCCBYEEggV9MIIFeTCCBXUGCyqGSIb3DQEMCgECoIIE7jCCBOowHAYKKoZIhvcNAQwBAzAOBAgBuFs33LOhvQICB9AEggTIUraSIsQUYIy6F728mC0bqqvhHc46az4HszAPt6wBJWYg2OOYCsuGruvj8bNSpK3dL0LGlNTu1Ja9IqTcEPP/yJsR57ry+ycjkPeyNBipzDNXpk0ItG8SbPAFASof07upVas/GAGYPF7GdZn3nS08uUlxq6isc45BCvgzcsDAC8emx33sf6apUPm/cXYjFsZLR+QwfkTIS8vf1N3uWpCTts9o7tcJaTKJLYNNpKAGD5rrTdyou3zND0LS8Pw3mAgEwLFXkXEXDA5twCTN/BFV+jA/ud2szNh0oUCl8CS2RoeDVZz2gEuXL8hdAxYK1n8yUhEKcFINj2AFEEdZZjLBQDegSEnBktImkIjJ/qL/8BlxBfktDBADtfjFJQMeOAd05Em4BccIokh1lzgp7CzLsgP0Owf1huvaCoi8l5b0yRGpn6QjnLOUE4EjkfJJet0Qp011woc6ejtEYq2hotAOoxubmQ+XU96jl4Put6HN75M7RMwq+9nyt1zjQVLE8BMCyL1ym8nSOZWTh8zNR8fbuGnlEHI7QEiyQk+930FUE9bX+MFUTnIK5CvIcFnBEA2zZ3ouBK5Qpn3pJY/52NXyrtfexLP2NJlpR2tCUOQ7coQ07qSn50QE5m62TLWaCJOL5qzOKTAeZX8HzksDaJarTuxySeGl6n/h1Xuqs9xAXOsLOrNYe6gKqmINtVYxmn4UQmfHWqWEjoWFuEKNaoyStHt7cIz6T64d/L0hR5cMP+uyrri3pkKqmCs3OkDlB68OpieBauE27SvhTGh70Eak6AMJz0THRnR4MTOZorg20bTjKYYYXaHgnmQmx6fEVDq87JoqxvmDmSTPB3mC7YjBVWnVV0cRnqMC8S/wP/T4id9JmXblZWrlyWcSjNCZpA/BbJzYXQbaKifWkqhqIkwUes85Ak5ZbEM5MtoryZK/YAmgPbvzeDvWrYKZGEsSHvUn8wivjngngBN4DdyYRIhT9C1buT7eZk2Mq9bAs8TXV+VwTg23eH0An3/pL4aP5aGwU/SyQBVhanbHL8YigofrAO4a1V4ViSm41owZDFQX2ue344/Ypht5caHVJEwWBfsY8M/DPnHd34Zv7Bmudxkgz4hLkJq15eqPuKnEtY1UuDa+0pTqnpX1MgQvz/v8NUrQvxmRoCWyLUHt7gzPHx+ccAyANx5NKjlitAOVErk/xASVxPHJU4utrITBlHHWN14q+ge/cw63pk9HtG+/EW5VqMMO7FHd7yPJxI3jc7pR8kY7cQMV1KDWnPGaDnUjxZN/ldCB9B2KriucNJlVj5vOPPGR6zAbk9/1YUN1QIf++1+6fVmyslPEYaeQkw+dlm5V3ZNYWbwyn3rKuoLE5sWoiDSUboS3/6n2AHaCQIQMKakM/IS65rzFOyTMSxOapEzetqQN46qMXP/491mBUrNu9LTj6O99zIM1kTrt49zCVD7Rovdjww5ASESEclmdNiq85s+QrCb+sO1S5tgJBQesK6zZQj7Pqc5+BWlrVDsSAQCwOVwLwYmeKKqptXcr8LcUQRD22nrQwOJdM9Q0twAakFrp/u7oNV6yoKUoMi3/7jpY+iegqoUrF+pwcINEkkL6BUxrSZ+oiHKRB4kkBxSNxjLwcC528cFIMXQwEwYJKoZIhvcNAQkVMQYEBAEAAAAwXQYJKwYBBAGCNxEBMVAeTgBNAGkAYwByAG8AcwBvAGYAdAAgAFMAbwBmAHQAdwBhAHIAZQAgAEsAZQB5ACAAUwB0AG8AcgBhAGcAZQAgAFAAcgBvAHYAaQBkAGUAcjCCA3cGCSqGSIb3DQEHBqCCA2gwggNkAgEAMIIDXQYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQMwDgQIF43Ykjsh2x0CAgfQgIIDMJNv2GLTodjiqt72U2XNFcnZ+Yh2LnCw0NQaTjbDdySq/meKKda+jWprtbD7fuU/1/9wGaBA63M4E69nPxOT/JhG7VU7tpCcqAF+uVbQhfiUbuyNuuFOWfoG/+/JFbPIxEwkNfJvcSCgohgmJqgek3N+TpSxvvd80bRM7jrxN0SVvAJ9VDxcH1I3IyKiB6k7AbY/onesh2s2yxR5dL0jDkZM0ux8YI2dwxBOfcBEvRMemQ0sNzSCS0TrdbJdqNdsq1fOyH0ebgdkULZsgk0AKsezkRteGSIDMKr31gxaT9ABAyEDGIEBfJ9fT0uX2zv9BlYL3l1yIi7wEykGC4niq1kxWrSKNpoQuPclgtQ2NamoPGl6l2DPi3XDPrUDlPGTuNj68mJzPkG4JN9HGx93JgnOuWcmr9QZOGYPTnkkPCGkiEBWPHXzaO3M8VJj4CWzsjoHuuy6L9PyoAMJcMt+xN5x9BH4gNeMAx87+eZjf3EF++NQtdGprZKJMkdHSeYqSwLHtWElfezN5hSGPRHnWMQlHa0d+Cn7rvEPgDoGJPiTPiX2n49NuQzYjVXYtT4+AvM3tQ9kMzq9I3xJRfd9W4mGP2Mx7Pc6jbXJAGJ3J5xPdLeblLwnVnE6ndxnfDt/sd++jvbWjzp0lV8HDA4hktfYFYGwZc7bOElwVYAiLqRICcT5TJO77UQhwrlhu482byy1NSDdOz6+D2R/wK20dNyVo+hq618M/8zIctBGgbpIKWYxhh6xCAWnthgstGBZ6N6j/JXLbgqgtyBzWXHuuFCNprCNPWdZW9x8MZBvJ1FyRFc7DExGNGvocdeVxund/UwKMfIWRcrE8FVqJqohx6z9sO5c43/6tokDe4JqJlnGJ45MldcZI9cMi5Pdol76XHE2X2V6XSO10RYh62M5tZNkkYnunbK0F7kGGeoKLXNd17auBimZzDoR9Xc3pZvYpN/C3/ftOH4e3PjLqlcCV4EJ13toolF0O+wfZ8MzMmGJ68KH1DszIX8fRl7EBbBk6TRzrPcUUxSFEubE2jIj7KWWm3MsSbCQeEsfdNiqjD8dVh+fw3q1fJ1CkFpFpB/3IDA7MB8wBwYFKw4DAhoEFG/aeOXAFyB59QdQ8afS9l2IYv/RBBRGiqO7Q6Bg9t2HzdbOvfYNwKgThgICB9A=';

const workspaceRoot = resolve(import.meta.dirname, '..', '..');
const walletRoot = resolve(workspaceRoot, 'apps', 'wallet');
const rpRoot = resolve(workspaceRoot, 'apps', 'reference-rp');
const tls = {
  pfx: Buffer.from(TLS_PFX_BASE64, 'base64'),
  passphrase: 'nexus-e2e',
};

// This process trusts only its own ephemeral test boundary. App code remains fail-closed.
process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = '0';

const stopRegistry = await startRegistryFixture(tls);
const servers: ViteDevServer[] = [];

try {
  const wallet = await startWallet();
  servers.push(wallet);
  const rpA = await startRp(RP_A_ORIGIN, 'rp-a');
  servers.push(rpA);
  const rpB = await startRp(RP_B_ORIGIN, 'rp-b');
  servers.push(rpB);
} catch (error) {
  await shutdown();
  throw error;
}

process.once('SIGINT', () => void shutdown().finally(() => process.exit(0)));
process.once('SIGTERM', () => void shutdown().finally(() => process.exit(0)));

async function startWallet(): Promise<ViteDevServer> {
  const server = await createServer({
    configFile: false,
    root: walletRoot,
    cacheDir: resolve(workspaceRoot, 'node_modules', '.vite-e2e-wallet'),
    appType: 'spa',
    plugins: [
      tailwindcss(),
      productionHeaders(resolve(walletRoot, 'public', '_headers'), REGISTRY_ORIGIN),
    ],
    define: {
      'import.meta.env.VITE_NEXUS_API_URL': JSON.stringify(REGISTRY_ORIGIN),
    },
    server: {
      host: '127.0.0.1',
      port: Number(new URL(WALLET_ORIGIN).port),
      strictPort: true,
      https: tls,
    },
  });
  await server.listen();
  return server;
}

async function startRp(origin: string, cacheName: string): Promise<ViteDevServer> {
  const server = await createServer({
    configFile: false,
    root: rpRoot,
    cacheDir: resolve(workspaceRoot, 'node_modules', `.vite-e2e-${cacheName}`),
    appType: 'spa',
    plugins: [
      tailwindcss(),
      createReferenceRpApiPlugin({
        audience: origin,
        nexusApiUrl: REGISTRY_ORIGIN,
      }),
      productionHeaders(resolve(rpRoot, 'public', '_headers')),
    ],
    define: {
      'import.meta.env.VITE_NEXUS_WALLET_URL': JSON.stringify(WALLET_ORIGIN),
    },
    server: {
      host: '127.0.0.1',
      port: Number(new URL(origin).port),
      strictPort: true,
      https: tls,
    },
  });
  await server.listen();
  return server;
}

function productionHeaders(file: string, additionalConnectSource?: string): Plugin {
  return {
    name: `nexus-e2e-production-headers:${file}`,
    async configureServer(server) {
      const headers = await readWildcardHeaders(file);
      if (additionalConnectSource !== undefined) {
        const csp = headers.get('Content-Security-Policy');
        if (csp === undefined || !csp.includes("connect-src 'self'")) {
          throw new Error('The wallet production CSP has no exact connect-src directive.');
        }
        headers.set(
          'Content-Security-Policy',
          csp.replace("connect-src 'self'", `connect-src 'self' ${additionalConnectSource}`),
        );
      }
      server.middlewares.use((_request, response, next) => {
        for (const [name, value] of headers) response.setHeader(name, value);
        next();
      });
    },
  };
}

async function readWildcardHeaders(file: string): Promise<Map<string, string>> {
  const headers = new Map<string, string>();
  let wildcard = false;
  for (const line of (await readFile(file, 'utf8')).split(/\r?\n/u)) {
    if (line.trim() === '' || line.trimStart().startsWith('/*')) {
      wildcard = line.trim() === '/*';
      continue;
    }
    if (!/^\s/u.test(line)) {
      wildcard = false;
      continue;
    }
    if (!wildcard) continue;
    const separator = line.indexOf(':');
    if (separator <= 0) continue;
    headers.set(line.slice(0, separator).trim(), line.slice(separator + 1).trim());
  }
  return headers;
}

async function shutdown(): Promise<void> {
  await Promise.allSettled(servers.map((server) => server.close()));
  await stopRegistry();
}
