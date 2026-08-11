# ROwO Nexus wallet

The wallet is a static React application. Private identity keys are created by `@nexus/wallet-core`
and retained in the browser's IndexedDB-backed key vault.

## API origin and CSP

`VITE_NEXUS_API_URL` must be an exact origin: no credentials, path, query, or hash.

- `vite dev` defaults to `http://localhost:8787` and permits HTTP only on a loopback host.
- production builds default to `https://nexus.rowo.link` and require HTTPS.

`public/_headers` is a safe development/E2E template with a self-only connection policy. The Vite
security-header plugin replaces the copied `dist/_headers` at the end of every production build. The
built `connect-src` contains only `'self'` and the validated API origin used for that build.
`script-src` remains `'self'`; the wallet loads no remote scripts, fonts, analytics, or other
third-party resources.

For a non-canonical deployment, set the value while building so the runtime URL and generated CSP
stay identical:

```text
VITE_NEXUS_API_URL=https://nexus.staging.rowo.link pnpm build
```

## Static-assets deployment

`wrangler.jsonc` deploys `dist` as Cloudflare static assets with SPA fallback and no Worker code or
bindings. `pnpm dry-run` rebuilds the wallet and validates the deploy bundle without publishing it.

## Interrupted registration recovery

Identity creation stores local key material before calling the idempotent registry endpoint. If a
successful registry response is lost, the retained identity appears as **Unregistered**. The wallet
offers **Retry registration**, which reuses the same subject through
`WalletCore.registerIdentity(localId)`. Proof, rotate, continuity-link, and dispose actions remain
unavailable until a verified registration receipt is retained.

The wallet intentionally offers no local-delete shortcut for this state. Without a confirmed
revocation, a lost success response cannot be distinguished safely from a failed registration.

## Local authorization history

After a proof is successfully created for an approved wallet request, the wallet stores a bounded
history on the selected local identity. Each entry contains only the approval time, exact app
origin, action, resource, whether the approval introduced a new local app scope, and whether the
request was context-bound. It never stores the proof, signature, nonce, context hash, or private key
material.

The newest 200 entries per identity are retained in the wallet's IndexedDB identity record. Existing
wallet records without this field open with an empty history. Users can view and clear history from
**View details** without removing remembered app scopes. The history is local activity metadata—not
cryptographic evidence—and it cannot observe operations an app performs under its own RP session.
