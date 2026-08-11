# Nexus reference relying party

Nexus Notes demonstrates a relying-party session built from one explicit wallet proof. The wallet
approves `session.start` for the exact Notes origin and the fixed `urn:rowo:nexus-notes:session`
resource. After verification, the RP stores only hashes and issues a five-minute `Secure`,
`HttpOnly`, `SameSite=Strict` cookie. Every later mutation rechecks the authoritative Nexus
lifecycle and the operation's visibility and ownership rules.

The session can:

- create public notes or creator-only private notes;
- edit or remove notes owned by the active subject;
- reply to public notes and to the subject's own private notes;
- remove a reply authored by the active subject, or any reply beneath its own note; and
- like or unlike public notes once per subject.

It is an RP-local convenience session, not a Nexus account or a reusable bearer authorization for
another origin. Revocation invalidates it before the next protected operation, and expiration never
extends beyond five minutes.

## Local HTTPS

Nexus ownership proofs require a canonical HTTPS audience. The reference RP therefore uses Vite's
basic SSL plugin while serving locally and opens at `https://127.0.0.1:4174`.

On the first visit, the browser will warn that the local development certificate is untrusted.
Accept that warning only for this loopback development origin. The generated certificate is for
local testing only and must never be trusted, copied, or deployed as a production certificate.

Copy `.env.example` to `.env`, start the local wallet and registry stack, then run the root `dev:rp`
script. Production builds do not enable the basic SSL plugin and should be served behind the
deployment platform's normal trusted TLS termination.

## Security checks

Run the app-local repository and Worker suites before changing session behavior:

```bash
pnpm --filter @nexus/reference-rp test
pnpm --filter @nexus/reference-rp test:worker
```

The root `pnpm test:e2e` journey adds real two-origin wallet approval, private-note isolation,
reply/like behavior, cookie-session cancellation, strict CSP, and post-revocation rejection.
