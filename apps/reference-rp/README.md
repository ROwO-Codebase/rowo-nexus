# Nexus reference relying party

## Local HTTPS

Nexus ownership proofs require a canonical HTTPS audience. The reference RP therefore uses Vite's
basic SSL plugin while serving locally and opens at `https://127.0.0.1:4174`.

On the first visit, the browser will warn that the local development certificate is untrusted.
Accept that warning only for this loopback development origin. The generated certificate is for
local testing only and must never be trusted, copied, or deployed as a production certificate.

Copy `.env.example` to `.env`, start the local wallet and registry stack, then run the root `dev:rp`
script. Production builds do not enable the basic SSL plugin and should be served behind the
deployment platform's normal trusted TLS termination.
