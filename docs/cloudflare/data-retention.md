# Data Retention and Privacy

Nexus minimizes telemetry and stores only cryptographic state necessary for the protocol. Public
lifecycle data may be permanent by design; network and operational telemetry must be short-lived.
The durations below are Phase 0 maximums and must also be enforced in Cloudflare account
configuration, not only in application code.

## Retention schedule

| Data class                                     | Content allowed                                                                                   | Maximum retention                                                                                                                          |
| ---------------------------------------------- | ------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| Local/preview application logs                 | Synthetic request ID, operation, typed result/error code, coarse latency bucket                   | Local session or 24 hours.                                                                                                                 |
| Staging/production application logs and traces | Random per-request ID, operation, result/error code, coarse size/latency bucket                   | 7 days.                                                                                                                                    |
| Aggregate metrics                              | Operation/result counters and coarse latency/size buckets                                         | 90 days.                                                                                                                                   |
| Authoritative Durable Object state/actions     | Public genesis/hash, active/revoked state, sequence, registry times, deterministic event metadata | Service lifetime; revocation records are terminal and must not expire while subjects/receipts remain supported.                            |
| Durable Object outbox                          | Canonical public registry event and retry metadata                                                | Pending until delivered; delivered entries may be pruned after 30 days only after reconciliation proves downstream idempotent persistence. |
| D1 projection/events                           | Rebuildable public cryptographic state and events                                                 | Service lifetime, or rebuild at any time from retained authoritative/audit material. Not an authorization source.                          |
| Restricted D1 export archives                  | Encrypted operational recovery snapshot containing public cryptographic projection only           | 30 days, rotated automatically.                                                                                                            |
| R2 transparency checkpoints/segments           | Hashes, roots, sizes, timestamps, signatures, and proofs                                          | Service lifetime and at least the full public verification promise.                                                                        |
| Service public-key history                     | Public JWK and `kid`, activation/retirement/incident metadata                                     | At least as long as any supported receipt/checkpoint under the key; normally service lifetime.                                             |
| Turnstile tokens                               | In-memory validation input only                                                                   | Never persisted after validation.                                                                                                          |
| Coarse abuse events                            | Endpoint/category/result bucket without subject, IP, UA, RP, nonce, or backup ID                  | 7 days.                                                                                                                                    |
| Encrypted vault backups                        | Disabled pending approval of [ADR-0011](../adr/0011-backup-security.md)                           | No production collection. The approved decision must define expiry and verified deletion before enablement.                                |

Cloudflare platform-level telemetry outside application control must be inventoried before
production. Configure the minimum available retention and disable fields/products that add
unnecessary IP, user-agent, geolocation, fingerprint, or cross-request correlation. A production
privacy review records any provider-retained metadata and its contractual duration.

## Forbidden data

Application code never logs or stores in telemetry:

- private identity or agreement keys;
- revocation secrets or backup capability secrets;
- backup decryption keys or plaintext vault contents;
- raw signed proof bodies or genesis documents in routine logs;
- subjects, genesis hashes, event IDs, proof IDs, nonces, backup IDs, RP origins, IP addresses, user
  agents, or device fingerprints as metric/log dimensions;
- stable request, installation, controller, account, or user identifiers;
- Turnstile tokens associated with subjects.

Identity-specific protocol payloads are stored only where the protocol requires public cryptographic
state. Identity identifiers stay out of URLs and query strings where practical; fixed POST endpoints
reduce accidental retention in browser history, access logs, caches, analytics, and proxies.

## Request IDs

A request ID is fresh CSPRNG output for one request. It is not derived from a subject, IP, device,
proof, or capability and is never reused across requests. It expires with the corresponding log
record and must not become an RP session or user identifier.

## Deletion and disposal

Identity disposal publishes an irreversible revocation and then performs best-effort local
crypto-shredding. Authoritative revocation and public receipt/checkpoint material are retained so
restored keys cannot regain current control; they are not removed as a privacy deletion shortcut.

Local wallet labels, scopes, key handles, and revocation secrets are erased after receipt
verification where browser/OS storage permits. Nexus must be transparent that physical deletion from
browser, device, backups, or storage media cannot be guaranteed.

Optional encrypted backups remain disabled. Before enablement,
[ADR-0011](../adr/0011-backup-security.md) must define capability lifecycle, inactivity/expiry
policy, user-triggered deletion, R2 version cleanup, deletion verification, disaster-recovery
copies, and how post-disposal backups are rewritten without revealing subjects.

## Review and enforcement

Quarterly and before every production launch:

1. inventory Cloudflare datasets, logs, traces, R2 objects, D1 exports, Queue dead letters, CI
   artifacts, and third-party processors;
2. verify automated expiry/lifecycle rules against this table;
3. sample application logs with synthetic identities to confirm forbidden values are absent;
4. confirm D1/KV/metrics cannot be used as lifecycle authority;
5. document and remediate any retention exception before release.

Nexus pseudonymity does not hide network metadata from Cloudflare, ISPs, relying parties, Tor exits,
or timing observers. Retention minimization reduces exposure but does not create a network-anonymity
guarantee.
