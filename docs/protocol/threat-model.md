# Threat Model and Privacy Invariants

Nexus assumes browsers, relying parties, Cloudflare services, storage systems, and networks can fail
or be attacked. It minimizes the identity data available to each boundary but does not claim network
anonymity.

## Privacy invariants

1. No permanent public controller, wallet, account, installation, or physical-device identifier. V2
   `nxd2_` identifiers are scoped to one subject and public key, never reused across subjects, and
   appear only in explicitly negotiated v2 device operations.
2. Each disposable identity uses independently generated random private key material. V2 device keys
   are also independently random and are never derived from an identity root or sibling device.
3. RP-to-identity scope mappings and local labels remain local to the wallet.
4. Genesis contains no RP audience, user metadata, or timestamp.
5. Cross-origin identity reuse requires explicit user confirmation.
6. Core protocol APIs are stateless and use no session cookies.
7. Logs exclude private keys, revocation secrets, raw proofs, routine subjects, IP addresses, and
   user agents.
8. Identity operations use fixed POST endpoints rather than subject-bearing URLs where practical.
9. No public subject directory or metadata enumeration endpoint.
10. D1 and KV never determine current lifecycle authorization.

## Threats and controls

| Threat                                | Required control                                                                                                                                                                                       |
| ------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| D1/R2/operational database compromise | No civil-identity map or server-custodied user keys; R2 contains transparency or restricted operational artifacts; registry state is public cryptographic data only.                                   |
| Public-key substitution               | Subject is the domain-separated SHA-256 hash of canonical immutable genesis; verifiers recompute it.                                                                                                   |
| Proof replay                          | Exact audience/action/resource binding, short expiry, CSPRNG backend nonce, and atomic single-use consumption.                                                                                         |
| Cross-application replay              | Exact HTTPS `aud` match; wallet derives audience from the sender origin.                                                                                                                               |
| Old key after disposal                | Strict current lifecycle check rejects terminally revoked subjects even when signatures remain valid.                                                                                                  |
| Malicious RP                          | Typed proof operations, visible consent context, origin-derived audience, exact-origin response, and no identity-list disclosure.                                                                      |
| Wallet-origin XSS                     | No third-party scripts, strict CSP, pinned/audited dependencies, no eval, and explicit approval. Non-extractable keys do not eliminate signing abuse by XSS.                                           |
| Correlating service operator          | No RP audience at registration, no proof transit through Nexus, minimal short-lived telemetry, and aggregate-only metrics.                                                                             |
| Sybil creation                        | Separate optional rate limits, Turnstile, invitations, or RP policy; never reinterpret anti-abuse as identity authentication.                                                                          |
| Nexus service-key compromise          | User signatures remain self-certifying; service keys use `kid`, retained public-key history, rotation, and incident statements.                                                                        |
| Root identity-key compromise          | Attacker can authorize or revoke devices only for that subject. Keep the root non-extractable and offline/rarely used; terminal identity revocation remains final containment.                         |
| Device-key compromise                 | Attacker can prove as the subject only through that device's grant. Exact device-status checks and irreversible self/root revocation contain the compromised key without affecting siblings.           |
| Device-transfer theft or cloning      | A stolen bundle may install an indistinguishable clone. Use authenticated encryption and high-entropy key establishment; one key per installation; revocation invalidates every clone of that `nxd2_`. |
| Root loss                             | Active devices cannot elevate themselves, renew, or authorize replacements. They may self-revoke; a retained v1 revocation secret can destroy but not recover the identity.                            |

## Trust and limitations

- Web Crypto and reviewed dependencies are trusted to implement standard primitives correctly.
- The wallet origin and its build/deployment pipeline are a high-value trusted computing boundary.
- Relying parties are responsible for nonce transactions, expected proof fields, lifecycle
  freshness, protected-resource integrity, and local sessions.
- The registry Durable Object is authoritative for lifecycle; receipt/status keys attest server time
  and state but cannot forge user identity signatures.
- Cloudflare, ISPs, Tor exits, RPs, or a broad observer may correlate IP, timing, browser, or
  traffic metadata. Nexus pseudonym unlinkability is not equivalent to network anonymity.
- Nexus does not provide one-human-one-identity, Sybil resistance from cryptography, recoverability
  of disposed keys, or reliable physical erasure from browser/OS storage.
- The v2 profile does not provide root recovery or guaranteed device-key migration. Export is a copy
  operation; Nexus cannot enumerate or separately revoke physical clones of one device key.

Production is blocked until independent crypto/code review, schema/canonicalization fuzzing,
origin-confusion review, replay/race review, Cloudflare review, service-key incident drill,
dependency audit, and privacy/retention review are complete.
