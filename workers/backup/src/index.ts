/**
 * Deliberately inert Phase 8 scaffold.
 *
 * NEXUS_SPEC.md sections 45, 69(18), and 79 forbid implementing encrypted
 * backup before a separate, reviewed KDF/backup security ADR is accepted.
 * Consequently this Worker has no fetch handler, RPC methods, bindings,
 * cryptography, serialization, capability handling, or storage access.
 */
export const BACKUP_IMPLEMENTATION_STATUS = 'blocked-pending-security-adr' as const;

// A default module export keeps the Phase 0 Worker scaffold buildable without
// registering a fetch, scheduled, queue, email, tail, trace, or RPC handler.
export default {} satisfies ExportedHandler<Record<string, never>>;
