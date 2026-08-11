# Nexus backup Worker — deliberately inert

This directory exists only to reserve the Phase 0 service boundary. The Worker has no handler, RPC,
R2 binding, routes, secrets, cryptography, serialization, or capability operations.

Implementation is blocked until a separate KDF/backup security ADR is reviewed and explicitly
accepted, as required by `NEXUS_SPEC.md` sections 45, 69(18), and 79. Creating this scaffold does
not satisfy that gate and must not be interpreted as backup support.
