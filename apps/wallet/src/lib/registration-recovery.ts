import type { RegistryReceiptV1 } from '@nexus/protocol';

export interface RegistrationRetrier {
  registerIdentity(localId: string): Promise<RegistryReceiptV1>;
}

/**
 * Replays the same idempotent registration for the locally retained subject.
 * It never deletes key material because a lost success response is ambiguous.
 */
export function retryIdentityRegistration(
  walletCore: RegistrationRetrier,
  localId: string,
): Promise<RegistryReceiptV1> {
  return walletCore.registerIdentity(localId);
}
