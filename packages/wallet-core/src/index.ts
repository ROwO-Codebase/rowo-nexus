export { WalletCoreError, isWalletCoreError, type WalletCoreErrorCode } from './errors.js';
export {
  IndexedDbIdentityStore,
  InMemoryIdentityStore,
  type IndexedDbIdentityStoreOptions,
} from './identity-store.js';
export {
  InMemoryKeyVault,
  WebCryptoIndexedDbKeyVault,
  type InMemoryKeyVaultOptions,
  type WebCryptoIndexedDbKeyVaultOptions,
} from './key-vault.js';
export {
  acceptUnsignedInMemoryRegistryReceipt,
  InMemoryRegistryClient,
  type InMemoryRegistryClientOptions,
} from './in-memory-registry.js';
export { captureWalletEventBoundary } from './trusted-wallet-event.js';
export { WalletCore, type WalletCoreOptions } from './wallet-core.js';
export type {
  Clock,
  ContinuityLinkOptions,
  CreatedLocalIdentity,
  CreateIdentityOptions,
  DisposeIdentityOptions,
  IdentityStore,
  KeyRef,
  KeyVault,
  LocalIdentityRecordV1,
  LocalIdentitySummary,
  RegistryClient,
  RegistryIdentityStatus,
  RegistryReceiptVerifier,
  RegistryRegisterRequest,
  RevokeIdentityOptions,
  RotateIdentityOptions,
  RotateIdentityResult,
  SecretRef,
  TrustedWalletEventBoundary,
  WalletCoreApi,
} from './types.js';
