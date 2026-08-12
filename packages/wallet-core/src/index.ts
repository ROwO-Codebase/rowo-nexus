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
  AuthorizationHistoryEntry,
  Clock,
  ContinuityLinkOptions,
  CreatedLocalIdentity,
  CreateIdentityOptions,
  DeviceRegistryReceiptVerifier,
  DeviceRegistryStatusExpectation,
  DeviceRegistryStatusVerifier,
  DeviceRequestOptions,
  DeviceRevocationOptions,
  DeviceTransferEnvelopeV2,
  DisposeIdentityOptions,
  IdentityStore,
  ImportedDeviceV2,
  IssueDeviceTransferOptions,
  IssuedDeviceTransferV2,
  KeyRef,
  KeyVault,
  KeyVaultStorage,
  LocalIdentityRecordV1,
  LocalIdentitySummary,
  LocalDeviceRecordV2,
  LocalIssuedDeviceRecordV2,
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
