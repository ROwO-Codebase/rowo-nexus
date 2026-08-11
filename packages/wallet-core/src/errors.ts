export type WalletCoreErrorCode =
  | 'IDENTITY_NOT_FOUND'
  | 'IDENTITY_REVOKED'
  | 'IDENTITY_NOT_REGISTERED'
  | 'INVALID_REQUEST'
  | 'INVALID_REGISTRY_RECEIPT'
  | 'REGISTRY_CONFLICT'
  | 'STORAGE_ERROR'
  | 'UNTRUSTED_WALLET_EVENT';

export class WalletCoreError extends Error {
  public readonly code: WalletCoreErrorCode;

  public constructor(code: WalletCoreErrorCode, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'WalletCoreError';
    this.code = code;
  }
}

export function isWalletCoreError(error: unknown): error is WalletCoreError {
  return error instanceof WalletCoreError;
}
