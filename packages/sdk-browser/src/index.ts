export {
  NEXUS_POPUP_CHANNEL,
  WALLET_PROOF_ERROR_CODES,
  parseWalletMessage,
  type NexusProofErrorMessage,
  type NexusProofRequestMessage,
  type NexusProofResultMessage,
  type NexusReadyMessage,
  type RpToWalletMessage,
  type WalletProofErrorCode,
  type WalletToRpMessage,
} from './messages.js';
export {
  NexusClient,
  NexusClientError,
  createNexusClient,
  type NexusClientErrorCode,
  type NexusClientOptions,
  type NexusProofResult,
  type RequestProofOptions,
} from './popup.js';
