export interface AppendResult {
  eventId: string;
  eventHash: string;
  shardId: string;
  leafIndex: number;
  treeSize: number;
  duplicate: boolean;
}

export interface StoredCheckpoint {
  shardId: string;
  treeSize: number;
  rootHash: string;
  checkpointedAt: number;
}

export interface StoredInclusionProof extends StoredCheckpoint {
  eventHash: string;
  leafIndex: number;
  auditPath: string[];
}

export interface DurableAppendRequest {
  eventId: string;
  eventHash: string;
  shardId: string;
}

export interface DurableCheckpointRequest {
  shardId: string;
  checkpointedAt: number;
}
