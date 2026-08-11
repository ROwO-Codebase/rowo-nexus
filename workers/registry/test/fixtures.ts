import {
  REVOKE_PROTOCOL_V1,
  REVOKE_SECRET_PROTOCOL_V1,
  encodeBase64Url,
  identityGenesisV1Schema,
  revokeBySecretV1Schema,
  revokeBySignaturePayloadV1Schema,
} from '@nexus/protocol';
import type {
  IdentityGenesisV1,
  RevokeBySecretV1,
  RevokeBySignaturePayloadV1,
} from '@nexus/protocol';
import { computeRevocationCommitment, deriveSubject, signProtocolPayload } from '@nexus/crypto';

import { prepareRegistration } from '../src/validation';
import type { PreparedRegistration } from '../src/types';

export interface IdentityFixture {
  genesis: IdentityGenesisV1;
  prepared: PreparedRegistration;
  privateKey: CryptoKey;
  secret: Uint8Array;
}

export async function createIdentityFixture(): Promise<IdentityFixture> {
  const keyPair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const publicKey = new Uint8Array(await crypto.subtle.exportKey('raw', keyPair.publicKey));
  const secret = crypto.getRandomValues(new Uint8Array(32));
  const commitment = await computeRevocationCommitment(secret);
  const genesis = identityGenesisV1Schema.parse({
    protocol: 'nexus.identity.v1',
    suite: 'NX-25519-SHA256-JCS-v1',
    signingKey: { alg: 'Ed25519', publicKey: encodeBase64Url(publicKey) },
    revocationCommitment: encodeBase64Url(commitment),
  });
  const subject = await deriveSubject(genesis);
  const preparedResult = await prepareRegistration({ subject, genesis });
  if (!preparedResult.ok) {
    throw new Error(`Fixture registration failed: ${preparedResult.error.code}`);
  }
  return { genesis, prepared: preparedResult.value, privateKey: keyPair.privateKey, secret };
}

export async function createSignatureRevocation(
  fixture: IdentityFixture,
): Promise<{ payload: RevokeBySignaturePayloadV1; signature: string }> {
  const payload = revokeBySignaturePayloadV1Schema.parse({
    protocol: REVOKE_PROTOCOL_V1,
    subject: fixture.prepared.subject,
    expectedSequence: 0,
    nonce: encodeBase64Url(crypto.getRandomValues(new Uint8Array(16))),
    iat: Math.floor(Date.now() / 1_000),
    reasonCode: 'dispose',
  });
  return {
    payload,
    signature: await signProtocolPayload(payload, fixture.privateKey),
  };
}

export function createSecretRevocation(fixture: IdentityFixture): RevokeBySecretV1 {
  return revokeBySecretV1Schema.parse({
    protocol: REVOKE_SECRET_PROTOCOL_V1,
    subject: fixture.prepared.subject,
    expectedSequence: 0,
    revocationSecret: encodeBase64Url(fixture.secret),
  });
}
