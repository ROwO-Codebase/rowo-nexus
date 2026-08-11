import { IDENTITY_PROTOCOL_V1, NEXUS_SUITE_V1 } from '@nexus/protocol';
import type { VerifiedSubject } from '@nexus/protocol';

import { verificationError } from './errors.js';
import { parseGenesis, verifyParsedSubject } from './internal.js';

export async function verifySubject(
  genesis: unknown,
  claimedSubject: unknown,
): Promise<VerifiedSubject> {
  const parsedGenesis = parseGenesis(genesis, IDENTITY_PROTOCOL_V1, NEXUS_SUITE_V1);

  if (typeof claimedSubject !== 'string') {
    throw verificationError('INVALID_SUBJECT');
  }

  return verifyParsedSubject(parsedGenesis, claimedSubject);
}
