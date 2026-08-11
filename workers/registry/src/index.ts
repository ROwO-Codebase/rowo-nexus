import { WorkerEntrypoint } from 'cloudflare:workers';

import { fail } from './errors';
export { IdentityState } from './identity-state-do';
import type {
  AuthoritativeStatus,
  RegisterCommand,
  RegistryEnv,
  RegistryMutation,
  RegistryResult,
  RevokeBySecretCommand,
  RevokeBySignatureCommand,
} from './types';
import {
  parseSecretCommand,
  parseSignatureCommand,
  parseStatusSubject,
  prepareRegistration,
} from './validation';

const MAX_STATUS_BATCH = 100;

/** Internal-only service-binding API; this Worker intentionally has no HTTP API. */
export default class RegistryService extends WorkerEntrypoint<RegistryEnv> {
  override fetch(): Response {
    return new Response('Not Found', { status: 404 });
  }

  async register(input: RegisterCommand): Promise<RegistryResult<RegistryMutation>> {
    try {
      const prepared = await prepareRegistration(input);
      if (!prepared.ok) {
        return prepared;
      }
      return await this.env.IDENTITY_STATE.getByName(prepared.value.subject).register(
        prepared.value,
      );
    } catch {
      return fail('INTERNAL_ERROR');
    }
  }

  async status(subject: string): Promise<RegistryResult<AuthoritativeStatus>> {
    try {
      const parsed = parseStatusSubject(subject);
      if (!parsed.ok) {
        return parsed;
      }
      return await this.env.IDENTITY_STATE.getByName(parsed.value).status();
    } catch {
      return fail('INTERNAL_ERROR');
    }
  }

  async statusBatch(subjects: string[]): Promise<Array<RegistryResult<AuthoritativeStatus>>> {
    if (!Array.isArray(subjects) || subjects.length > MAX_STATUS_BATCH) {
      const size = Array.isArray(subjects) ? subjects.length : 1;
      return Array.from({ length: size }, () => fail('BAD_REQUEST'));
    }
    return await Promise.all(subjects.map(async (subject) => await this.status(subject)));
  }

  async revokeBySignature(
    input: RevokeBySignatureCommand,
  ): Promise<RegistryResult<RegistryMutation>> {
    const parsed = parseSignatureCommand(input);
    if (!parsed.ok) {
      return parsed;
    }
    const subject = parseStatusSubject(parsed.value.payload.subject);
    if (!subject.ok) {
      return subject;
    }
    try {
      return await this.env.IDENTITY_STATE.getByName(subject.value).revokeBySignature(parsed.value);
    } catch {
      return fail('INTERNAL_ERROR');
    }
  }

  async revokeBySecret(input: RevokeBySecretCommand): Promise<RegistryResult<RegistryMutation>> {
    const parsed = parseSecretCommand(input);
    if (!parsed.ok) {
      return parsed;
    }
    const subject = parseStatusSubject(parsed.value.subject);
    if (!subject.ok) {
      return subject;
    }
    try {
      return await this.env.IDENTITY_STATE.getByName(subject.value).revokeBySecret(parsed.value);
    } catch {
      return fail('INTERNAL_ERROR');
    }
  }
}

export type {
  AuthoritativeStatus,
  RegisterCommand,
  RegistryErrorCode,
  RegistryFault,
  RegistryMutation,
  RegistryResult,
  RevokeBySecretCommand,
  RevokeBySignatureCommand,
} from './types';
