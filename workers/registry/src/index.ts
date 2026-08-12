import { WorkerEntrypoint } from 'cloudflare:workers';

import { fail } from './errors';
export { IdentityState } from './identity-state-do';
import type {
  AuthoritativeStatus,
  AuthoritativeDeviceStatusV2,
  DeviceRegistryMutationV2,
  DeviceStatusCommand,
  RegisterCommand,
  RegistryEnv,
  RegistryMutation,
  RegistryResult,
  RevokeBySecretCommand,
  RevokeBySignatureCommand,
} from './types';
import type {
  DeviceActivationRequestV2,
  DeviceRootRevokeRequestV2,
  DeviceSelfRevokeRequestV2,
} from '@nexus/protocol';
import {
  parseDeviceActivationCommand,
  parseDeviceRootRevokeCommand,
  parseDeviceSelfRevokeCommand,
  parseDeviceStatusCommand,
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

  async activateDevice(
    input: DeviceActivationRequestV2,
  ): Promise<RegistryResult<DeviceRegistryMutationV2>> {
    const parsed = parseDeviceActivationCommand(input);
    if (!parsed.ok) return parsed;
    try {
      return await this.env.IDENTITY_STATE.getByName(parsed.value.payload.subject).activateDevice(
        parsed.value,
      );
    } catch {
      return fail('INTERNAL_ERROR');
    }
  }

  async deviceStatus(
    input: DeviceStatusCommand,
  ): Promise<RegistryResult<AuthoritativeDeviceStatusV2>> {
    const parsed = parseDeviceStatusCommand(input);
    if (!parsed.ok) return parsed;
    try {
      return await this.env.IDENTITY_STATE.getByName(parsed.value.subject).deviceStatus({
        deviceId: parsed.value.deviceId,
        authorizationId: parsed.value.authorizationId,
      });
    } catch {
      return fail('INTERNAL_ERROR');
    }
  }

  async deviceStatusBatch(
    inputs: DeviceStatusCommand[],
  ): Promise<Array<RegistryResult<AuthoritativeDeviceStatusV2>>> {
    if (!Array.isArray(inputs) || inputs.length > MAX_STATUS_BATCH) {
      const size = Array.isArray(inputs) ? inputs.length : 1;
      return Array.from({ length: size }, () => fail('BAD_REQUEST'));
    }
    return await Promise.all(inputs.map(async (input) => await this.deviceStatus(input)));
  }

  async revokeDeviceSelf(
    input: DeviceSelfRevokeRequestV2,
  ): Promise<RegistryResult<DeviceRegistryMutationV2>> {
    const parsed = parseDeviceSelfRevokeCommand(input);
    if (!parsed.ok) return parsed;
    try {
      return await this.env.IDENTITY_STATE.getByName(parsed.value.payload.subject).revokeDeviceSelf(
        parsed.value,
      );
    } catch {
      return fail('INTERNAL_ERROR');
    }
  }

  async revokeDeviceRoot(
    input: DeviceRootRevokeRequestV2,
  ): Promise<RegistryResult<DeviceRegistryMutationV2>> {
    const parsed = parseDeviceRootRevokeCommand(input);
    if (!parsed.ok) return parsed;
    try {
      return await this.env.IDENTITY_STATE.getByName(parsed.value.payload.subject).revokeDeviceRoot(
        parsed.value,
      );
    } catch {
      return fail('INTERNAL_ERROR');
    }
  }
}

export type {
  AuthoritativeStatus,
  AuthoritativeDeviceStatusV2,
  DeviceRegistryMutationV2,
  DeviceStatusCommand,
  RegisterCommand,
  RegistryErrorCode,
  RegistryFault,
  RegistryMutation,
  RegistryResult,
  RevokeBySecretCommand,
  RevokeBySignatureCommand,
} from './types';
