#!/usr/bin/env node

import { readFile, stat, writeFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

import {
  WebCryptoProvider,
  signProtocolPayload,
  type CryptoProvider,
} from '../packages/crypto/src/index.js';
import {
  TRANSPARENCY_GLOBAL_CHECKPOINT_PROTOCOL_V1,
  base64Url32Schema,
  base64Url64Schema,
  decodeBase64Url,
  signerKidSchema,
  type GlobalCheckpointShardV1,
  type GlobalTransparencyCheckpointPayloadV1,
  type SignedGlobalTransparencyCheckpointV1,
} from '../packages/protocol/src/index.js';

export type {
  GlobalCheckpointShardV1,
  GlobalTransparencyCheckpointPayloadV1,
  SignedGlobalTransparencyCheckpointV1,
} from '../packages/protocol/src/index.js';

export const TRANSPARENCY_GLOBAL_CHECKPOINT_PROTOCOL = TRANSPARENCY_GLOBAL_CHECKPOINT_PROTOCOL_V1;

export const CHECKPOINT_PRIVATE_KEY_ENV = 'TRANSPARENCY_SIGNING_KEY_PKCS8_B64URL' as const;
export const CHECKPOINT_KID_ENV = 'TRANSPARENCY_SIGNING_KID' as const;
export const DEFAULT_UPLOAD_URL_ENV = 'NEXUS_CHECKPOINT_UPLOAD_URL' as const;

const REGISTRY_PRIVATE_KEY_ENVIRONMENTS = [
  'RECEIPT_SIGNING_PRIVATE_KEY',
  'STATUS_SIGNING_PRIVATE_KEY',
  'REGISTRY_SIGNING_KEY_PKCS8_B64URL',
] as const;
const REGISTRY_KID_ENVIRONMENTS = [
  'RECEIPT_SIGNING_KID',
  'STATUS_SIGNING_KID',
  'REGISTRY_SIGNING_KID',
] as const;
const MAX_MANIFEST_BYTES = 1024 * 1024;
const SHARD_COUNT = 256;
const ENVIRONMENT_NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/u;

export type UnsignedGlobalCheckpointManifestV1 = Omit<
  GlobalTransparencyCheckpointPayloadV1,
  'signerKid'
>;

export interface CheckpointSigningOptions {
  readonly keyPurpose: 'transparency-checkpoint';
  readonly signerKid: string;
  /** Canonical unpadded base64url Ed25519 PKCS#8. */
  readonly privateKeyPkcs8Base64Url: string;
  readonly provider?: CryptoProvider;
}

export interface PublishCheckpointArguments {
  readonly help: boolean;
  readonly input?: string;
  readonly signerKid?: string;
  readonly output?: string;
  readonly upload: boolean;
  readonly uploadUrlEnvironment: string;
  readonly uploadTokenEnvironment?: string;
}

export interface UploadCheckpointOptions {
  readonly url: string;
  readonly bearerToken?: string;
  readonly fetchImpl?: typeof fetch;
}

export interface PublishCheckpointCliDependencies {
  readonly environment?: Readonly<Record<string, string | undefined>>;
  readonly readInput?: (path: string) => Promise<string>;
  readonly writeOutput?: (path: string, body: string) => Promise<void>;
  readonly upload?: (body: string, options: UploadCheckpointOptions) => Promise<void>;
  readonly stdout?: (text: string) => void;
}

export class CheckpointScriptError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = 'CheckpointScriptError';
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function assertExactKeys(
  value: Record<string, unknown>,
  allowedKeys: readonly string[],
  label: string,
): void {
  const allowed = new Set(allowedKeys);
  const unknownKeys = Object.keys(value).filter((key) => !allowed.has(key));
  if (unknownKeys.length > 0) {
    throw new CheckpointScriptError(`${label} contains prohibited field(s).`);
  }
  const missingKeys = allowedKeys.filter(
    (key) => !Object.prototype.hasOwnProperty.call(value, key),
  );
  if (missingKeys.length > 0) {
    throw new CheckpointScriptError(
      `${label} is missing required field(s): ${missingKeys.join(', ')}.`,
    );
  }
}

function parseSafeNonNegativeInteger(value: unknown, label: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw new CheckpointScriptError(`${label} must be a non-negative safe integer.`);
  }
  return value;
}

function canonicalShardId(index: number): string {
  return index.toString(16).padStart(2, '0');
}

function parseShard(value: unknown, index: number): GlobalCheckpointShardV1 {
  if (!isRecord(value)) {
    throw new CheckpointScriptError(`shards[${String(index)}] must be an object.`);
  }
  assertExactKeys(value, ['shardId', 'treeSize', 'rootHash'], `shards[${String(index)}]`);

  const expectedShardId = canonicalShardId(index);
  if (value.shardId !== expectedShardId) {
    throw new CheckpointScriptError(
      `shards[${String(index)}].shardId must be ${expectedShardId}; shards must be complete and canonically ordered.`,
    );
  }
  const rootHash = base64Url32Schema.safeParse(value.rootHash);
  if (!rootHash.success) {
    throw new CheckpointScriptError(
      `shards[${String(index)}].rootHash must be a canonical 32-byte base64url hash.`,
    );
  }

  return {
    shardId: expectedShardId,
    treeSize: parseSafeNonNegativeInteger(value.treeSize, `shards[${String(index)}].treeSize`),
    rootHash: rootHash.data,
  };
}

/**
 * Strictly accepts only the hash-only global manifest shape. In particular,
 * subject, event, identity, and registry-record fields are rejected as unknown.
 */
export function parseUnsignedCheckpointManifest(
  input: unknown,
): UnsignedGlobalCheckpointManifestV1 {
  let decoded: unknown = input;
  if (typeof input === 'string') {
    if (new TextEncoder().encode(input).byteLength > MAX_MANIFEST_BYTES) {
      throw new CheckpointScriptError('Checkpoint manifest exceeds the 1 MiB limit.');
    }
    try {
      decoded = JSON.parse(input) as unknown;
    } catch {
      throw new CheckpointScriptError('Checkpoint input must be valid JSON.');
    }
  }

  if (!isRecord(decoded)) {
    throw new CheckpointScriptError('Checkpoint input must be a JSON object.');
  }
  assertExactKeys(decoded, ['protocol', 'checkpointedAt', 'shards'], 'Checkpoint manifest');
  if (decoded.protocol !== TRANSPARENCY_GLOBAL_CHECKPOINT_PROTOCOL) {
    throw new CheckpointScriptError(`protocol must be ${TRANSPARENCY_GLOBAL_CHECKPOINT_PROTOCOL}.`);
  }
  if (!Array.isArray(decoded.shards) || decoded.shards.length !== SHARD_COUNT) {
    throw new CheckpointScriptError(
      `shards must contain exactly ${String(SHARD_COUNT)} entries (00 through ff).`,
    );
  }

  return {
    protocol: TRANSPARENCY_GLOBAL_CHECKPOINT_PROTOCOL,
    checkpointedAt: parseSafeNonNegativeInteger(decoded.checkpointedAt, 'checkpointedAt'),
    shards: decoded.shards.map((shard, index) => parseShard(shard, index)),
  };
}

/** Signs a validated hash-only manifest with a purpose-separated checkpoint key. */
export async function signCheckpointManifest(
  manifest: UnsignedGlobalCheckpointManifestV1,
  options: CheckpointSigningOptions,
): Promise<SignedGlobalTransparencyCheckpointV1> {
  if (options.keyPurpose !== 'transparency-checkpoint') {
    throw new CheckpointScriptError('Only a transparency-checkpoint key may sign this manifest.');
  }
  const validatedManifest = parseUnsignedCheckpointManifest(manifest);
  const parsedKid = signerKidSchema.safeParse(options.signerKid);
  if (!parsedKid.success) {
    throw new CheckpointScriptError('The checkpoint signer kid must be non-empty printable ASCII.');
  }

  let pkcs8: Uint8Array;
  try {
    pkcs8 = decodeBase64Url(options.privateKeyPkcs8Base64Url);
  } catch {
    throw new CheckpointScriptError(
      `${CHECKPOINT_PRIVATE_KEY_ENV} must contain canonical unpadded base64url PKCS#8.`,
    );
  }
  if (pkcs8.byteLength === 0 || pkcs8.byteLength > 4096) {
    pkcs8.fill(0);
    throw new CheckpointScriptError('The checkpoint PKCS#8 value has an invalid length.');
  }

  const provider = options.provider ?? new WebCryptoProvider();
  let privateKey: CryptoKey;
  try {
    privateKey = await provider.importEd25519PrivateKey(pkcs8, {
      extractable: false,
    });
  } catch {
    throw new CheckpointScriptError('The checkpoint PKCS#8 value is not a valid Ed25519 key.');
  } finally {
    pkcs8.fill(0);
  }

  const payload: GlobalTransparencyCheckpointPayloadV1 = {
    protocol: validatedManifest.protocol,
    checkpointedAt: validatedManifest.checkpointedAt,
    shards: validatedManifest.shards.map((shard) => ({ ...shard })),
    signerKid: parsedKid.data,
  };
  const signature = base64Url64Schema.safeParse(
    await signProtocolPayload(payload, privateKey, provider),
  );
  if (!signature.success) {
    throw new CheckpointScriptError('Checkpoint signing returned an invalid signature.');
  }
  return { payload, signature: signature.data };
}

export function serializeSignedCheckpoint(
  checkpoint: SignedGlobalTransparencyCheckpointV1,
): string {
  return JSON.stringify(checkpoint);
}

function requireArgumentValue(
  arguments_: readonly string[],
  index: number,
  option: string,
): string {
  const value = arguments_[index + 1];
  if (value === undefined || value.startsWith('--')) {
    throw new CheckpointScriptError(`${option} requires a value.`);
  }
  return value;
}

function parseEnvironmentName(value: string, option: string): string {
  if (!ENVIRONMENT_NAME_PATTERN.test(value)) {
    throw new CheckpointScriptError(`${option} must name an environment variable.`);
  }
  return value;
}

/** Strict CLI parsing is exported and has no file or network side effects. */
export function parsePublishCheckpointArguments(
  arguments_: readonly string[],
): PublishCheckpointArguments {
  if (arguments_.includes('--help') || arguments_.includes('-h')) {
    if (arguments_.length !== 1) {
      throw new CheckpointScriptError('--help cannot be combined with other arguments.');
    }
    return {
      help: true,
      upload: false,
      uploadUrlEnvironment: DEFAULT_UPLOAD_URL_ENV,
    };
  }

  let input: string | undefined;
  let signerKid: string | undefined;
  let output: string | undefined;
  let upload = false;
  let uploadUrlEnvironment: string = DEFAULT_UPLOAD_URL_ENV;
  let uploadUrlEnvironmentSeen = false;
  let uploadTokenEnvironment: string | undefined;

  for (let index = 0; index < arguments_.length; index += 1) {
    const argument = arguments_[index];
    if (argument === '--upload') {
      if (upload) {
        throw new CheckpointScriptError('--upload may be supplied only once.');
      }
      upload = true;
      continue;
    }

    const valueOptions = [
      '--input',
      '--kid',
      '--output',
      '--upload-url-env',
      '--upload-token-env',
    ] as const;
    if (!(valueOptions as readonly (string | undefined)[]).includes(argument)) {
      throw new CheckpointScriptError('Unknown or positional argument. See --help.');
    }
    const value = requireArgumentValue(arguments_, index, argument as string);
    index += 1;

    switch (argument) {
      case '--input':
        if (input !== undefined) {
          throw new CheckpointScriptError('--input may be supplied only once.');
        }
        input = value;
        break;
      case '--kid':
        if (signerKid !== undefined) {
          throw new CheckpointScriptError('--kid may be supplied only once.');
        }
        signerKid = value;
        break;
      case '--output':
        if (output !== undefined) {
          throw new CheckpointScriptError('--output may be supplied only once.');
        }
        output = value;
        break;
      case '--upload-url-env':
        if (uploadUrlEnvironmentSeen) {
          throw new CheckpointScriptError('--upload-url-env may be supplied only once.');
        }
        uploadUrlEnvironmentSeen = true;
        uploadUrlEnvironment = parseEnvironmentName(value, '--upload-url-env');
        break;
      case '--upload-token-env':
        if (uploadTokenEnvironment !== undefined) {
          throw new CheckpointScriptError('--upload-token-env may be supplied only once.');
        }
        uploadTokenEnvironment = parseEnvironmentName(value, '--upload-token-env');
        break;
    }
  }

  if (input === undefined) {
    throw new CheckpointScriptError('--input is required. Use - to read stdin.');
  }
  if (!upload && uploadUrlEnvironment !== DEFAULT_UPLOAD_URL_ENV) {
    throw new CheckpointScriptError('--upload-url-env requires --upload.');
  }
  if (!upload && uploadTokenEnvironment !== undefined) {
    throw new CheckpointScriptError('--upload-token-env requires --upload.');
  }
  return {
    help: false,
    input,
    ...(signerKid === undefined ? {} : { signerKid }),
    ...(output === undefined ? {} : { output }),
    upload,
    uploadUrlEnvironment,
    ...(uploadTokenEnvironment === undefined ? {} : { uploadTokenEnvironment }),
  };
}

export async function uploadSignedCheckpoint(
  body: string,
  options: UploadCheckpointOptions,
): Promise<void> {
  let url: URL;
  try {
    url = new URL(options.url);
  } catch {
    throw new CheckpointScriptError('The checkpoint upload URL is invalid.');
  }
  if (url.protocol !== 'https:' || url.username !== '' || url.password !== '' || url.hash !== '') {
    throw new CheckpointScriptError(
      'The checkpoint upload URL must be HTTPS and contain no credentials or fragment.',
    );
  }

  const headers = new Headers({
    'content-type': 'application/nexus+json',
  });
  if (options.bearerToken !== undefined) {
    if (options.bearerToken.length === 0) {
      throw new CheckpointScriptError('The checkpoint upload token must not be empty.');
    }
    headers.set('authorization', `Bearer ${options.bearerToken}`);
  }

  const fetchImpl = options.fetchImpl ?? fetch;
  let response: Response;
  try {
    response = await fetchImpl(url, {
      method: 'PUT',
      headers,
      body,
      redirect: 'error',
    });
  } catch {
    throw new CheckpointScriptError('Checkpoint upload failed.');
  }
  if (!response.ok) {
    throw new CheckpointScriptError(
      `Checkpoint upload failed with HTTP ${String(response.status)}.`,
    );
  }
}

async function readCheckpointInput(path: string): Promise<string> {
  let content: string;
  if (path === '-') {
    process.stdin.setEncoding('utf8');
    const chunks: string[] = [];
    let totalBytes = 0;
    for await (const chunk of process.stdin) {
      if (typeof chunk !== 'string') {
        throw new CheckpointScriptError('Checkpoint stdin must be UTF-8 text.');
      }
      totalBytes += Buffer.byteLength(chunk, 'utf8');
      if (totalBytes > MAX_MANIFEST_BYTES) {
        throw new CheckpointScriptError('Checkpoint manifest exceeds the 1 MiB limit.');
      }
      chunks.push(chunk);
    }
    content = chunks.join('');
  } else {
    const details = await stat(path);
    if (!details.isFile()) {
      throw new CheckpointScriptError('--input must refer to a regular file or stdin (-).');
    }
    if (details.size > MAX_MANIFEST_BYTES) {
      throw new CheckpointScriptError('Checkpoint manifest exceeds the 1 MiB limit.');
    }
    content = await readFile(path, 'utf8');
  }
  if (Buffer.byteLength(content, 'utf8') > MAX_MANIFEST_BYTES) {
    throw new CheckpointScriptError('Checkpoint manifest exceeds the 1 MiB limit.');
  }
  return content;
}

async function writeCheckpointOutput(path: string, body: string): Promise<void> {
  await writeFile(path, `${body}\n`, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
}

function requiredEnvironmentValue(
  environment: Readonly<Record<string, string | undefined>>,
  name: string,
): string {
  const value = environment[name];
  if (value === undefined || value.length === 0) {
    throw new CheckpointScriptError(`Required environment variable ${name} is not set.`);
  }
  return value;
}

function rejectRegistryKeyReuse(
  environment: Readonly<Record<string, string | undefined>>,
  checkpointPrivateKey: string,
  checkpointKid: string,
): void {
  for (const name of REGISTRY_PRIVATE_KEY_ENVIRONMENTS) {
    const registryKey = environment[name];
    if (registryKey !== undefined && registryKey === checkpointPrivateKey) {
      throw new CheckpointScriptError(
        'The transparency checkpoint key must not reuse a registry signing key.',
      );
    }
  }
  for (const name of REGISTRY_KID_ENVIRONMENTS) {
    const registryKid = environment[name];
    if (registryKid !== undefined && registryKid === checkpointKid) {
      throw new CheckpointScriptError(
        'The transparency checkpoint kid must be distinct from registry signing kids.',
      );
    }
  }
}

export const PUBLISH_CHECKPOINT_HELP = `Usage:
  pnpm tsx scripts/publish-checkpoint.ts --input <file|-> [options]

Strictly validate and sign a hash-only global transparency checkpoint manifest.
The default action reads input, signs it, and prints compact JSON to stdout. It
does not write a file or contact the network.

Required:
  --input <file|->           Unsigned JSON manifest; - reads stdin
  ${CHECKPOINT_PRIVATE_KEY_ENV}  Dedicated checkpoint PKCS#8 secret
  --kid <kid> or ${CHECKPOINT_KID_ENV}

Explicit side effects:
  --output <new-file>        Write once; refuses to overwrite an existing path
  --upload                   PUT to the HTTPS URL in ${DEFAULT_UPLOAD_URL_ENV}
  --upload-url-env <name>    Read upload URL from another named environment var
  --upload-token-env <name>  Add a bearer token from the named environment var

Other:
  -h, --help                 Show this help without reading input or secrets

Input must contain exactly protocol, checkpointedAt, and 256 canonically ordered
{shardId, treeSize, rootHash} entries. Subject and event fields are prohibited.
The signing key is read only from ${CHECKPOINT_PRIVATE_KEY_ENV}; registry keys are
never accepted as a fallback.`;

export async function runPublishCheckpointCli(
  arguments_: readonly string[],
  dependencies: PublishCheckpointCliDependencies = {},
): Promise<void> {
  const parsed = parsePublishCheckpointArguments(arguments_);
  const stdout = dependencies.stdout ?? ((text: string) => process.stdout.write(text));
  if (parsed.help) {
    stdout(`${PUBLISH_CHECKPOINT_HELP}\n`);
    return;
  }

  const environment = dependencies.environment ?? process.env;
  const checkpointPrivateKey = requiredEnvironmentValue(environment, CHECKPOINT_PRIVATE_KEY_ENV);
  const checkpointKid =
    parsed.signerKid ?? requiredEnvironmentValue(environment, CHECKPOINT_KID_ENV);
  rejectRegistryKeyReuse(environment, checkpointPrivateKey, checkpointKid);

  const readInput = dependencies.readInput ?? readCheckpointInput;
  const input = await readInput(parsed.input as string);
  const manifest = parseUnsignedCheckpointManifest(input);
  const signed = await signCheckpointManifest(manifest, {
    keyPurpose: 'transparency-checkpoint',
    signerKid: checkpointKid,
    privateKeyPkcs8Base64Url: checkpointPrivateKey,
  });
  const body = serializeSignedCheckpoint(signed);

  if (parsed.output !== undefined) {
    const writeOutput = dependencies.writeOutput ?? writeCheckpointOutput;
    await writeOutput(parsed.output, body);
  }
  if (parsed.upload) {
    const uploadUrl = requiredEnvironmentValue(environment, parsed.uploadUrlEnvironment);
    const bearerToken =
      parsed.uploadTokenEnvironment === undefined
        ? undefined
        : requiredEnvironmentValue(environment, parsed.uploadTokenEnvironment);
    const upload = dependencies.upload ?? uploadSignedCheckpoint;
    await upload(body, {
      url: uploadUrl,
      ...(bearerToken === undefined ? {} : { bearerToken }),
    });
  }

  stdout(`${body}\n`);
}

function safeErrorMessage(error: unknown): string {
  if (error instanceof CheckpointScriptError) {
    return error.message;
  }
  if (isRecord(error) && typeof error.code === 'string' && error.code === 'EEXIST') {
    return 'The output path already exists; refusing to overwrite it.';
  }
  return 'Checkpoint publication failed.';
}

if (process.argv[1] !== undefined && pathToFileURL(process.argv[1]).href === import.meta.url) {
  runPublishCheckpointCli(process.argv.slice(2)).catch((error: unknown) => {
    process.stderr.write(`Error: ${safeErrorMessage(error)}\n`);
    process.exitCode = 1;
  });
}
