import { verifyTestVectorDirectory } from '../packages/test-vectors/src/verify.js';

const directory = new URL('../packages/test-vectors/vectors/', import.meta.url);
const verified = await verifyTestVectorDirectory(directory);
process.stdout.write(`Verified ${String(verified.length)} Nexus vector groups.\n`);
