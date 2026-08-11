import { writeTestVectorFiles } from '../packages/test-vectors/src/generate.js';

const directory = new URL('../packages/test-vectors/vectors/', import.meta.url);
const files = await writeTestVectorFiles(directory);
process.stdout.write(`Generated ${String(files.length)} deterministic Nexus vector files.\n`);
