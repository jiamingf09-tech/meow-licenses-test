import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { statusRemainingHours } from './publish-status.mjs';

// Usage: node automation/status-health.mjs <minimum-hours> [repository-directory]
// Prints the remaining validity and exits non-zero when it is below the minimum.
const minimum = Number(process.argv[2] ?? '48');
const directory = resolve(process.argv[3] || '.');
try {
  const hours = statusRemainingHours(await readFile(resolve(directory, 'v1/status.json')));
  console.log(`remaining=${hours.toFixed(1)}`);
  if (!(hours >= minimum)) {
    console.error(`Published authorization status has ${hours.toFixed(1)} hours left (minimum ${minimum}).`);
    process.exitCode = 1;
  }
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
