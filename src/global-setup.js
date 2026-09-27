import fs from 'node:fs';
import { FINDINGS_FILE } from './report/findings.js';

/** Findings accumulate as JSONL across parallel workers; start each run clean. */
export default function globalSetup() {
  fs.rmSync(FINDINGS_FILE, { force: true });
}
