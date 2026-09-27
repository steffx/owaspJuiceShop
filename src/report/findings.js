/**
 * Records a security finding for the dashboard and the score board coverage report.
 *
 * A finding is a single detector result: the check ran, and it observed the expected
 * behaviour (`detected: true`) or did not. Findings are appended as JSONL so parallel
 * Playwright workers can all write safely; the dashboard aggregates them at the end.
 */
import fs from 'node:fs';
import path from 'node:path';

const RESULTS_DIR = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..', 'results');
const FILE = path.join(RESULTS_DIR, 'findings.jsonl');

/**
 * @param {object} f
 * @param {string} f.id            stable id, e.g. "AC-01"
 * @param {string} f.area          focus-area key (access-control | headers | authentication | data-exposure)
 * @param {string} f.owasp         OWASP category id, e.g. "API1:2023"
 * @param {string} f.title         short human description
 * @param {'info'|'low'|'medium'|'high'|'critical'} f.severity
 * @param {boolean} f.detected     did the detector observe the expected behaviour?
 * @param {string} [f.evidence]    short, non-sensitive evidence string
 */
export function recordFinding(f) {
  for (const key of ['id', 'area', 'owasp', 'title', 'severity']) {
    if (!f[key]) throw new Error(`finding is missing "${key}"`);
  }
  fs.mkdirSync(RESULTS_DIR, { recursive: true });
  fs.appendFileSync(FILE, `${JSON.stringify({ ...f, recordedAt: new Date().toISOString() })}\n`);
}

export function readFindings() {
  if (!fs.existsSync(FILE)) return [];
  return fs
    .readFileSync(FILE, 'utf8')
    .trim()
    .split('\n')
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

export const FINDINGS_FILE = FILE;
