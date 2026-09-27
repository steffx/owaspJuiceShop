import fs from 'node:fs';
import path from 'node:path';
import { test, expect } from '../../src/fixtures.js';
import { buildCoverage } from '../../src/scoreboard.js';
import { readFindings } from '../../src/report/findings.js';

/**
 * Ties the suite's checks back to Juice Shop's own score board.
 *
 * Runs after the security project (see the project dependency in the config), so the findings
 * file already lists which focus areas produced results. We fetch the full challenge catalogue,
 * map its categories onto our four focus areas and write a coverage report for the dashboard.
 */
test('score board coverage report', { tag: '@coverage' }, async ({ api }) => {
  const res = await api.challenges();
  expect(res.status(), 'score board must be reachable').toBe(200);
  const challenges = (await res.json()).data;
  expect(Array.isArray(challenges)).toBe(true);

  const exercised = new Set(readFindings().map((f) => f.area));
  const coverage = buildCoverage(challenges, exercised);

  const dir = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..', '..', 'results');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'coverage.json'), JSON.stringify(coverage, null, 2));

  // The suite must exercise every focus area it claims to cover.
  const notExercised = coverage.areas.filter((a) => !a.exercised).map((a) => a.label);
  expect(notExercised, 'every focus area should have at least one finding').toEqual([]);
  expect(coverage.totalChallenges).toBeGreaterThan(0);
});
