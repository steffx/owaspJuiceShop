import { test, expect } from '@playwright/test';
import { mapCategoryToFocus, summariseChallenges, buildCoverage } from '../../src/scoreboard.js';
import { maxSeverity, severityRank, focusAreaFor, FOCUS_AREAS } from '../../src/security/owasp.js';

const SAMPLE = [
  { name: 'View Basket', category: 'Broken Access Control', solved: true },
  { name: 'Admin Section', category: 'Broken Access Control', solved: false },
  { name: 'Weird Crypto', category: 'Cryptographic Issues', solved: false },
  { name: 'Login Admin', category: 'Broken Authentication', solved: false },
  { name: 'Deprecated Interface', category: 'Security Misconfiguration', solved: false },
  { name: 'Access Log', category: 'Sensitive Data Exposure', solved: true },
  { name: 'Reflected XSS', category: 'XSS', solved: false },
];

test.describe('Score board category mapping', () => {
  const cases = [
    ['Broken Access Control', 'access-control'],
    ['Security Misconfiguration', 'headers'],
    ['Broken Authentication', 'authentication'],
    ['Sensitive Data Exposure', 'data-exposure'],
    ['XSS', null],
    ['Injection', null],
    [undefined, null],
  ];
  for (const [category, expected] of cases) {
    test(`"${category}" -> ${expected}`, () => expect(mapCategoryToFocus(category)).toBe(expected));
  }
});

test('summarises challenges per category with solved counts', () => {
  const summary = summariseChallenges(SAMPLE);
  expect(summary['Broken Access Control']).toEqual({ total: 2, solved: 1 });
  expect(summary['Sensitive Data Exposure']).toEqual({ total: 1, solved: 1 });
});

test.describe('Coverage report', () => {
  test('marks only exercised areas as covered', () => {
    const coverage = buildCoverage(SAMPLE, new Set(['access-control', 'headers']));
    const byKey = Object.fromEntries(coverage.areas.map((a) => [a.key, a]));
    expect(byKey['access-control'].exercised).toBe(true);
    expect(byKey['headers'].exercised).toBe(true);
    expect(byKey['authentication'].exercised).toBe(false);
    expect(coverage.areasExercised).toBe(2);
    expect(coverage.areasTotal).toBe(4);
  });

  test('counts challenges that fall inside a focus area', () => {
    const coverage = buildCoverage(SAMPLE, new Set());
    // 2 access-control + 1 auth + 1 misconfig + 1 data-exposure = 5 of 7
    expect(coverage.challengesInFocusAreas).toBe(5);
    expect(coverage.totalChallenges).toBe(7);
  });

  test('lists the score board categories under each area', () => {
    const coverage = buildCoverage(SAMPLE, new Set(['access-control']));
    const ac = coverage.areas.find((a) => a.key === 'access-control');
    expect(ac.scoreboardCategories[0]).toMatchObject({ name: 'Broken Access Control', total: 2, solved: 1 });
    expect(ac.challengeCount).toBe(2);
  });

  test('every focus area is represented even with no challenges', () => {
    const coverage = buildCoverage([], new Set());
    expect(coverage.areas.map((a) => a.key)).toEqual(FOCUS_AREAS.map((a) => a.key));
  });
});

test.describe('Severity helpers', () => {
  test('ranks severities in order', () => {
    expect(severityRank('info')).toBeLessThan(severityRank('critical'));
  });

  test('maxSeverity picks the worst', () => {
    expect(maxSeverity(['low', 'high', 'medium'])).toBe('high');
    expect(maxSeverity([])).toBeNull();
  });

  test('throws on an unknown severity', () => {
    expect(() => severityRank('spicy')).toThrow(/Unknown severity/);
  });

  test('focusAreaFor resolves an OWASP category key', () => {
    expect(focusAreaFor('API1').key).toBe('access-control');
    expect(focusAreaFor('API8').key).toBe('headers');
  });
});
