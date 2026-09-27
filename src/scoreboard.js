/**
 * Score board integration.
 *
 * Juice Shop exposes every challenge at GET /api/Challenges, each tagged with a `category`
 * (e.g. "Broken Access Control", "Security Misconfiguration"). This module maps those
 * categories onto the suite's four focus areas and builds a coverage report: for each area,
 * how many challenge categories the score board defines and whether our suite exercises it.
 *
 * This ties our checks back to an external, authoritative catalogue of weaknesses instead of
 * a list we invented.
 */
import { FOCUS_AREAS } from './security/owasp.js';

/** Maps a Juice Shop challenge category to one of our focus-area keys, or null. */
export function mapCategoryToFocus(category) {
  const c = String(category || '').toLowerCase();
  if (c.includes('access control')) return 'access-control';
  if (c.includes('misconfiguration')) return 'headers';
  if (c.includes('authentication')) return 'authentication';
  if (c.includes('sensitive data') || c.includes('data exposure')) return 'data-exposure';
  return null;
}

/** Counts challenges per category from the /api/Challenges payload. */
export function summariseChallenges(challenges) {
  const byCategory = {};
  for (const ch of challenges) {
    const cat = ch.category ?? 'Unknown';
    (byCategory[cat] ??= { total: 0, solved: 0 }).total += 1;
    if (ch.solved) byCategory[cat].solved += 1;
  }
  return byCategory;
}

/**
 * Builds the coverage report.
 * @param {Array} challenges         parsed /api/Challenges list
 * @param {Set<string>} exercised    focus-area keys the suite has at least one passing test for
 */
export function buildCoverage(challenges, exercised) {
  const byCategory = summariseChallenges(challenges);
  const areas = FOCUS_AREAS.map((area) => {
    const categories = Object.entries(byCategory)
      .filter(([cat]) => mapCategoryToFocus(cat) === area.key)
      .map(([name, counts]) => ({ name, ...counts }));
    return {
      key: area.key,
      label: area.label,
      owasp: area.categories,
      scoreboardCategories: categories,
      challengeCount: categories.reduce((sum, c) => sum + c.total, 0),
      exercised: exercised.has(area.key),
    };
  });
  const mappable = challenges.filter((ch) => mapCategoryToFocus(ch.category) !== null).length;
  return {
    generatedAt: new Date().toISOString(),
    totalChallenges: challenges.length,
    challengesInFocusAreas: mappable,
    areasExercised: areas.filter((a) => a.exercised).length,
    areasTotal: areas.length,
    areas,
  };
}
