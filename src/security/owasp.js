/**
 * OWASP API Security Top 10 (2023) categories that this suite exercises, and a mapping
 * from each of our security specs to the categories it covers.
 *
 * The suite treats OWASP Juice Shop as a deliberately vulnerable *training target*: the goal
 * is not to attack it, but to demonstrate a maintainable, CI-friendly security-regression
 * framework. Each check documents an expected behaviour of a security control (an access
 * boundary, a response header, a token property, a response field) and asserts it, exactly
 * as a bank's security-regression pipeline would against its own services.
 */

export const OWASP = Object.freeze({
  API1: { id: 'API1:2023', title: 'Broken Object Level Authorization', short: 'BOLA / IDOR' },
  API2: { id: 'API2:2023', title: 'Broken Authentication', short: 'Authentication' },
  API3: { id: 'API3:2023', title: 'Broken Object Property Level Authorization', short: 'Excessive data exposure' },
  API5: { id: 'API5:2023', title: 'Broken Function Level Authorization', short: 'Function-level authz' },
  API8: { id: 'API8:2023', title: 'Security Misconfiguration', short: 'Headers & config' },
});

/** The four focus areas the suite reports coverage against. */
export const FOCUS_AREAS = Object.freeze([
  { key: 'access-control', label: 'Broken access control', categories: ['API1', 'API5'] },
  { key: 'headers', label: 'Security headers & configuration', categories: ['API8'] },
  { key: 'authentication', label: 'Authentication', categories: ['API2'] },
  { key: 'data-exposure', label: 'Sensitive data exposure', categories: ['API3'] },
]);

export const SEVERITY = Object.freeze(['info', 'low', 'medium', 'high', 'critical']);

export function severityRank(severity) {
  const rank = SEVERITY.indexOf(severity);
  if (rank === -1) throw new Error(`Unknown severity: ${severity}`);
  return rank;
}

/** Highest severity in a list (used to summarise a category on the dashboard). */
export function maxSeverity(severities) {
  if (severities.length === 0) return null;
  return severities.reduce((worst, s) => (severityRank(s) > severityRank(worst) ? s : worst));
}

export function focusAreaFor(categoryKey) {
  return FOCUS_AREAS.find((a) => a.categories.includes(categoryKey));
}
