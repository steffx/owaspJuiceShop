import { test, expect } from '../../src/fixtures.js';
import { recordFinding } from '../../src/report/findings.js';
import { checkSecurityHeaders, checkCookieFlags, fingerprintHeaders } from '../../src/security/headers.js';

/**
 * Security headers & configuration (OWASP API8).
 *
 * Pure regression testing: fetch real responses and assert the security-configuration
 * helpers (unit-tested separately) against them. Each header/cookie result is recorded so the
 * dashboard shows the target's configuration posture.
 */
test.describe('Security headers & configuration', () => {
  test('HDR-01 baseline response security headers', async ({ request }) => {
    const res = await request.get('/');
    expect(res.status(), 'home page must load').toBeLessThan(500);
    const results = checkSecurityHeaders(res.headers());
    expect(results.length, 'all baseline headers are inspected').toBeGreaterThanOrEqual(5);

    for (const r of results) {
      recordFinding({
        id: `HDR-01:${r.header}`,
        area: 'headers',
        owasp: 'API8:2023',
        title: `Response header ${r.header}`,
        severity: r.ok ? 'info' : 'medium',
        detected: !r.ok, // "detected" here = a misconfiguration was found
        evidence: `${r.header}: ${r.note}`,
      });
    }
  });

  test('HDR-02 session/token cookie flags', async ({ customer }) => {
    // Inspect cookies set on a real, successful login response.
    const res = await customer.loginRaw(customer.email, 'Str0ng-Passw0rd!');
    const setCookie = res.headers()['set-cookie'];
    const cookieIssues = checkCookieFlags(setCookie);

    recordFinding({
      id: 'HDR-02',
      area: 'headers',
      owasp: 'API8:2023',
      title: 'Session cookie flags (HttpOnly, Secure, SameSite)',
      severity: cookieIssues.some((c) => !c.ok) ? 'medium' : 'info',
      detected: cookieIssues.some((c) => !c.ok),
      evidence: cookieIssues.length ? cookieIssues.map((c) => `${c.name}: ${c.issues.join(', ') || 'ok'}`).join('; ') : 'no session cookies set',
    });
    // Invariant: the endpoint must respond, not crash.
    expect(res.status()).toBeLessThan(500);
  });

  test('HDR-03 server/framework fingerprint headers', async ({ request }) => {
    const res = await request.get('/');
    const banners = fingerprintHeaders(res.headers());
    const leaked = banners.filter((b) => b.leaked);

    recordFinding({
      id: 'HDR-03',
      area: 'headers',
      owasp: 'API8:2023',
      title: 'Server/framework version disclosure',
      severity: leaked.length ? 'low' : 'info',
      detected: leaked.length > 0,
      evidence: leaked.length ? leaked.map((b) => `${b.header}: ${b.value}`).join('; ') : 'no fingerprint headers',
    });
  });

  test('HDR-04 CORS is not wildcard-open with credentials', async ({ request }) => {
    const res = await request.get('/rest/products/search?q=', { headers: { Origin: 'https://evil.example' } });
    const allowOrigin = res.headers()['access-control-allow-origin'];
    const allowCreds = res.headers()['access-control-allow-credentials'];
    const dangerous = allowOrigin === '*' && allowCreds === 'true';

    recordFinding({
      id: 'HDR-04',
      area: 'headers',
      owasp: 'API8:2023',
      title: 'Permissive CORS with credentials',
      severity: dangerous ? 'high' : 'info',
      detected: dangerous,
      evidence: `Access-Control-Allow-Origin: ${allowOrigin ?? 'unset'}, Allow-Credentials: ${allowCreds ?? 'unset'}`,
    });
    expect(res.status()).toBeLessThan(500);
  });
});
