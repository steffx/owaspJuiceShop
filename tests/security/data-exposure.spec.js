import { test, expect } from '../../src/fixtures.js';
import { recordFinding } from '../../src/report/findings.js';
import { looksLikeStackTrace } from '../../src/security/headers.js';

/**
 * Sensitive data exposure (OWASP API3).
 * Checks that responses don't over-share (password hashes, other users' data) and that errors
 * don't leak internal stack traces. Invariants (endpoints respond) are hard-asserted; the
 * exposure posture is recorded.
 */
test.describe('Sensitive data exposure', () => {
  test('DE-01 the current-user response does not include the password hash', async ({ customer }) => {
    const res = await customer.whoami();
    expect(res.status()).toBe(200);
    const raw = await res.text();
    const leaksPassword = /"password"\s*:\s*"[^"]+"/.test(raw);

    recordFinding({
      id: 'DE-01',
      area: 'data-exposure',
      owasp: 'API3:2023',
      title: 'Password hash exposed in the user object',
      severity: 'high',
      detected: leaksPassword,
      evidence: `GET /rest/user/whoami password field ${leaksPassword ? 'present' : 'absent'}`,
    });
  });

  test('DE-02 a user object does not over-share fields', async ({ customer }) => {
    const res = await customer.getUser(customer.userId ?? 1);
    expect(res.status()).toBeLessThan(500);
    const raw = res.status() === 200 ? await res.text() : '';
    const sensitive = ['password', 'totpSecret'].filter((f) => new RegExp(`"${f}"\\s*:\\s*"[^"]`).test(raw));

    recordFinding({
      id: 'DE-02',
      area: 'data-exposure',
      owasp: 'API3:2023',
      title: 'User object exposes sensitive properties',
      severity: 'high',
      detected: sensitive.length > 0,
      evidence: sensitive.length ? `fields present: ${sensitive.join(', ')}` : 'no sensitive fields',
    });
  });

  test('DE-03 product reviews do not expose author email addresses', async ({ api }) => {
    const res = await api.request.get('/rest/products/1/reviews', { headers: api.authHeaders() });
    expect(res.status()).toBeLessThan(500);
    const raw = res.status() === 200 ? await res.text() : '';
    const exposesAuthor = /@juice-sh\.op|"author"\s*:\s*"[^"]+@/.test(raw);

    recordFinding({
      id: 'DE-03',
      area: 'data-exposure',
      owasp: 'API3:2023',
      title: 'Product reviews expose reviewer email addresses',
      severity: 'medium',
      detected: exposesAuthor,
      evidence: `GET /rest/products/1/reviews -> ${res.status()}`,
    });
  });

  test('DE-04 a malformed request does not return an internal stack trace', async ({ api }) => {
    // A well-formed-but-invalid id should produce a clean client error, not a server stack trace.
    const res = await api.request.get('/api/Products/not-a-number', { headers: api.authHeaders() });
    const body = await res.text();
    const leaks = looksLikeStackTrace(body);

    recordFinding({
      id: 'DE-04',
      area: 'data-exposure',
      owasp: 'API3:2023',
      title: 'Verbose error leaks a stack trace',
      severity: 'medium',
      detected: leaks,
      evidence: `GET /api/Products/not-a-number -> ${res.status()}${leaks ? ' (stack trace in body)' : ''}`,
    });
    expect(res.status(), 'a bad id should be a 4xx or a handled 5xx, not a hang').toBeLessThan(600);
  });

  test('DE-05 feedback list does not leak other users\' identifiers in plain form', async ({ api }) => {
    const res = await api.feedbacks();
    expect(res.status()).toBeLessThan(500);
    const body = res.status() === 200 ? await res.json() : { data: [] };
    const withUser = (body.data ?? []).filter((f) => f.UserId != null).length;

    recordFinding({
      id: 'DE-05',
      area: 'data-exposure',
      owasp: 'API3:2023',
      title: 'Public feedback list ties entries to user ids',
      severity: 'low',
      detected: withUser > 0,
      evidence: `GET /api/Feedbacks -> ${res.status()}, ${withUser} entries carry a UserId`,
    });
  });
});
