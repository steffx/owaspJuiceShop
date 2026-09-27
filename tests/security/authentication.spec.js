import { test, expect } from '../../src/fixtures.js';
import { uniqueEmail } from '../../src/JuiceShopClient.js';
import { recordFinding } from '../../src/report/findings.js';

/** Decodes a JWT header/payload without verifying (for inspecting the algorithm and claims). */
function decodeJwt(token) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) return null;
  const decode = (seg) => JSON.parse(Buffer.from(seg.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));
  try {
    return { header: decode(parts[0]), payload: decode(parts[1]) };
  } catch {
    return null;
  }
}

/**
 * Authentication (OWASP API2).
 * Invariants (a valid login works, a wrong password is rejected) are hard-asserted; password
 * policy, token properties, user enumeration and lockout posture are recorded as findings.
 */
test.describe('Authentication', () => {
  test('a valid credential authenticates and a wrong one is rejected', { tag: '@invariant' }, async ({ api }) => {
    const email = uniqueEmail('auth');
    const password = 'Str0ng-Passw0rd!';
    expect((await api.register(email, password)).status()).toBe(201);
    expect((await api.loginRaw(email, password)).status()).toBe(200);
    expect((await api.loginRaw(email, 'not-the-password')).status()).toBe(401);
  });

  test('AU-01 password policy at registration', async ({ api }) => {
    const res = await api.register(uniqueEmail('weak'), '123');
    const accepted = res.status() === 201;
    recordFinding({
      id: 'AU-01',
      area: 'authentication',
      owasp: 'API2:2023',
      title: 'Weak password accepted at registration',
      severity: 'medium',
      detected: accepted,
      evidence: `register with "123" -> ${res.status()}`,
    });
    expect(res.status(), 'registration must not crash').toBeLessThan(500);
  });

  test('AU-02 access token algorithm and expiry', async ({ customer }) => {
    const login = await customer.loginRaw(customer.email, 'Str0ng-Passw0rd!');
    const token = (await login.json()).authentication?.token;
    const decoded = decodeJwt(token);
    expect(decoded, 'auth token should be a JWT').not.toBeNull();

    const alg = decoded.header.alg;
    const hasExpiry = typeof decoded.payload.exp === 'number';
    recordFinding({
      id: 'AU-02',
      area: 'authentication',
      owasp: 'API2:2023',
      title: 'JWT algorithm and expiry',
      severity: alg === 'none' ? 'critical' : hasExpiry ? 'info' : 'low',
      detected: alg === 'none' || !hasExpiry,
      evidence: `alg=${alg}, exp=${hasExpiry ? 'set' : 'missing'}`,
    });
    expect(alg, 'the "none" algorithm must never be used').not.toBe('none');
  });

  test('AU-03 login error reveals whether an account exists (user enumeration)', async ({ api }) => {
    const email = uniqueEmail('enum');
    await api.register(email, 'Str0ng-Passw0rd!');
    const unknown = await api.loginRaw(uniqueEmail('ghost'), 'whatever');
    const wrongPassword = await api.loginRaw(email, 'whatever');

    const differ = unknown.status() !== wrongPassword.status();
    recordFinding({
      id: 'AU-03',
      area: 'authentication',
      owasp: 'API2:2023',
      title: 'Login responses distinguish unknown vs. wrong-password',
      severity: differ ? 'low' : 'info',
      detected: differ,
      evidence: `unknown email -> ${unknown.status()}, wrong password -> ${wrongPassword.status()}`,
    });
  });

  test('AU-04 repeated failed logins are not rate-limited or locked out', async ({ api }) => {
    const email = uniqueEmail('lock');
    await api.register(email, 'Str0ng-Passw0rd!');
    const statuses = [];
    for (let i = 0; i < 6; i++) statuses.push((await api.loginRaw(email, `wrong-${i}`)).status());
    const throttled = statuses.some((s) => s === 429 || s === 423);

    recordFinding({
      id: 'AU-04',
      area: 'authentication',
      owasp: 'API2:2023',
      title: 'No lockout or throttling after repeated failures',
      severity: 'medium',
      detected: !throttled,
      evidence: `6 failed logins -> statuses ${statuses.join(',')}`,
    });
    // Invariant: the correct password still works afterwards (no self-inflicted outage in the test).
    expect((await api.loginRaw(email, 'Str0ng-Passw0rd!')).status()).toBe(200);
  });
});
