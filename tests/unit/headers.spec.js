import { test, expect } from '@playwright/test';
import { checkSecurityHeaders, parseSetCookie, checkCookieFlags, looksLikeStackTrace, fingerprintHeaders } from '../../src/security/headers.js';

test.describe('Security header checks', () => {
  test('flags a missing HSTS and a permissive CSP', () => {
    const results = checkSecurityHeaders({ 'content-security-policy': "default-src 'self' 'unsafe-inline'" });
    const byHeader = Object.fromEntries(results.map((r) => [r.header, r]));
    expect(byHeader['strict-transport-security'].ok).toBe(false);
    expect(byHeader['content-security-policy'].ok).toBe(false);
    expect(byHeader['content-security-policy'].note).toMatch(/unsafe-inline/);
  });

  test('passes a hardened set of headers', () => {
    const results = checkSecurityHeaders({
      'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
      'strict-transport-security': 'max-age=31536000; includeSubDomains',
      'x-content-type-options': 'nosniff',
      'x-frame-options': 'DENY',
      'referrer-policy': 'no-referrer',
    });
    expect(results.every((r) => r.ok)).toBe(true);
  });

  test('accepts frame-ancestors in CSP as clickjacking protection', () => {
    const results = checkSecurityHeaders({ 'content-security-policy': "default-src 'self'; frame-ancestors 'none'" });
    expect(results.find((r) => r.header === 'x-frame-options').ok).toBe(true);
  });

  test('rejects an HSTS max-age below six months', () => {
    const results = checkSecurityHeaders({ 'strict-transport-security': 'max-age=3600' });
    expect(results.find((r) => r.header === 'strict-transport-security').ok).toBe(false);
  });
});

test.describe('Cookie flag checks', () => {
  test('parses flags from a single Set-Cookie string', () => {
    const [cookie] = parseSetCookie('token=abc; Path=/; HttpOnly; Secure; SameSite=Strict');
    expect(cookie).toMatchObject({ name: 'token', httpOnly: true, secure: true, sameSite: 'Strict' });
  });

  test('parses an array of cookies', () => {
    const cookies = parseSetCookie(['a=1; HttpOnly', 'session=2; Secure']);
    expect(cookies.map((c) => c.name)).toEqual(['a', 'session']);
  });

  test('flags a session cookie missing HttpOnly and Secure', () => {
    const issues = checkCookieFlags('token=abc; Path=/');
    expect(issues).toHaveLength(1);
    expect(issues[0].ok).toBe(false);
    expect(issues[0].issues).toEqual(['not HttpOnly', 'not Secure', 'no SameSite']);
  });

  test('ignores non-session cookies', () => {
    expect(checkCookieFlags('language=en; Path=/')).toHaveLength(0);
  });

  test('passes a fully protected session cookie', () => {
    const [issue] = checkCookieFlags('sessionId=x; HttpOnly; Secure; SameSite=Lax');
    expect(issue.ok).toBe(true);
    expect(issue.issues).toEqual([]);
  });
});

test.describe('Stack-trace and fingerprint detection', () => {
  const leaks = [
    'Error: ENOENT\n    at /app/routes/login.js:42:15',
    'SequelizeDatabaseError: near "SELECT"',
    'at Object.<anonymous> (/app/node_modules/express/index.js:10:5)',
  ];
  for (const [i, body] of leaks.entries()) {
    test(`detects a stack trace #${i + 1}`, () => expect(looksLikeStackTrace(body)).toBe(true));
  }

  test('does not flag a clean JSON error', () => {
    expect(looksLikeStackTrace({ error: 'Invalid credentials' })).toBe(false);
  });

  test('detects a leaked server banner', () => {
    const results = fingerprintHeaders({ 'x-powered-by': 'Express', server: 'nginx' });
    expect(results.every((r) => r.leaked)).toBe(true);
  });

  test('reports no leak when banners are absent', () => {
    expect(fingerprintHeaders({}).some((r) => r.leaked)).toBe(false);
  });
});
