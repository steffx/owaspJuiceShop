/**
 * Pure helpers for asserting security configuration on an HTTP response.
 *
 * These functions take a plain headers object (lower-cased keys, as Playwright's
 * response.headers() returns) and return structured findings, so they can be unit-tested
 * without a live server and reused across specs.
 */

const asString = (headers, name) => {
  const value = headers[name.toLowerCase()];
  return value === undefined ? undefined : String(value);
};

/**
 * Checks the baseline security headers a hardened web app should send.
 * Returns one result per expected header: { header, present, value, ok, note }.
 */
export function checkSecurityHeaders(headers) {
  const results = [];
  const add = (header, ok, note, value) => results.push({ header, present: value !== undefined, value, ok, note });

  const csp = asString(headers, 'content-security-policy');
  add('content-security-policy', csp !== undefined && !/unsafe-inline|unsafe-eval/.test(csp),
    csp === undefined ? 'no CSP set' : /unsafe-inline|unsafe-eval/.test(csp) ? 'CSP allows unsafe-inline/eval' : 'restrictive CSP', csp);

  const hsts = asString(headers, 'strict-transport-security');
  add('strict-transport-security', hsts !== undefined && /max-age=\d+/.test(hsts) && Number(/max-age=(\d+)/.exec(hsts)?.[1]) >= 15552000,
    hsts === undefined ? 'no HSTS' : 'HSTS present', hsts);

  const xcto = asString(headers, 'x-content-type-options');
  add('x-content-type-options', xcto === 'nosniff', xcto === undefined ? 'missing' : `value "${xcto}"`, xcto);

  const xfo = asString(headers, 'x-frame-options');
  const frameAncestors = csp !== undefined && /frame-ancestors/.test(csp);
  add('x-frame-options', (xfo !== undefined && /^(DENY|SAMEORIGIN)$/i.test(xfo)) || frameAncestors,
    xfo === undefined && !frameAncestors ? 'clickjacking protection missing' : 'clickjacking protection present', xfo);

  const refpol = asString(headers, 'referrer-policy');
  add('referrer-policy', refpol !== undefined, refpol === undefined ? 'missing' : `value "${refpol}"`, refpol);

  return results;
}

/** Parses a Set-Cookie header (string or array) into flag objects. */
export function parseSetCookie(setCookie) {
  const raw = setCookie === undefined ? [] : Array.isArray(setCookie) ? setCookie : String(setCookie).split(/,(?=[^;]+?=)/);
  return raw.filter(Boolean).map((line) => {
    const [pair, ...attrs] = line.split(';').map((s) => s.trim());
    const eq = pair.indexOf('=');
    const flags = new Set(attrs.map((a) => a.split('=')[0].toLowerCase()));
    const sameSite = attrs.map((a) => a.split('=')).find(([k]) => k.toLowerCase() === 'samesite')?.[1];
    return {
      name: pair.slice(0, eq),
      httpOnly: flags.has('httponly'),
      secure: flags.has('secure'),
      sameSite: sameSite ?? null,
    };
  });
}

/** Flags session/auth cookies that are missing HttpOnly, Secure or SameSite. */
export function checkCookieFlags(setCookie, { sessionCookieNames = [/sess/i, /token/i, /jwt/i, /auth/i] } = {}) {
  return parseSetCookie(setCookie)
    .filter((cookie) => sessionCookieNames.some((re) => re.test(cookie.name)))
    .map((cookie) => ({
      name: cookie.name,
      httpOnly: cookie.httpOnly,
      secure: cookie.secure,
      sameSite: cookie.sameSite,
      ok: cookie.httpOnly && cookie.secure && cookie.sameSite !== null,
      issues: [
        !cookie.httpOnly && 'not HttpOnly',
        !cookie.secure && 'not Secure',
        cookie.sameSite === null && 'no SameSite',
      ].filter(Boolean),
    }));
}

/** Heuristic: does a response body leak an internal stack trace or framework detail? */
export function looksLikeStackTrace(body) {
  const text = typeof body === 'string' ? body : JSON.stringify(body ?? '');
  return /at\s+\/?\w[\w./-]*:\d+:\d+|\n\s+at\s+\w|Sequelize\w+Error|node_modules|ENOENT|\.ts:\d+|\.js:\d+\)/.test(text);
}

/** Server/framework banner headers that reveal the stack (defense-in-depth: they should be absent). */
export function fingerprintHeaders(headers) {
  return ['server', 'x-powered-by'].map((name) => ({ header: name, value: asString(headers, name), leaked: asString(headers, name) !== undefined }));
}
