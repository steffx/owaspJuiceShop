import { test, expect } from '../../src/fixtures.js';
import { recordFinding } from '../../src/report/findings.js';

/**
 * Broken access control (OWASP API1 & API5).
 *
 * These detectors are validated against Juice Shop, a target whose access-control weaknesses
 * are documented, so we know the detector fires correctly before pointing it at a real service.
 * Hard assertions cover the invariants that must always hold (auth is required, no server error);
 * the observed authorization outcome is recorded as a finding for the dashboard.
 */

/** Classifies an authorization response without assuming the target is vulnerable or patched. */
function classify(status) {
  if (status === 200) return 'allowed';
  if (status === 401 || status === 403) return 'denied';
  return 'unexpected';
}

test.describe('Access control', () => {
  test('unauthenticated access to the current user is refused', { tag: '@invariant' }, async ({ api }) => {
    const res = await api.whoami();
    expect(res.status(), 'whoami without a token must be 401').toBe(401);
  });

  test('AC-01 a user cannot read another user\'s basket (BOLA)', async ({ newCustomer }) => {
    const alice = await newCustomer();
    const bob = await newCustomer();
    expect(bob.basketId, 'each customer gets their own basket id').not.toBe(alice.basketId);

    const res = await alice.getBasket(bob.basketId);
    const outcome = classify(res.status());
    expect(outcome, `unexpected status ${res.status()} reading another basket`).not.toBe('unexpected');

    recordFinding({
      id: 'AC-01',
      area: 'access-control',
      owasp: 'API1:2023',
      title: "Read another user's basket by id",
      severity: 'high',
      detected: outcome === 'allowed',
      evidence: `GET /rest/basket/${bob.basketId} as another user -> ${res.status()} (${outcome})`,
    });
  });

  test('AC-02 a user cannot add items to another user\'s basket', async ({ newCustomer, api }) => {
    const alice = await newCustomer();
    const bob = await newCustomer();
    const products = await (await api.products()).json();
    const productId = products.data?.[0]?.id ?? 1;

    const res = await alice.addBasketItem(bob.basketId, productId, 1);
    const outcome = classify(res.status() === 201 ? 200 : res.status());
    expect(res.status(), 'must not be a server error').toBeLessThan(500);

    recordFinding({
      id: 'AC-02',
      area: 'access-control',
      owasp: 'API1:2023',
      title: "Write into another user's basket",
      severity: 'high',
      detected: res.status() === 200 || res.status() === 201,
      evidence: `POST /api/BasketItems into basket ${bob.basketId} -> ${res.status()}`,
    });
  });

  test('AC-03 a normal user cannot list all users (function-level authz)', async ({ customer }) => {
    const res = await customer.request.get('/api/Users', { headers: customer.authHeaders() });
    expect(res.status(), 'must not be a server error').toBeLessThan(500);
    const body = res.status() === 200 ? await res.json() : null;
    const exposedAll = Array.isArray(body?.data) && body.data.length > 1;

    recordFinding({
      id: 'AC-03',
      area: 'access-control',
      owasp: 'API5:2023',
      title: 'List all user accounts as a normal user',
      severity: 'high',
      detected: exposedAll,
      evidence: `GET /api/Users -> ${res.status()}${exposedAll ? ` (${body.data.length} users returned)` : ''}`,
    });
  });

  test('AC-04 a user cannot read an arbitrary user object by id', async ({ customer }) => {
    // Ask for a different user id than our own.
    const otherId = customer.userId === 1 ? 2 : 1;
    const res = await customer.getUser(otherId);
    expect(res.status(), 'must not be a server error').toBeLessThan(500);
    const body = res.status() === 200 ? await res.json() : null;
    const gotOther = body?.data?.id !== undefined && body.data.id !== customer.userId;

    recordFinding({
      id: 'AC-04',
      area: 'access-control',
      owasp: 'API1:2023',
      title: 'Read another user object by id',
      severity: 'medium',
      detected: gotOther,
      evidence: `GET /api/Users/${otherId} -> ${res.status()}`,
    });
  });
});
