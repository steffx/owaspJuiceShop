import { test, expect } from '../../src/fixtures.js';

/**
 * A small functional smoke test. The suite is security-focused, but a security finding is only
 * meaningful if the core shopping flow actually works, so these guard the baseline.
 */
test.describe('Shopping flow', () => {
  test('the product catalogue is available', { tag: '@smoke' }, async ({ api }) => {
    const res = await api.products();
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(Array.isArray(body.data)).toBe(true);
    expect(body.data.length).toBeGreaterThan(0);
    expect(body.data[0]).toHaveProperty('name');
    expect(body.data[0]).toHaveProperty('price');
  });

  test('a customer can register, log in and see who they are', { tag: '@smoke' }, async ({ customer }) => {
    expect(customer.token).toBeTruthy();
    const who = await customer.whoami();
    expect(who.status()).toBe(200);
    expect((await who.json()).user.email).toBe(customer.email);
  });

  test('a customer can add a product to their own basket', async ({ customer, api }) => {
    const product = (await (await api.products()).json()).data[0];
    const res = await customer.addBasketItem(customer.basketId, product.id, 2);
    expect([200, 201]).toContain(res.status());

    const basket = await customer.getBasket(customer.basketId);
    expect(basket.status()).toBe(200);
    const contents = await basket.json();
    const items = contents.data?.Products ?? contents.data?.products ?? [];
    expect(Array.isArray(items)).toBe(true);
  });

  test('the score board challenge feed is reachable', { tag: '@smoke' }, async ({ api }) => {
    const res = await api.challenges();
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(Array.isArray(body.data)).toBe(true);
    expect(body.data[0]).toHaveProperty('category');
  });
});
