import { test as base, expect } from '@playwright/test';
import { JuiceShopClient } from './JuiceShopClient.js';

export const test = base.extend({
  /** Factory: an unauthenticated client (raw request wrapper). */
  api: async ({ request }, use) => {
    await use(new JuiceShopClient(request));
  },

  /** Factory: create as many freshly registered + logged-in customers as a test needs. */
  newCustomer: async ({ playwright, baseURL }, use) => {
    const contexts = [];
    await use(async () => {
      const context = await playwright.request.newContext({ baseURL, ignoreHTTPSErrors: true });
      contexts.push(context);
      return new JuiceShopClient(context).registerAndLogin();
    });
    await Promise.all(contexts.map((c) => c.dispose()));
  },

  /** A single logged-in customer, for the common case. */
  customer: async ({ newCustomer }, use) => {
    await use(await newCustomer());
  },
});

export { expect };
