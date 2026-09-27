#!/usr/bin/env node
/** Waits until Juice Shop answers, so `npm run juice:up` blocks until the app is ready. */
const url = (process.env.JUICE_SHOP_URL || 'http://localhost:3000') + '/rest/admin/application-version';
const deadlineMs = Date.now() + 120_000;

async function wait() {
  while (Date.now() < deadlineMs) {
    try {
      const res = await fetch(url);
      if (res.ok) {
        const body = await res.json().catch(() => ({}));
        console.log(`Juice Shop is up${body.version ? ` (version ${body.version})` : ''}`);
        return;
      }
    } catch {
      // not ready yet
    }
    await new Promise((r) => setTimeout(r, 2000));
  }
  console.error('Juice Shop did not become ready within 120s');
  process.exit(1);
}

wait();
