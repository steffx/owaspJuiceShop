/**
 * REST client for OWASP Juice Shop. Wraps the handful of endpoints the security specs use,
 * so tests read as intent ("A requests B's basket") rather than URL plumbing.
 *
 * Endpoints used (stable across Juice Shop versions):
 *   POST /api/Users              register
 *   POST /rest/user/login        login -> { authentication: { token, bid, umail } }
 *   GET  /rest/user/whoami       current user
 *   GET  /api/Products           catalogue
 *   GET  /rest/basket/:id        a basket (object-level authorization boundary)
 *   POST /api/BasketItems        add an item to a basket
 *   GET  /api/Users/:id          a user object (property-level authorization)
 *   GET  /api/Feedbacks          feedback list
 *   GET  /api/Challenges         the score board
 */
import crypto from 'node:crypto';

export function uniqueEmail(prefix = 'user') {
  return `${prefix}.${crypto.randomBytes(5).toString('hex')}@juice-sh.op`;
}

export class JuiceShopClient {
  /** @param {import('@playwright/test').APIRequestContext} request */
  constructor(request) {
    this.request = request;
    this.token = null;
    this.email = null;
    this.userId = null;
    this.basketId = null;
  }

  authHeaders(extra = {}) {
    return { ...(this.token ? { Authorization: `Bearer ${this.token}` } : {}), ...extra };
  }

  register(email, password, extra = {}) {
    return this.request.post('/api/Users', {
      data: { email, password, passwordRepeat: password, ...extra },
      headers: { 'Content-Type': 'application/json' },
    });
  }

  loginRaw(email, password) {
    return this.request.post('/rest/user/login', {
      data: { email, password },
      headers: { 'Content-Type': 'application/json' },
    });
  }

  /** Registers a fresh customer and logs them in, populating token/basketId/userId. */
  async registerAndLogin(password = 'Str0ng-Passw0rd!') {
    this.email = uniqueEmail();
    const reg = await this.register(this.email, password);
    if (reg.status() !== 201) throw new Error(`register failed: ${reg.status()} ${await reg.text()}`);
    const login = await this.loginRaw(this.email, password);
    if (login.status() !== 200) throw new Error(`login failed: ${login.status()} ${await login.text()}`);
    const auth = (await login.json()).authentication;
    this.token = auth.token;
    this.basketId = auth.bid;
    const who = await (await this.whoami()).json();
    this.userId = who?.user?.id ?? null;
    return this;
  }

  whoami() {
    return this.request.get('/rest/user/whoami', { headers: this.authHeaders() });
  }

  products() {
    return this.request.get('/api/Products', { headers: this.authHeaders() });
  }

  getBasket(basketId) {
    return this.request.get(`/rest/basket/${basketId}`, { headers: this.authHeaders() });
  }

  addBasketItem(basketId, productId, quantity = 1) {
    return this.request.post('/api/BasketItems', {
      data: { BasketId: basketId, ProductId: productId, quantity },
      headers: this.authHeaders({ 'Content-Type': 'application/json' }),
    });
  }

  getUser(userId) {
    return this.request.get(`/api/Users/${userId}`, { headers: this.authHeaders() });
  }

  feedbacks() {
    return this.request.get('/api/Feedbacks', { headers: this.authHeaders() });
  }

  challenges() {
    return this.request.get('/api/Challenges', { headers: this.authHeaders() });
  }
}
