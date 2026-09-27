# OWASP Juice Shop — security regression suite

[![Security suite](https://github.com/steffx/owaspJuiceShop/actions/workflows/ci.yml/badge.svg)](https://github.com/steffx/owaspJuiceShop/actions/workflows/ci.yml)
![Playwright](https://img.shields.io/badge/Playwright-JavaScript-2EAD33?logo=playwright)
![OWASP](https://img.shields.io/badge/OWASP-API%20Top%2010-000000?logo=owasp)

**Live dashboard:** https://steffx.github.io/owaspJuiceShop/

A security-focused test suite for [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/), the
intentionally vulnerable web app OWASP publishes so people can practise security testing. The suite
runs Juice Shop in Docker and checks four areas with Playwright's API client:

- **Broken access control** (OWASP API1 & API5) — reading and writing other users' data, listing all users
- **Security headers & configuration** (API8) — CSP, HSTS, cookie flags, CORS, version disclosure
- **Authentication** (API2) — password policy, JWT algorithm and expiry, user enumeration, lockout
- **Sensitive data exposure** (API3) — password hashes, over-shared fields, verbose stack traces

It also reads Juice Shop's own **score board** API to report how the suite's focus areas map onto the
app's documented challenge categories.

> Juice Shop is deliberately insecure and is used here only as a system under test. The suite never
> attacks a third-party system; it exercises a target that OWASP publishes for exactly this purpose.

## The idea: validate the detectors on a known-vulnerable target

The interesting problem in security testing is *trusting your checks*. A check that never fires is
useless, and you can't tell the difference on a well-configured app. So each check here is a **detector**
run against a target whose weaknesses are documented. If the detector correctly reports the known state
of Juice Shop, you can trust it when you point the same check at a real service — where "green" means
the control is configured correctly.

Each check therefore does two things:

1. **Hard-asserts an invariant** that must always hold (authentication is required where it must be,
   a valid login works, no endpoint returns a 5xx). These fail the build if the app is broken.
2. **Records a finding** — whether the weakness or misconfiguration is present on the target — which
   feeds the dashboard and the score board coverage report.

This mirrors the "test the tests" idea: the same way you validate a fraud model on labelled data, you
validate a security detector on a labelled-vulnerable app.

## Test suite

| Project | Tests | Runs against | Covers |
| --- | ---: | --- | --- |
| `unit` | 31 | nothing (pure logic) | Header/cookie/stack-trace helpers and score board coverage mapping, each with positive and negative cases |
| `functional` | 4 | Juice Shop | Catalogue, register/login, basket, score board reachable — the baseline the security checks depend on |
| `security` | 19 | Juice Shop | The four focus areas below (17 checks + 2 invariant guards) |
| `coverage` | 1 | Juice Shop | Maps findings onto the score board and asserts every focus area was exercised |

### Security checks

| ID | Area | OWASP | Check |
| --- | --- | --- | --- |
| AC-01 | Access control | API1 | Read another user's basket by id (BOLA/IDOR) |
| AC-02 | Access control | API1 | Write into another user's basket |
| AC-03 | Access control | API5 | List all users as a normal user (function-level authz) |
| AC-04 | Access control | API1 | Read an arbitrary user object by id |
| HDR-01 | Headers | API8 | CSP, HSTS, X-Content-Type-Options, clickjacking, Referrer-Policy |
| HDR-02 | Headers | API8 | Session cookie HttpOnly / Secure / SameSite flags |
| HDR-03 | Headers | API8 | Server / framework version disclosure |
| HDR-04 | Headers | API8 | Permissive CORS with credentials |
| AU-01 | Authentication | API2 | Weak password accepted at registration |
| AU-02 | Authentication | API2 | JWT algorithm (never `none`) and expiry set |
| AU-03 | Authentication | API2 | Login responses distinguish unknown vs. wrong password |
| AU-04 | Authentication | API2 | No lockout/throttling after repeated failures |
| DE-01 | Data exposure | API3 | Password hash in the current-user response |
| DE-02 | Data exposure | API3 | User object over-shares sensitive properties |
| DE-03 | Data exposure | API3 | Product reviews expose reviewer emails |
| DE-04 | Data exposure | API3 | Verbose error leaks a stack trace |
| DE-05 | Data exposure | API3 | Public feedback ties entries to user ids |

`AU-02` hard-fails if the JWT algorithm is ever `none`, and every check hard-fails on a 5xx —
those are real defects, not posture. Everything else is recorded and shown on the dashboard.

## Getting started

Requirements: Node.js 20+ and Docker (for the target).

```bash
npm install

npm run test:unit          # pure-logic checks, no Docker needed

npm run juice:up           # starts Juice Shop in Docker and waits for it
npm test                   # unit + functional + security + coverage
npm run juice:down

npm run dashboard          # builds site/index.html from results/
npm run report             # Playwright HTML report
```

Point the suite at any Juice Shop instance with `JUICE_SHOP_URL=http://host:3000 npm test`.

## CI

GitHub Actions runs Juice Shop as a service container, executes the whole suite (no browser download —
everything uses Playwright's API request context), builds the dashboard and publishes it to GitHub Pages.
A weekly scheduled run keeps it fresh. Publishing needs one setting: *Settings → Pages → Source: GitHub Actions*.

## Project structure

```
src/
  JuiceShopClient.js     REST client for the Juice Shop API
  security/owasp.js      focus areas, OWASP categories, severity helpers
  security/headers.js    header / cookie / stack-trace detectors (unit-tested)
  scoreboard.js          challenge-category -> focus-area mapping and coverage
  report/findings.js     JSONL findings recorder
  report/build-dashboard.js
tests/
  unit/  functional/  security/  coverage/
docker-compose.yml       Juice Shop as the system under test
.github/workflows/ci.yml
```

## Design decisions

- **Detectors validated on a labelled target.** The whole point: prove a check fires before trusting it.
- **Invariants vs. posture.** Hard assertions catch real breakage; findings capture the security posture without making the suite brittle to the target's exact version.
- **No browser needed.** Every test uses the REST API, so CI is fast and stable.
- **Coverage tied to an external catalogue.** The score board is the source of truth for what weakness classes exist, so coverage isn't a number the suite made up.
