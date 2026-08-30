# Development Guide

Setup, configuration, database workflow and the sharp edges you will hit.

## Prerequisites

- **Node.js 20+** — `tsconfig.json` targets ES2023 with `module: nodenext`
- **yarn** — `yarn.lock` is committed; do not mix in npm or pnpm
- **Docker** — for the local PostgreSQL 16 container

## First run

```bash
yarn install
cp .env.example .env          # then fill in the blanks
docker compose up -d          # postgres:16-alpine, host port 5434
yarn prisma:migrate           # applies migrations + generates the client
yarn prisma:seed              # fills both question banks (idempotent)
yarn start:dev
```

`GET http://localhost:3000/` should return the wrapped `"Hello World!"`.

The seed step is not optional if you intend to test the gamification flow: with fewer than 3 active
questions, `GET /gamification/prayer-questions/:type` fails with `INSUFFICIENT_PRAYER_QUESTIONS`
(503).

## Environment variables

All of them are required except `TRUST_PROXY`, `LOG_LEVEL`, `COOKIE_SAMESITE` and `COOKIE_DOMAIN`.
Missing values fail at different times, which matters when debugging a boot error.

| Variable                                       | Used by                                                    | Failure mode if missing                                                                 |
| ---------------------------------------------- | ---------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| `DATABASE_URL`                                 | `PrismaService`, `prisma.config.ts`                        | throws in the `PrismaService` constructor at boot                                       |
| `JWT_SECRET`                                   | `AuthModule`, `OtpModule`, `JwtStrategy`                   | Passport throws at boot; tokens would otherwise be unsigned                             |
| `JWT_EXPIRES_IN`                               | access-token lifetime (`ms` format: `15m`, `1h`, `7d`)     | `undefined` expiry → tokens never expire                                                |
| `PEPPER`                                       | password hashing                                           | silently hashes `password + "undefined"` — **all hashes become wrong**                  |
| `FRONTEND_BASE_URL`                            | password-reset link **and** the CORS origin                | link becomes `undefined/reset-password?...`; CORS falls back to `http://localhost:3000` |
| `TRUST_PROXY`                                  | Express `trust proxy` → the IP the throttler keys on       | **optional**; empty = trust nothing. See below                                          |
| `LOG_LEVEL`                                    | pino log level (`trace`…`fatal`)                           | **optional**; defaults to `info` when `NODE_ENV=production`, otherwise `debug`          |
| `COOKIE_SAMESITE`                              | `SameSite` of the refresh-token cookie                     | **optional**; defaults to `lax`. `none` forces `Secure`                                 |
| `COOKIE_DOMAIN`                                | `Domain` of the refresh-token cookie                       | **optional**; empty = host-only cookie                                                  |
| `CONSENT_VERSION_TERMS_OF_SERVICE`             | `legalConfig`                                              | **throws at boot**: `LEGAL_DOCUMENTS_NOT_CONFIGURED`                                    |
| `CONSENT_VERSION_PRIVACY_POLICY`               | `legalConfig`                                              | same                                                                                    |
| `CONSENT_VERSION_SPECIAL_CATEGORY_DATA`        | `legalConfig`                                              | same                                                                                    |
| `CONSENT_VERSION_COOKIE_POLICY`                | `legalConfig`                                              | same                                                                                    |
| `CONSENT_EFFECTIVE_DATE_<DOC>` (4 documents)   | `legalConfig`                                              | same (ISO `YYYY-MM-DD`; a malformed value is reported by key)                            |
| `MAILJET_API_KEY` / `MAILJET_API_SECRET`       | `EmailService`                                             | OTP and reset emails fail at send time                                                  |
| `MAILJET_SENDER_EMAIL` / `MAILJET_SENDER_NAME` | `EmailService`                                             | Mailjet rejects the message                                                             |
| `MAILJET_OTP_TEMPLATE_ID`                      | OTP email                                                  | `Number(undefined)` → `NaN` → Mailjet rejects                                           |
| `MAILJET_FORGOT_PASSWORD_TEMPLATE_ID`          | reset email                                                | same                                                                                    |
| `VAPID_PUBLIC_KEY`                             | `webPushConfig`, served by `GET /notifications/public-key` | **throws at boot**: `WEB_PUSH_NOT_CONFIGURED`                                           |
| `VAPID_PRIVATE_KEY`                            | `webPushConfig` → `WebPushService`                         | same                                                                                    |
| `VAPID_SUBJECT`                                | VAPID `sub` claim; must start with `mailto:` or `https://` | same, or `WEB_PUSH_INVALID_SUBJECT`                                                     |

`PEPPER` is the dangerous one: it fails **silently**. Changing it invalidates every stored password
hash, so treat it as immutable once any account exists.

`PORT` is optional and not listed in `.env.example` — `src/main.ts` falls back to `3000`.

`FRONTEND_BASE_URL` does double duty: it is the base of the password-reset link **and** the only
origin CORS accepts (trailing slashes are stripped). Consequences: the frontend must be served from
exactly that scheme/host/port, the value must not contain a path, and there is no way to allow a
second origin without a code change.

The refresh token is delivered as an **httpOnly cookie** (`refresh_token`), not in the response body
— client-side JavaScript cannot read it, so an XSS cannot steal a long-lived session. Two optional
variables tune that cookie:

| Variable          | Value                               | When you need it                                                    |
| ----------------- | ----------------------------------- | ------------------------------------------------------------------- |
| `COOKIE_SAMESITE` | `lax` (default) / `strict` / `none` | `none` only when the frontend is on a different site — forces HTTPS |
| `COOKIE_DOMAIN`   | empty (default) / `.example.com`    | share the cookie across subdomains                                  |

Because the cookie is sent cross-origin, `FRONTEND_BASE_URL` must match the frontend exactly and the
frontend must send credentialed requests (`withCredentials: true`).

`TRUST_PROXY` decides what `req.ip` is, and therefore what the per-IP rate limiter buckets on. Leave
it empty locally. In front of a reverse proxy set it, or every user in the world shares one bucket:

| Deployment                        | Value                 |
| --------------------------------- | --------------------- |
| Local / directly exposed          | empty (default)       |
| One proxy hop (Nginx, ALB)        | `1`                   |
| Two hops (Cloudflare → ALB)       | `2`                   |
| Only specific proxies are trusted | `10.0.0.0/8,loopback` |

Setting it when there is **no** proxy in front is a real vulnerability: `X-Forwarded-For` is
attacker-controlled, so a client could hand itself a fresh rate-limit bucket per request. An
unparseable value throws at boot rather than failing per-request.

## Database workflow

```bash
# after editing prisma/schema.prisma
yarn prisma:migrate                 # prisma migrate dev — creates + applies a migration
yarn prisma:generate                # if the TS types look stale
yarn prisma:studio                  # browse data

# production
yarn prisma:migrate:deploy
```

If TypeScript complains about a field that clearly exists in `schema.prisma`, run
`yarn prisma:generate` — the client is generated into `node_modules` and does not regenerate on its
own.

The Docker container maps **host 5434 → container 5432** to avoid clashing with a local PostgreSQL,
so `DATABASE_URL` must use port 5434. Data lives in the named volume `postgres_data`;
`docker compose down -v` destroys it.

`docker-compose.yml` reads `POSTGRES_USER` (default `postgres`) and `POSTGRES_DB` (default `kible`)
from the environment but **hardcodes the password to `postgres`** — local only, never reuse this
compose file for anything reachable.

## Seeding

```bash
yarn prisma:seed              # ts-node prisma/seed.ts
```

There is still no `prisma db seed` hook in `prisma.config.ts`; the script is invoked directly.

**It is idempotent.** Every row gets a deterministic id (`seedUuid()` in
`prisma/seeds/seed-types.ts` — a v5-style UUID derived with `node:crypto` from a fixed namespace
plus the scope and the prompt text), and the seed `upsert`s on that id. Running it twice updates the
same rows instead of duplicating them. Editing a question's prompt mints a new id, so the old row
survives as an orphan — deactivate or delete it by hand if that matters.

Nothing is ever deleted, with one exception: options whose `orderIndex` is beyond the current option
list are removed, so shortening a question does not leave stale choices behind.

Before writing anything the script validates the data and aborts on: a duplicate prompt within a
pool, an option count below 2, a question without exactly one correct option, an empty
`explanation`, or a guide question whose `correctAnswer` is not one of its `options`.

What it writes:

| Rows                                     | Count | Source                               |
| ---------------------------------------- | ----- | ------------------------------------ |
| `prayer_questions` with `scope = PRAYER` | 200   | `prisma/seeds/prayer-questions/*.ts` |
| `prayer_questions` with `scope = GUIDE`  | 64    | `prisma/seeds/guide-questions.ts`    |

Both go into the same table (plus their `prayer_question_options` rows). Guide questions are
authored as a flat `options: string[]` + `correctAnswer`; the seed expands that into option rows and
derives `isCorrect`.

Option rows are upserted on `(questionId, orderIndex)`, not on a synthetic id — that is what lets
rows created by the `unify_question_bank` migration (which minted random option ids) be updated in
place instead of duplicated.

> **Migrating from the old SQL seed.** `prisma/seeds/prayer_questions.seed.sql` has been removed;
> all 60 of its questions were carried over into the TypeScript data. If you ran that file before,
> its rows carry random UUIDs that the new seed cannot match, so seeding on top of them leaves 60
> duplicates. On a local database, clear the table and reseed:
>
> ```sql
> DELETE FROM prayer_questions;   -- prayer_question_options cascades
> ```
>
> ```bash
> yarn prisma:seed
> ```
>
> `prayer_quiz_questions.questionId` is `onDelete: Restrict`, so this fails while any quiz
> submission still references a question. Delete those submissions first, or reseed on a fresh
> database.

## Testing

Test coverage is currently minimal: `src/app.controller.spec.ts` is the only spec file.

```bash
yarn test          # jest, rootDir src, matches *.spec.ts
yarn test:cov      # coverage into ./coverage
```

`yarn test:e2e` references `./test/jest-e2e.json`, which is **not present** in the repo — the script
fails until that config and a `test/` directory are added.

When adding tests, the highest-value targets are the pure units that already exist:
`LevelCalculator`, `LocalDate`, `buildPrayerSlots`, `StreakService` gap arithmetic, and
`FastingProgressService`.

## Code style

Prettier (`.prettierrc`): 100 columns, 2-space indent, single quotes, semicolons, trailing commas
everywhere, LF endings, `proseWrap: always` (so Markdown gets hard-wrapped too).

ESLint (`eslint.config.mjs`): flat config, `typescript-eslint` `recommendedTypeChecked`, with
Prettier as an error-level rule. Deliberately relaxed: `@typescript-eslint/no-explicit-any` off,
`no-floating-promises` and `no-unsafe-argument` reduced to warnings.

TypeScript is **not** in full strict mode: `strictNullChecks` is on, but `noImplicitAny` and
`strictBindCallApply` are off.

```bash
yarn lint && yarn format
```

### Known lint violations

`npx eslint --no-fix src` is **not** clean on a fresh checkout. As of 2026-08-23 it reports 46
problems (40 errors, 6 warnings) across 18 files, none of them in code written for the audit fixes:

| File(s)                                                                 | Rule                                                          |
| ----------------------------------------------------------------------- | ------------------------------------------------------------- |
| `guides/strategies/*.strategy.ts` (8 files)                             | `require-await` — `getGuide()` is async but returns a literal |
| `otp/guards/otp-jwt.guard.ts`, `otp/otp.service.ts`                     | `no-unsafe-*` — untyped JWT payload / `catch (e: any)`        |
| `auth/auth.service.ts`                                                  | `no-unsafe-*` on the `mutualFollowers` preview mapping        |
| `auth/strategies/jwt.strategy.ts`                                       | `no-unused-vars` on the `_credentials` rest-destructure       |
| `auth/services/login-attempt.service.ts`                                | `no-empty` — two intentional `catch {}`                       |
| `auth/password-reset.service.ts`                                        | `no-unused-vars` on an unused `err` binding                   |
| `email/email.service.ts`, `common/interceptors/response.interceptor.ts` | `no-unsafe-member-access`                                     |
| `gamification/services/prayer-quiz.service.ts`                          | `require-await`, unused `questions` parameter                 |
| `main.ts`                                                               | `no-floating-promises` (warning) on `bootstrap()`             |

These are observations, not a backlog — see the "Known gaps" rule in `CLAUDE.md`. What the rule in
`CLAUDE.md` does require is that **your** changes do not add to this list: run
`npx eslint --no-fix <the files you touched>` before finishing.

## Manual API walkthrough

```bash
BASE=http://localhost:3000

# 1. register — returns tempToken, sends a 6-digit code by email
curl -s -X POST $BASE/auth/register -H 'Content-Type: application/json' -d '{
  "username":"test_user","email":"you@example.com","password":"password123",
  "gender":"MALE","country":"Türkiye","city":"İstanbul",
  "latitude":41.0082,"longitude":28.9784,"madhab":"HANAFI","language":"tr",
  "termsAccepted":true,"privacyPolicyAccepted":true,"specialCategoryDataAccepted":true }'

# 2. verify — creates the user, returns access + refresh tokens
curl -s -X POST $BASE/otp/verify \
  -H "Authorization: Bearer $TEMP_TOKEN" -H 'Content-Type: application/json' \
  -d '{"code":"123456"}'

# 3. authenticated calls
curl -s "$BASE/worship?date=$(date +%F)" -H "Authorization: Bearer $ACCESS_TOKEN"
curl -s "$BASE/gamification/daily-prayers?date=$(date +%F)" -H "Authorization: Bearer $ACCESS_TOKEN"
```

Registration and password reset send **real email through Mailjet**, including from a dev machine.
Use an address you control.

If you need a user without touching email, insert the rows directly (`users` + `user_credentials` +
`user_xp` + `user_streaks` + `user_avatar_configs` + three `user_consents`) — that is exactly what
`OtpService.verify` does.

## Troubleshooting

| Symptom                                                      | Cause                                                                                                             |
| ------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------- |
| Boot: `LEGAL_DOCUMENTS_NOT_CONFIGURED: …`                    | a `CONSENT_VERSION_*` / `CONSENT_EFFECTIVE_DATE_*` variable is unset, blank or malformed                                                                  |
| Boot: `DATABASE_URL environment variable is not set`         | `.env` missing or not loaded                                                                                      |
| Login always `INVALID_CREDENTIALS` for a known-good password | `PEPPER` changed since the hash was written                                                                       |
| `400 VALIDATION_ERROR` on a request that looks correct       | an extra field — `forbidNonWhitelisted: true` rejects anything not on the DTO                                     |
| `503 INSUFFICIENT_PRAYER_QUESTIONS`                          | the pool for that prayer type has fewer than 3 active rows — run `yarn prisma:seed`                               |
| `409 PRAYER_WINDOW_NOT_OPEN_YET` / `PRAYER_WINDOW_CLOSED`    | you are outside the prayer's window; windows are derived from the user's coordinates, not the server clock's zone |
| `409 PRAYER_MARKING_LOCKED`                                  | a failed/expired quiz already exists for that prayer today — by design, there is no retry                         |
| `409 NO_STREAK_FREEZE_AVAILABLE`                             | expected: nothing in the codebase ever grants a freeze                                                            |
| CORS blocked in the browser                                  | the browser's origin does not match `FRONTEND_BASE_URL` (default `http://localhost:3000`) exactly                 |
| Prisma type errors after a schema edit                       | run `yarn prisma:generate`                                                                                        |

## Deployment notes

Only what is verifiable from the repo — there is no CI config, Dockerfile for the app, or deploy
manifest here.

```bash
yarn install
yarn build                    # → dist/
yarn prisma:migrate:deploy
yarn start:prod               # node dist/main
```

`docker-compose.yml` provisions the local database only; it does not build or run the API.

Before a first deployment, someone will need to decide on: the production `FRONTEND_BASE_URL` value
(it gates CORS), a production `PEPPER` and `JWT_SECRET`, and whether all three cron sweepers (OTP,
password resets, expired refresh tokens) should run in every replica.

## Web Push (VAPID)

Notifications need a VAPID key pair. Generate one per environment:

```bash
npx web-push generate-vapid-keys
```

Put the pair in `.env` (`VAPID_PUBLIC_KEY`, `VAPID_PRIVATE_KEY`) together with a `VAPID_SUBJECT`
that starts with `mailto:` or `https://`. All three are required — the app throws
`WEB_PUSH_NOT_CONFIGURED` at boot if any is missing, deliberately, so notifications can never fail
silently.

The public key is served to the browser by `GET /notifications/public-key`, so the frontend needs no
VAPID env var of its own. Rotating the pair invalidates every existing `push_subscriptions` row: the
browser must re-subscribe with the new key, and old endpoints start returning 403/410 and get pruned
automatically.

Push only works over HTTPS or on `localhost`. On `localhost` Chrome treats the origin as secure, so
`yarn start:dev` + the frontend on `http://localhost:3000` is enough for local testing.

### Verifying the chain

Use the **"Deneme bildirimi gönder"** button on `/settings/notifications`
(`POST /notifications/test`) rather than replaying a real trigger. Real triggers are deduped per
calendar day, so unfollowing and re-following the same account, or waiting through the same prayer
twice, produces nothing the second time — which looks identical to a broken setup.

If the row in `notification_deliveries` says `SENT` but nothing appeared on screen, the push left
the server and the browser accepted it; the problem is downstream:

- **macOS**: System Settings → Notifications → the browser must be allowed. A browser-level
  `granted` is not enough, and this failure is completely silent.
- **Focus / Do Not Disturb** suppresses the banner without any error.
- The service worker must be active — check `chrome://serviceworker-internals` or DevTools →
  Application → Service Workers for `/sw.js`.
- Two profiles on one machine are two separate subscriptions; check that the _receiving_ profile is
  the one with a `push_subscriptions` row.
