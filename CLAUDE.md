# CLAUDE.md

Guidance for AI coding agents (Claude Code, Cursor, Codex, Gemini, …) working in this repository.
Everything here was derived from the source tree — where a statement is inferred rather than
verified by running code, it is marked as such.

---

## Rules — apply to every task

These apply to **every** task in this repository, without being asked. The rest of this file is
reference material; this section is the working agreement.

### R1 — Read before you write

Before touching any code, read this file in full plus the doc that covers the area you are about to
change:

| You are working on…                          | Read first                             |
| -------------------------------------------- | -------------------------------------- |
| Anything at all                              | `CLAUDE.md` (this file)                |
| A new/changed endpoint                       | `docs/API.md` + `docs/ARCHITECTURE.md` |
| Prayer times, quiz, XP, streaks, guides      | `docs/DOMAIN.md`                       |
| `prisma/schema.prisma`, a migration, a query | `docs/DATA-MODEL.md`                   |
| Module wiring, guards, interceptors, cron    | `docs/ARCHITECTURE.md`                 |
| Setup, env vars, seeding, tooling            | `docs/DEVELOPMENT.md`                  |

Do not reconstruct behavior from file names or from memory of a similar project. If a doc and the
code disagree, **the code wins** — fix the doc in the same change and say so in your summary.

### R2 — Documentation is part of the change, not a follow-up

A task is not finished until the docs match the new reality. Use this mapping:

| Change you made                                                                                                        | Doc you must update                                                |
| ---------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| Added / removed / renamed an endpoint, or changed its body, response, guard or error keys                              | `docs/API.md`                                                      |
| Edited `prisma/schema.prisma` or added a migration                                                                     | `docs/DATA-MODEL.md` (+ `docs/API.md` if a response shape changed) |
| Changed a rule: prayer window, XP value, level curve, streak/freeze logic, quiz timing, guide content                  | `docs/DOMAIN.md` (its tables carry the actual numbers)             |
| Added a module, guard, interceptor, cron job, or changed `main.ts` / `app.module.ts`                                   | `docs/ARCHITECTURE.md`                                             |
| Added or renamed an env var                                                                                            | `.env.example` **and** the variable table in `docs/DEVELOPMENT.md` |
| Added a `package.json` script or changed the toolchain                                                                 | `docs/DEVELOPMENT.md` + the Commands block in this file            |
| Closed one of the items under [Known gaps](#known-gaps--do-not-fix-these-silently-and-do-not-document-them-as-working) | Delete that bullet from this file                                  |
| Introduced a new convention or invariant a future agent could break                                                    | Add it to this file                                                |

Two rules about _how_ you write those updates:

- **Only write what you verified.** Every claim in these docs is traceable to source. If you are
  reasoning from framework behavior rather than from code you read, mark it as inferred — exactly as
  the `ConsentGuard` note does.
- **Do not let the docs drift into fiction.** Deleting a stale sentence is as valuable as adding a
  new one. Never document a planned feature as if it exists.

Markdown is Prettier-formatted (`proseWrap: always`, 100 cols). Run `npx prettier --write <files>`
on any doc you edit.

### R3 — Respect the conventions already in place

The [Conventions](#conventions-you-must-follow) section below is binding: the global response
envelope, `SCREAMING_SNAKE_CASE` error keys, exhaustive DTOs, `LocalDate` for calendar days, and
`tx: Prisma.TransactionClient` for helpers that join a transaction. Match the surrounding file's
style over your own preference. Prefer the smallest correct change; do not refactor, reformat, or
"tidy" code you were not asked to touch.

### R4 — Leave the known gaps alone

The [Known gaps](#known-gaps--do-not-fix-these-silently-and-do-not-document-them-as-working) list is
a record of deliberate observations, not a backlog. Do not fix any of them as a side effect of an
unrelated task — several look like bugs but may be intentional. If one blocks your task, say so and
ask before changing it.

### R5 — Never touch secrets or production-shaped state

- Never read out, print, log, commit or copy values from `.env`. Add new keys to `.env.example` with
  an empty value and a comment.
- **`PEPPER` and `JWT_SECRET` are immutable.** Changing `PEPPER` invalidates every stored password
  hash. Never suggest rotating them as a fix.
- Never run destructive database commands (`prisma migrate reset`, `db push --force-reset`,
  `docker compose down -v`, `DELETE`/`DROP`/`TRUNCATE`) without explicit, in-the-moment confirmation
  for that specific command. A general "go ahead" earlier does not carry over.
- Never edit a migration that has already been applied — write a new one.

### R6 — Never trigger real outbound email

`/auth/register`, `/auth/forgot-password` and `/otp/resend` send live email through Mailjet, from a
dev machine too. Do not call them against a real address to "test" something. To get a usable
account, insert the rows directly (see `docs/DEVELOPMENT.md`) or use an address you own.

### R7 — Religious content is not yours to adjust

Prayer times, window boundaries, calculation method and madhab, Hijri dates, rakat counts, and the
Turkish text of guides and quiz questions are religiously significant. Do not change them
speculatively, do not "correct" them from your own knowledge, and do not generate new worship
content. Propose the change and ask first.

### R8 — Report honestly

State what you actually did:

- Say plainly whether something was **run and verified**, **read and inferred**, or **written but
  untested**. If you did not run the tests, say so.
- If part of the task is blocked, finish everything else and name exactly what you left out and why.
- Name the missing input (a file, an env var, a decision) instead of guessing — especially for
  auth/authorization, consent, and anything touching stored password material.

### R9 — Definition of done

Before you report a code change as complete:

1. `yarn lint` passes on the files you touched.
2. `yarn build` succeeds if you changed types, modules, or `prisma/schema.prisma`.
3. `yarn prisma:generate` was run if you edited the schema.
4. The docs named in **R2** are updated in the same change.
5. New endpoints follow the envelope + error-key conventions, and their DTOs are exhaustive
   (`forbidNonWhitelisted: true` rejects anything undeclared).
6. Your summary lists the files changed and any assumption you made.

---

## What this project is

`kible` is the **NestJS backend for NamazGo**, a gamified Islamic prayer (namaz) companion app. It
serves prayer times, step-by-step worship guides, a prayer-completion quiz loop, XP/level/streak
gamification, social follow graph, and account/consent management.

- Public API only — there is no frontend in this repo. `FRONTEND_BASE_URL` points at a separate app
  and doubles as the allowed CORS origin.
- Content (guides, questions, emails) is **Turkish**; code identifiers and error keys are English.
- Repo: `https://github.com/malikozturkk/kible`, default branch `main`.

## Stack

| Concern      | Choice                                                                     |
| ------------ | -------------------------------------------------------------------------- |
| Runtime      | Node.js + TypeScript 5.7 (`module: nodenext`, target ES2023)               |
| Framework    | NestJS 11 (Express platform)                                               |
| Database     | PostgreSQL 16, Prisma 7 with the `@prisma/adapter-pg` driver adapter       |
| Auth         | Passport JWT (`@nestjs/jwt`, `passport-jwt`) + bcrypt + server-side pepper |
| Scheduling   | `@nestjs/schedule` (cron cleanup jobs)                                     |
| Prayer times | [`adhan`](https://www.npmjs.com/package/adhan)                             |
| Dates        | `luxon` + `tz-lookup`; Hijri via `Intl` `islamic-umalqura` calendar        |
| Email        | Mailjet (`node-mailjet`) with template IDs                                 |
| Validation   | `class-validator` / `class-transformer`                                    |
| HTTP headers | `helmet` (applied in `src/common/security/security-headers.ts`)            |
| Logging      | `nestjs-pino` (pino) — structured JSON, request logs, request ids          |
| Package mgr  | **yarn** (`yarn.lock` is committed — do not introduce `package-lock.json`) |

## Commands

```bash
yarn install
docker compose up -d          # PostgreSQL on host port 5434
yarn prisma:migrate           # prisma migrate dev
yarn start:dev                # watch mode, listens on $PORT (default 3000)

yarn lint                     # eslint --fix
yarn format                   # prettier --write .
yarn build                    # nest build
yarn test                     # jest (two specs: app.controller, http-exception.filter)
yarn prisma:generate          # regenerate client after schema.prisma changes
yarn prisma:seed              # fill both question banks (idempotent, see docs/DEVELOPMENT.md)
yarn prisma:studio
```

`yarn lint` runs `eslint --fix`, so it **rewrites files as a side effect**. Run it deliberately and
check `git status` afterwards; to inspect without touching the tree use
`npx eslint --no-fix <path>`.

`yarn test:e2e` is defined in `package.json` but points at `./test/jest-e2e.json`, which **does not
exist** in this repo — the script will fail until that config is added.

## Repository layout

```
prisma/
  schema.prisma               # single source of truth for the DB
  migrations/                 # 12 migrations, oldest 20260420201800_consent
  seed.ts                     # idempotent seed runner — `yarn prisma:seed`
  seeds/                      # seed data: prayer-questions/*.ts, guide-questions.ts
src/
  main.ts                     # bootstrap: CORS, ValidationPipe, interceptor, filter, listen()
  app.module.ts               # composition root
  common/                     # response envelope, exception filter, LocalDate, timezone util, throttler,
                              # security headers (helmet), trust-proxy util, shared validators,
                              # logging/ (nestjs-pino config: request logs, request ids, redaction)
  prisma/                     # @Global PrismaModule + PrismaService
  auth/                       # register/login/refresh/logout, profile, password reset, follow
  otp/                        # registration OTP; the user row is created here, not in auth
  email/                      # Mailjet wrapper
  consent/                    # ToS / privacy-policy versioning + ConsentGuard (via JwtAuthGuard)
  users/                      # user search, public/self stats
  worship/                    # prayer times, countdowns, fasting + day progress
  gamification/               # daily prayer slots, quiz, completion, XP, streak
  leaderboard/                # XP / streak / prayer-count rankings (metric × scope × period)
  guides/                     # static step-by-step wudu/ghusl/prayer guides (strategy pattern)
  questions/                  # guide-quiz check (shares the question bank, scope = GUIDE)
  telemetry/                  # POST /telemetry/client-errors — frontend error reports → error log
  config/consent.config.ts    # fails fast if consent version env vars are missing
```

## Conventions you must follow

**Module shape.** One feature = one Nest module directory. Inside it: `*.module.ts`,
`*.controller.ts`, `*.service.ts`, then `dto/`, `services/`, `constants/`, `enums/`, `types/`,
`helpers/`, `domain/`, `guards/`, `strategies/`, `utils/`, `mappers/`, `factories/` as needed.
Controllers stay thin — they delegate to a service and return a DTO.

**Response envelope.** `ResponseInterceptor` wraps every successful response:

```jsonc
{ "date": 1730000000000, "success": true, "data": <payload|null>, "error": null }
```

`GlobalExceptionFilter` produces the mirror shape on failure:

```jsonc
{ "date": …, "success": false, "data": null,
  "error": { "code": 409, "message": "PRAYER_ALREADY_COMPLETED", "attachment": null } }
```

Never hand-roll this envelope in a controller.

**Error messages are machine keys, not prose.** Always throw with a `SCREAMING_SNAKE_CASE` key
(`USER_NOT_FOUND`, `PRAYER_WINDOW_CLOSED`, …); the client localizes it. `GlobalExceptionFilter` only
passes a message through when it matches `/^[A-Z][A-Z0-9_]*$/` — anything else is replaced by a
status-derived default, so a human-readable message is silently lost. `class-validator` failures
collapse to `VALIDATION_ERROR` with the joined details in `attachment`.

Use `BusinessException(messageKey, httpStatus, attachment?)` from `src/common/exceptions/` for
domain errors; built-in Nest exceptions (`NotFoundException('USER_NOT_FOUND')`) are also used and
work fine. Both styles exist in the codebase — match the surrounding file.

**Logging.** All output is one structured pino stream (`AppLoggingModule`, wired in `main.ts` via
`useLogger`). Use Nest's `Logger` (or `PinoLogger`) — never `console.log`. Every request is already
access-logged with a request id, and `GlobalExceptionFilter` logs any 5xx/unexpected exception with
its stack — do not add ad-hoc catch-and-log around expected domain errors. **Never log secrets,
tokens, passwords, emails or request bodies**; serializers deliberately drop headers/bodies and
`LOG_LEVEL` is the only tuning knob (optional env).

**Validation.** The global `ValidationPipe` runs with `whitelist: true`,
`forbidNonWhitelisted: true`, `transform: true`. Any field not declared on the DTO makes the request
**400**, so DTOs must be exhaustive. Query/param numbers need `@Type(() => Number)`.

**Dates.** Two rules, and breaking either causes real bugs:

1. A calendar day is `LocalDate` (`src/common/utils/local-date.ts`) and is persisted as **UTC
   midnight** of that local day (`toUtcMidnight()`), matching the `@db.Date` columns. Read it back
   with `LocalDate.fromPersisted()`, never `new Date(row.prayerDate)` arithmetic.
2. An instant is a Luxon `DateTime` in the _user's_ zone. The zone is derived from the user's
   `latitude`/`longitude` via `resolveTimezone()` (`tz-lookup`, falling back to `Europe/Istanbul`).
   There is no `timezone` column on `User` — it was deliberately removed (commit `164298b`).

**Prisma access.** `PrismaService` is `@Global`; inject it directly. Multi-write flows use
`this.prisma.$transaction(async (tx) => …)` and helper methods take `tx: Prisma.TransactionClient`
so they can join the caller's transaction — preserve that signature style.

**Style.** Prettier: 100 cols, single quotes, trailing commas, LF. ESLint runs
`recommendedTypeChecked`; `no-explicit-any` is off, `no-floating-promises` and `no-unsafe-argument`
are warnings. Run `yarn lint` before finishing.

## Domain rules an agent will get wrong by guessing

- **Prayer windows are derived, never stored.** `buildPrayerSlots()` computes each slot from adhan
  times: Fajr `fajr→sunrise`, Dhuhr `dhuhr→asr` (replaced by **Jumuah on Fridays**), Asr
  `asr→maghrib`, Maghrib `maghrib→isha`, Isha `isha→tomorrow's fajr`. Tarawih (Ramadan) is
  `isha+30m→tomorrow's fajr`; Eid prayers are `sunrise+30m→dhuhr` and are prepended to the list.
  **Jumuah is the exception**: its window is only `dhuhr−15m→dhuhr+15m`
  (`JUMUAH_MARK_WINDOW_MINUTES`), not the full dhuhr→asr span.
- **Every slot has two ends.** `windowEndsAt` closes the prayer's own time; `markWindowEndsAt` is
  the start of the next _daily_ prayer and is the real cutoff for marking. Marking in between is
  allowed and recorded as `PrayerCompletionStatus.LATE` (kaza) for **half** the prayer's XP
  (`LATE_PRAYER_XP_MULTIPLIER`; the first-of-day bonus is not reduced). Guard code must use
  `isWithinMarkWindow()`, not `isWithinWindow()` — the latter now answers only "would this be on
  time?". Streaks ignore the distinction entirely. Tarawih/Eid never shorten another slot's cutoff.
- **Calculation method is always `Turkey`; the madhab is always the user's.** Both `/worship` and
  `PrayerScheduleService` (gamification) now pass the stored `madhab`. Gamification used to hardcode
  `Shafi` (commit `823c539`), which put the two screens more than an hour apart for Hanafi users and
  closed Dhuhr's markable window at the Shafi Asr. Keep the two in sync — they must agree.
- **A prayer is completed only by passing its quiz.** There is no "mark as prayed" endpoint. 3
  questions, 25 s each (+2 s grace). A **wrong** answer and a **lapsed timer** are equivalent: both
  retire the submission as `FAILED`, lock the remaining questions, and close that prayer for that
  date — there is no retry and no per-day attempt budget. Timers are client-side, so
  `PrayerQuizExpiryService` settles stale submissions lazily — including from
  `GET /gamification/daily-prayers`, so the daily view never offers a button that is guaranteed
  to 409. `assertNotLockedOut()` and the daily view must keep treating `FAILED` **and** `EXPIRED` as
  locked; `EXPIRED` rows predate this rule.
- **One question bank, two scopes.** `prayer_questions` holds both the prayer-quiz questions
  (`scope = PRAYER`, selected by `prayerType`, where NULL means "every prayer") and the guide checks
  (`scope = GUIDE`, selected by `guideId`). Any query that builds a prayer-quiz pool **must** filter
  `scope = PRAYER` — a `GUIDE` row also has `prayerType = null` and would otherwise be selectable.
  Answers are always graded by option id; there is no text comparison anywhere.
- **Hijri conversion is anchored to 12:00 UTC of the local calendar day** (`toHijri` takes a Luxon
  `DateTime`, not a `Date`). Handing it a raw instant is what made Ramadan and both Eids land a day
  late for every user east of UTC — `2027-03-09T00:00+03` is `2027-03-08T21:00Z`.
- **Uniqueness is `(userId, prayerType, prayerDate)`** on `prayer_completions`; the code checks
  first and also catches Prisma `P2002` as `PRAYER_ALREADY_COMPLETED`.
- **Streak advances only on the first completion of a local day**, and the freeze flow uses a
  `Serializable` transaction plus a `SELECT … FOR UPDATE` on `user_streaks`. A reset that overwrites
  a broken streak stores it in `recoverableStreak` / `brokenSinceDate` while the 3-day freeze window
  is open; the freeze's recovery branch restores it and **merges** it into the running streak (pray
  then freeze ≡ freeze then pray). Do not "simplify" either side away — the two orders must stay
  equivalent.

- **Auth is rate limited in two independent layers.** Per-IP throttling on every credential- or
  email-touching route (`src/common/throttler/throttle.constants.ts`, registered globally by
  `AppThrottlerModule`) **plus** a per-account lockout in `LoginAttemptService`. Neither is
  sufficient alone. Do not move the throttler back into a feature module — it was private to
  `ConsentModule`, which is why nothing else was protected.
- **`JwtAuthGuard` is also the consent gate.** It authenticates via Passport and then delegates to
  `ConsentGuard`, so every route behind it returns **403 `CONSENT_REQUIRED`** while a required
  document version is unaccepted. `ConsentGuard` used to be an `APP_GUARD`, which runs _before_
  route guards — `req.user` was unset, its `if (!userId) return true` fired, and the gate never
  blocked anything. Do not move it back to `APP_GUARD`, and put new protected routes behind
  `JwtAuthGuard` so they inherit the gate. `ConsentModule` is `@Global()` and exports `ConsentGuard`
  for this reason.
- **Rate limiting depends on `TRUST_PROXY`.** `@nestjs/throttler` keys on `req.ip`; behind a proxy
  that is the proxy's address unless Express `trust proxy` is set, which collapses every user into
  one global bucket. `main.ts` sets it from `TRUST_PROXY` (hop count or trusted IP/CIDR list); empty
  means trust nothing, which is the safe default — enabling it without a proxy in front lets clients
  spoof `X-Forwarded-For` and reset their own limit.
- **A calendar date parameter is `@IsCalendarDate()`**, not a regex. `^\d{4}-\d{2}-\d{2}$` accepts
  `2026-13-45` and `2026-02-30`, which reach Luxon/adhan and throw uncaught → 500. Use the shared
  validator in `src/common/validators/` for any new date query param.
- **`city` / `country` are validated, not just length-capped.** `PLACE_NAME_PATTERN` in
  `src/auth/constants/location.constants.ts` is the one place the rule lives; register and profile
  update both use it. `city` is shown to strangers in the leaderboard, so it is untrusted input.
- **Coordinates are derived from the city server-side — never taken from the client.** Neither
  `RegisterDto` nor `UpdateProfileDto` accepts `latitude`/`longitude`; `register()` and
  `updateProfile()` call `resolveCityCoordinates()` (`src/auth/constants/tr-cities.constants.ts`, the
  81-province catalog kept in sync with the frontend `TR_CITIES`) and persist the province-center
  coordinate onto `User`. Every reader (`worship`, `PrayerScheduleService`, `resolveTimezone`,
  leaderboard) is unchanged because the columns still exist. Do **not** re-add lat/lon to the DTOs or
  read them off the request — a city that is not in the catalog must fail with `INVALID_CITY`.
- **Access tokens are revocable.** Each carries a `tv` claim equal to
  `user_credentials.tokenVersion`; `JwtStrategy` rejects a mismatch. Any change that must end every
  session increments that counter — revoking refresh tokens alone leaves issued access tokens
  working until they expire. `PATCH /auth/profile` returns a replacement pair so the caller is not
  signed out by their own action.
- **Credential rules are shared.** `src/auth/constants/credential.constants.ts` is the one place
  username length and password complexity are defined; register, profile update and reset all use
  it. The frontend mirrors them for UX only — the backend is the boundary.

See `docs/DOMAIN.md` for the full rules (XP table, level curve, badges, freeze window,
leaderboards).

## Known gaps — do not "fix" these silently, and do not document them as working

These are verified facts about the current tree, not bugs to fold into an unrelated change:

- `streakFreezeCount` is **never incremented** anywhere in `src/` (only decremented). Users start at
  0, so `POST /gamification/action` with `STREAK_FREEZE` always fails with
  `NO_STREAK_FREEZE_AVAILABLE` unless the row is edited by hand. A granting mechanic (a paid store)
  is planned but deliberately not built yet — do not add an automatic one.
- `@Public()` (`src/common/decorators/public.decorator.ts`) is defined and read by `ConsentGuard`,
  but never applied to any handler.
- `DEFAULT_MADHAB` (`'HANAFI'`) and `DEFAULT_LANGUAGE` in `src/auth/constants/` are unused; the
  Prisma default for `User.madhab` is `SHAFI`. Don't assume the constant is authoritative.
- `RegisterDto.termsAccepted` / `privacyPolicyAccepted` / `specialCategoryDataAccepted` are
  validated as `Equals(true)` but never read by `AuthService.register()` — the recorded consent
  versions come from the env config (`CONSENT_VERSION_*`) instead.
- `User.gender` does not exist; gender lives on `user_avatar_configs` (and transiently on
  `otp_verifications`).
- Throttler storage is the in-memory default, so limits are **per instance**. Running more than one
  replica multiplies every limit by the replica count. A shared (Redis) storage backend is the fix
  and is not built.
- CORS allows exactly one origin, taken from `FRONTEND_BASE_URL` (trailing slashes stripped) and
  defaulting to `http://localhost:3000` in `src/main.ts`. That variable also builds the
  password-reset link, so it must stay a bare `scheme://host:port`; there is no list/regex support,
  so a second frontend origin needs a code change. The port is configurable via `PORT`, defaulting
  to `3000`.
- Test coverage is effectively nil: `src/app.controller.spec.ts` and
  `src/common/filters/http-exception.filter.spec.ts` are the only specs.

## Safety notes

- `.env` is git-ignored and holds live Mailjet credentials, `JWT_SECRET`, and `PEPPER`. Never print,
  commit, or copy its values. `.env.example` lists the keys only.
- `PEPPER` is concatenated to every password before hashing. **Changing it invalidates every stored
  password hash.** Treat it as immutable.
- Email sending goes to real inboxes via Mailjet. Do not trigger `/auth/register`,
  `/auth/forgot-password`, or `/otp/resend` against real addresses from a dev context.
- Prayer times, Hijri dates, and worship guide content are religiously significant. Do not adjust
  calculation parameters, window boundaries, or guide text speculatively — ask first.

## Further reading

| File                   | Purpose                                                 |
| ---------------------- | ------------------------------------------------------- |
| `README.md`            | Project overview and quick start                        |
| `docs/ARCHITECTURE.md` | Module graph, request lifecycle, cross-cutting concerns |
| `docs/API.md`          | Every endpoint, its guard, input and output             |
| `docs/DOMAIN.md`       | Prayer/quiz/XP/streak business rules                    |
| `docs/DATA-MODEL.md`   | Prisma models, keys, and lifecycles                     |
| `docs/DEVELOPMENT.md`  | Setup, env vars, migrations, seeding, troubleshooting   |
