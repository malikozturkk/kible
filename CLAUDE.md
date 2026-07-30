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

- Public API only — there is no frontend in this repo. `FRONTEND_BASE_URL` points at a separate app.
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
yarn test                     # jest (only one spec exists today)
yarn prisma:generate          # regenerate client after schema.prisma changes
yarn prisma:studio
```

`yarn test:e2e` is defined in `package.json` but points at `./test/jest-e2e.json`, which **does not
exist** in this repo — the script will fail until that config is added.

## Repository layout

```
prisma/
  schema.prisma               # single source of truth for the DB
  migrations/                 # 5 migrations, oldest 20260420201800_consent
  seeds/prayer_questions.seed.sql   # raw SQL, run manually (no `prisma db seed` hook)
src/
  main.ts                     # bootstrap: CORS, ValidationPipe, interceptor, filter, listen()
  app.module.ts               # composition root
  common/                     # response envelope, exception filter, LocalDate, timezone util
  prisma/                     # @Global PrismaModule + PrismaService
  auth/                       # register/login/refresh/logout, profile, password reset, follow
  otp/                        # registration OTP; the user row is created here, not in auth
  email/                      # Mailjet wrapper
  consent/                    # ToS / privacy-policy versioning + global ConsentGuard
  users/                      # user search, public/self stats
  worship/                    # prayer times, countdowns, fasting + day progress
  gamification/               # daily prayer slots, quiz, completion, XP, streak
  guides/                     # static step-by-step wudu/ghusl/prayer guides (strategy pattern)
  questions/                  # free-text guide questions (separate from the prayer quiz)
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
- **Calculation method is always `Turkey`.** `/worship` uses the user's `madhab`, but
  `PrayerScheduleService` (gamification) **hardcodes `Shafi`** — intentional, see commit `823c539`.
  Changing one without the other desynchronizes quiz windows from displayed prayer times.
- **A prayer is completed only by passing its quiz.** There is no "mark as prayed" endpoint. 3
  questions, 25 s each (+2 s grace). One wrong or late answer fails the submission, locks the
  remaining questions, and **locks the user out of that prayer for that date entirely** — no retry.
- **Uniqueness is `(userId, prayerType, prayerDate)`** on `prayer_completions`; the code checks
  first and also catches Prisma `P2002` as `PRAYER_ALREADY_COMPLETED`.
- **Streak advances only on the first completion of a local day**, and the freeze flow uses a
  `Serializable` transaction plus a `SELECT … FOR UPDATE` on `user_streaks`.

See `docs/DOMAIN.md` for the full rules (XP table, level curve, badges, freeze window).

## Known gaps — do not "fix" these silently, and do not document them as working

These are verified facts about the current tree, not bugs to fold into an unrelated change:

- `streakFreezeCount` is **never incremented** anywhere in `src/` (only decremented). Users start at
  0, so `POST /gamification/action` with `STREAK_FREEZE` always fails with
  `NO_STREAK_FREEZE_AVAILABLE` unless the row is edited by hand.
- `StreakService.inspectStreakRisk()` is fully implemented but never called — no endpoint exposes
  it.
- `@Public()` (`src/common/decorators/public.decorator.ts`) is defined and read by `ConsentGuard`,
  but never applied to any handler.
- `DEFAULT_MADHAB` (`'HANAFI'`) and `DEFAULT_LANGUAGE` in `src/auth/constants/` are unused; the
  Prisma default for `User.madhab` is `SHAFI`. Don't assume the constant is authoritative.
- `RegisterDto.termsAccepted` / `privacyPolicyAccepted` are validated as `Equals(true)` but never
  read by `AuthService.register()` — the recorded consent versions come from the env config instead.
- `updateProfile()` re-hashes passwords with bcrypt cost **10** while register/reset use **12**.
- `refresh()` issues a new refresh token but does **not** revoke the presented one, so old tokens
  stay valid until their 1-day expiry.
- **`ConsentGuard` very likely never blocks.** It is registered as `APP_GUARD`, and in NestJS global
  guards run _before_ controller/route-scoped guards — so `req.user` is still unset when it runs and
  the `if (!userId) return true;` early-exit fires. _Inferred from framework ordering semantics, not
  verified at runtime._ Verify before relying on it, and before changing it.
- `User.gender` does not exist; gender lives on `user_avatar_configs` (and transiently on
  `otp_verifications`).
- The CORS origin `http://localhost:3001` is hardcoded in `src/main.ts` (the port is configurable
  via `PORT`, defaulting to `3000`).
- Test coverage is effectively nil: `src/app.controller.spec.ts` is the only spec.

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
