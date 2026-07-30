# kible

Backend API for **NamazGo** — a gamified Islamic prayer companion. NamazGo learns where to face from
Kible.

Built with NestJS 11, PostgreSQL 16 and Prisma 7. It serves prayer times, step-by-step worship
guides, a quiz-gated prayer completion loop, XP/level/streak gamification, a social follow graph,
and account, OTP and consent management.

There is no frontend in this repository.

---

## Features

| Area             | What it does                                                                                                                                     |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Auth**         | Email/username + password login, JWT access tokens, opaque refresh tokens, OTP-verified registration, password reset by email                    |
| **Consent**      | Versioned Terms of Service / Privacy Policy acceptance with re-accept detection                                                                  |
| **Worship**      | Daily prayer times (`adhan`, Turkey method), next-prayer countdown, fasting progress, Hijri date, Ramadan day counter                            |
| **Gamification** | Per-prayer time windows, a 3-question timed quiz that gates completion, XP with a level curve and badges, daily streaks with a freeze mechanic   |
| **Guides**       | Static Turkish step-by-step guides for wudu, ghusl and each of the five daily prayers + Jumuah, with an optional random knowledge-check question |
| **Users**        | Trigram-based username search ranked by social distance, public and self statistics                                                              |
| **Social**       | Follow / unfollow, follower and following lists, mutual-follower previews                                                                        |

## Quick start

Requires Node.js (ES2023-capable, 20+), yarn and Docker.

```bash
# 1. Install
yarn install

# 2. Configure — copy the template and fill in real values
cp .env.example .env

# 3. Start PostgreSQL (host port 5434)
docker compose up -d

# 4. Apply migrations
yarn prisma:migrate

# 5. Seed the prayer-quiz question bank (raw SQL, run once)
psql "$DATABASE_URL" -f prisma/seeds/prayer_questions.seed.sql

# 6. Run
yarn start:dev
```

The API listens on **http://localhost:3000**. `GET /` returns `Hello World!` as a liveness check.

Every environment variable in `.env.example` is required — the app throws on boot if the consent
versions or `DATABASE_URL` are missing. See [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) for what
each one does.

## Scripts

| Script                       | Purpose                                   |
| ---------------------------- | ----------------------------------------- |
| `yarn start:dev`             | Watch-mode dev server                     |
| `yarn start:prod`            | Run the compiled build (`node dist/main`) |
| `yarn build`                 | Compile to `dist/`                        |
| `yarn lint`                  | ESLint with `--fix`                       |
| `yarn format`                | Prettier over the repo                    |
| `yarn test`                  | Jest unit tests                           |
| `yarn prisma:migrate`        | `prisma migrate dev`                      |
| `yarn prisma:migrate:deploy` | `prisma migrate deploy` (production)      |
| `yarn prisma:generate`       | Regenerate the Prisma client              |
| `yarn prisma:studio`         | Prisma Studio                             |

`yarn test:e2e` is declared but its config file (`test/jest-e2e.json`) is not present in the repo.

## API shape

Every response uses the same envelope, applied globally by `ResponseInterceptor` and
`GlobalExceptionFilter`:

```jsonc
// success
{ "date": 1730000000000, "success": true, "data": { }, "error": null }

// failure
{ "date": 1730000000000, "success": false, "data": null,
  "error": { "code": 404, "message": "USER_NOT_FOUND", "attachment": null } }
```

`error.message` is always a machine-readable key in `SCREAMING_SNAKE_CASE` — the client is
responsible for localizing it. Full endpoint reference: [`docs/API.md`](docs/API.md).

## Registration flow

Registration is two-phase, because the `users` row is only created after the email is proven:

```
POST /auth/register  →  { tempToken }        pending row in otp_verifications + OTP email (3 min)
POST /otp/verify     →  { accessToken, refreshToken, user }
   Authorization: Bearer <tempToken>          creates user + credentials + xp + streak
                                              + avatar config + consent records, atomically
```

The temp token is valid for 10 minutes; the OTP code for 3. Expired rows are swept every minute by a
cron job.

## Documentation

| Document                                       | Contents                                                                              |
| ---------------------------------------------- | ------------------------------------------------------------------------------------- |
| [`CLAUDE.md`](CLAUDE.md)                       | Rules (R1–R9) every AI agent must follow, plus conventions, invariants and known gaps |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Module graph, request lifecycle, cross-cutting concerns                               |
| [`docs/API.md`](docs/API.md)                   | Endpoint-by-endpoint reference                                                        |
| [`docs/DOMAIN.md`](docs/DOMAIN.md)             | Prayer windows, quiz, XP, levels, streaks                                             |
| [`docs/DATA-MODEL.md`](docs/DATA-MODEL.md)     | Prisma models and their lifecycles                                                    |
| [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md)   | Setup, env vars, migrations, seeding, troubleshooting                                 |

## License

The [`LICENSE`](LICENSE) file is MIT (© 2026 Malik Öztürk), while `package.json` declares
`"license": "UNLICENSED"` and `"private": true`. These disagree — worth reconciling before the code
is published or shared.
