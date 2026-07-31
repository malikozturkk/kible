# Architecture

How the NestJS application is composed, what happens to a request, and where cross-cutting behavior
lives. Endpoint details are in [`API.md`](API.md); business rules are in [`DOMAIN.md`](DOMAIN.md).

## Bootstrap (`src/main.ts`)

```ts
NestFactory.create(AppModule)
  .enableCors({ origin: FRONTEND_BASE_URL ?? 'http://localhost:3000', credentials: true, … })
  .useGlobalPipes(new ValidationPipe({ whitelist, forbidNonWhitelisted, transform }))
  .useGlobalInterceptors(new ResponseInterceptor())
  .useGlobalFilters(new GlobalExceptionFilter())
  .listen(process.env.PORT ?? 3000)
```

The CORS origin comes from `FRONTEND_BASE_URL` (trailing slashes stripped) and falls back to
`http://localhost:3000` when unset — a single origin, not a list. The same variable also builds the
password-reset link, so it must stay a bare `scheme://host:port`. The port falls back to `3000` when
`PORT` is unset. `dotenv/config` is imported at the top of `main.ts` and again in
`prisma.config.ts`, so `.env` is loaded before Nest reads any `process.env` value.

## Module graph

`AppModule` imports seven modules; two more join the graph transitively.

```
AppModule
├─ ConfigModule.forRoot({ isGlobal: true, load: [consentConfig] })
├─ ScheduleModule.forRoot()
├─ PrismaModule            @Global — exports PrismaService everywhere
├─ AuthModule
│  ├─ JwtModule.register({ secret: JWT_SECRET, expiresIn: JWT_EXPIRES_IN })
│  ├─ PassportModule
│  ├─ OtpModule            → OtpController is registered through this import
│  │  └─ EmailModule
│  └─ EmailModule
├─ GamificationModule
│  └─ WorshipModule        (reuses PrayerTimeFactory)
├─ GuidesModule
│  └─ QuestionsModule      → QuestionsController is registered through this import
├─ WorshipModule
├─ UsersModule
└─ ConsentModule
   ├─ CacheModule.register()      non-global, in-memory
   ├─ ThrottlerModule.forRoot([{ ttl: 60_000, limit: 10 }])
   └─ APP_GUARD → ConsentGuard    application-wide guard
```

Note that `OtpModule` and `QuestionsModule` are not listed in `AppModule` — their controllers are
still mounted because the modules are reachable through `AuthModule` and `GuidesModule`.

`consentConfig` (`src/config/consent.config.ts`) reads `CONSENT_VERSION_TERMS_OF_SERVICE` and
`CONSENT_VERSION_PRIVACY_POLICY` and **throws at boot** if either is missing, exposing them as the
`CONSENT_VERSIONS` config key.

## Request lifecycle

```
HTTP request
  → CORS
  → APP_GUARD: ConsentGuard              (see caveat below)
  → controller/route guards: JwtAuthGuard | OtpJwtGuard | ThrottlerGuard
  → ValidationPipe (+ ParseEnumPipe / ParseUUIDPipe on params)
  → Controller → Service → PrismaService → PostgreSQL
  → ResponseInterceptor wraps the return value in the envelope
  → (on throw) GlobalExceptionFilter renders the error envelope
```

**ConsentGuard ordering caveat.** NestJS executes global guards _before_ controller- and
route-scoped guards. `ConsentGuard` reads `req.user?.id` and returns `true` when it is absent — but
`req.user` is populated by `JwtAuthGuard`, which runs later. The practical consequence is that the
consent gate is unlikely to ever block a request. This is inferred from framework ordering semantics
and has **not** been verified at runtime; confirm before depending on it either way. The guard also
honors `@ConsentBypass()`, `@Public()`, and a static `CONSENT_BYPASS_ROUTES` regex list covering
`/consent/status`, `/consent/accept`, `/auth/logout`, `/auth/refresh` and `/legal/*`.

## Cross-cutting concerns

### Response envelope — `src/common/`

`ResponseInterceptor` maps every controller return value to
`{ date, success: true, data, error: null }`. A handler returning `void`/`undefined` yields
`data: null`.

`GlobalExceptionFilter` catches everything and emits
`{ date, success: false, data: null, error: { code, message, attachment } }`:

| Thrown                                               | `error.message`                             | `error.attachment`        |
| ---------------------------------------------------- | ------------------------------------------- | ------------------------- |
| `BusinessException(key, status, attachment)`         | `key`                                       | as supplied               |
| `HttpException` with a `SCREAMING_SNAKE_CASE` string | that string                                 | `null`                    |
| `HttpException` with prose                           | status default (`NOT_FOUND`, `CONFLICT`, …) | `null`                    |
| `ValidationPipe` (array of messages)                 | `VALIDATION_ERROR`                          | messages joined with `; ` |
| Anything else                                        | `INTERNAL_SERVER_ERROR`                     | `null`                    |

Because prose messages are discarded, always throw with a key.

### Persistence — `src/prisma/`

`PrismaService extends PrismaClient` and is registered by the `@Global` `PrismaModule`. It builds a
`PrismaPg` driver adapter from `DATABASE_URL` (throwing at construction if unset), logs only
`error`, and connects/disconnects on the module lifecycle hooks.

`prisma/schema.prisma` declares `datasource db { provider = "postgresql" }` with **no `url`** — the
connection string comes from `prisma.config.ts`, which is the Prisma 7 config entry point.

Transactions: `PrayerCompletionService`, `PrayerQuizService.answerQuestion`, `OtpService.verify` and
`PasswordResetService.resetPassword` all wrap their writes in `$transaction`. Helpers that must join
an outer transaction (`XpService.award`, `StreakService.registerDailyActivity`,
`StreakService.lockStreakRow`, `PrayerQuizService.markPassed`) accept a
`tx: Prisma.TransactionClient` as their first argument.

`StreakService.useStreakFreeze` runs at `Serializable` isolation and takes a row lock via
`` tx.$executeRaw`SELECT id FROM "user_streaks" WHERE "userId" = ${userId} FOR UPDATE` `` — the only
raw SQL in `src/`.

### Time and locale — `src/common/utils/`

- `LocalDate` — an immutable `(year, month, day)` value object backed by Luxon. It is the boundary
  between "a calendar day in the user's zone" and the `@db.Date` columns, which store **UTC
  midnight** of that day. Key methods: `todayIn(tz)`, `fromInstant(dt, tz)`, `fromPersisted(Date)`,
  `toUtcMidnight()`, `toISO()`, `plusDays`, `daysUntil`.
- `resolveTimezone(lat, lon)` — `tz-lookup`, falling back to `Europe/Istanbul` on any error. Called
  by `WorshipService` and `PrayerScheduleService`; there is no `timezone` column on `User`.
- Hijri conversion uses `Intl.DateTimeFormat` with the `islamic-umalqura` calendar
  (`gamification/helpers/hijri.helper.ts` and, duplicated, inside `FastingProgressService`).

### Scheduled jobs

Two `@Cron(CronExpression.EVERY_MINUTE)` sweepers, enabled by `ScheduleModule.forRoot()`:

| Where                                 | What                                         |
| ------------------------------------- | -------------------------------------------- |
| `OtpService.cleanupExpiredRecords`    | deletes `otp_verifications` past `expiresAt` |
| `PasswordResetService.cleanupExpired` | deletes `password_resets` past `expiresAt`   |

Both run in every process — running multiple replicas means duplicated (idempotent) deletes.

### Caching and rate limiting

Only the consent module uses them: a non-global in-memory `CacheModule` caches each user's latest
consent per type for 30 s under the key `consent:<userId>` (invalidated on accept), and
`ThrottlerModule` limits `POST /consent/accept` to 10 requests per minute. No other endpoint is
rate-limited, including login, register and password reset.

## Notable design patterns

**Strategy — worship guides.** `GuideStrategy` is an abstract class with `supports(type)` and
`getGuide()`. Eight concrete strategies (wudu, ghusl, fajr, dhuhr, asr, maghrib, isha, jumuah) are
injected into `GuidesService`, which picks the first that supports the requested type. Prayer
strategies compose their steps from the static `PrayerStepBuilder` helpers (`buildTakbirStep`,
`buildQiyamWithRecitation`, `buildRukuh`, `buildIftiraj`, `buildSujud`, `buildTashahhudAndSalam`),
then call `PrayerStepBuilder.syncTotalSteps()` to normalize `totalSteps`. Adding a guide type means
adding an enum member, a strategy class, and registering it in both `GuidesModule.providers` and the
`GuidesService` strategy array.

**Factory — prayer times.** `PrayerTimeFactory` is the single place adhan is configured:
`CalculationMethod[method]` (default `Turkey`), `Madhab[madhab]` (default `Shafi`),
`HighLatitudeRule.MiddleOfTheNight`. `WorshipModule` exports it so `GamificationModule` reuses it.

**Service decomposition.** The two largest modules split their work into single-purpose services
rather than one fat service:

- `gamification/services/` — `PrayerScheduleService` (build slots, daily view), `PrayerQuizService`
  (issue/start/answer), `PrayerCompletionService` (the completion transaction), `StreakService`,
  `XpService`, `GamificationActionService` (a dispatch switch over `GamificationActionType`).
  `GamificationService` is a thin facade the controller talks to.
- `worship/services/` — `PrayerCountdownService`, `FastingProgressService`, `DayProgressService`,
  plus `WorshipResponseMapper` for the response shape.

**Domain object.** `LevelCalculator` (`gamification/domain/`) is pure and static — XP curve, level
resolution and badge keys with no I/O. It is reused by `UserStatsService`.
