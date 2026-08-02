# Data Model

Source of truth: [`prisma/schema.prisma`](../prisma/schema.prisma). PostgreSQL 16, accessed through
Prisma 7 with the `@prisma/adapter-pg` driver adapter. Every model maps to a `snake_case` table via
`@@map`; column names stay camelCase and therefore need double quotes in raw SQL.

All primary keys are `String @id @default(uuid())`.

## Enums

| Enum                       | Values                                                                                 |
| -------------------------- | -------------------------------------------------------------------------------------- |
| `Gender`                   | `MALE`, `FEMALE`                                                                       |
| `Madhab`                   | `SHAFI`, `HANAFI`                                                                      |
| `ConsentType`              | `TERMS_OF_SERVICE`, `PRIVACY_POLICY`                                                   |
| `PrayerType`               | `FAJR`, `DHUHR`, `ASR`, `MAGHRIB`, `ISHA`, `JUMUAH`, `TARAWIH`, `EID_FITR`, `EID_ADHA` |
| `PrayerCategory`           | `DAILY`, `WEEKLY`, `RAMADAN`, `EID`                                                    |
| `PrayerCompletionStatus`   | `ON_TIME`, `LATE`                                                                      |
| `PrayerQuizStatus`         | `PENDING`, `PASSED`, `FAILED`, `EXPIRED`                                               |
| `PrayerQuizQuestionStatus` | `PENDING`, `SHOWN`, `CORRECT`, `INCORRECT`, `EXPIRED`, `LOCKED`                        |
| `StreakFreezeReason`       | `USER_INITIATED`                                                                       |

`PrayerCategory` exists only in the DB enum — it is not stored on any column; the category is
attached at runtime from `PRAYER_TYPE_METADATA`.

## Relationship overview

```
User ──1:1── UserCredential          (passwordHash)
     ──1:1── UserAvatarConfig        (gender, colors, accessories)
     ──1:1── UserXp                  (xp, totalXp)
     ──1:1── UserStreak              (current/longest/freezeCount, lastActiveDate)
     ──1:1── UserPrayerStats         (per-type counters)
     ──1:N── RefreshToken
     ──1:N── UserConsent
     ──1:N── PrayerCompletion ──0..1── PrayerQuizSubmission
     ──1:N── PrayerQuizSubmission ──1:N── PrayerQuizQuestion ──N:1── PrayerQuestion
     ──1:N── StreakFreezeUsage
     ──N:N── User via Follow (self-referential)

PrayerQuestion ──1:N── PrayerQuestionOption

OtpVerification    standalone — holds the pending signup until the OTP is verified
PasswordReset      standalone — userId is NOT a foreign key
Question           standalone — guideId is a plain string, not a foreign key
```

Every `User` relation uses `onDelete: Cascade`, so deleting a user removes their whole footprint —
except `PasswordReset` and `OtpVerification`, which have no FK and are cleaned by cron instead.

---

## Identity and auth

### `User` → `users`

`email` and `username` are both `@unique`. Profile columns: `avatar`, `country`, `city`, `latitude`,
`longitude`, `madhab` (default `SHAFI`), `language` (default `"tr"`).

`locationChangeCount` and `madhabChangeCount` are **one-time quotas** (`MAX_LOCATION_CHANGES` /
`MAX_MADHAB_CHANGES`, both 1). Location decides the timezone every prayer window is derived from, so
an uncapped edit lets a user miss Fajr in İstanbul, move to a city several hours west where Fajr is
still inside its window, and mark it `ON_TIME`. A no-op update (same values) does not consume the
quota.

Two things that surprise people:

- **There is no `gender` column on `User`.** Gender lives on `UserAvatarConfig` (and transiently on
  `OtpVerification`).
- **There is no `timezone` column.** It is derived from the coordinates on every request —
  deliberately removed in commit `164298b`.

`latitude` / `longitude` are nullable, so every prayer endpoint must handle `USER_LOCATION_NOT_SET`.

`usernameUpdatedAt` records the last rename and drives the 30-day cooldown
(`USERNAME_CHANGE_COOLDOWN_DAYS`); null means the user has never renamed.

### `UserCredential` → `user_credentials`

One per user. `passwordHash` is `bcrypt(password + PEPPER)` at cost 12 on every write path;
`passwordUpdatedAt` is bumped by both `POST /auth/reset-password` and `PATCH /auth/profile`.

| Column                | Purpose                                                                                                               |
| --------------------- | --------------------------------------------------------------------------------------------------------------------- |
| `tokenVersion`        | Stamped into each access token as `tv`. Incremented on any password change, which retires every token already issued. |
| `failedLoginAttempts` | Consecutive failed logins. Cleared on success or on a completed reset.                                                |
| `lockedUntil`         | Set once `LOGIN_MAX_FAILED_ATTEMPTS` (10) is reached; blocks login for `LOGIN_LOCK_DURATION_MS` (15 min).             |

See [`DOMAIN.md` §8](DOMAIN.md#brute-force-protection).

### `RefreshToken` → `refresh_tokens`

Stores `tokenHash` (SHA-256 of a 32-byte random hex token, `@unique`), `isRevoked`, `expiresAt`
(created at now + 1 day). Rows are **never deleted** — revoked and expired tokens accumulate
indefinitely; there is no cleanup cron for this table. `/auth/refresh` rotates: it flips `isRevoked`
on the presented row while inserting the replacement, so each token is single-use.

### `OtpVerification` → `otp_verifications`

The staging area for a signup. It duplicates every registration field (`email`, `username`,
`passwordHash`, `gender`, `country`, `city`, `latitude`, `longitude`, `madhab`, `language`,
`termsVersion`, `privacyPolicyVersion`) plus `tokenHash` (`@unique`, SHA-256 of the temp JWT),
`otpCode`, `otpExpiresAt` (+3 min) and `expiresAt` (+10 min).

**Adding a field to registration means adding a column here too** — the `users` row is built from
this table in `OtpService.verify`. A minute-ly cron deletes rows past `expiresAt`.

### `PasswordReset` → `password_resets`

`tokenHash` is a **bcrypt** hash (not SHA-256, unlike refresh tokens) and is _not_ unique, so lookup
is by `userId` + `isUsed: false`, newest first, then a bcrypt compare. `failedAttempts` exists but
is never incremented. `userId` is a plain column with an index — no foreign key, no cascade.

### `UserConsent` → `user_consents`

Append-only acceptance log, unique on `(userId, type, version)`. "Currently accepted" is the newest
`acceptedAt` per type (`distinct: ['type']` with a descending sort), cached in memory for 30 s.

### `UserAvatarConfig` → `user_avatar_configs`

`gender` (default `MALE`), plus `colors` and `accessories` as `Json` defaulting to `{}`. The JSON is
untyped in the DB and normalized in `avatar-config.util.ts`: unknown keys are dropped, missing keys
fall back to `DEFAULT_AVATAR_COLORS`, and a missing row yields a full default payload. Adding an
avatar color means editing `AVATAR_COLOR_KEYS` + `DEFAULT_AVATAR_COLORS` + `AvatarColorsDto` — no
migration needed.

### `Follow` → `follows`

Self-referential join with `@@unique([followerId, followingId])` and an index on each side.
`follower` = the person doing the following (`UserFollowing` relation), `following` = the person
followed (`UserFollowers` relation). Naming is easy to invert — check the relation name, not the
field name.

---

## Gamification

### `UserXp` → `user_xp`

`xp` (level basis) and `totalXp` (lifetime). Both incremented by the same amount today; `xp` is
indexed for a future leaderboard.

### `UserStreak` → `user_streaks`

`currentStreak`, `longestStreak`, `streakFreezeCount`, `lastActiveDate` (a `DateTime?` holding UTC
midnight of a local day). Indexed on `currentStreak`. This is the row locked with
`SELECT … FOR UPDATE` during completion and freeze.

### `StreakFreezeUsage` → `streak_freeze_usages`

One row per protected day, unique on `(userId, protectedDate)` — that constraint is what makes
re-running a freeze idempotent.

### `UserPrayerStats` → `user_prayer_stats`

Denormalized counters: `totalCompleted` plus `totalFajr … totalEidAdha`, the punctuality pair
`totalOnTime` / `totalLate`, and `lastCompletedAt`. Upserted inside the completion transaction.
`totalOnTime + totalLate == totalCompleted` holds for every row touched at or after the
`20260801130000_prayer_late_marking` migration, which backfills `totalOnTime = totalCompleted` (no
completion could have been late before it). **Adding a `PrayerType` requires a new column here** and
a new branch in `PrayerCompletionService.statsFieldFor()`, which throws `UNKNOWN_PRAYER_TYPE` (500)
on an unmapped type.

### `PrayerCompletion` → `prayer_completions`

The record that a prayer was performed.

- `prayerDate` is `@db.Date`, holding UTC midnight of the user's local day.
- `@@unique([userId, prayerType, prayerDate])` — the idempotency guarantee; `P2002` here is mapped
  to `PRAYER_ALREADY_COMPLETED`.
- `timezone`, `xpAwarded` and `xpBeforePenalty` are snapshotted so history survives a later profile
  or XP-table change.
- `status` is a `PrayerCompletionStatus` (`ON_TIME` | `LATE`), resolved from the slot at the moment
  the quiz was passed — see [`DOMAIN.md` §2.1](DOMAIN.md#21-on-time-vs-late-kaza). `xpBeforePenalty`
  is what the same marking would have earned on time; it equals `xpAwarded` for `ON_TIME` rows.
  Indexed as `(userId, status)`.
- `isFirstOfDay`, `streakContributed` are set by the completion transaction. `streakFreezeApplied`
  is always written `false` and never updated.

### `PrayerQuestion` / `PrayerQuestionOption`

**The single question bank for both quiz flows.** A question has a `prompt`, optional `explanation`
(never returned by the API), a `difficulty` (1 easy … 3 hard), `isActive`, and a `scope` that
decides which flow may select it:

| `scope`  | Selector                                          | Used by                              |
| -------- | ------------------------------------------------- | ------------------------------------ |
| `PRAYER` | `prayerType` (**null = applies to every prayer**) | the prayer-marking quiz              |
| `GUIDE`  | `guideId` (a plain `GuideType` string)            | the short check shown inside a guide |

`prayerType` is meaningful only for `PRAYER` rows and `guideId` only for `GUIDE` rows; the other is
always null. **A query that selects prayer-quiz candidates must filter on `scope`** — a `GUIDE` row
also has `prayerType = null`, so without the filter it would match the "every prayer" pool.
`PrayerQuizService.issueQuiz()` does this.

Options carry `isCorrect` and `orderIndex`; `isCorrect` is never serialized to clients, and answers
are graded by option id, never by comparing text. `@@unique([questionId, orderIndex])` keeps
positions unambiguous and lets the seed upsert an option by position.

Indexed on `(prayerType, isActive)`, `(isActive)` and `(scope, guideId, isActive)`. Seed data lives
in [`prisma/seeds/`](../prisma/seeds) and is written by `yarn prisma:seed` — 200 `PRAYER` rows (20
per `PrayerType` + 20 with `prayerType = NULL`) and 64 `GUIDE` rows (8 per `GuideType`). There is no
unique constraint on `prompt`; idempotency comes from deterministic ids computed by `seedUuid()`,
not from the schema — see [`DEVELOPMENT.md`](DEVELOPMENT.md#seeding).

### `PrayerQuizSubmission` → `prayer_quiz_submissions`

One quiz attempt for `(user, prayerType, prayerDate)`. Holds `questionIds` (a denormalized
`String[]` mirroring the child rows), the window snapshot (`windowStartsAt`, `windowEndsAt`,
`markWindowEndsAt`), `expiresAt` (mark-window end + 5 min), `status`, `attemptCount`, and
`prayerCompletionId` (`@unique`, `onDelete: SetNull`) linking the passing attempt to its completion.

`assertQuizUsable()` gates on `markWindowEndsAt`, not `windowEndsAt` — crossing the latter only
means the resulting completion will be `LATE`.

There is **no unique constraint** on `(userId, prayerType, prayerDate)` — multiple submissions per
prayer per day are possible at the schema level; the lockout is enforced in application code
(`assertNotLockedOut`).

### `PrayerQuizQuestion` → `prayer_quiz_questions`

Per-question state: `orderIndex`, `timeLimitSeconds`, `shownAt`, `deadlineAt`, `answeredAt`,
`selectedOptionId`, `isCorrect`, `status`. Unique on `(submissionId, questionId)`. The relation to
`PrayerQuestion` is `onDelete: Restrict`, so a question that has ever been served cannot be deleted
— deactivate it with `isActive = false` instead.

---

## Guides

### Guide questions

There is **no `questions` table** — it was folded into `prayer_questions` by the
`20260801120000_unify_question_bank` migration. Guide questions are the `scope = GUIDE` rows
described above.

`guideId` is an indexed **plain string** expected to equal a `GuideType` value (`'wudu'`, `'fajr'`,
…) — there is no guides table and no foreign key, so a typo simply yields no questions.

The old model stored `options String[]` plus a `correctAnswer` text that was compared with
Turkish-locale case folding. That is gone: options are real `prayer_question_options` rows and
`POST /question/guide/check` grades by option id.

---

## Migrations

`prisma/migrations/`, in order:

| Migration                                 | Contents (migration names do not always match what they do)                                                                                                                                                                                                                          |
| ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `20260420201800_consent`                  | The initial baseline: `users`, `user_credentials`, `refresh_tokens`, `otp_verifications`, `password_resets`, `user_consents`, `user_avatar_configs`, `user_xp`, `user_streaks`, `follows`, `questions` + the `Gender` / `ConsentType` enums                                          |
| `20260525184341_streak`                   | `prayer_completions`, `prayer_questions`, `prayer_question_options`, `prayer_quiz_submissions`, `user_prayer_stats`, `streak_freeze_usages` + `PrayerType` / `PrayerCategory` / `PrayerQuizStatus` / `StreakFreezeReason`                                                            |
| `20260601120000_user_profile_fields`      | `Madhab` enum; country / city / latitude / longitude / madhab / language on `users` and `otp_verifications`                                                                                                                                                                          |
| `20260604120000_prayer_quiz_per_question` | `prayer_quiz_questions` + `PrayerQuizQuestionStatus`                                                                                                                                                                                                                                 |
| `20260605114914_prayer_quiz`              | only sets `language DEFAULT 'tr'` on `users` and `otp_verifications`                                                                                                                                                                                                                 |
| `20260801120000_unify_question_bank`      | `QuestionScope` enum; `scope` / `guideId` on `prayer_questions`; `@@unique(questionId, orderIndex)` on `prayer_question_options`; copies `questions` rows in (ids preserved, `options[]` expanded into option rows) and **drops `questions`**                                        |
| `20260801130000_prayer_late_marking`      | `PrayerCompletionStatus` enum; `status` / `xpBeforePenalty` + `(userId, status)` index on `prayer_completions`; `markWindowEndsAt` on `prayer_quiz_submissions`; `totalOnTime` / `totalLate` on `user_prayer_stats`; backfills all four (every pre-existing completion is `ON_TIME`) |

| `20260801200000_profile_change_quotas` | `locationChangeCount` / `madhabChangeCount` on `users`,
both defaulting to 0 so every existing user keeps one change | | `20260802120000_login_lockout` |
`failedLoginAttempts` / `lockedUntil` on `user_credentials`; `usernameUpdatedAt` on `users` (null =
never renamed, so nobody is retroactively inside the rename cooldown) | |
`20260802130000_token_version` | `tokenVersion` on `user_credentials`, default 0 — matching the `tv`
claim's fallback, so tokens issued before this shipped keep validating | | Note that `schema.prisma`
declares `datasource db { provider = "postgresql" }` with **no `url`** — the connection string is
supplied by [`prisma.config.ts`](../prisma.config.ts), which reads `DATABASE_URL` after loading
`.env`. Prisma CLI commands therefore work without a `url` in the schema.
