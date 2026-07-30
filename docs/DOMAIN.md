# Domain Rules

The business logic an agent cannot infer from the type signatures. Everything here is read off the
source files named in each section.

---

## 1. Location, timezone and calculation method

A user has `latitude`, `longitude` and `madhab`. There is **no timezone column** — the zone is
resolved on every request from the coordinates:

```ts
resolveTimezone(lat, lon); // tz-lookup, falls back to 'Europe/Istanbul' on any error
```

Prayer times come from the `adhan` library via `PrayerTimeFactory`
(`src/worship/factories/prayer-time.factory.ts`):

| Parameter             | Value                                                                     |
| --------------------- | ------------------------------------------------------------------------- |
| Calculation method    | **`Turkey`** — the default, and nothing in `src/` ever passes another one |
| High-latitude rule    | `MiddleOfTheNight`                                                        |
| Madhab (`/worship`)   | the user's stored `madhab` (`SHAFI` / `HANAFI`)                           |
| Madhab (gamification) | **hardcoded `Shafi`** in `PrayerScheduleService.buildSlots()`             |

That split is deliberate — commit `823c539`, "force Shafi madhab for Turkey prayer calculation
method". It means the Asr boundary used for quiz windows can differ from the Asr time a Hanafi user
sees in `/worship`. Do not "unify" them without asking.

If `latitude` or `longitude` is null, every prayer-dependent endpoint fails with
`USER_LOCATION_NOT_SET`.

---

## 2. Prayer slots and windows

`buildPrayerSlots()` (`src/gamification/helpers/prayer-schedule.helper.ts`) derives the day's slots
from today's and tomorrow's adhan times. Windows are half-open: `now >= start && now < end`.

| Prayer     | Category | Window                          | Obligatory | Base XP |
| ---------- | -------- | ------------------------------- | ---------- | ------- |
| `FAJR`     | DAILY    | fajr → sunrise                  | yes        | 20      |
| `DHUHR`    | DAILY    | dhuhr → asr                     | yes        | 15      |
| `ASR`      | DAILY    | asr → maghrib                   | yes        | 15      |
| `MAGHRIB`  | DAILY    | maghrib → isha                  | yes        | 15      |
| `ISHA`     | DAILY    | isha → _tomorrow's_ fajr        | yes        | 15      |
| `JUMUAH`   | WEEKLY   | dhuhr → asr                     | no         | 25      |
| `TARAWIH`  | RAMADAN  | isha + 30 min → tomorrow's fajr | no         | 20      |
| `EID_FITR` | EID      | sunrise + 30 min → dhuhr        | no         | 50      |
| `EID_ADHA` | EID      | sunrise + 30 min → dhuhr        | no         | 50      |

Conditional slots:

- **Friday** (`DateTime.weekday === 5`): `JUMUAH` **replaces** `DHUHR` — they never coexist.
- **Ramadan** (Hijri month 9): `TARAWIH` is appended.
- **Eid al-Fitr** (Shawwal 1) / **Eid al-Adha** (Dhu al-Hijjah 10): the Eid slot is _prepended_ to
  the list with `unshift`, so it sorts first.

Hijri dates use `Intl.DateTimeFormat` with the `islamic-umalqura` calendar, computed from the zoned
date's UTC midnight.

---

## 3. Completing a prayer

**There is no "mark as prayed" endpoint.** The only way to record a completion is to answer a
3-question quiz correctly inside the prayer's window.

```
GET  /gamification/prayer-questions/:prayerType          issue (or resume) the quiz
POST …/questions/:questionId/start                       reveal one question, start its 25 s timer
POST …/questions/:questionId/answer                      answer it
   ↳ when all 3 are CORRECT → PrayerCompletion is created in the same request
```

### Issuing (`PrayerQuizService.issueQuiz`)

Preconditions, in order — each throws and stops the flow:

1. The slot exists today → else `PRAYER_NOT_AVAILABLE_TODAY` (404).
2. `now` is inside the window → else `PRAYER_WINDOW_NOT_OPEN_YET` / `PRAYER_WINDOW_CLOSED` (409).
3. No `PrayerCompletion` for `(user, type, date)` → else `PRAYER_ALREADY_COMPLETED` (409).
4. No `FAILED` or `EXPIRED` submission for `(user, type, date)` → else `PRAYER_MARKING_LOCKED`
   (409).

An existing `PENDING`, unexpired submission is **resumed**, not replaced. Otherwise 3 questions are
picked at random (partial Fisher–Yates) from active `PrayerQuestion` rows where
`prayerType IS NULL OR prayerType = :type`. Fewer than 3 candidates →
`INSUFFICIENT_PRAYER_QUESTIONS` (503).

`expiresAt = windowEndsAt + 5 minutes` (`PRAYER_QUIZ_EXPIRY_GRACE_MINUTES`).

### Timing

| Constant                                        | Value |
| ----------------------------------------------- | ----- |
| `PRAYER_QUIZ_QUESTION_COUNT`                    | 3     |
| `PRAYER_QUIZ_QUESTION_TIME_LIMIT_SECONDS`       | 25    |
| `PRAYER_QUIZ_QUESTION_TIME_LIMIT_GRACE_SECONDS` | 2     |
| `PRAYER_QUIZ_EXPIRY_GRACE_MINUTES`              | 5     |

The clock starts at `/start`, not at issue: `deadlineAt = shownAt + 25 s`. An answer arriving after
`deadlineAt + 2 s` is treated as expired. Overdue `SHOWN` questions are also swept to `EXPIRED`
lazily whenever the quiz is re-read.

### Question state machine

```
PENDING ──/start──▶ SHOWN ──correct──▶ CORRECT
                      ├────wrong────▶ INCORRECT   ─┐
                      └────timeout──▶ EXPIRED     ─┤
                                                   ├─▶ siblings become LOCKED
                                                   └─▶ submission becomes FAILED
```

`CORRECT`, `INCORRECT`, `EXPIRED` and `LOCKED` are terminal. Submission statuses: `PENDING`,
`PASSED`, `FAILED`, `EXPIRED`.

**One mistake ends the day for that prayer.** There is no retry: the `FAILED` submission makes step
4 above fail for the rest of the day. `attemptCount` is incremented but never used as a budget.

Option correctness (`isCorrect`) is never serialized to the client — options are returned as
`{ id, text }` only.

### Completion (`PrayerCompletionService.completeFromPassedQuiz`)

Triggered from inside `answerQuestion` when the third answer lands. In one transaction:

1. `SELECT … FOR UPDATE` on the user's `user_streaks` row (via `StreakService.lockStreakRow`).
2. `isFirstOfDay = (count of prayer_completions for this local date === 0)`.
3. `xpAwarded = base XP + 10` when first of the day (`PRAYER_FIRST_OF_DAY_BONUS_XP`), else base XP.
4. Insert `PrayerCompletion`.
5. If first of day, run the streak update and set `streakContributed` when the streak advanced.
6. Upsert `UserPrayerStats` (`totalCompleted` + the per-type counter + `lastCompletedAt`).
7. Award XP.
8. Mark the submission `PASSED` and link `prayerCompletionId`.

The window is re-checked before the transaction (`PRAYER_WINDOW_CLOSED`), and a `P2002` unique
violation on `(userId, prayerType, prayerDate)` is translated to `PRAYER_ALREADY_COMPLETED`.

`streakFreezeApplied` is written as `false` and never updated elsewhere.

---

## 4. XP and levels

`src/gamification/domain/level-calculator.ts` — pure, static, no I/O.

```
requiredXp(level)          = 40 + 10·level + 2·level²
cumulativeXpForLevel(n)    = Σ requiredXp(1..n)
```

So level 1 costs 52 XP, level 2 costs 68 (120 cumulative), level 3 costs 88 (208 cumulative), and
the marginal cost grows quadratically. A user with 0 XP is **level 0**.

`computeLevelFromXp(xp)` returns
`{ xp, level, currentLevelXp, xpToNextLevel, totalXpForNextLevel, badgeKey, progressPercent }`,
where `progressPercent` is clamped to 0–100.

`UserXp` tracks two counters: `xp` (used for the level) and `totalXp` (lifetime). `XpService.award`
increments both by the same amount, so today they never diverge — `xp` exists so a future spend
mechanic can reduce it without rewriting history. `award()` rejects non-positive or non-finite
amounts with `INVALID_XP_AMOUNT`.

### Badges (`getBadgeKey`)

| Level | Key                     |
| ----- | ----------------------- |
| < 10  | `steadfast_beginner`    |
| < 20  | `prayer_committed`      |
| < 30  | `consistent_worshipper` |
| < 40  | `dedicated_servant`     |
| < 50  | `steadfast_believer`    |
| < 75  | `mindful_devotee`       |
| < 100 | `spiritual_guardian`    |
| < 150 | `excellence_in_prayer`  |
| < 200 | `community_inspiration` |
| ≥ 200 | `legacy_of_devotion`    |

Level 0 is reported with the level-1 badge (`Math.max(1, level)`).

---

## 5. Streaks

`src/gamification/services/streak.service.ts`. `lastActiveDate` is a local calendar day stored as
UTC midnight; `gap = lastActiveDate.daysUntil(today)`.

### Daily activity — runs only on the **first** completion of a local day

| `gap`               | Result                                                                        |
| ------------------- | ----------------------------------------------------------------------------- |
| no `lastActiveDate` | `currentStreak = 1`, advanced                                                 |
| ≤ 0                 | no change (already counted today)                                             |
| 1                   | `currentStreak + 1`, advanced                                                 |
| > 1                 | **reset to 1**, advanced (and `streakReset = true` if the old streak was > 0) |

`longestStreak = max(longestStreak, currentStreak)`.

### Streak freeze — `POST /gamification/action`

Repairs a gap retroactively. Runs at `Serializable` isolation behind the row lock.

- `gap ≤ 1` → `STREAK_NOT_AT_RISK` (409)
- `gap > STREAK_FREEZE_MAX_GAP_DAYS` (3) → `STREAK_FREEZE_WINDOW_EXPIRED` (409)
- `streakFreezeCount < 1` → `NO_STREAK_FREEZE_AVAILABLE` (409)

On success it writes one `StreakFreezeUsage` row per missed day (`lastActive+1 … today-1`),
decrements `streakFreezeCount` by **1 regardless of how many days were covered**, and back-dates
`lastActiveDate` to _yesterday_ — so the next completion continues the streak instead of resetting
it. Note the current streak number itself is not incremented for the frozen days.

Re-running when every day is already protected is idempotent: `alreadyApplied: true`, nothing is
charged.

**Nothing in the codebase grants freezes.** `streakFreezeCount` starts at 0 and is only ever
decremented, so this endpoint effectively always returns `NO_STREAK_FREEZE_AVAILABLE` until a row is
edited by hand or a granting mechanic is added.

`StreakService.inspectStreakRisk()` computes `atRisk` / `canFreezeNow` / `freezeWindowExpired` but
is **not wired to any endpoint**.

---

## 6. Fasting and day progress (`/worship`)

`FastingProgressService` treats the window as `fajr → maghrib` on the requested day:

- `now < fajr` → `progressPercent 0`, `remainingSeconds` = the full window
- inside → elapsed/total as a percentage, `remainingSeconds` to maghrib
- `now >= maghrib` → `100`, `0`

`isRamadan` is Hijri month 9. During Ramadan the response also carries
`{ ramadanDay, totalDays, remainingDays }`, where `totalDays` comes from a local Hijri month-length
approximation (odd months 30 days, even 29, with a 30-year leap pattern applied to month 12) — an
approximation, not an observed calendar.

`DayProgressService` is simply seconds-since-local-midnight ÷ 86400, to 2 decimals.

---

## 7. Guides

Static Turkish content, one strategy class per type, assembled at request time — nothing is read
from the database except the optional random question.

| `:type`   | Title         | Rakats | Sunnah before / after |
| --------- | ------------- | ------ | --------------------- |
| `wudu`    | Abdest        | —      | —                     |
| `ghusl`   | Gusül Abdesti | —      | —                     |
| `fajr`    | Sabah Namazı  | 2      | 2 / —                 |
| `dhuhr`   | Öğle Namazı   | 4      | 4 / 2                 |
| `asr`     | İkindi Namazı | 4      | 0 / 0                 |
| `maghrib` | Akşam Namazı  | 3      | — / 2                 |
| `isha`    | Yatsı Namazı  | 4      | 0 / 2                 |
| `jumuah`  | Cuma Namazı   | 2      | —                     |

Prayer guides are composed per rakat by `PrayerStepBuilder`: takbir → for each rakat (qiyam +
recitation → rukû → post-rukû standing → sujud) → tashahhud + salam. `syncTotalSteps()` rewrites
`totalSteps` on every step after assembly, so the builders' hardcoded counts do not have to be
exact.

**Random question:** with probability `0.8` (`RANDOM_QUESTION_SHOW_PROBABILITY`) `GuidesService`
pulls a random row from `questions` where `guideId` equals the guide id (`'wudu'`, `'fajr'`, …) and
attaches it to a randomly chosen step as `randomQuestion`. There is no foreign key — `guideId` is a
plain string that must match a `GuideType` value. Answers are graded by `POST /question/guide/check`
using Turkish-locale case folding.

This flow is **completely separate** from the prayer quiz: different tables (`questions` vs
`prayer_questions`), no XP, no completion effect.

---

## 8. Authentication and account lifecycle

### Registration (two phases)

```
POST /auth/register
  ├─ reject if username or email already exists           (409)
  ├─ bcrypt(password + PEPPER, cost 12)
  ├─ delete expired / stale otp_verifications for this email+username
  ├─ reject if an unexpired pending registration exists    ACTIVE_REGISTRATION_EXISTS
  ├─ sign tempToken { email, username, purpose: 'register' }, 10 min
  └─ insert otp_verifications (all profile fields + consent versions from env), email a 6-digit code

POST /otp/verify   (Bearer tempToken)
  └─ transaction: create users + user_credentials + user_xp + user_streaks
                  + user_avatar_configs + 2× user_consents, delete the otp row
```

The user row is created by **`OtpService`**, not `AuthService` — that is where to look when adding a
field that must exist from day one. A new field generally has to be threaded through: `RegisterDto`
→ `RegisterData` → the `otp_verifications` column (needs a migration) → `tx.user.create`.

OTP lifetimes: code 3 minutes, whole registration 10 minutes. `/otp/resend` only works once the
current code has expired **and** ≥ 3 minutes of registration time remain. OTP comparison uses
`crypto.timingSafeEqual`. Send failures during `create` are swallowed and logged; failures during
`resend` are not.

### Passwords

`bcrypt(password + PEPPER)`. Cost **12** in register and reset, **10** in `updateProfile` — an
inconsistency, not a rule. `PEPPER` is a server-side secret: changing it invalidates every stored
hash.

### Tokens

- **Access token** — JWT `{ sub, username }`, signed with `JWT_SECRET`, lifetime `JWT_EXPIRES_IN`.
  `JwtStrategy` re-reads the user from the database on every request, so `req.user` is
  `{ id, username, email, avatar }` and a deleted user is rejected immediately.
- **Refresh token** — 32 random bytes, hex. Only its SHA-256 hash is stored; expiry is **1 day**
  (`REFRESH_TOKEN_EXPIRES_IN_DAYS`, hardcoded in both `AuthService` and `OtpService`).
  `/auth/refresh` issues a new pair but does not revoke the presented token; `/auth/logout` revokes
  one token; a password reset revokes all of them.

### Password reset

Token = 32 random bytes, stored **bcrypt-hashed** (cost 12), 30-minute lifetime, single active reset
per user. Lookup is by `userId` + `isUsed: false` (the newest row), then a bcrypt comparison — the
`failedAttempts` column exists but is never incremented. A minute-ly cron deletes expired rows.

### Consent

Current versions live in env (`CONSENT_VERSION_TERMS_OF_SERVICE`, `CONSENT_VERSION_PRIVACY_POLICY`)
and are loaded by `consentConfig`, which **throws at boot** if either is missing. Acceptances are
append-only rows unique on `(userId, type, version)`; "current" means the newest `acceptedAt` per
type. Bumping a version makes `requiresReaccept` true for everyone until they re-accept.

See the `ConsentGuard` ordering caveat in [`ARCHITECTURE.md`](ARCHITECTURE.md#request-lifecycle) —
the enforcement side of this feature is probably inert today.

---

## 9. User search

`UsersService.searchUsers` does similarity ranking **in the application**, not in PostgreSQL:

1. Fetch up to **500** candidates matching `username ILIKE %query%` or any 3-gram of the query.
2. Score each with Jaccard similarity over 3-gram sets; drop anything ≤ `0.1`.
3. Tier: `0` exact match → `1` you already follow → `2` followed by someone you follow → `3` other.
4. Sort by tier, then similarity desc, then username asc.
5. Paginate by array offset (`cursor`), returning `nextCursor` or `null`.

Consequences worth knowing before touching it: the 500-row cap is applied _before_ scoring, so a
common substring can push relevant users out of the result set; `totalCount` counts scored
candidates, not all matches; and each result page issues two extra follow queries per user (`N+1` on
mutual followers).
