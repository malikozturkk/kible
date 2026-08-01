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
| Madhab (gamification) | the user's stored `madhab` — same value                                   |

Gamification used to hardcode `Shafi` (commit `823c539`). That split shipped a real defect: for a
Hanafi user in Gaziantep on 2026-08-01, `/worship` showed Asr at 17:37 while the markable window
still ended at the Shafi 16:29, so Dhuhr became unmarkable 69 minutes before its real end. Both
paths now read the stored madhab and must stay in sync.

Verified against `api.aladhan.com` (method 13 = Diyanet) for Gaziantep, İstanbul and Erzurum across
three dates, both madhabs: 45 comparisons, none off by more than a minute.

If `latitude` or `longitude` is null, every prayer-dependent endpoint fails with
`USER_LOCATION_NOT_SET`.

---

## 2. Prayer slots and windows

`buildPrayerSlots()` (`src/gamification/helpers/prayer-schedule.helper.ts`) derives the day's slots
from today's and tomorrow's adhan times. Windows are half-open: `now >= start && now < end`.

Each slot carries **two** ends. `windowEndsAt` closes the prayer's own time; `markWindowEndsAt` is
the start of the next _daily_ prayer and is the hard cutoff for marking at all. Marking between the
two records a `LATE` (kaza) completion — see [§2.1](#21-on-time-vs-late-kaza).

| Prayer     | Category | Own window (`ON_TIME`)          | Mark cutoff (`markWindowEndsAt`) | Obligatory | Base XP | Late XP |
| ---------- | -------- | ------------------------------- | -------------------------------- | ---------- | ------- | ------- |
| `FAJR`     | DAILY    | fajr → sunrise                  | dhuhr                            | yes        | 20      | 10      |
| `DHUHR`    | DAILY    | dhuhr → asr                     | asr (same)                       | yes        | 15      | 8       |
| `ASR`      | DAILY    | asr → maghrib                   | maghrib (same)                   | yes        | 15      | 8       |
| `MAGHRIB`  | DAILY    | maghrib → isha                  | isha (same)                      | yes        | 15      | 8       |
| `ISHA`     | DAILY    | isha → _tomorrow's_ fajr        | tomorrow's fajr (same)           | yes        | 15      | 8       |
| `JUMUAH`   | WEEKLY   | dhuhr − 15 min → dhuhr + 15 min | asr                              | no         | 25      | 13      |
| `TARAWIH`  | RAMADAN  | isha + 30 min → tomorrow's fajr | tomorrow's fajr (same)           | no         | 20      | 10      |
| `EID_FITR` | EID      | sunrise + 30 min → dhuhr        | dhuhr (same)                     | no         | 50      | 25      |
| `EID_ADHA` | EID      | sunrise + 30 min → dhuhr        | dhuhr (same)                     | no         | 50      | 25      |

Only `FAJR` and `JUMUAH` actually gain a late tail — every other prayer's own window already runs up
to the next daily prayer, so its two ends coincide. Tarawih and the Eid prayers are supererogatory
and deliberately do **not** shorten anyone's cutoff; otherwise Tarawih would cut Isha's markable
span down to 30 minutes throughout Ramadan.

Conditional slots:

- **Friday** (`DateTime.weekday === 5`): `JUMUAH` **replaces** `DHUHR` — they never coexist. Its
  `scheduledAt` is the dhuhr time and its **on-time** window is only ±`JUMUAH_MARK_WINDOW_MINUTES`
  (15) around it, not the full dhuhr → asr span. Between `dhuhr + 15 min` and asr it is still
  markable, but as `LATE`.
- **Ramadan** (Hijri month 9): `TARAWIH` is appended.
- **Eid al-Fitr** (Shawwal 1) / **Eid al-Adha** (Dhu al-Hijjah 10): the Eid slot is _prepended_ to
  the list with `unshift`, so it sorts first.

Hijri dates use `Intl.DateTimeFormat` with the `islamic-umalqura` calendar. `toHijri` takes the
zoned Luxon `DateTime` and anchors the conversion to **12:00 UTC of that calendar day** — it used to
receive the raw `startOf('day')` instant, which for any zone east of UTC (`2027-03-09T00:00+03` =
`2027-03-08T21:00Z`) resolved to the previous Hijri day. The visible symptom was Ramadan, Eid
al-Fitr and Eid al-Adha all landing one day late, with Tarawih shown on the night of Eid itself.

### 2.1 On time vs. late (kaza)

`PrayerCompletion.status` is a `PrayerCompletionStatus` — `ON_TIME` or `LATE`:

| `now` relative to the slot          | Markable? | Recorded status |
| ----------------------------------- | --------- | --------------- |
| before `windowStartsAt`             | no        | —               |
| `windowStartsAt` … `windowEndsAt`   | yes       | `ON_TIME`       |
| `windowEndsAt` … `markWindowEndsAt` | yes       | `LATE`          |
| at or after `markWindowEndsAt`      | no        | —               |

The three helpers in `prayer-schedule.helper.ts` express exactly this: `isWithinWindow()` (own
window, i.e. would be on time), `isWithinMarkWindow()` (markable at all), and
`resolveCompletionStatus()` (which of the two statuses applies right now).

**Status is decided when the quiz is passed, not when it is issued.** A quiz started at 06:00 inside
Fajr's window but finished at 06:20 after sunrise yields a `LATE` completion. This is deliberate —
the record should reflect when the user actually confirmed the prayer.

**XP.** A `LATE` completion earns `round(base XP × LATE_PRAYER_XP_MULTIPLIER)` where the multiplier
is `0.5`. The first-of-day bonus (`PRAYER_FIRST_OF_DAY_BONUS_XP`, 10) is **not** reduced — it
rewards showing up at all. `PrayerCompletion.xpBeforePenalty` stores what the same marking would
have earned on time, so the client can show the penalty; it equals `xpAwarded` for `ON_TIME` rows.

**Streaks are status-blind.** A `LATE` completion advances the streak exactly like an `ON_TIME` one
— the streak counts days on which any prayer was completed. Only XP differs.

---

## 3. Completing a prayer

**There is no "mark as prayed" endpoint.** The only way to record a completion is to answer a
3-question quiz correctly inside the prayer's **markable** span (own window plus the kaza tail, see
[§2.1](#21-on-time-vs-late-kaza)).

```
GET  /gamification/prayer-questions/:prayerType          issue (or resume) the quiz
POST …/questions/:questionId/start                       reveal one question, start its 25 s timer
POST …/questions/:questionId/answer                      answer it
   ↳ when all 3 are CORRECT → PrayerCompletion is created in the same request
```

### Issuing (`PrayerQuizService.issueQuiz`)

Preconditions, in order — each throws and stops the flow:

1. The slot exists today → else `PRAYER_NOT_AVAILABLE_TODAY` (404).
2. `now` is inside the **mark** window (`isWithinMarkWindow`) → else `PRAYER_WINDOW_NOT_OPEN_YET` /
   `PRAYER_WINDOW_CLOSED` (409). Being past the own window is fine; it only makes the eventual
   completion `LATE`.
3. No `PrayerCompletion` for `(user, type, date)` → else `PRAYER_ALREADY_COMPLETED` (409).
4. No `FAILED` or `EXPIRED` submission for `(user, type, date)` → else `PRAYER_MARKING_LOCKED`
   (409).

An existing `PENDING`, unexpired submission is **resumed**, not replaced. Otherwise 3 questions are
picked at random (partial Fisher–Yates) from active `PrayerQuestion` rows where
`prayerType IS NULL OR prayerType = :type`. Fewer than 3 candidates →
`INSUFFICIENT_PRAYER_QUESTIONS` (503).

The submission stores both ends (`windowEndsAt`, `markWindowEndsAt`) and
`expiresAt = markWindowEndsAt + 5 minutes` (`PRAYER_QUIZ_EXPIRY_GRACE_MINUTES`).

> **The 5-minute grace is unreachable.** `assertQuizUsable()` re-checks `now >= markWindowEndsAt` →
> `PRAYER_WINDOW_CLOSED` (409) on every `start` and `answer` call, and that check fires before
> `expiresAt` is ever consulted. A quiz begun late therefore fails at the mark-window boundary, not
> at `expiresAt`. The submission stays `PENDING` (it is not marked `FAILED`), so the user is not
> locked out — but the prayer can no longer be completed for that day.
>
> `JUMUAH` used to be the worst case at 30 minutes; since its cutoff now extends to asr, a quiz
> started near the end of the ±15 min window can still be finished — it just lands as `LATE`.

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

Before the transaction the **mark** window is re-checked (`PRAYER_WINDOW_CLOSED`) and
`resolveCompletionStatus(slot, now)` decides `ON_TIME` vs `LATE`. Then, in one transaction:

1. `SELECT … FOR UPDATE` on the user's `user_streaks` row (via `StreakService.lockStreakRow`).
2. `isFirstOfDay = (count of prayer_completions for this local date === 0)`.
3. `dayBonus = 10` when first of the day (`PRAYER_FIRST_OF_DAY_BONUS_XP`), else 0.
   `xpBeforePenalty = base XP + dayBonus`; `xpAwarded = (LATE ? late XP : base XP) + dayBonus`.
4. Insert `PrayerCompletion` with `status`, `xpAwarded` and `xpBeforePenalty`.
5. If first of day, run the streak update and set `streakContributed` when the streak advanced —
   `LATE` completions advance the streak identically.
6. Upsert `UserPrayerStats` (`totalCompleted`, `totalOnTime`/`totalLate`, the per-type counter,
   `lastCompletedAt`).
7. Award XP.
8. Mark the submission `PASSED` and link `prayerCompletionId`.

A `P2002` unique violation on `(userId, prayerType, prayerDate)` is translated to
`PRAYER_ALREADY_COMPLETED`.

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

Prayer XP comes from `PRAYER_XP_REWARDS` (see the table in [§2](#2-prayer-slots-and-windows)); a
`LATE` completion earns `round(base × LATE_PRAYER_XP_MULTIPLIER)` with the multiplier at `0.5`, and
the first-of-day bonus is exempt from the reduction.

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

A day counts as active as soon as **any** prayer is completed on it, `ON_TIME` or `LATE` alike —
punctuality affects XP only, never the streak.

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
edited by hand. A paid store is the intended granting mechanic and is not built yet; an automatic
milestone grant was prototyped and deliberately removed so it would not collide with that design.

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
pulls a random active row from `prayer_questions` where `scope = GUIDE` and `guideId` equals the
guide id (`'wudu'`, `'fajr'`, …), and attaches it to a randomly chosen step as `randomQuestion`.
There is no foreign key — `guideId` is a plain string that must match a `GuideType` value. Answers
are graded by `POST /question/guide/check`, by option id.

The two flows now share **one table**, discriminated by `scope`, but remain separate **flows**: the
guide check awards no XP, records no completion, and creates no quiz session. The consequence to
remember is the reverse direction — `issueQuiz()` must filter `scope = PRAYER`, because a `GUIDE`
row also carries `prayerType = null` and would otherwise land in the "every prayer" pool.

### Question bank

One table, `prayer_questions`, filled by `yarn prisma:seed` (see
[`DEVELOPMENT.md`](DEVELOPMENT.md#seeding)).

| `scope`  | Rows | Shape                                                       |
| -------- | ---- | ----------------------------------------------------------- |
| `PRAYER` | 200  | 20 per `PrayerType` (9 types) + 20 with `prayerType = NULL` |
| `GUIDE`  | 64   | 8 per `GuideType` (8 guides)                                |

The `prayerType = NULL` pool is what makes every quiz issuable: the picker selects from
`scope = PRAYER AND (prayerType IS NULL OR prayerType = :type)`, so each prayer draws from 40
candidates.

All content is Turkish and every question has exactly one correct option; `explanation` is filled
for `PRAYER` rows and null for `GUIDE` rows (the guide UI does not show it). Where a ruling differs
between schools the question names the school (e.g. "…(Hanefî)") rather than presenting one view as
the only one.

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
