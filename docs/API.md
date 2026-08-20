# API Reference

Base URL: `http://localhost:3000`. Every response is wrapped by the global envelope described in
[`ARCHITECTURE.md`](ARCHITECTURE.md#response-envelope--srccommon) — the **Returns** column below
describes the `data` field only.

**Auth column:**

| Value  | Meaning                                                                               |
| ------ | ------------------------------------------------------------------------------------- |
| —      | No guard                                                                              |
| `JWT`  | `JwtAuthGuard` — `Authorization: Bearer <accessToken>`                                |
| `TEMP` | `OtpJwtGuard` — `Authorization: Bearer <tempToken>` (the token from `/auth/register`) |

Unlisted request fields are rejected with **400 `VALIDATION_ERROR`** (`forbidNonWhitelisted: true`).

---

## Health

| Method | Path | Auth | Returns          |
| ------ | ---- | ---- | ---------------- |
| `GET`  | `/`  | —    | `"Hello World!"` |

---

## Auth — `src/auth/auth.controller.ts`

### `POST /auth/register` — —

Starts registration. Does **not** create a user; it stores a pending `otp_verifications` row and
emails a 6-digit code.

```jsonc
{
  "username": "malik_o", // ^[a-zA-Z0-9_]+$, 3–20 chars
  "email": "user@example.com",
  "password": "Str0ng!Pass", // 8–72 chars, must contain lower + upper + digit + symbol
  "gender": "MALE", // MALE | FEMALE
  "country": "Türkiye", // ≤ 64, PLACE_NAME_PATTERN
  "city": "İstanbul", // ≤ 85, PLACE_NAME_PATTERN — must be one of the 81 TR provinces
  "madhab": "HANAFI", // SHAFI | HANAFI
  "language": "tr", // ^[a-z]{2}(-[A-Z]{2})?$
  "termsAccepted": true, // must be exactly true
  "privacyPolicyAccepted": true, // must be exactly true
  "specialCategoryDataAccepted": true, // must be exactly true — KVKK special-category consent
}
```

Returns `{ "tempToken": "<jwt>" }` — valid 10 minutes, carries `purpose: "register"`.

> **Coordinates are never taken from the client.** The body carries only `city`; the server derives
> `latitude`/`longitude` from the chosen province via `resolveCityCoordinates()`
> (`src/auth/constants/tr-cities.constants.ts`) and stages those onto the pending row. A `city` that
> is not one of the 81 TR provinces is rejected with `INVALID_CITY` (400).

Errors: `INVALID_CITY` (400 — city not in the province catalog), `USERNAME_ALREADY_EXISTS` (409),
`USER_ALREADY_EXISTS` (409), `ACTIVE_REGISTRATION_EXISTS`
(409 — an unexpired pending registration already holds that email/username), plus 400
`VALIDATION_ERROR` with `USERNAME_TOO_SHORT` / `USERNAME_TOO_LONG` / `PASSWORD_TOO_SHORT` /
`PASSWORD_TOO_LONG` / `PASSWORD_TOO_WEAK` / `TERMS_NOT_ACCEPTED` / `PRIVACY_POLICY_NOT_ACCEPTED` /
`SPECIAL_CATEGORY_CONSENT_NOT_ACCEPTED` in `attachment`.

Throttled: **5 requests / hour** per IP (each call sends a real email).

The credential rules live in `src/auth/constants/credential.constants.ts` and are shared by
register, `PATCH /auth/profile` and `POST /auth/reset-password`, so no path is weaker than another.
The frontend mirrors them in `secde/src/validations/auth.validation.ts` for pre-submit feedback only
— the backend is the boundary.

> The accepted consent **versions** are read from the server's `CONSENT_VERSION_*` env vars, not
> from the request. `termsAccepted` / `privacyPolicyAccepted` / `specialCategoryDataAccepted` are
> validated but otherwise unused.

### `POST /auth/login` — — · `200`

`{ "identifier": "<email or username>", "password": "…" }` — the identifier is routed by an email
regex. Returns `{ accessToken, refreshToken, user }`.

Errors: `INVALID_CREDENTIALS` (401) for both unknown user and wrong password;
`ACCOUNT_TEMPORARILY_LOCKED` (401) once the account is locked out.

Two independent limits guard this route:

| Layer           | Bound                                    | Where                                                 |
| --------------- | ---------------------------------------- | ----------------------------------------------------- |
| IP throttle     | 5 requests / minute → **429**            | `@Throttle` + `THROTTLE_LOGIN`                        |
| Account lockout | 10 consecutive failures → 15-minute lock | `LoginAttemptService`, `user_credentials.lockedUntil` |

The password is compared _before_ the lock is reported, so a locked account is indistinguishable
from a wrong password to a caller who does not know the password. A successful login clears the
counter; so does a completed password reset.

### `POST /auth/refresh` — — · `200`

`{ "refreshToken": "<64-hex>" }` → a new `{ accessToken, refreshToken, user }`. Errors:
`INVALID_OR_EXPIRED_REFRESH_TOKEN` (401). Throttled: 20 requests / minute.

The presented refresh token **is revoked** as part of issuing the replacement pair (rotation), so
replaying it returns `INVALID_OR_EXPIRED_REFRESH_TOKEN`.

### `POST /auth/logout` — `JWT` · `200`

`{ "refreshToken": "…" }` → `null`. Marks that token `isRevoked`. Errors: `INVALID_REFRESH_TOKEN`
(401, also when the token belongs to another user), `TOKEN_ALREADY_INVALIDATED` (401),
`REFRESH_TOKEN_EXPIRED` (401).

### `DELETE /auth/me` — `JWT` · `200`

Deletes the caller's account (KVKK right-to-erasure). No request body; returns `null`.

In one transaction it deletes the user's `password_resets` rows (`userId` is not a foreign key, so
the cascade would miss them), any `otp_verifications` rows holding the same email, and finally the
`users` row — every other table is removed by `onDelete: Cascade`.

The route is on the static `CONSENT_BYPASS_ROUTES` list, so it stays reachable even while a consent
re-accept is pending — the consent gate must not be able to block an erasure request.

Errors: `USER_NOT_FOUND` (404).

### `GET /auth/:username` — `JWT`

Profile of `:username` as seen by the caller.

```jsonc
{
  "username": "…",
  "avatar": null,
  "createdAt": "…",
  "country": "…",
  "city": "…",
  "language": "tr",
  // owner only:
  "id": "…",
  "email": "…",
  "madhab": "SHAFI",
  "updatedAt": "…",
  "locationChangeCount": 0,
  "madhabChangeCount": 0,
  "avatarCustomization": { "gender": "MALE", "colors": {}, "accessories": {} },
  "isFollowing": false, // null when viewing your own profile
  "followerCount": 0,
  "followingCount": 0,
  "mutualFollowers": { "count": 0, "preview": [/* ≤ 3 */] },
}
```

`id`, `email`, `madhab`, `updatedAt`, `locationChangeCount` and `madhabChangeCount` are returned
**only** when the caller is the profile owner. `madhab` is special-category data under KVKK (it
reveals religious belief), so it was removed from the public profile — other users never see it.
Errors: `USER_NOT_FOUND` (404).

### `PATCH /auth/profile` — `JWT`

All fields optional; only the supplied ones change.

```jsonc
{
  "username": "new_name", // 3–20 chars; at most one change per 30 days
  "avatar": "…",
  "gender": "FEMALE", // stored on the avatar config
  "avatarColors": { "hair": "#2e1f14" }, // partial patch, each ^#[0-9A-Fa-f]{6}$
  "currentPassword": "…",
  "newPassword": "…", // both required together; same complexity rule as register
  "language": "tr", // must be in SUPPORTED_LANGUAGES (only "tr")

  // Location + madhab. Prayer times are derived from these, so they must stay editable.
  "country": "Türkiye", // ≤ 64, PLACE_NAME_PATTERN
  "city": "Konya", // ≤ 85, PLACE_NAME_PATTERN — one of the 81 TR provinces
  "madhab": "HANAFI", // SHAFI | HANAFI
}
```

`country` and `city` are validated server-side, not just length-capped: leading/trailing whitespace
is trimmed and internal runs collapsed, then the value must match `PLACE_NAME_PATTERN`
(`src/auth/constants/location.constants.ts`) — a Unicode letter followed by letters, combining
marks, spaces, `-`, `'`, `’` and `.`. `<img src=x onerror=alert(1)>` is now `400 VALIDATION_ERROR` /
`INVALID_CITY` instead of being stored verbatim and shown to strangers in the leaderboard. Same rule
on `POST /auth/register`.

`country` and `city` move as a unit — sending one but not the other returns
`INCOMPLETE_LOCATION_UPDATE` (400). Coordinates are **not** accepted from the client: when the
province changes, the server re-derives `latitude`/`longitude` from the new `city` via
`resolveCityCoordinates()` and stores those, so prayer times follow the chosen province. A `city`
outside the 81-province catalog is rejected with `INVALID_CITY` (400). `madhab` may be sent on its
own.

Returns the updated user with `avatarCustomization`, plus `locationChangeCount` /
`madhabChangeCount`.

**When the password changed**, the response also carries a replacement token pair:

```jsonc
{ /* …user fields… */, "tokens": { "accessToken": "…", "refreshToken": "…" } }
```

A password change ends every _other_ session: `passwordUpdatedAt` is bumped, `tokenVersion` is
incremented (retiring every access token already issued, including the one that made this request)
and all refresh tokens are revoked. The caller must adopt `tokens` or its own next request will
`401`. Hashing uses cost **12**, matching register and reset.

Errors: `USERNAME_ALREADY_EXISTS` (409), `USERNAME_CHANGE_COOLDOWN_ACTIVE` (409 — renamed within the
last `USERNAME_CHANGE_COOLDOWN_DAYS`, 30), `PASSWORD_FIELDS_REQUIRED` (400),
`INVALID_CURRENT_PASSWORD` (401), `INCOMPLETE_LOCATION_UPDATE` (400),
`LOCATION_CHANGE_LIMIT_REACHED` (409), `MADHAB_CHANGE_LIMIT_REACHED` (409), plus 400
`VALIDATION_ERROR` for the username/password rules above.

> `MAX_LOCATION_CHANGES` and `MAX_MADHAB_CHANGES` are both **1** — location and madhab can each be
> changed once, ever. Prayer times derive from them, so this is a deliberate product constraint, not
> an oversight; the settings screen states it explicitly.

Valid `avatarColors` keys: `iris`, `pupil`, `hair`, `skin`, `lips`, `nose`, `earInner`, `neck`,
`eyebrow`, `outfit`, `background`. Unset keys fall back to `DEFAULT_AVATAR_COLORS`.

### `POST /auth/resume-registration` — — · `200` · throttled 5 req/min

`{ "email": "…" }` → `{ "tempToken": "<jwt>" }`.

Re-issues a temp token for a registration that is **already pending**, so a user who loses the
in-memory one (page refresh on `/verify-otp`, closed tab, back button) is not locked out for the
remaining ~10 minutes of the registration window.

It creates nothing and sends no email. The pending row's `tokenHash` is rewritten, which invalidates
the previous temp token — only one is ever live. The OTP code and its 3-minute clock are untouched.

Errors: `NO_PENDING_REGISTRATION` (400) — returned identically for an unknown email and an expired
registration, so this is not an account-existence oracle. The token alone grants nothing:
`/otp/verify` still requires the emailed code.

### `POST /auth/forgot-password` — —

`{ "email": "…" }` → `{ "message": "FORGOT_PASSWORD_EMAIL_SENT" }`. Throttled: **3 requests /
hour**.

Returns success even for unknown emails (no account enumeration), but **does** return
`ACTIVE_RESET_EXISTS` (409) when an unused, unexpired reset already exists. The emailed link is
`${FRONTEND_BASE_URL}/reset-password?user_id=<id>&token=<raw>`, valid 30 minutes. If Mailjet fails
the reset row is deleted and `EMAIL_SEND_FAILED` (500) is returned.

### `POST /auth/validate-reset-token` — —

`{ "userId": "…", "token": "…" }` → `true`. Throttled: 5 requests / minute. Errors:
`INVALID_OR_EXPIRED_TOKEN` (400), `USER_NOT_FOUND` (401).

### `POST /auth/reset-password` — —

`{ "userId", "token", "newPassword", "confirmPassword" }` → `null`. `newPassword` follows the shared
complexity rule (see `POST /auth/register`). Throttled: 5 requests / minute.

On success, in one transaction: the password hash is replaced, `passwordUpdatedAt` is bumped,
`tokenVersion` is incremented (which invalidates every outstanding **access** token — see
[`DOMAIN.md` §8](DOMAIN.md#tokens)), **all** of the user's refresh tokens are revoked, any
brute-force lockout is cleared, and the reset row is marked used.

Errors: `PASSWORDS_DO_NOT_MATCH` (400), `INVALID_OR_EXPIRED_TOKEN` (400), `USER_NOT_FOUND` (400),
`PASSWORD_UPDATE_FAILED` (500).

### Social

| Method | Path                        | Auth  | Returns                                                     |
| ------ | --------------------------- | ----- | ----------------------------------------------------------- |
| `POST` | `/auth/:username/follow`    | `JWT` | `{ "following": true \| false }` — toggles                  |
| `GET`  | `/auth/:username/followers` | `JWT` | `[{ username, avatar, avatarCustomization }]`, newest first |
| `GET`  | `/auth/:username/following` | `JWT` | same shape                                                  |

Follow errors: `USER_NOT_FOUND` (404), `CANNOT_FOLLOW_YOURSELF` (400).

---

## OTP — `src/otp/otp.controller.ts`

### `POST /otp/verify` — `TEMP` · `200`

`{ "code": "123456" }` (exactly 6 digits). Throttled: **5 requests / minute** — a 6-digit code is
only 10⁶ combinations with a 3-minute life. On success, atomically creates the `users` row plus its
`user_credentials`, `user_xp`, `user_streaks` and `user_avatar_configs` records and three
`user_consents` rows (`TERMS_OF_SERVICE`, `PRIVACY_POLICY`, `SPECIAL_CATEGORY_DATA`), deletes the
pending registration, and returns `{ accessToken, refreshToken, user }` — the same shape as login.

Errors: `MISSING_TOKEN` / `INVALID_TOKEN_PURPOSE` / `INVALID_OR_EXPIRED_TOKEN` (401),
`OTP_NOT_FOUND` (400), `REGISTRATION_EXPIRED` (400), `OTP_EXPIRED` (400), `INVALID_OTP_CODE` (400),
`USER_ALREADY_EXISTS` (409).

### `POST /otp/resend` — `TEMP` · `200`

No body. Throttled: **3 requests / hour** (sends a real email). Issues a new code only if the
current one has already expired **and** at least 3 minutes of registration lifetime remain.

Errors: `NO_PENDING_REGISTRATION` (400), `REGISTRATION_EXPIRED` (400), `ACTIVE_OTP_EXISTS` (400 —
the current code is still valid), `INSUFFICIENT_TIME_FOR_NEW_OTP` (400).

---

## Consent — `src/consent/consent.controller.ts`

### `GET /consent/status` — `JWT`

```jsonc
{
  "items": [
    {
      "type": "TERMS_OF_SERVICE",
      "acceptedVersion": "1.0.0",
      "currentVersion": "1.1.0",
      "requiresReaccept": true,
    },
    {
      "type": "PRIVACY_POLICY",
      "acceptedVersion": "1.0.0",
      "currentVersion": "1.0.0",
      "requiresReaccept": false,
    },
    {
      "type": "SPECIAL_CATEGORY_DATA",
      "acceptedVersion": "1.0.0",
      "currentVersion": "1.0.0",
      "requiresReaccept": false,
    },
  ],
  "blocked": true,
}
```

### `POST /consent/accept` — `JWT` · `200` · throttled 10 req/min

`{ "type": "TERMS_OF_SERVICE" | "PRIVACY_POLICY" | "SPECIAL_CATEGORY_DATA", "version": "1.1.0" }` →
`null`. The version must equal the server's current version, otherwise `CONSENT_OUTDATED` (400).
Re-accepting the same version is a no-op (the `P2002` unique violation is swallowed).

Both routes carry `@ConsentBypass()`, so they stay reachable while a re-accept is pending.

---

## Worship — `src/worship/worship.controller.ts`

### `GET /worship?date=YYYY-MM-DD` — `JWT`

`date` is **required** and validated by `@IsCalendarDate()`
(`src/common/validators/is-calendar-date.validator.ts`), which checks the calendar and not just the
shape: `2026-13-45`, `2026-02-30`, `not-a-date` and an empty value all give **400
`VALIDATION_ERROR`** with `date must be YYYY-MM-DD` in `attachment`. The same validator guards
`/gamification/daily-prayers` and `/gamification/prayer-history`.

Coordinates, madhab and timezone all come from the authenticated user. `meta.hijriDate` /
`meta.hijriMonthName` are produced by `toHijriLabel()`, anchored to 12:00 UTC of the **user's**
calendar day, so they do not shift with the server's `TZ`.

```jsonc
{
  "meta": {
    "latitude": 41.0082,
    "longitude": 28.9784,
    "timezone": "Europe/Istanbul",
    "gregorianDate": "2026-07-31",
    "hijriDate": "…",
    "hijriMonthName": "…",
    "calculationMethod": "Turkey",
    "madhab": "Hanafi",
  },
  "times": {
    "fajr": {
      "time": "04:12",
      "iso": "…",
      "remainingSeconds": 0,
      "isNext": false, // the entry the countdown runs toward — see below
      "isPassed": true,
    },
    "sunrise": {},
    "dhuhr": {},
    "asr": {},
    "maghrib": {},
    "isha": {},
  },
  "nextPrayer": "asr",
  "nextPrayerAt": "…",
  "secondsUntilNext": 4231,
  "lastPrayer": "dhuhr",
  "dayProgressPercent": 54.32,
  "fasting": {
    "isRamadan": false,
    "isFastingTime": true,
    "fastingStart": "…",
    "fastingEnd": "…",
    "remainingSeconds": 12345,
    "progressPercent": 61.2,
    "ramadan": null, // { ramadanDay, totalDays, remainingDays } during Ramadan
  },
}
```

`remainingSeconds` inside `times` counts to the **next occurrence** — tomorrow's instance once
today's has passed.

`isNext` is `nextPrayer.time > now && nextPrayer.name === key`, i.e. it marks the entry the
countdown is running toward, whether that occurrence is today's or tomorrow's:

| Situation                      | Row carrying `isNext`                        |
| ------------------------------ | -------------------------------------------- |
| Mid-day                        | the next prayer of the requested day         |
| Between isha and the next fajr | `fajr` — `isPassed` stays `true` on that row |
| A day entirely in the past     | none                                         |
| A future day                   | `fajr`                                       |

The second row is the reason for the condition: `nextPrayer.isTomorrow` used to suppress the flag,
so for the ~6 hours between isha and fajr no entry was `isNext` at all while `nextPrayer` still said
`"fajr"` — the client marked all six as passed and contradicted its own hero card.

Errors: `USER_NOT_FOUND` (400), `USER_LOCATION_NOT_SET` (400), `VALIDATION_ERROR` (400 — bad
`date`).

---

## Gamification — `src/gamification/gamification.controller.ts`

`JwtAuthGuard` is applied at the controller level; all routes require `JWT`.

### `GET /gamification/daily-prayers?date=YYYY-MM-DD`

`date` is required and must match `^\d{4}-\d{2}-\d{2}$`.

```jsonc
{
  "date": "2026-07-31",
  "timezone": "Europe/Istanbul",
  "isFriday": true,
  "isRamadan": false,
  "isEidDay": false,
  "firstOfDayBonusXp": 10, // PRAYER_FIRST_OF_DAY_BONUS_XP
  "firstOfDayBonusAvailable": true, // false once anything is completed today
  "prayers": [
    {
      "type": "FAJR",
      "category": "DAILY",
      "isObligatory": true,
      "scheduledAt": "…",
      "windowStartsAt": "…",
      "windowEndsAt": "…", // end of the prayer's own window — marking up to here is ON_TIME
      "markWindowEndsAt": "…", // start of the next daily prayer — the hard cutoff for marking
      "xpReward": 20, // XP for an on-time marking
      "lateXpReward": 10, // XP for a late (kaza) marking
      "isCompleted": false,
      "canMarkAsCompleted": true, // not completed && not locked && now inside the MARK window
      "isLateWindow": false, // still markable, but would be recorded as LATE
      "completionStatus": null, // "ON_TIME" | "LATE" once completed, else null
      "completedAt": null,
      "streakContribution": false,
      "xpAwarded": null, // XP actually granted; null until completed
      "pendingQuizId": null, // id of an open PENDING quiz, if any
      "isLocked": false, // a FAILED or EXPIRED quiz closed this prayer for the day
    },
  ],
}
```

The slot list is day-dependent: `JUMUAH` replaces `DHUHR` on Fridays, `TARAWIH` is appended during
Ramadan, and `EID_FITR` / `EID_ADHA` are prepended on those days. See [`DOMAIN.md`](DOMAIN.md).

**This endpoint settles lapsed quizzes before it answers.** Question timers run in the browser, so
the server only learns a question expired when something touches the quiz. `PrayerQuizExpiryService`
runs that sweep here, which is why `canMarkAsCompleted` and `isLocked` are accurate on a plain read
— previously a timed-out quiz kept reporting the slot as markable and clicking it returned `409`.

`firstOfDayBonusXp` + `firstOfDayBonusAvailable` let the client show what a marking actually pays.
The card used to print the slot's base reward alone and under-report the day's first prayer by the
bonus (15 advertised, 25 awarded).

`markWindowEndsAt` equals `windowEndsAt` for every prayer whose own window already runs up to the
next daily prayer; only `FAJR` (sunrise → dhuhr) and `JUMUAH` (dhuhr + 15 min → asr) have a real
late tail. See [`DOMAIN.md` §2.1](DOMAIN.md#21-on-time-vs-late-kaza).

### `GET /gamification/streak-risk`

Whether the caller's streak is currently broken and whether a freeze can still repair it. Uses the
caller's own timezone (resolved from their coordinates) to decide what "today" is.

```jsonc
{
  "currentStreak": 0, // effective value — 0 as soon as the streak is broken
  "longestStreak": 7,
  "freezesAvailable": 2,
  "lastActiveDate": "2026-07-31",
  "daysSinceLastActive": 2,
  "isBroken": true,
  "recoverableStreak": 7, // what a freeze would give back; nonzero also after a restart while the stored recovery's window is open
  "atRisk": false, // true when gap === 1: alive, but breaks at local midnight
  "canFreezeNow": true, // a freeze would succeed now: (broken && within the 3-day window) || open stored recovery — and freezesAvailable > 0
  "freezeWindowExpired": false,
  "lastFreezeUsedAt": null, // most recent protected day, or null
}
```

Repair goes through `POST /gamification/action` with `actionType: "STREAK_FREEZE"`. See
[`DOMAIN.md` §5](DOMAIN.md#5-streaks).

### `GET /gamification/prayer-history?from=YYYY-MM-DD&to=YYYY-MM-DD`

Per-day completion counts for the caller — the source of truth for calendar/heat-map views. Both
params are required and must match `^\d{4}-\d{2}-\d{2}$`.

```jsonc
{
  "from": "2026-07-01",
  "to": "2026-07-31", // may be earlier than requested: future days are dropped
  "timezone": "Europe/Istanbul",
  "days": [
    {
      "date": "2026-07-01",
      "completedCount": 2, // rows in prayer_completions for that day
      "totalCount": 5, // slots that existed that day (Friday/Ramadan/Eid change this)
      "isComplete": false, // totalCount > 0 && completedCount >= totalCount
      "isFrozen": false, // covered by a streak_freeze_usages row
    },
  ],
}
```

`totalCount` is recomputed per day via `PrayerScheduleService.buildSlots()`, so a Friday reports the
Jumuah slot and a Ramadan day includes Tarawih. Days before the user had any activity are still
returned, with `completedCount: 0`.

Errors:

| Status | `message`                        | When                                         |
| ------ | -------------------------------- | -------------------------------------------- |
| `400`  | `INVALID_DATE_RANGE`             | unparsable date, or `to` earlier than `from` |
| `400`  | `PRAYER_HISTORY_RANGE_TOO_LARGE` | span > `PRAYER_HISTORY_MAX_RANGE_DAYS` (62)  |
| `400`  | `USER_LOCATION_NOT_SET`          | the user has no `latitude` / `longitude`     |
| `404`  | `USER_NOT_FOUND`                 | —                                            |

### `GET /gamification/prayer-questions/:prayerId`

`:prayerId` is a `PrayerType` enum value (`FAJR`, `DHUHR`, `ASR`, `MAGHRIB`, `ISHA`, `JUMUAH`,
`TARAWIH`, `EID_FITR`, `EID_ADHA`). Issues — or returns the already-open — quiz for that prayer
**today**. The date is always "now" in the user's zone; it is not parameterizable.

```jsonc
{
  "quizId": "<uuid>",
  "expiresAt": "…",
  "quizStatus": "PENDING",
  "isLocked": false,
  "questions": [
    {
      "id": "<questionId>",
      "prompt": "…",
      "options": [{ "id": "<uuid>", "text": "…" }], // correctness is never exposed
      "orderIndex": 0,
      "timeLimitSeconds": 25,
      "status": "PENDING",
      "shownAt": null,
      "deadlineAt": null,
      "answeredAt": null,
      "selectedOptionId": null,
      "isCorrect": null,
      "isAnswerable": false,
      "canBeAnsweredAgain": false,
      "isExpired": false,
    },
  ],
}
```

Errors: `PRAYER_NOT_AVAILABLE_TODAY` (404), `PRAYER_WINDOW_NOT_OPEN_YET` (409),
`PRAYER_WINDOW_CLOSED` (409), `PRAYER_ALREADY_COMPLETED` (409), `PRAYER_MARKING_LOCKED` (409 — a
**wrong answer or a lapsed timer** closed this prayer for the day), `INSUFFICIENT_PRAYER_QUESTIONS`
(503 — fewer than 3 active questions in the pool), `USER_LOCATION_NOT_SET` (400).

A quiz whose timer lapsed is retired as `FAILED`, exactly like a wrong answer: there is no retry and
no per-day attempt budget. See [`DOMAIN.md` §3](DOMAIN.md#3-completing-a-prayer).

### `POST /gamification/prayer-questions/:quizId/questions/:questionId/start` · `200`

Both params must be UUIDs. Reveals a question and starts its 25-second timer, returning
`{ quizId, quizStatus, question }`. Calling it again while the question is `SHOWN` is idempotent.

Errors: `QUIZ_NOT_FOUND` (404, also when the quiz belongs to another user),
`QUIZ_QUESTION_NOT_FOUND` (404), `QUIZ_QUESTION_NOT_STARTABLE` (409), `QUIZ_EXPIRED` (410),
`PRAYER_MARKING_LOCKED` (409), `PRAYER_WINDOW_CLOSED` (409).

### `POST /gamification/prayer-questions/:quizId/questions/:questionId/answer` · `200`

Body `{ "optionId": "<uuid>" }`.

```jsonc
{
  "quizId": "…",
  "quizStatus": "PENDING",
  "result": "CORRECT", // CORRECT | INCORRECT | EXPIRED
  "isLocked": false,
  "question": {/* the updated question */},
  "prayerCompletion": {
    // present only when this answer completed the quiz
    "prayerCompletionId": "…",
    "prayerType": "ASR",
    "prayerDate": "2026-07-31",
    "completedAt": "…",
    "status": "ON_TIME", // ON_TIME | LATE — decided when the quiz was passed
    "xpAwarded": 25,
    "xpBeforePenalty": 25, // what it would have earned on time; > xpAwarded when LATE
    "xpAfter": 310,
    "level": 3,
    "leveledUp": false,
    "streakAdvanced": true,
    "streakReset": false, // true when this completion restarted a broken streak at 1
    "currentStreak": 5,
    "longestStreak": 12,
    "isFirstOfDay": true,
  },
}
```

The two failure modes are equivalent:

| Answer      | `quizStatus` | `isLocked` | Can retry today?          |
| ----------- | ------------ | ---------- | ------------------------- |
| `INCORRECT` | `FAILED`     | `true`     | no — the prayer is closed |
| `EXPIRED`   | `FAILED`     | `true`     | no — the prayer is closed |

`result` still distinguishes the two (`INCORRECT` vs `EXPIRED`) so the client can word the message
correctly, but both lock every remaining question in that submission and close the prayer for the
rest of the day.

Errors: `QUIZ_NOT_FOUND` (404), `QUIZ_QUESTION_NOT_FOUND` (404), `QUIZ_QUESTION_ALREADY_ANSWERED`
(409), `QUIZ_QUESTION_NOT_STARTED` (409), `QUIZ_OPTION_INVALID` (400), `QUIZ_EXPIRED` (410),
`PRAYER_WINDOW_CLOSED` (409), `PRAYER_ALREADY_COMPLETED` (409).

### `POST /gamification/action` · `200`

```jsonc
{ "actionType": "STREAK_FREEZE", "clientRequestId": "optional, ≤ 128 chars" }
```

`STREAK_FREEZE` is currently the only member of `GamificationActionType`. Returns:

```jsonc
{
  "actionType": "STREAK_FREEZE",
  "streakFreezeUsage": {
    "currentStreak": 7,
    "longestStreak": 12,
    "freezesRemaining": 0,
    "protectedDates": ["2026-07-30"],
    "alreadyApplied": false,
  },
}
```

When the streak is broken (gap 2–3 days) the freeze protects the missed days and keeps the streak
running. When the user already restarted (gap ≤ 1) but a stored recovery exists, the freeze restores
the broken streak and **merges** it into the running one (`currentStreak` in the response is the
merged total). See [`DOMAIN.md` §5](DOMAIN.md#5-streaks).

Errors: `STREAK_NOT_FOUND` (404), `STREAK_NOT_AT_RISK` (409 — gap ≤ 1 day and no stored recovery),
`STREAK_FREEZE_WINDOW_EXPIRED` (409 — more than 3 days since the broken streak's last active day),
`NO_STREAK_FREEZE_AVAILABLE` (409), `UNKNOWN_GAMIFICATION_ACTION` (400).

> No code path ever grants a freeze (`streakFreezeCount` is only decremented), so in practice this
> returns `NO_STREAK_FREEZE_AVAILABLE` unless the row is edited directly.

---

## Users — `src/users/users.controller.ts`

Controller-level `JwtAuthGuard`; all routes require `JWT`.

### `GET /users/search?query=…&pageSize=…&cursor=…`

`query` non-empty; `pageSize` 1–50 (required); `cursor` ≥ 0 offset (optional, default 0).

```jsonc
{
  "users": [{
    "username": "…",
    "avatarCustomization": { },
    "isFollowing": false,
    "mutualFollowers": { "count": 2, "preview": [{ "username", "avatarCustomization" }] }
  }],
  "totalCount": 17,
  "nextCursor": 20   // null on the last page
}
```

Ranking tiers: exact username match → people you follow → friends-of-friends → everyone else, then
by similarity, then alphabetically.

`query` is escaped before it reaches Prisma's `contains` (`escapeLikePattern`: `\`, `%`, `_`), so
LIKE metacharacters are matched literally. Without it `_` was a single-character wildcard and
returned every user in the table; `%` returned everything too.

Similarity has two modes. At **3+ characters** it is the trigram **overlap coefficient**
(`|A ∩ B| / min(|A|,|B|)`); below that there are no trigrams to compare, so scoring falls back to
substring position and length. Candidates scoring under `SEARCH_MIN_SIMILARITY` (0.5) are dropped.

This replaced a Jaccard index with a `> 0.1` floor, which had two opposite failures: queries shorter
than 3 characters matched **nothing** (typing `qa` returned "hiçbir eşleşme bulamadık" with 17
matching users), while the low floor let unrelated names through (`qa_social` returned `qa_q1`). See
[`DOMAIN.md`](DOMAIN.md#user-search).

### `GET /users/me/stats`

Full statistics for the caller: level (with `xp`, `totalXp`, `currentLevelXp`, `xpToNextLevel`,
`totalXpForNextLevel`, `badgeKey`, `progressPercent`), streak (`current`, `longest`, `freezeCount`,
`lastActiveDate`), prayers (`totalCompleted`, per-type `breakdown`, a `punctuality` block,
`lastCompletedAt`, and a `quiz` block with `totalAttempts` / `passed` / `failed` /
`accuracyPercent`), and `social` counts.

```jsonc
"punctuality": {
  "onTime": 42,        // completions marked inside the prayer's own window
  "late": 8,           // completions marked as kaza
  "onTimePercent": 84, // onTime / (onTime + late), rounded; 0 when nothing is completed
}
```

`accuracyPercent` counts only `PASSED` + `FAILED` submissions; `PENDING` and `EXPIRED` are excluded.

`streak.lastActiveDate` is a **calendar day** (`"2026-07-31"`), not an instant — it is serialized
with `LocalDate.fromPersisted(...).toISO()` to match the `@db.Date` column it comes from.

### `GET /users/:username/stats`

The public subset: level (`level`, `badgeKey`, `progressPercent` only), streak (`current`,
`longest`), prayers (`totalCompleted`, `breakdown`, `punctuality`), `social`, and `isSelf`. Errors:
`USER_NOT_FOUND` (404).

---

## Leaderboard — `src/leaderboard/leaderboard.controller.ts`

### `GET /leaderboard` — `JWT`

Rankings. Replaced a hardcoded five-person list that the dashboard rendered as if it were real data.

| Query    | Values                            | Default    |
| -------- | --------------------------------- | ---------- |
| `metric` | `STREAK` · `XP` · `PRAYERS`       | `STREAK`   |
| `scope`  | `GLOBAL` · `CITY` · `FOLLOWING`   | `GLOBAL`   |
| `period` | `ALL_TIME` · `WEEKLY` · `MONTHLY` | `ALL_TIME` |
| `limit`  | 1–50                              | 10         |

`period` only affects `PRAYERS`; `XP` and `STREAK` are running totals with no per-period history.
`CITY` uses the caller's own `city`; `FOLLOWING` is the people they follow plus themselves.

```jsonc
{
  "metric": "STREAK",
  "scope": "GLOBAL",
  "period": "ALL_TIME",
  "city": null, // the board's city when scope = CITY
  "entries": [
    {
      "rank": 1,
      "username": "…",
      "city": "İstanbul", // city only — never coordinates
      "avatar": null,
      "avatarCustomization": {},
      "score": 7, // in the unit implied by metric
      "isCurrentUser": false,
    },
  ],
  "currentUser": { "rank": 12, "score": 3, "inTopList": false },
}
```

Each row carries only what `/users/:username/stats` already treats as public — no email, id,
coordinates or XP breakdown. `currentUser` is present even when the caller falls outside `entries`,
so the client can state their real standing instead of inventing one.

**`STREAK` is ranked in two passes.** `user_streaks.currentStreak` is the streak as of
`lastActiveDate`, not as of today, so ranking on the raw column would put abandoned accounts on top.
The indexed column selects a candidate window, then `evaluateStreakStatus()` re-evaluates each
candidate in their own timezone — the same function `/users/me/stats` uses — and broken streaks fall
to 0 and off the board. `XP` and `PRAYERS` rank entirely in SQL.

Errors: `USER_NOT_FOUND` (404), plus 400 `VALIDATION_ERROR` with `INVALID_LEADERBOARD_METRIC` /
`INVALID_LEADERBOARD_SCOPE` / `INVALID_LEADERBOARD_PERIOD` / `INVALID_LEADERBOARD_LIMIT`.

Adding a board later ("bu ay en çok XP", "İstanbul'da en çok seri") is a new enum member plus a
branch in `LeaderboardService` — not a new endpoint.

---

## Guides — `src/guides/guides.controller.ts`

### `GET /guides/:type` — —

`:type` ∈ `wudu`, `ghusl`, `fajr`, `dhuhr`, `asr`, `maghrib`, `isha`, `jumuah` (lowercase). **No
authentication.**

```jsonc
{
  "id": "fajr",
  "title": "Sabah Namazı",
  "totalSteps": 10,
  "totalRakats": 2,
  "sunnahBefore": 2, // optional; ablution guides omit them,
  // and `sunnahAfter` appears only where relevant
  "steps": [
    {
      "step": 1,
      "totalSteps": 10,
      "type": "takbir",
      "name": "Niyet ve Tekbir",
      "shortDescription": "…",
      "description": "…",
      "tips": ["…"],
      "recitation": "…",
      "isFard": true,
      "rekat": 1,
      "bodyPart": "Eller",
      "repeat": "3 kez", // ablution guides only
      "randomQuestion": null, // see below
    },
  ],
}
```

Content is static and in Turkish. With **80 % probability** one randomly chosen step carries a
`randomQuestion` drawn from the `scope = GUIDE` rows of `prayer_questions` for that guide:

```jsonc
{
  "id": "…",
  "question": "Abdest alırken organları sırayla yıkamaya ne denir?",
  "options": [{ "id": "…", "text": "Tertip" }], // isCorrect is never sent
}
```

Answers are checked via `POST /question/guide/check`. Errors: `GUIDE_NOT_FOUND` — **404** for an
unknown `:type` (the `ParseEnumPipe` used to surface a bare `BAD_REQUEST`, which is a status name
rather than a domain key).

---

## Questions — `src/questions/questions.controller.ts`

### `POST /question/guide/check` — —

`{ "questionId": "<uuid>", "optionId": "<uuid>" }` →
`{ "isCorrect": true, "correctOptionId": "<uuid>" }`.

Grading is an **option-id lookup**, not a text comparison — the old `toLocaleLowerCase('tr-TR')`
match is gone, so punctuation or whitespace drift in an option can no longer mark a correct answer
wrong. **No authentication**, and `correctOptionId` is returned on every call so the client can
highlight the right choice.

Errors:

| Status | `message`                        | When                                                      |
| ------ | -------------------------------- | --------------------------------------------------------- |
| `400`  | `QUIZ_OPTION_INVALID`            | `optionId` does not belong to `questionId`                |
| `404`  | `QUESTION_NOT_FOUND`             | no `scope = GUIDE` question with that id                  |
| `404`  | `QUESTION_HAS_NO_CORRECT_OPTION` | data defect — the question has no option with `isCorrect` |

> The guide check and the gamification quiz now share one table (`prayer_questions`, discriminated
> by `scope`) but remain separate **flows**: the guide check awards no XP, records no completion,
> and has no session tables. `PrayerQuizSubmission` / `PrayerQuizQuestion` stay quiz-session-only.

---

## Telemetry — `src/telemetry/telemetry.controller.ts`

### `POST /telemetry/client-errors` — — · `202` · throttled 10 req/min

Ingests a browser-side error report from the frontend and writes it to the server log as an
`error`-level `CLIENT_ERROR` line (see `ARCHITECTURE.md` → Logging). Nothing is stored in the
database; the response body is the envelope with `data: null`.

```json
{
  "message": "x is not a function",
  "source": "window_error",
  "stack": "TypeError: x is not a function\n  at …",
  "url": "/worship",
  "digest": "1234567890"
}
```

| Field     | Rules                                                                                                                  |
| --------- | ---------------------------------------------------------------------------------------------------------------------- |
| `message` | required, ≤ 500 chars                                                                                                  |
| `source`  | required, one of `window_error` `unhandled_rejection` `react_render_error`                                             |
| `stack`   | optional, ≤ 8000 chars                                                                                                 |
| `url`     | optional, ≤ 300 chars — the frontend sends the **path only** (no query/hash), so URL-borne tokens never reach the logs |
| `digest`  | optional, ≤ 100 chars — Next.js production error digest                                                                |

**No authentication** — client errors also occur for logged-out users and during broken auth flows;
the per-IP throttle is the abuse boundary. The `User-Agent` header is logged alongside the report.
Errors: `400 VALIDATION_ERROR` (missing/oversized/unknown fields), `429 TOO_MANY_REQUESTS`.
