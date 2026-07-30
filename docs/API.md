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
  "username": "malik_o", // ^[a-zA-Z0-9_]+$
  "email": "user@example.com",
  "password": "min8chars", // ≥ 8
  "gender": "MALE", // MALE | FEMALE
  "country": "Türkiye", // ≤ 64
  "city": "İstanbul", // ≤ 85
  "latitude": 41.0082, // -90..90, ≤ 8 decimals
  "longitude": 28.9784, // -180..180, ≤ 8 decimals
  "madhab": "HANAFI", // SHAFI | HANAFI
  "language": "tr", // ^[a-z]{2}(-[A-Z]{2})?$
  "termsAccepted": true, // must be exactly true
  "privacyPolicyAccepted": true, // must be exactly true
}
```

Returns `{ "tempToken": "<jwt>" }` — valid 10 minutes, carries `purpose: "register"`.

Errors: `USERNAME_ALREADY_EXISTS` (409), `USER_ALREADY_EXISTS` (409), `ACTIVE_REGISTRATION_EXISTS`
(409 — an unexpired pending registration already holds that email/username).

> The accepted consent **versions** are read from the server's `CONSENT_VERSION_*` env vars, not
> from the request. `termsAccepted` / `privacyPolicyAccepted` are validated but otherwise unused.

### `POST /auth/login` — — · `200`

`{ "identifier": "<email or username>", "password": "…" }` — the identifier is routed by an email
regex. Returns `{ accessToken, refreshToken, user }`.

Errors: `INVALID_CREDENTIALS` (401) for both unknown user and wrong password.

### `POST /auth/refresh` — — · `200`

`{ "refreshToken": "<64-hex>" }` → a new `{ accessToken, refreshToken, user }`. Errors:
`INVALID_OR_EXPIRED_REFRESH_TOKEN` (401).

> The presented refresh token is **not** revoked, so it remains usable until its 1-day expiry.

### `POST /auth/logout` — `JWT` · `200`

`{ "refreshToken": "…" }` → `null`. Marks that token `isRevoked`. Errors: `INVALID_REFRESH_TOKEN`
(401, also when the token belongs to another user), `TOKEN_ALREADY_INVALIDATED` (401),
`REFRESH_TOKEN_EXPIRED` (401).

### `GET /auth/:username` — `JWT`

Profile of `:username` as seen by the caller.

```jsonc
{
  "username": "…",
  "avatar": null,
  "createdAt": "…",
  "country": "…",
  "city": "…",
  "madhab": "SHAFI",
  "language": "tr",
  // owner only:
  "id": "…",
  "email": "…",
  "updatedAt": "…",
  "avatarCustomization": { "gender": "MALE", "colors": {}, "accessories": {} },
  "isFollowing": false, // null when viewing your own profile
  "followerCount": 0,
  "followingCount": 0,
  "mutualFollowers": { "count": 0, "preview": [/* ≤ 3 */] },
}
```

`id`, `email` and `updatedAt` are returned **only** when the caller is the profile owner. Errors:
`USER_NOT_FOUND` (404).

### `PATCH /auth/profile` — `JWT`

All fields optional; only the supplied ones change.

```jsonc
{
  "username": "new_name",
  "avatar": "…",
  "gender": "FEMALE", // stored on the avatar config
  "avatarColors": { "hair": "#2e1f14" }, // partial patch, each ^#[0-9A-Fa-f]{6}$
  "currentPassword": "…",
  "newPassword": "…", // both required together, new ≥ 8
  "language": "tr", // must be in SUPPORTED_LANGUAGES (only "tr")
}
```

Returns the updated user with `avatarCustomization`. Errors: `USERNAME_ALREADY_EXISTS` (409),
`PASSWORD_FIELDS_REQUIRED` (400), `INVALID_CURRENT_PASSWORD` (401).

Valid `avatarColors` keys: `iris`, `pupil`, `hair`, `skin`, `lips`, `nose`, `earInner`, `neck`,
`eyebrow`, `outfit`, `background`. Unset keys fall back to `DEFAULT_AVATAR_COLORS`.

### `POST /auth/forgot-password` — —

`{ "email": "…" }` → `{ "message": "FORGOT_PASSWORD_EMAIL_SENT" }`.

Returns success even for unknown emails (no account enumeration), but **does** return
`ACTIVE_RESET_EXISTS` (409) when an unused, unexpired reset already exists. The emailed link is
`${FRONTEND_BASE_URL}/reset-password?user_id=<id>&token=<raw>`, valid 30 minutes. If Mailjet fails
the reset row is deleted and `EMAIL_SEND_FAILED` (500) is returned.

### `POST /auth/validate-reset-token` — —

`{ "userId": "…", "token": "…" }` → `true`. Errors: `INVALID_OR_EXPIRED_TOKEN` (400),
`USER_NOT_FOUND` (401).

### `POST /auth/reset-password` — —

`{ "userId", "token", "newPassword" (≥ 8), "confirmPassword" }` → `null`. On success, in one
transaction: the password hash is replaced, `passwordUpdatedAt` is bumped, **all** of the user's
refresh tokens are revoked, and the reset row is marked used.

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

`{ "code": "123456" }` (exactly 6 digits). On success, atomically creates the `users` row plus its
`user_credentials`, `user_xp`, `user_streaks` and `user_avatar_configs` records and two
`user_consents` rows, deletes the pending registration, and returns
`{ accessToken, refreshToken, user }` — the same shape as login.

Errors: `MISSING_TOKEN` / `INVALID_TOKEN_PURPOSE` / `INVALID_OR_EXPIRED_TOKEN` (401),
`OTP_NOT_FOUND` (400), `REGISTRATION_EXPIRED` (400), `OTP_EXPIRED` (400), `INVALID_OTP_CODE` (400),
`USER_ALREADY_EXISTS` (409).

### `POST /otp/resend` — `TEMP` · `200`

No body. Issues a new code only if the current one has already expired **and** at least 3 minutes of
registration lifetime remain.

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
  ],
  "blocked": true,
}
```

### `POST /consent/accept` — `JWT` · `200` · throttled 10 req/min

`{ "type": "TERMS_OF_SERVICE" | "PRIVACY_POLICY", "version": "1.1.0" }` → `null`. The version must
equal the server's current version, otherwise `CONSENT_OUTDATED` (400). Re-accepting the same
version is a no-op (the `P2002` unique violation is swallowed).

Both routes carry `@ConsentBypass()`, so they stay reachable while a re-accept is pending.

---

## Worship — `src/worship/worship.controller.ts`

### `GET /worship?date=YYYY-MM-DD` — `JWT`

`date` is **required**. Coordinates, madhab and timezone all come from the authenticated user.

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
      "isNext": false,
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
today's has passed. Errors: `USER_NOT_FOUND` (400), `USER_LOCATION_NOT_SET` (400).

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
  "prayers": [
    {
      "type": "FAJR",
      "category": "DAILY",
      "isObligatory": true,
      "scheduledAt": "…",
      "windowStartsAt": "…",
      "windowEndsAt": "…",
      "xpReward": 20,
      "isCompleted": false,
      "canMarkAsCompleted": true, // not completed && not locked && now inside the window
      "completedAt": null,
      "streakContribution": false,
      "pendingQuizId": null, // id of an open PENDING quiz, if any
      "isLocked": false, // a FAILED/EXPIRED quiz exists for this prayer+date
    },
  ],
}
```

The slot list is day-dependent: `JUMUAH` replaces `DHUHR` on Fridays, `TARAWIH` is appended during
Ramadan, and `EID_FITR` / `EID_ADHA` are prepended on those days. See [`DOMAIN.md`](DOMAIN.md).

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
`PRAYER_WINDOW_CLOSED` (409), `PRAYER_ALREADY_COMPLETED` (409), `PRAYER_MARKING_LOCKED` (409),
`INSUFFICIENT_PRAYER_QUESTIONS` (503 — fewer than 3 active questions in the pool),
`USER_LOCATION_NOT_SET` (400).

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
    "xpAwarded": 25,
    "xpAfter": 310,
    "level": 3,
    "leveledUp": false,
    "streakAdvanced": true,
    "currentStreak": 5,
    "longestStreak": 12,
    "isFirstOfDay": true,
  },
}
```

An `INCORRECT` or `EXPIRED` answer sets `quizStatus: "FAILED"`, `isLocked: true`, locks every
remaining question, and blocks any further attempt at that prayer for the day.

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

Errors: `STREAK_NOT_FOUND` (404), `STREAK_NOT_AT_RISK` (409 — gap ≤ 1 day),
`STREAK_FREEZE_WINDOW_EXPIRED` (409 — gap > 3 days), `NO_STREAK_FREEZE_AVAILABLE` (409),
`UNKNOWN_GAMIFICATION_ACTION` (400).

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
by trigram similarity, then alphabetically. See the caveats in [`DOMAIN.md`](DOMAIN.md#user-search).

### `GET /users/me/stats`

Full statistics for the caller: level (with `xp`, `totalXp`, `currentLevelXp`, `xpToNextLevel`,
`totalXpForNextLevel`, `badgeKey`, `progressPercent`), streak (`current`, `longest`, `freezeCount`,
`lastActiveDate`), prayers (`totalCompleted`, per-type `breakdown`, `lastCompletedAt`, and a `quiz`
block with `totalAttempts` / `passed` / `failed` / `accuracyPercent`), and `social` counts.

`accuracyPercent` counts only `PASSED` + `FAILED` submissions; `PENDING` and `EXPIRED` are excluded.

### `GET /users/:username/stats`

The public subset: level (`level`, `badgeKey`, `progressPercent` only), streak (`current`,
`longest`), prayers (`totalCompleted`, `breakdown`), `social`, and `isSelf`. Errors:
`USER_NOT_FOUND` (404).

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
`randomQuestion` (`{ id, question, options }`) drawn from the `questions` table for that guide;
answers are checked via `POST /question/guide/check`. Errors: `GUIDE_NOT_FOUND` (400), plus 400 from
`ParseEnumPipe` for an unknown type.

---

## Questions — `src/questions/questions.controller.ts`

### `POST /question/guide/check` — —

`{ "questionId": "…", "answer": "…" }` → `{ "isCorrect": true, "correctAnswer": "…" }`. Comparison
is trimmed and lowercased with the Turkish locale (`toLocaleLowerCase('tr-TR')`), so `I`/`İ` behave
correctly. **No authentication**, and the correct answer is returned on every call.

Errors: `QUESTION_NOT_FOUND` (404).

> This is the free-text guide question flow, entirely separate from the `PrayerQuestion` /
> `PrayerQuizSubmission` tables used by the gamification quiz.
