-- Unify the two question banks.
--
-- `questions` (guide checks) is folded into `prayer_questions`, discriminated by
-- the new `scope` column. Rows keep their original id, so anything that already
-- referenced a guide question by id stays valid — and the seed, which derives
-- ids deterministically, upserts the very same rows instead of duplicating them.
--
-- The denormalized `options String[]` / `correctAnswer` pair becomes real
-- `prayer_question_options` rows, which removes the Turkish-locale text
-- comparison from the answer path.

-- ── 1. Schema ────────────────────────────────────────────────────────────────
CREATE TYPE "QuestionScope" AS ENUM ('PRAYER', 'GUIDE');

ALTER TABLE "prayer_questions"
  ADD COLUMN "scope" "QuestionScope" NOT NULL DEFAULT 'PRAYER',
  ADD COLUMN "guideId" TEXT;

CREATE INDEX "prayer_questions_scope_guideId_isActive_idx"
  ON "prayer_questions"("scope", "guideId", "isActive");

-- Lets the seed upsert an option by (question, position) instead of a synthetic id.
CREATE UNIQUE INDEX "prayer_question_options_questionId_orderIndex_key"
  ON "prayer_question_options"("questionId", "orderIndex");

-- ── 2. Data migration ────────────────────────────────────────────────────────
-- Guide questions carry no explanation and no prayerType; difficulty was
-- nullable there but is NOT NULL here, so it falls back to 1 (kolay).
INSERT INTO "prayer_questions"
  (id, prompt, explanation, scope, "prayerType", "guideId", difficulty, "isActive", "createdAt", "updatedAt")
SELECT
  q.id,
  q.question,
  NULL,
  'GUIDE',
  NULL,
  q."guideId",
  COALESCE(q.difficulty, 1),
  true,
  q."createdAt",
  NOW()
FROM "questions" q;

-- `WITH ORDINALITY` preserves the array order, so orderIndex mirrors the
-- position the options were authored in. Exactly one option matches
-- correctAnswer; the seed's validator guarantees that for future rows.
INSERT INTO "prayer_question_options"
  (id, "questionId", text, "isCorrect", "orderIndex", "createdAt")
SELECT
  gen_random_uuid(),
  q.id,
  opt.text,
  (opt.text = q."correctAnswer"),
  (opt.idx - 1)::int,
  NOW()
FROM "questions" q,
     LATERAL unnest(q.options) WITH ORDINALITY AS opt(text, idx);

-- ── 3. Drop the old table ────────────────────────────────────────────────────
DROP TABLE "questions";
