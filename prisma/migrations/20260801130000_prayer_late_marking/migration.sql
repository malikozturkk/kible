-- CreateEnum
CREATE TYPE "PrayerCompletionStatus" AS ENUM ('ON_TIME', 'LATE');

-- AlterTable: prayer_completions
-- Every pre-existing completion was only markable inside its own window, so ON_TIME
-- is the correct backfill and xpBeforePenalty equals the XP that was actually awarded.
ALTER TABLE "prayer_completions"
  ADD COLUMN "status" "PrayerCompletionStatus" NOT NULL DEFAULT 'ON_TIME',
  ADD COLUMN "xpBeforePenalty" INTEGER NOT NULL DEFAULT 0;

UPDATE "prayer_completions" SET "xpBeforePenalty" = "xpAwarded" WHERE "xpBeforePenalty" = 0;

-- CreateIndex
CREATE INDEX "prayer_completions_userId_status_idx" ON "prayer_completions"("userId", "status");

-- AlterTable: prayer_quiz_submissions
-- Old rows had no kaza window; their mark cutoff was the end of the prayer's own window.
ALTER TABLE "prayer_quiz_submissions" ADD COLUMN "markWindowEndsAt" TIMESTAMP(3);
UPDATE "prayer_quiz_submissions" SET "markWindowEndsAt" = "windowEndsAt" WHERE "markWindowEndsAt" IS NULL;
ALTER TABLE "prayer_quiz_submissions" ALTER COLUMN "markWindowEndsAt" SET NOT NULL;

-- AlterTable: user_prayer_stats
ALTER TABLE "user_prayer_stats"
  ADD COLUMN "totalOnTime" INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN "totalLate" INTEGER NOT NULL DEFAULT 0;

-- Backfill the on-time counter from the aggregate: all historical completions are ON_TIME.
UPDATE "user_prayer_stats" SET "totalOnTime" = "totalCompleted" WHERE "totalOnTime" = 0;
