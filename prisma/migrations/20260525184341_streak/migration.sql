-- CreateEnum
CREATE TYPE "PrayerType" AS ENUM ('FAJR', 'DHUHR', 'ASR', 'MAGHRIB', 'ISHA', 'JUMUAH', 'TARAWIH', 'EID_FITR', 'EID_ADHA');

-- CreateEnum
CREATE TYPE "PrayerCategory" AS ENUM ('DAILY', 'WEEKLY', 'RAMADAN', 'EID');

-- CreateEnum
CREATE TYPE "PrayerQuizStatus" AS ENUM ('PENDING', 'PASSED', 'FAILED', 'EXPIRED');

-- CreateEnum
CREATE TYPE "StreakFreezeReason" AS ENUM ('USER_INITIATED');

-- CreateTable
CREATE TABLE "prayer_questions" (
    "id" TEXT NOT NULL,
    "prompt" TEXT NOT NULL,
    "explanation" TEXT,
    "prayerType" "PrayerType",
    "difficulty" INTEGER NOT NULL DEFAULT 1,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "prayer_questions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "prayer_question_options" (
    "id" TEXT NOT NULL,
    "questionId" TEXT NOT NULL,
    "text" TEXT NOT NULL,
    "isCorrect" BOOLEAN NOT NULL DEFAULT false,
    "orderIndex" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "prayer_question_options_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "prayer_quiz_submissions" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "prayerType" "PrayerType" NOT NULL,
    "prayerDate" DATE NOT NULL,
    "timezone" TEXT NOT NULL,
    "questionIds" TEXT[],
    "windowStartsAt" TIMESTAMP(3) NOT NULL,
    "windowEndsAt" TIMESTAMP(3) NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "status" "PrayerQuizStatus" NOT NULL DEFAULT 'PENDING',
    "attemptCount" INTEGER NOT NULL DEFAULT 0,
    "submittedAt" TIMESTAMP(3),
    "prayerCompletionId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "prayer_quiz_submissions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "prayer_completions" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "prayerType" "PrayerType" NOT NULL,
    "prayerDate" DATE NOT NULL,
    "completedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "timezone" TEXT NOT NULL,
    "xpAwarded" INTEGER NOT NULL,
    "isFirstOfDay" BOOLEAN NOT NULL DEFAULT false,
    "streakContributed" BOOLEAN NOT NULL DEFAULT false,
    "streakFreezeApplied" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "prayer_completions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "user_prayer_stats" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "totalCompleted" INTEGER NOT NULL DEFAULT 0,
    "totalFajr" INTEGER NOT NULL DEFAULT 0,
    "totalDhuhr" INTEGER NOT NULL DEFAULT 0,
    "totalAsr" INTEGER NOT NULL DEFAULT 0,
    "totalMaghrib" INTEGER NOT NULL DEFAULT 0,
    "totalIsha" INTEGER NOT NULL DEFAULT 0,
    "totalJumuah" INTEGER NOT NULL DEFAULT 0,
    "totalTarawih" INTEGER NOT NULL DEFAULT 0,
    "totalEidFitr" INTEGER NOT NULL DEFAULT 0,
    "totalEidAdha" INTEGER NOT NULL DEFAULT 0,
    "lastCompletedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "user_prayer_stats_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "streak_freeze_usages" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "protectedDate" DATE NOT NULL,
    "usedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "reason" "StreakFreezeReason" NOT NULL DEFAULT 'USER_INITIATED',

    CONSTRAINT "streak_freeze_usages_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "prayer_questions_prayerType_isActive_idx" ON "prayer_questions"("prayerType", "isActive");

-- CreateIndex
CREATE INDEX "prayer_questions_isActive_idx" ON "prayer_questions"("isActive");

-- CreateIndex
CREATE INDEX "prayer_question_options_questionId_idx" ON "prayer_question_options"("questionId");

-- CreateIndex
CREATE UNIQUE INDEX "prayer_quiz_submissions_prayerCompletionId_key" ON "prayer_quiz_submissions"("prayerCompletionId");

-- CreateIndex
CREATE INDEX "prayer_quiz_submissions_userId_prayerDate_idx" ON "prayer_quiz_submissions"("userId", "prayerDate");

-- CreateIndex
CREATE INDEX "prayer_quiz_submissions_userId_status_idx" ON "prayer_quiz_submissions"("userId", "status");

-- CreateIndex
CREATE INDEX "prayer_quiz_submissions_userId_prayerType_prayerDate_idx" ON "prayer_quiz_submissions"("userId", "prayerType", "prayerDate");

-- CreateIndex
CREATE INDEX "prayer_completions_userId_prayerDate_idx" ON "prayer_completions"("userId", "prayerDate");

-- CreateIndex
CREATE INDEX "prayer_completions_userId_completedAt_idx" ON "prayer_completions"("userId", "completedAt");

-- CreateIndex
CREATE UNIQUE INDEX "prayer_completions_userId_prayerType_prayerDate_key" ON "prayer_completions"("userId", "prayerType", "prayerDate");

-- CreateIndex
CREATE UNIQUE INDEX "user_prayer_stats_userId_key" ON "user_prayer_stats"("userId");

-- CreateIndex
CREATE INDEX "streak_freeze_usages_userId_usedAt_idx" ON "streak_freeze_usages"("userId", "usedAt");

-- CreateIndex
CREATE UNIQUE INDEX "streak_freeze_usages_userId_protectedDate_key" ON "streak_freeze_usages"("userId", "protectedDate");

-- AddForeignKey
ALTER TABLE "prayer_question_options" ADD CONSTRAINT "prayer_question_options_questionId_fkey" FOREIGN KEY ("questionId") REFERENCES "prayer_questions"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "prayer_quiz_submissions" ADD CONSTRAINT "prayer_quiz_submissions_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "prayer_quiz_submissions" ADD CONSTRAINT "prayer_quiz_submissions_prayerCompletionId_fkey" FOREIGN KEY ("prayerCompletionId") REFERENCES "prayer_completions"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "prayer_completions" ADD CONSTRAINT "prayer_completions_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "user_prayer_stats" ADD CONSTRAINT "user_prayer_stats_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "streak_freeze_usages" ADD CONSTRAINT "streak_freeze_usages_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;
