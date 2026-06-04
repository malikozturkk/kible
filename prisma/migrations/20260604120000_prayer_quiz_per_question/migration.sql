-- CreateEnum
CREATE TYPE "PrayerQuizQuestionStatus" AS ENUM ('PENDING', 'SHOWN', 'CORRECT', 'INCORRECT', 'EXPIRED', 'LOCKED');

-- CreateTable
CREATE TABLE "prayer_quiz_questions" (
    "id" TEXT NOT NULL,
    "submissionId" TEXT NOT NULL,
    "questionId" TEXT NOT NULL,
    "orderIndex" INTEGER NOT NULL,
    "timeLimitSeconds" INTEGER NOT NULL,
    "shownAt" TIMESTAMP(3),
    "deadlineAt" TIMESTAMP(3),
    "answeredAt" TIMESTAMP(3),
    "selectedOptionId" TEXT,
    "isCorrect" BOOLEAN,
    "status" "PrayerQuizQuestionStatus" NOT NULL DEFAULT 'PENDING',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "prayer_quiz_questions_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "prayer_quiz_questions_submissionId_questionId_key" ON "prayer_quiz_questions"("submissionId", "questionId");

-- CreateIndex
CREATE INDEX "prayer_quiz_questions_submissionId_status_idx" ON "prayer_quiz_questions"("submissionId", "status");

-- AddForeignKey
ALTER TABLE "prayer_quiz_questions" ADD CONSTRAINT "prayer_quiz_questions_submissionId_fkey" FOREIGN KEY ("submissionId") REFERENCES "prayer_quiz_submissions"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "prayer_quiz_questions" ADD CONSTRAINT "prayer_quiz_questions_questionId_fkey" FOREIGN KEY ("questionId") REFERENCES "prayer_questions"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
