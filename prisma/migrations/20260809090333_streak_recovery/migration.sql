-- AlterTable
ALTER TABLE "user_streaks" ADD COLUMN     "brokenSinceDate" DATE,
ADD COLUMN     "recoverableStreak" INTEGER NOT NULL DEFAULT 0;
