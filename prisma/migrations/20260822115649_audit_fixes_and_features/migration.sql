/*
  Warnings:

  - The required column `familyId` was added to the `refresh_tokens` table with a prisma-level default value. This is not possible if the table is not empty. Please add this column as optional, then populate it before making it required.

*/
-- CreateEnum
CREATE TYPE "PasswordHashScheme" AS ENUM ('LEGACY_CONCAT', 'HMAC_BCRYPT');

-- CreateEnum
CREATE TYPE "QadaSource" AS ENUM ('AUTO_DETECTED', 'MANUAL_BACKLOG');

-- CreateEnum
CREATE TYPE "FastingStatus" AS ENUM ('FASTED', 'EXCUSED', 'MISSED');

-- CreateEnum
CREATE TYPE "NotificationTopic" AS ENUM ('PRAYER_TIME', 'MARK_WINDOW_CLOSING', 'STREAK_AT_RISK', 'QADA_REMINDER', 'RAMADAN_SUHOOR', 'RAMADAN_IFTAR');

-- CreateEnum
CREATE TYPE "NotificationDeliveryStatus" AS ENUM ('SENT', 'FAILED', 'SUBSCRIPTION_GONE');

-- AlterTable
ALTER TABLE "otp_verifications" ADD COLUMN     "failedAttempts" INTEGER NOT NULL DEFAULT 0;

-- AlterTable
-- NG-09: familyId önce nullable eklenir, mevcut satırlar kendi id'leriyle doldurulur
-- (her eski token kendi zincirinin kökü sayılır), sonra NOT NULL'a çevrilir.
ALTER TABLE "refresh_tokens" ADD COLUMN     "familyId" TEXT;
UPDATE "refresh_tokens" SET "familyId" = "id" WHERE "familyId" IS NULL;
ALTER TABLE "refresh_tokens" ALTER COLUMN "familyId" SET NOT NULL;

-- AlterTable
ALTER TABLE "user_consents" ADD COLUMN     "withdrawnAt" TIMESTAMP(3);

-- AlterTable
ALTER TABLE "user_credentials" ADD COLUMN     "hashScheme" "PasswordHashScheme" NOT NULL DEFAULT 'LEGACY_CONCAT';

-- CreateTable
CREATE TABLE "qada_ledgers" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "prayerType" "PrayerType" NOT NULL,
    "manualDebt" INTEGER NOT NULL DEFAULT 0,
    "manualFulfilled" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "qada_ledgers_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "qada_entries" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "prayerType" "PrayerType" NOT NULL,
    "missedDate" DATE NOT NULL,
    "source" "QadaSource" NOT NULL DEFAULT 'AUTO_DETECTED',
    "fulfilledAt" TIMESTAMP(3),
    "xpAwarded" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "qada_entries_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "fasting_days" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "fastDate" DATE NOT NULL,
    "status" "FastingStatus" NOT NULL DEFAULT 'FASTED',
    "xpAwarded" INTEGER NOT NULL DEFAULT 0,
    "hijriYear" INTEGER NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "fasting_days_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "push_subscriptions" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "endpoint" TEXT NOT NULL,
    "p256dh" TEXT NOT NULL,
    "auth" TEXT NOT NULL,
    "userAgent" TEXT,
    "failureCount" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "push_subscriptions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "notification_preferences" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "topic" "NotificationTopic" NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT false,
    "optedInAt" TIMESTAMP(3),
    "optedOutAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "notification_preferences_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "notification_deliveries" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "topic" "NotificationTopic" NOT NULL,
    "dedupeKey" TEXT NOT NULL,
    "status" "NotificationDeliveryStatus" NOT NULL,
    "sentAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "notification_deliveries_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "question_mastery" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "questionId" TEXT NOT NULL,
    "correctStreak" INTEGER NOT NULL DEFAULT 0,
    "totalCorrect" INTEGER NOT NULL DEFAULT 0,
    "totalWrong" INTEGER NOT NULL DEFAULT 0,
    "lastAnsweredAt" TIMESTAMP(3),
    "dueAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "question_mastery_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "qada_ledgers_userId_idx" ON "qada_ledgers"("userId");

-- CreateIndex
CREATE UNIQUE INDEX "qada_ledgers_userId_prayerType_key" ON "qada_ledgers"("userId", "prayerType");

-- CreateIndex
CREATE INDEX "qada_entries_userId_fulfilledAt_idx" ON "qada_entries"("userId", "fulfilledAt");

-- CreateIndex
CREATE INDEX "qada_entries_userId_missedDate_idx" ON "qada_entries"("userId", "missedDate");

-- CreateIndex
CREATE UNIQUE INDEX "qada_entries_userId_prayerType_missedDate_key" ON "qada_entries"("userId", "prayerType", "missedDate");

-- CreateIndex
CREATE INDEX "fasting_days_userId_hijriYear_idx" ON "fasting_days"("userId", "hijriYear");

-- CreateIndex
CREATE UNIQUE INDEX "fasting_days_userId_fastDate_key" ON "fasting_days"("userId", "fastDate");

-- CreateIndex
CREATE UNIQUE INDEX "push_subscriptions_endpoint_key" ON "push_subscriptions"("endpoint");

-- CreateIndex
CREATE INDEX "push_subscriptions_userId_idx" ON "push_subscriptions"("userId");

-- CreateIndex
CREATE INDEX "notification_preferences_userId_idx" ON "notification_preferences"("userId");

-- CreateIndex
CREATE UNIQUE INDEX "notification_preferences_userId_topic_key" ON "notification_preferences"("userId", "topic");

-- CreateIndex
CREATE INDEX "notification_deliveries_userId_sentAt_idx" ON "notification_deliveries"("userId", "sentAt");

-- CreateIndex
CREATE INDEX "notification_deliveries_sentAt_idx" ON "notification_deliveries"("sentAt");

-- CreateIndex
CREATE UNIQUE INDEX "notification_deliveries_userId_dedupeKey_key" ON "notification_deliveries"("userId", "dedupeKey");

-- CreateIndex
CREATE INDEX "question_mastery_userId_dueAt_idx" ON "question_mastery"("userId", "dueAt");

-- CreateIndex
CREATE UNIQUE INDEX "question_mastery_userId_questionId_key" ON "question_mastery"("userId", "questionId");

-- CreateIndex
CREATE INDEX "refresh_tokens_familyId_idx" ON "refresh_tokens"("familyId");

-- AddForeignKey
ALTER TABLE "qada_ledgers" ADD CONSTRAINT "qada_ledgers_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "qada_entries" ADD CONSTRAINT "qada_entries_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "fasting_days" ADD CONSTRAINT "fasting_days_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "push_subscriptions" ADD CONSTRAINT "push_subscriptions_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "notification_preferences" ADD CONSTRAINT "notification_preferences_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "notification_deliveries" ADD CONSTRAINT "notification_deliveries_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "question_mastery" ADD CONSTRAINT "question_mastery_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "question_mastery" ADD CONSTRAINT "question_mastery_questionId_fkey" FOREIGN KEY ("questionId") REFERENCES "prayer_questions"("id") ON DELETE CASCADE ON UPDATE CASCADE;
