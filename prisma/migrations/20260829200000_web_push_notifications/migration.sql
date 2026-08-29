-- NotificationTopic: Ramazan başlıkları (RAMADAN_SUHOOR, RAMADAN_IFTAR) kaldırıldı,
-- NEW_FOLLOWER eklendi. İki eski değer hiçbir satırda kullanılmamıştı.
-- fasting_days ve question_mastery: hiç yazan olmayan, boş özellik tabloları.

-- AlterEnum
BEGIN;
CREATE TYPE "NotificationTopic_new" AS ENUM ('PRAYER_TIME', 'MARK_WINDOW_CLOSING', 'STREAK_AT_RISK', 'NEW_FOLLOWER');
ALTER TABLE "notification_preferences" ALTER COLUMN "topic" TYPE "NotificationTopic_new" USING ("topic"::text::"NotificationTopic_new");
ALTER TABLE "notification_deliveries" ALTER COLUMN "topic" TYPE "NotificationTopic_new" USING ("topic"::text::"NotificationTopic_new");
ALTER TYPE "NotificationTopic" RENAME TO "NotificationTopic_old";
ALTER TYPE "NotificationTopic_new" RENAME TO "NotificationTopic";
DROP TYPE "public"."NotificationTopic_old";
COMMIT;

-- DropForeignKey
ALTER TABLE "fasting_days" DROP CONSTRAINT "fasting_days_userId_fkey";

-- DropForeignKey
ALTER TABLE "question_mastery" DROP CONSTRAINT "question_mastery_questionId_fkey";

-- DropForeignKey
ALTER TABLE "question_mastery" DROP CONSTRAINT "question_mastery_userId_fkey";

-- DropTable
DROP TABLE "fasting_days";

-- DropTable
DROP TABLE "question_mastery";

-- DropEnum
DROP TYPE "FastingStatus";

