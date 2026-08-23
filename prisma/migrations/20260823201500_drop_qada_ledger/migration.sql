-- AlterEnum
BEGIN;
CREATE TYPE "NotificationTopic_new" AS ENUM ('PRAYER_TIME', 'MARK_WINDOW_CLOSING', 'STREAK_AT_RISK', 'RAMADAN_SUHOOR', 'RAMADAN_IFTAR');
ALTER TABLE "notification_preferences" ALTER COLUMN "topic" TYPE "NotificationTopic_new" USING ("topic"::text::"NotificationTopic_new");
ALTER TABLE "notification_deliveries" ALTER COLUMN "topic" TYPE "NotificationTopic_new" USING ("topic"::text::"NotificationTopic_new");
ALTER TYPE "NotificationTopic" RENAME TO "NotificationTopic_old";
ALTER TYPE "NotificationTopic_new" RENAME TO "NotificationTopic";
DROP TYPE "public"."NotificationTopic_old";
COMMIT;

-- DropForeignKey
ALTER TABLE "qada_entries" DROP CONSTRAINT "qada_entries_userId_fkey";

-- DropForeignKey
ALTER TABLE "qada_ledgers" DROP CONSTRAINT "qada_ledgers_userId_fkey";

-- DropTable
DROP TABLE "qada_entries";

-- DropTable
DROP TABLE "qada_ledgers";

-- DropEnum
DROP TYPE "QadaSource";

