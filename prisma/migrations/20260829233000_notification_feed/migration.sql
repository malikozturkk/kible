-- AlterEnum
ALTER TYPE "NotificationDeliveryStatus" ADD VALUE 'NO_DEVICE';

-- AlterTable
-- Icerik sutunlari NOT NULL: bildirim akisinda basliksiz bir satir gosterilemez.
-- Mevcut satirlar bu alanlar eklenmeden once yazildigi icin gecici bir varsayilanla
-- doldurulur, ardindan varsayilan kaldirilir; yeni satirlarin icerigi acikca
-- yazilmak zorundadir.
ALTER TABLE "notification_deliveries" ADD COLUMN "title" TEXT NOT NULL DEFAULT '';
ALTER TABLE "notification_deliveries" ADD COLUMN "body" TEXT NOT NULL DEFAULT '';
ALTER TABLE "notification_deliveries" ADD COLUMN "url" TEXT NOT NULL DEFAULT '/';
ALTER TABLE "notification_deliveries" ADD COLUMN "readAt" TIMESTAMP(3);

ALTER TABLE "notification_deliveries" ALTER COLUMN "title" DROP DEFAULT;
ALTER TABLE "notification_deliveries" ALTER COLUMN "body" DROP DEFAULT;
ALTER TABLE "notification_deliveries" ALTER COLUMN "url" DROP DEFAULT;

-- CreateIndex
CREATE INDEX "notification_deliveries_userId_readAt_idx" ON "notification_deliveries"("userId", "readAt");
