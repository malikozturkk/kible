-- KVKK m.6 uyumu: mezhep + ibadet kayıtları için ayrı açık rıza türü.
-- otp_verifications geçici bir tablodur (satır ömrü <= 10 dk); NOT NULL kolon
-- eklenebilmesi için bekleyen kayıt taslakları temizlenir. Kullanıcı verisi silinmez —
-- etkilenen kayıtlar yalnızca henüz tamamlanmamış, süreli kayıt denemeleridir.

-- AlterEnum
ALTER TYPE "ConsentType" ADD VALUE 'SPECIAL_CATEGORY_DATA';

-- Clear transient registration drafts so the new NOT NULL column can be added safely
DELETE FROM "otp_verifications";

-- AlterTable
ALTER TABLE "otp_verifications" ADD COLUMN "specialCategoryVersion" TEXT NOT NULL;
