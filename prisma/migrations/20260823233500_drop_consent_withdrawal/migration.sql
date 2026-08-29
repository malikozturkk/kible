-- Açık rıza geri çekme özelliği üründen kaldırıldı: rızasını geri almak isteyen
-- kullanıcı hesabını siler (DELETE /auth/me). Kolonun tek yazarı olan
-- POST /consent/withdraw ucu da bu değişiklikte silindiği için okuyanı kalmadı.
-- Bırakılan denetim izi kaybı yok: kolon hiçbir satırda dolu değildi.

-- AlterTable
ALTER TABLE "user_consents" DROP COLUMN "withdrawnAt";
