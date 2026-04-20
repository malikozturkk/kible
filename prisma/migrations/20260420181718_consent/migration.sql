-- DropIndex
DROP INDEX "idx_users_username_trgm";

-- AlterTable
ALTER TABLE "otp_verifications" ALTER COLUMN "termsVersion" DROP DEFAULT,
ALTER COLUMN "privacyPolicyVersion" DROP DEFAULT;
