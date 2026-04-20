-- CreateEnum
CREATE TYPE "ConsentType" AS ENUM ('TERMS_OF_SERVICE', 'PRIVACY_POLICY');

-- AlterTable: OtpVerification - add consent version columns
ALTER TABLE "otp_verifications" ADD COLUMN "termsVersion" TEXT NOT NULL DEFAULT '1.0';
ALTER TABLE "otp_verifications" ADD COLUMN "privacyPolicyVersion" TEXT NOT NULL DEFAULT '1.0';

-- CreateTable
CREATE TABLE "user_consents" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "type" "ConsentType" NOT NULL,
    "version" TEXT NOT NULL,
    "acceptedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "user_consents_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "user_consents_userId_idx" ON "user_consents"("userId");

-- CreateUniqueIndex
CREATE UNIQUE INDEX "user_consents_userId_type_version_key" ON "user_consents"("userId", "type", "version");

-- AddForeignKey
ALTER TABLE "user_consents" ADD CONSTRAINT "user_consents_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;
