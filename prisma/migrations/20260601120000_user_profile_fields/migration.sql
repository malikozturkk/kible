-- CreateEnum
CREATE TYPE "Madhab" AS ENUM ('SHAFI', 'HANAFI');

-- AlterTable
ALTER TABLE "users" ADD COLUMN     "country" TEXT,
ADD COLUMN     "city" TEXT,
ADD COLUMN     "latitude" DOUBLE PRECISION,
ADD COLUMN     "longitude" DOUBLE PRECISION,
ADD COLUMN     "madhab" "Madhab" NOT NULL DEFAULT 'SHAFI',
ADD COLUMN     "language" TEXT NOT NULL DEFAULT 'en';

-- AlterTable
ALTER TABLE "otp_verifications" ADD COLUMN     "gender" "Gender" NOT NULL DEFAULT 'MALE',
ADD COLUMN     "country" TEXT,
ADD COLUMN     "city" TEXT,
ADD COLUMN     "latitude" DOUBLE PRECISION,
ADD COLUMN     "longitude" DOUBLE PRECISION,
ADD COLUMN     "madhab" "Madhab" NOT NULL DEFAULT 'SHAFI',
ADD COLUMN     "language" TEXT NOT NULL DEFAULT 'en';
