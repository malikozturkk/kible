-- AlterTable: gender lives with avatar customization (1:1)
ALTER TABLE "user_avatar_configs"
ADD COLUMN "gender" "Gender" NOT NULL DEFAULT 'MALE';

-- Sync existing avatar rows from users.gender
UPDATE "user_avatar_configs" uac
SET "gender" = u."gender"
FROM "users" u
WHERE u."id" = uac."userId";

-- Users without an avatar config row: create one so gender is not lost before users.gender is dropped
INSERT INTO "user_avatar_configs" ("id", "userId", "gender", "colors", "accessories", "createdAt", "updatedAt")
SELECT
  gen_random_uuid()::text,
  u."id",
  u."gender",
  '{}'::jsonb,
  '{}'::jsonb,
  CURRENT_TIMESTAMP,
  CURRENT_TIMESTAMP
FROM "users" u
WHERE NOT EXISTS (
  SELECT 1 FROM "user_avatar_configs" uac WHERE uac."userId" = u."id"
);

-- AlterTable
ALTER TABLE "users" DROP COLUMN "gender";
