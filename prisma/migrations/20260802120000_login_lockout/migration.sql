ALTER TABLE "user_credentials"
  ADD COLUMN "failedLoginAttempts" INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN "lockedUntil" TIMESTAMP(3);
  
ALTER TABLE "users" ADD COLUMN "usernameUpdatedAt" TIMESTAMP(3);

