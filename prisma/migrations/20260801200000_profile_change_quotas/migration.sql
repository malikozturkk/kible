-- One-time change quotas for location and madhab.
--
-- Location determines the timezone every prayer window is derived from. Without a cap a
-- user can miss Fajr in İstanbul, switch to a city several hours west where Fajr is still
-- inside its window, and mark it as ON_TIME. Existing users start at 0 so everyone keeps
-- exactly one change; completions already recorded are left untouched.
ALTER TABLE "users"
  ADD COLUMN "locationChangeCount" INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN "madhabChangeCount" INTEGER NOT NULL DEFAULT 0;
