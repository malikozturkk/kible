import { LocalDate } from '../../common/utils/local-date';
import { STREAK_FREEZE_MAX_GAP_DAYS } from '../constants/streak.constants';

export interface StreakSnapshot {
  currentStreak: number;
  longestStreak: number;
  streakFreezeCount: number;
  lastActiveDate: Date | null;
}

export interface StreakStatus {
  currentStreak: number;
  longestStreak: number;
  freezesAvailable: number;
  lastActiveDate: string | null;
  daysSinceLastActive: number | null;
  isBroken: boolean;
  recoverableStreak: number;
  atRisk: boolean;
  canFreezeNow: boolean;
  freezeWindowExpired: boolean;
}

const IDLE_STATUS: StreakStatus = {
  currentStreak: 0,
  longestStreak: 0,
  freezesAvailable: 0,
  lastActiveDate: null,
  daysSinceLastActive: null,
  isBroken: false,
  recoverableStreak: 0,
  atRisk: false,
  canFreezeNow: false,
  freezeWindowExpired: false,
};

export function evaluateStreakStatus(
  snapshot: StreakSnapshot | null,
  today: LocalDate,
): StreakStatus {
  if (!snapshot) return IDLE_STATUS;

  const base = {
    longestStreak: snapshot.longestStreak,
    freezesAvailable: snapshot.streakFreezeCount,
  };

  if (!snapshot.lastActiveDate || snapshot.currentStreak <= 0) {
    return {
      ...IDLE_STATUS,
      ...base,
      lastActiveDate: snapshot.lastActiveDate
        ? LocalDate.fromPersisted(snapshot.lastActiveDate).toISO()
        : null,
    };
  }

  const lastActive = LocalDate.fromPersisted(snapshot.lastActiveDate);
  const gap = lastActive.daysUntil(today);
  const isBroken = gap >= 2;
  const freezeWindowExpired = isBroken && gap > STREAK_FREEZE_MAX_GAP_DAYS;

  return {
    ...base,
    currentStreak: isBroken ? 0 : snapshot.currentStreak,
    lastActiveDate: lastActive.toISO(),
    daysSinceLastActive: gap,
    isBroken,
    recoverableStreak: isBroken ? snapshot.currentStreak : 0,
    atRisk: gap === 1,
    canFreezeNow: isBroken && !freezeWindowExpired && snapshot.streakFreezeCount > 0,
    freezeWindowExpired,
  };
}
