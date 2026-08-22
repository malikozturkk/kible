import { PrayerCategory, PrayerType } from '@prisma/client';

export const PRAYER_QUIZ_QUESTION_TIME_LIMIT_SECONDS = 25;
export const PRAYER_QUIZ_QUESTION_TIME_LIMIT_GRACE_SECONDS = 2;
export const PRAYER_QUIZ_EXPIRY_GRACE_MINUTES = 5;
export const PRAYER_QUIZ_QUESTION_COUNT = 3;
export const PRAYER_FIRST_OF_DAY_BONUS_XP = 10;
export const CONGREGATIONAL_MARK_WINDOW_MINUTES = 15;
export const PRAYER_HISTORY_MAX_RANGE_DAYS = 62;

export const PRAYER_XP_REWARDS: Record<PrayerType, number> = {
  FAJR: 20,
  DHUHR: 15,
  ASR: 15,
  MAGHRIB: 15,
  ISHA: 15,
  JUMUAH: 25,
  TARAWIH: 20,
  EID_FITR: 50,
  EID_ADHA: 50,
};

export function getPrayerBaseXp(type: PrayerType): number {
  return PRAYER_XP_REWARDS[type];
}

export const LATE_PRAYER_XP_MULTIPLIER = 0.5;

export function getLatePrayerXp(type: PrayerType): number {
  return Math.round(getPrayerBaseXp(type) * LATE_PRAYER_XP_MULTIPLIER);
}

export interface PrayerTypeMetadata {
  type: PrayerType;
  category: PrayerCategory;
  isObligatory: boolean;
}

export const PRAYER_TYPE_METADATA: Record<PrayerType, PrayerTypeMetadata> = {
  FAJR: { type: 'FAJR', category: 'DAILY', isObligatory: true },
  DHUHR: { type: 'DHUHR', category: 'DAILY', isObligatory: true },
  ASR: { type: 'ASR', category: 'DAILY', isObligatory: true },
  MAGHRIB: { type: 'MAGHRIB', category: 'DAILY', isObligatory: true },
  ISHA: { type: 'ISHA', category: 'DAILY', isObligatory: true },
  JUMUAH: { type: 'JUMUAH', category: 'WEEKLY', isObligatory: false },
  TARAWIH: { type: 'TARAWIH', category: 'RAMADAN', isObligatory: false },
  EID_FITR: { type: 'EID_FITR', category: 'EID', isObligatory: false },
  EID_ADHA: { type: 'EID_ADHA', category: 'EID', isObligatory: false },
};

export function getPrayerMetadata(type: PrayerType): PrayerTypeMetadata {
  return PRAYER_TYPE_METADATA[type];
}
