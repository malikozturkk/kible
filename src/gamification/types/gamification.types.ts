import { DateTime } from 'luxon';
import { PrayerType, PrayerCategory } from '@prisma/client';

export interface PrayerSlot {
  type: PrayerType;
  category: PrayerCategory;
  scheduledAt: DateTime;
  windowStartsAt: DateTime;
  windowEndsAt: DateTime;
  xpReward: number;
  isObligatory: boolean;
}

export interface PrayerScheduleParams {
  userId: string;
  latitude: number;
  longitude: number;
  date: string;
  timezone: string;
  method?: string;
  madhab?: string;
}
