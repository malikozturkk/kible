import { DateTime } from 'luxon';
import { PrayerType, PrayerCategory, Madhab } from '@prisma/client';

export interface PrayerSlot {
  type: PrayerType;
  category: PrayerCategory;
  scheduledAt: DateTime;
  windowStartsAt: DateTime;
  windowEndsAt: DateTime;
  xpReward: number;
  isObligatory: boolean;
}

export interface UserPrayerConfig {
  latitude: number;
  longitude: number;
  madhab: Madhab;
  timezone: string;
}

export interface PrayerViewRequest {
  userId: string;
  date?: string;
}

export interface PrayerScheduleParams {
  userId: string;
  latitude: number;
  longitude: number;
  date: string;
  timezone: string;
  madhab: Madhab;
}
