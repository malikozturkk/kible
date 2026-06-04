import { DateTime } from 'luxon';
import type { CalculationMethodKey, MadhabKey } from '../constants/prayer-options.constants';

export type PrayerName = 'fajr' | 'sunrise' | 'dhuhr' | 'asr' | 'maghrib' | 'isha';

export interface PrayerEntry {
  key: PrayerName;
  time: DateTime;
}

export interface PrayerTimeDTO {
  time: string;
  iso: string | null;
  remainingSeconds: number;
  isNext: boolean;
  isPassed: boolean;
}

export interface MetaDTO {
  latitude: number;
  longitude: number;
  timezone: string;
  gregorianDate: string | null;
  hijriDate: string | null;
  hijriMonthName: string | null;
  calculationMethod: CalculationMethodKey;
  madhab: MadhabKey;
}

export type PrayerTimesRecord = Record<PrayerName, PrayerTimeDTO>;

export interface RamadanDTO {
  ramadanDay: number;
  totalDays: number;
  remainingDays: number;
}

export interface FastingDTO {
  isRamadan: boolean;
  isFastingTime: boolean;
  fastingStart: string | null;
  fastingEnd: string | null;
  remainingSeconds: number;
  progressPercent: number;
  ramadan: RamadanDTO | null;
}

export interface WorshipResponseDTO {
  meta: MetaDTO;
  times: PrayerTimesRecord;
  nextPrayer: PrayerName;
  nextPrayerAt: string | null;
  secondsUntilNext: number;
  lastPrayer: PrayerName;
  dayProgressPercent: number;
  fasting: FastingDTO;
}

export interface AdhanParams {
  userId: string;
  date: string;
}

export interface NextPrayerResult {
  name: PrayerName;
  time: DateTime;
  isTomorrow: boolean;
}
