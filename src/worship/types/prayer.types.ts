import { DateTime } from 'luxon';

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
  date: string | null;
  calculationMethod: string;
  madhab: string;
}

export type PrayerTimesRecord = Record<PrayerName, PrayerTimeDTO>;

export interface WorshipResponseDTO {
  meta: MetaDTO;
  times: PrayerTimesRecord;
  nextPrayer: PrayerName;
  nextPrayerAt: string | null;
  secondsUntilNext: number;
  lastPrayer: PrayerName;
  dayProgressPercent: number;
  fastingProgress: number | null;
}

export interface AdhanParams {
  latitude: number;
  longitude: number;
  date: string;
  timezone: string;
}

export interface NextPrayerResult {
  name: PrayerName;
  time: DateTime;
  isTomorrow: boolean;
}
