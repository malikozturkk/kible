import { Injectable } from '@nestjs/common';
import { Coordinates, CalculationMethod, HighLatitudeRule, PrayerTimes } from 'adhan';
import { DateTime } from 'luxon';
import type { Madhab as UserMadhab } from '@prisma/client';
import { PrayerEntry, PrayerName } from '../types/prayer.types';
import {
  DEFAULT_PRAYER_CALCULATION_PROFILE,
  PrayerCalculationProfile,
  resolvePrayerCalculationProfile,
  toAdhanMadhab,
} from '../constants/prayer-calculation.constants';

export const PRAYER_NAMES: readonly PrayerName[] = [
  'fajr',
  'sunrise',
  'dhuhr',
  'asr',
  'maghrib',
  'isha',
];

export interface PrayerTimesInput {
  latitude: number;
  longitude: number;
  date: DateTime;
  timezone: string;
  madhab?: UserMadhab | null;
}

export interface PrayerDayTimes {
  profile: PrayerCalculationProfile;
  timezone: string;
  date: DateTime;
  entries: PrayerEntry[];
  tomorrowEntries: PrayerEntry[];
  prayerTimes: PrayerTimes;
  tomorrowPrayerTimes: PrayerTimes;
}

@Injectable()
export class PrayerTimesService {
  getDay(input: PrayerTimesInput): PrayerDayTimes {
    const { latitude, longitude, date, timezone } = input;
    const profile = resolvePrayerCalculationProfile(input.madhab);

    const prayerTimes = this.compute(latitude, longitude, date, profile);
    const tomorrowPrayerTimes = this.compute(latitude, longitude, date.plus({ days: 1 }), profile);

    return {
      profile,
      timezone,
      date,
      entries: this.toEntries(prayerTimes, timezone),
      tomorrowEntries: this.toEntries(tomorrowPrayerTimes, timezone),
      prayerTimes,
      tomorrowPrayerTimes,
    };
  }

  private compute(
    latitude: number,
    longitude: number,
    date: DateTime,
    profile: PrayerCalculationProfile,
  ): PrayerTimes {
    const factory =
      CalculationMethod[profile.method] ??
      CalculationMethod[DEFAULT_PRAYER_CALCULATION_PROFILE.method];
    const params = factory();
    params.madhab = toAdhanMadhab(profile.asrShadowRatio);
    params.highLatitudeRule = HighLatitudeRule.MiddleOfTheNight;

    return new PrayerTimes(new Coordinates(latitude, longitude), date.toJSDate(), params);
  }

  private toEntries(prayerTimes: PrayerTimes, timezone: string): PrayerEntry[] {
    return PRAYER_NAMES.map((key) => ({
      key,
      time: DateTime.fromJSDate(prayerTimes[key], { zone: timezone }),
    }));
  }
}
