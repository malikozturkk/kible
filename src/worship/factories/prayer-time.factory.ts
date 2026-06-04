import { Injectable } from '@nestjs/common';
import { Coordinates, CalculationMethod, PrayerTimes, Madhab, HighLatitudeRule } from 'adhan';
import { DateTime } from 'luxon';
import { PrayerEntry, PrayerName } from '../types/prayer.types';
import {
  CalculationMethodKey,
  DEFAULT_CALCULATION_METHOD,
  DEFAULT_MADHAB,
  MadhabKey,
  resolveAdhanSelection,
} from '../constants/prayer-options.constants';

export interface BuildPrayerTimesOptions {
  method?: string;
  madhab?: string;
}

export interface BuiltPrayerTimes {
  prayerTimes: PrayerTimes;
  method: CalculationMethodKey;
  madhab: MadhabKey;
}

@Injectable()
export class PrayerTimeFactory {
  private buildCalculationParams(method: CalculationMethodKey, madhab: MadhabKey) {
    const factory = CalculationMethod[method] ?? CalculationMethod[DEFAULT_CALCULATION_METHOD];
    const params = factory();
    params.madhab = Madhab[madhab] ?? Madhab[DEFAULT_MADHAB];
    params.highLatitudeRule = HighLatitudeRule.MiddleOfTheNight;
    return params;
  }

  buildPrayerTimes(
    latitude: number,
    longitude: number,
    date: Date,
    options: BuildPrayerTimesOptions = {},
  ): PrayerTimes {
    return this.buildPrayerTimesWithMeta(latitude, longitude, date, options).prayerTimes;
  }

  buildPrayerTimesWithMeta(
    latitude: number,
    longitude: number,
    date: Date,
    options: BuildPrayerTimesOptions = {},
  ): BuiltPrayerTimes {
    const { method, madhab } = resolveAdhanSelection(options.method, options.madhab);
    const coordinates = new Coordinates(latitude, longitude);
    const params = this.buildCalculationParams(method, madhab);
    return {
      prayerTimes: new PrayerTimes(coordinates, date, params),
      method,
      madhab,
    };
  }

  toPrayerEntries(prayerTimes: PrayerTimes, timezone: string): PrayerEntry[] {
    const toZoned = (d: Date): DateTime => DateTime.fromJSDate(d, { zone: timezone });
    const keys: PrayerName[] = ['fajr', 'sunrise', 'dhuhr', 'asr', 'maghrib', 'isha'];
    return keys.map((key) => ({ key, time: toZoned(prayerTimes[key]) }));
  }
}
