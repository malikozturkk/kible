import { Injectable } from '@nestjs/common';
import { Coordinates, CalculationMethod, PrayerTimes, Madhab, HighLatitudeRule } from 'adhan';
import { DateTime } from 'luxon';
import { PrayerEntry, PrayerName } from '../types/prayer.types';

@Injectable()
export class PrayerTimeFactory {
    private buildCalculationParams() {
        const params = CalculationMethod.Turkey();
        params.madhab = Madhab.Shafi;
        params.highLatitudeRule = HighLatitudeRule.MiddleOfTheNight;
        return params;
    }

    buildPrayerTimes(latitude: number, longitude: number, date: Date): PrayerTimes {
        const coordinates = new Coordinates(latitude, longitude);
        const params = this.buildCalculationParams();
        return new PrayerTimes(coordinates, date, params);
    }

    toPrayerEntries(prayerTimes: PrayerTimes, timezone: string): PrayerEntry[] {
        const toZoned = (d: Date): DateTime => DateTime.fromJSDate(d, { zone: timezone });
        const keys: PrayerName[] = ['fajr', 'sunrise', 'dhuhr', 'asr', 'maghrib', 'isha'];
        return keys.map((key) => ({ key, time: toZoned(prayerTimes[key]) }));
    }
}
