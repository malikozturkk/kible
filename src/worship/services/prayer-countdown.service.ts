import { Injectable } from '@nestjs/common';
import { DateTime } from 'luxon';
import { PrayerEntry, PrayerName, NextPrayerResult } from '../types/prayer.types';

@Injectable()
export class PrayerCountdownService {
  resolveNextPrayer(
    entries: PrayerEntry[],
    now: DateTime,
    tomorrowFajr: DateTime,
  ): NextPrayerResult {
    for (const entry of entries) {
      if (entry.time > now) {
        return { name: entry.key, time: entry.time, isTomorrow: false };
      }
    }
    return { name: 'fajr', time: tomorrowFajr, isTomorrow: true };
  }

  resolveLastPrayer(entries: PrayerEntry[], now: DateTime): PrayerName {
    for (let i = entries.length - 1; i >= 0; i--) {
      if (entries[i].time <= now) {
        return entries[i].key;
      }
    }
    return 'isha';
  }

  secondsUntil(target: DateTime, now: DateTime): number {
    return Math.max(0, Math.floor(target.diff(now).as('seconds')));
  }

  nextOccurrence(entry: PrayerEntry, now: DateTime, tomorrowTime: DateTime): DateTime {
    return entry.time > now ? entry.time : tomorrowTime;
  }
}
