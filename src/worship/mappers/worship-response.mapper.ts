import { Injectable } from '@nestjs/common';
import { DateTime } from 'luxon';
import {
  PrayerEntry,
  PrayerTimeDTO,
  PrayerTimesRecord,
  NextPrayerResult,
} from '../types/prayer.types';
import { PrayerCountdownService } from '../services/prayer-countdown.service';

@Injectable()
export class WorshipResponseMapper {
  constructor(private readonly countdownService: PrayerCountdownService) {}

  buildTimesRecord(
    entries: PrayerEntry[],
    tomorrowEntries: PrayerEntry[],
    nextPrayer: NextPrayerResult,
    now: DateTime,
  ): PrayerTimesRecord {
    const record = {} as PrayerTimesRecord;
    const tomorrowByKey = new Map(tomorrowEntries.map((entry) => [entry.key, entry.time]));

    for (const entry of entries) {
      const tomorrowTime = tomorrowByKey.get(entry.key) ?? entry.time;
      const occurrence = this.countdownService.nextOccurrence(entry, now, tomorrowTime);

      const dto: PrayerTimeDTO = {
        time: entry.time.toFormat('HH:mm'),
        iso: entry.time.toISO(),
        remainingSeconds: this.countdownService.secondsUntil(occurrence, now),
        isNext: nextPrayer.time > now && nextPrayer.name === entry.key,
        isPassed: entry.time <= now,
      };

      record[entry.key] = dto;
    }

    return record;
  }
}
