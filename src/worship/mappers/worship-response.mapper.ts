import { Injectable } from '@nestjs/common';
import { DateTime } from 'luxon';
import {
  PrayerEntry,
  PrayerTimeDTO,
  PrayerTimesRecord,
  NextPrayerResult,
} from '../types/prayer.types';
import { PrayerTimes } from 'adhan';
import { PrayerCountdownService } from '../services/prayer-countdown.service';

@Injectable()
export class WorshipResponseMapper {
  constructor(private readonly countdownService: PrayerCountdownService) {}

  buildTimesRecord(
    entries: PrayerEntry[],
    tomorrowPrayerTimes: PrayerTimes,
    nextPrayer: NextPrayerResult,
    now: DateTime,
    timezone: string,
  ): PrayerTimesRecord {
    const record = {} as PrayerTimesRecord;

    for (const entry of entries) {
      const tomorrowJs: Date = tomorrowPrayerTimes[entry.key];
      const tomorrowDt = DateTime.fromJSDate(tomorrowJs, { zone: timezone });
      const occurrence = this.countdownService.nextOccurrence(entry, now, tomorrowDt);

      const dto: PrayerTimeDTO = {
        time: DateTime.fromJSDate(entry.time.toJSDate(), { zone: timezone }).toFormat('HH:mm'),
        iso: entry.time.toISO(),
        remainingSeconds: this.countdownService.secondsUntil(occurrence, now),
        isNext: !nextPrayer.isTomorrow && nextPrayer.name === entry.key,
        isPassed: entry.time <= now,
      };

      record[entry.key] = dto;
    }

    return record;
  }
}
