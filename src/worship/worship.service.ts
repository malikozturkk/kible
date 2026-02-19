import { Injectable } from '@nestjs/common';
import { DateTime } from 'luxon';
import { AdhanParams, WorshipResponseDTO } from './types/prayer.types';
import { PrayerTimeFactory } from './factories/prayer-time.factory';
import { PrayerCountdownService } from './services/prayer-countdown.service';
import { FastingProgressService } from './services/fasting-progress.service';
import { DayProgressService } from './services/day-progress.service';
import { WorshipResponseMapper } from './mappers/worship-response.mapper';

@Injectable()
export class WorshipService {
  constructor(
    private readonly prayerTimeFactory: PrayerTimeFactory,
    private readonly countdownService: PrayerCountdownService,
    private readonly fastingProgressService: FastingProgressService,
    private readonly dayProgressService: DayProgressService,
    private readonly responseMapper: WorshipResponseMapper,
  ) {}

  async adhan(params: AdhanParams): Promise<WorshipResponseDTO> {
    const { latitude, longitude, date, timezone } = params;

    const zonedDate = DateTime.fromISO(date, { zone: timezone });
    const now = DateTime.now().setZone(timezone);

    const todayPrayerTimes = this.prayerTimeFactory.buildPrayerTimes(
      latitude,
      longitude,
      zonedDate.toJSDate(),
    );
    const tomorrowPrayerTimes = this.prayerTimeFactory.buildPrayerTimes(
      latitude,
      longitude,
      zonedDate.plus({ days: 1 }).toJSDate(),
    );

    const entries = this.prayerTimeFactory.toPrayerEntries(todayPrayerTimes, timezone);
    const tomorrowFajr = DateTime.fromJSDate(tomorrowPrayerTimes.fajr, { zone: timezone });

    const nextPrayer = this.countdownService.resolveNextPrayer(entries, now, tomorrowFajr);
    const lastPrayer = this.countdownService.resolveLastPrayer(entries, now);
    const secondsUntilNext = this.countdownService.secondsUntil(nextPrayer.time, now);

    const fajrEntry = entries.find((e) => e.key === 'fajr')!;
    const maghribEntry = entries.find((e) => e.key === 'maghrib')!;
    const fasting = this.fastingProgressService.calculate(fajrEntry.time, maghribEntry.time, now);

    const dayProgressPercent = this.dayProgressService.calculate(now);

    const times = this.responseMapper.buildTimesRecord(
      entries,
      tomorrowPrayerTimes,
      nextPrayer,
      now,
      timezone,
    );

    return {
      meta: {
        latitude,
        longitude,
        timezone,
        date: zonedDate.toISODate(),
        calculationMethod: 'Turkey',
        madhab: 'Shafi',
      },
      times,
      nextPrayer: nextPrayer.name,
      nextPrayerAt: nextPrayer.time.toISO(),
      secondsUntilNext,
      lastPrayer,
      dayProgressPercent,
      fasting,
    };
  }
}
