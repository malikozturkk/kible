import { Injectable, BadRequestException } from '@nestjs/common';
import { DateTime } from 'luxon';
import { PrismaService } from '../prisma/prisma.service';
import { AdhanParams, WorshipResponseDTO } from './types/prayer.types';
import { PrayerTimeFactory } from './factories/prayer-time.factory';
import { PrayerCountdownService } from './services/prayer-countdown.service';
import { FastingProgressService } from './services/fasting-progress.service';
import { DayProgressService } from './services/day-progress.service';
import { WorshipResponseMapper } from './mappers/worship-response.mapper';
import { resolveTimezone } from '../common/utils/timezone.util';

@Injectable()
export class WorshipService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly prayerTimeFactory: PrayerTimeFactory,
    private readonly countdownService: PrayerCountdownService,
    private readonly fastingProgressService: FastingProgressService,
    private readonly dayProgressService: DayProgressService,
    private readonly responseMapper: WorshipResponseMapper,
  ) {}

  async adhan(params: AdhanParams): Promise<WorshipResponseDTO> {
    const { userId, date } = params;

    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { latitude: true, longitude: true, madhab: true },
    });

    if (!user) {
      throw new BadRequestException('USER_NOT_FOUND');
    }

    if (user.latitude === null || user.longitude === null) {
      throw new BadRequestException('USER_LOCATION_NOT_SET');
    }

    const latitude = user.latitude;
    const longitude = user.longitude;
    const madhab = user.madhab;
    const timezone = resolveTimezone(latitude, longitude);

    const zonedDate = DateTime.fromISO(date, { zone: timezone });
    const now = DateTime.now().setZone(timezone);

    const today = this.prayerTimeFactory.buildPrayerTimesWithMeta(
      latitude,
      longitude,
      zonedDate.toJSDate(),
      { madhab },
    );
    const tomorrow = this.prayerTimeFactory.buildPrayerTimesWithMeta(
      latitude,
      longitude,
      zonedDate.plus({ days: 1 }).toJSDate(),
      { madhab },
    );

    const todayPrayerTimes = today.prayerTimes;
    const tomorrowPrayerTimes = tomorrow.prayerTimes;

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
    const hijriLocale = 'tr-TR-u-ca-islamic-umalqura';
    const hijriFormatter = new Intl.DateTimeFormat(hijriLocale, {
      day: '2-digit',
      month: '2-digit',
      year: 'numeric',
    });
    const hijriMonthNameFormatter = new Intl.DateTimeFormat(hijriLocale, {
      month: 'long',
    });

    const hijriDate = hijriFormatter.format(zonedDate.toJSDate());
    const hijriMonthName = hijriMonthNameFormatter.format(zonedDate.toJSDate());

    return {
      meta: {
        latitude,
        longitude,
        timezone,
        gregorianDate: zonedDate.toISODate(),
        hijriDate,
        hijriMonthName,
        calculationMethod: today.method,
        madhab: today.madhab,
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
