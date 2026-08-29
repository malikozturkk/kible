import { Injectable, BadRequestException } from '@nestjs/common';
import { DateTime } from 'luxon';
import { PrismaService } from '../prisma/prisma.service';
import { AdhanParams, WorshipResponseDTO } from './types/prayer.types';
import { PrayerTimesService } from './services/prayer-times.service';
import { PrayerCountdownService } from './services/prayer-countdown.service';
import { FastingProgressService } from './services/fasting-progress.service';
import { DayProgressService } from './services/day-progress.service';
import { WorshipResponseMapper } from './mappers/worship-response.mapper';
import { resolveTimezone } from '../common/utils/timezone.util';
import { toHijriLabel } from '../gamification/helpers/hijri.helper';

@Injectable()
export class WorshipService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly prayerTimesService: PrayerTimesService,
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
    const timezone = resolveTimezone(latitude, longitude);

    const zonedDate = DateTime.fromISO(date, { zone: timezone });
    const now = DateTime.now().setZone(timezone);

    const day = this.prayerTimesService.getDay({
      latitude,
      longitude,
      date: zonedDate,
      timezone,
      madhab: user.madhab,
    });

    const entries = day.entries;
    const tomorrowFajr = day.tomorrowEntries.find((e) => e.key === 'fajr')!.time;

    const nextPrayer = this.countdownService.resolveNextPrayer(entries, now, tomorrowFajr);
    const lastPrayer = this.countdownService.resolveLastPrayer(entries, now);
    const secondsUntilNext = this.countdownService.secondsUntil(nextPrayer.time, now);

    const fajrEntry = entries.find((e) => e.key === 'fajr')!;
    const maghribEntry = entries.find((e) => e.key === 'maghrib')!;
    const fasting = this.fastingProgressService.calculate(fajrEntry.time, maghribEntry.time, now);

    const dayProgressPercent = this.dayProgressService.calculate(now);

    const times = this.responseMapper.buildTimesRecord(
      entries,
      day.tomorrowEntries,
      nextPrayer,
      now,
    );
    const hijri = toHijriLabel(zonedDate);

    return {
      meta: {
        latitude,
        longitude,
        timezone,
        gregorianDate: zonedDate.toISODate(),
        hijriDate: hijri.date,
        hijriMonthName: hijri.monthName,
        calculationMethod: day.profile.method,
        calculationProfile: day.profile.key,
        asrShadowRatio: day.profile.asrShadowRatio,
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
