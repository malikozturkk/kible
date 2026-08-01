import { HttpStatus, Injectable } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import { BusinessException } from '../../common/exceptions/business.exception';
import { LocalDate } from '../../common/utils/local-date';
import { PRAYER_HISTORY_MAX_RANGE_DAYS } from '../constants/prayer.constants';
import { PrayerHistoryDayDto, PrayerHistoryResponseDto } from '../dto/prayer-history.dto';
import { PrayerScheduleService } from './prayer-schedule.service';

@Injectable()
export class PrayerHistoryService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly scheduleService: PrayerScheduleService,
  ) {}

  async getHistory(userId: string, from: string, to: string): Promise<PrayerHistoryResponseDto> {
    const config = await this.scheduleService.getUserPrayerConfig(userId);
    const timezone = config.timezone;

    const fromDate = this.parse(from);
    const requestedTo = this.parse(to);

    if (fromDate.daysUntil(requestedTo) < 0) {
      throw new BusinessException('INVALID_DATE_RANGE', HttpStatus.BAD_REQUEST);
    }
    if (fromDate.daysUntil(requestedTo) + 1 > PRAYER_HISTORY_MAX_RANGE_DAYS) {
      throw new BusinessException('PRAYER_HISTORY_RANGE_TOO_LARGE', HttpStatus.BAD_REQUEST);
    }

    const today = LocalDate.todayIn(timezone);
    const lastDate = requestedTo.daysUntil(today) < 0 ? today : requestedTo;

    if (fromDate.daysUntil(lastDate) < 0) {
      return { from: fromDate.toISO(), to: fromDate.toISO(), timezone, days: [] };
    }

    const [completions, freezes] = await Promise.all([
      this.prisma.prayerCompletion.groupBy({
        by: ['prayerDate'],
        where: {
          userId,
          prayerDate: { gte: fromDate.toUtcMidnight(), lte: lastDate.toUtcMidnight() },
        },
        _count: { _all: true },
      }),
      this.prisma.streakFreezeUsage.findMany({
        where: {
          userId,
          protectedDate: { gte: fromDate.toUtcMidnight(), lte: lastDate.toUtcMidnight() },
        },
        select: { protectedDate: true },
      }),
    ]);

    const completedByDate = new Map(
      completions.map((row) => [LocalDate.fromPersisted(row.prayerDate).toISO(), row._count._all]),
    );
    const frozenDates = new Set(
      freezes.map((row) => LocalDate.fromPersisted(row.protectedDate).toISO()),
    );

    const days: PrayerHistoryDayDto[] = [];
    for (let cursor = fromDate; cursor.daysUntil(lastDate) >= 0; cursor = cursor.plusDays(1)) {
      const date = cursor.toISO();
      const { slots } = this.scheduleService.buildSlots({
        userId,
        latitude: config.latitude,
        longitude: config.longitude,
        date,
        timezone,
        madhab: config.madhab,
      });
      const totalCount = slots.length;
      const completedCount = completedByDate.get(date) ?? 0;

      days.push({
        date,
        completedCount,
        totalCount,
        isComplete: totalCount > 0 && completedCount >= totalCount,
        isFrozen: frozenDates.has(date),
      });
    }

    return { from: fromDate.toISO(), to: lastDate.toISO(), timezone, days };
  }

  private parse(value: string): LocalDate {
    try {
      return LocalDate.fromISO(value);
    } catch {
      throw new BusinessException('INVALID_DATE_RANGE', HttpStatus.BAD_REQUEST);
    }
  }
}
