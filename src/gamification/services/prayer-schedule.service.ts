import { HttpStatus, Injectable } from '@nestjs/common';
import { PrayerType } from '@prisma/client';
import { DateTime } from 'luxon';
import { PrismaService } from '../../prisma/prisma.service';
import { PrayerTimeFactory } from '../../worship/factories/prayer-time.factory';
import { BusinessException } from '../../common/exceptions/business.exception';
import { LocalDate } from '../../common/utils/local-date';
import { PrayerSlot, PrayerScheduleParams } from '../types/gamification.types';
import { buildPrayerSlots, isWithinWindow } from '../helpers/prayer-schedule.helper';
import { toHijri, isRamadan, isEidFitr, isEidAdha, isFriday } from '../helpers/hijri.helper';
import { DailyPrayersResponseDto, PrayerCardDto } from '../dto/daily-prayers.dto';

@Injectable()
export class PrayerScheduleService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly prayerTimeFactory: PrayerTimeFactory,
  ) {}

  buildSlots(params: PrayerScheduleParams): {
    slots: PrayerSlot[];
    zonedDate: DateTime;
    isFriday: boolean;
    isRamadan: boolean;
    isEidDay: boolean;
  } {
    const { latitude, longitude, date, timezone, method, madhab } = params;

    const zonedDate = DateTime.fromISO(date, { zone: timezone });
    if (!zonedDate.isValid) {
      throw new BusinessException('INVALID_DATE_OR_TIMEZONE', HttpStatus.BAD_REQUEST);
    }

    const built = this.prayerTimeFactory.buildPrayerTimesWithMeta(
      latitude,
      longitude,
      zonedDate.toJSDate(),
      { method, madhab },
    );

    const hijri = toHijri(zonedDate.startOf('day').toJSDate());

    const slots = buildPrayerSlots({
      todayPrayerTimes: built.prayerTimes,
      zonedDate,
      timezone,
      hijri,
    });

    return {
      slots,
      zonedDate,
      isFriday: isFriday(zonedDate),
      isRamadan: isRamadan(hijri),
      isEidDay: isEidFitr(hijri) || isEidAdha(hijri),
    };
  }

  resolveSlot(
    params: PrayerScheduleParams,
    prayerType: PrayerType,
  ): { slot: PrayerSlot; zonedDate: DateTime } {
    const { slots, zonedDate } = this.buildSlots(params);
    const slot = slots.find((s) => s.type === prayerType);
    if (!slot) {
      throw new BusinessException('PRAYER_NOT_AVAILABLE_TODAY', HttpStatus.NOT_FOUND);
    }
    return { slot, zonedDate };
  }

  async getDailyView(params: PrayerScheduleParams): Promise<DailyPrayersResponseDto> {
    const { userId, timezone } = params;
    const {
      slots,
      zonedDate,
      isFriday: friday,
      isRamadan: ramadan,
      isEidDay,
    } = this.buildSlots(params);
    const localDate = LocalDate.fromInstant(zonedDate, timezone);
    const now = DateTime.now().setZone(timezone);

    const [completions, pendingQuizzes] = await Promise.all([
      this.prisma.prayerCompletion.findMany({
        where: { userId, prayerDate: localDate.toUtcMidnight() },
      }),
      this.prisma.prayerQuizSubmission.findMany({
        where: {
          userId,
          prayerDate: localDate.toUtcMidnight(),
          status: 'PENDING',
        },
        select: { id: true, prayerType: true, expiresAt: true },
      }),
    ]);

    const completionByType = new Map(completions.map((c) => [c.prayerType, c]));
    const pendingQuizByType = new Map(
      pendingQuizzes.filter((q) => q.expiresAt > new Date()).map((q) => [q.prayerType, q]),
    );

    const cards: PrayerCardDto[] = slots.map((slot) => {
      const completion = completionByType.get(slot.type);
      const isCompleted = Boolean(completion);
      const inWindow = isWithinWindow(slot, now);
      const pending = pendingQuizByType.get(slot.type);

      return {
        type: slot.type,
        category: slot.category,
        isObligatory: slot.isObligatory,
        scheduledAt: slot.scheduledAt.toISO()!,
        windowStartsAt: slot.windowStartsAt.toISO()!,
        windowEndsAt: slot.windowEndsAt.toISO()!,
        xpReward: slot.xpReward,
        isCompleted,
        canMarkAsCompleted: !isCompleted && inWindow,
        completedAt: completion?.completedAt?.toISOString() ?? null,
        streakContribution: completion?.streakContributed ?? false,
        pendingQuizId: pending?.id ?? null,
      };
    });

    return {
      date: localDate.toISO(),
      timezone,
      isFriday: friday,
      isRamadan: ramadan,
      isEidDay,
      prayers: cards,
    };
  }
}
