import { HttpStatus, Injectable, Logger } from '@nestjs/common';
import { Prisma, PrayerType } from '@prisma/client';
import { DateTime } from 'luxon';
import { PrismaService } from '../../prisma/prisma.service';
import { BusinessException } from '../../common/exceptions/business.exception';
import { LocalDate } from '../../common/utils/local-date';
import { StreakService } from './streak.service';
import { XpService } from './xp.service';
import { PrayerScheduleService } from './prayer-schedule.service';
import { PrayerQuizService } from './prayer-quiz.service';
import { PRAYER_FIRST_OF_DAY_BONUS_XP } from '../constants/prayer.constants';
import { isWithinWindow } from '../helpers/prayer-schedule.helper';
import { PrayerScheduleParams } from '../types/gamification.types';
import { PrayerCompletionResultDto } from '../dto/gamification-action.dto';

@Injectable()
export class PrayerCompletionService {
  private readonly logger = new Logger(PrayerCompletionService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly scheduleService: PrayerScheduleService,
    private readonly quizService: PrayerQuizService,
    private readonly streakService: StreakService,
    private readonly xpService: XpService,
  ) {}

  async completeFromPassedQuiz(
    userId: string,
    quizId: string,
    prayerType: PrayerType,
  ): Promise<PrayerCompletionResultDto> {
    const config = await this.scheduleService.getUserPrayerConfig(userId);
    const timezone = config.timezone;
    const now = DateTime.now().setZone(timezone);

    const params: PrayerScheduleParams = {
      userId,
      latitude: config.latitude,
      longitude: config.longitude,
      date: now.toISODate()!,
      timezone,
      madhab: config.madhab,
    };
    const { slot, zonedDate } = this.scheduleService.resolveSlot(params, prayerType);

    if (!isWithinWindow(slot, now)) {
      throw new BusinessException('PRAYER_WINDOW_CLOSED', HttpStatus.CONFLICT);
    }

    const localDate = LocalDate.fromInstant(zonedDate, timezone);
    const prayerDate = localDate.toUtcMidnight();

    const preexisting = await this.prisma.prayerCompletion.findUnique({
      where: {
        userId_prayerType_prayerDate: { userId, prayerType, prayerDate },
      },
      select: { id: true },
    });
    if (preexisting) {
      throw new BusinessException('PRAYER_ALREADY_COMPLETED', HttpStatus.CONFLICT);
    }

    try {
      return await this.prisma.$transaction(async (tx) => {
        await this.streakService.lockStreakRow(tx, userId);

        const existingCount = await tx.prayerCompletion.count({
          where: { userId, prayerDate },
        });
        const isFirstOfDay = existingCount === 0;
        const baseXp = slot.xpReward;
        const xpAwarded = isFirstOfDay ? baseXp + PRAYER_FIRST_OF_DAY_BONUS_XP : baseXp;

        const completion = await tx.prayerCompletion.create({
          data: {
            userId,
            prayerType,
            prayerDate,
            completedAt: now.toJSDate(),
            timezone,
            xpAwarded,
            isFirstOfDay,
            streakContributed: false,
            streakFreezeApplied: false,
          },
        });

        let streakAdvanced = false;
        let currentStreak: number;
        let longestStreak: number;
        if (isFirstOfDay) {
          const streakResult = await this.streakService.registerDailyActivity(
            tx,
            userId,
            localDate,
          );
          streakAdvanced = streakResult.streakAdvanced;
          currentStreak = streakResult.currentStreak;
          longestStreak = streakResult.longestStreak;

          if (streakAdvanced) {
            await tx.prayerCompletion.update({
              where: { id: completion.id },
              data: { streakContributed: true },
            });
          }
        } else {
          const current = await tx.userStreak.findUnique({ where: { userId } });
          currentStreak = current?.currentStreak ?? 0;
          longestStreak = current?.longestStreak ?? 0;
        }

        await this.updateStats(tx, userId, prayerType, now);
        const xpResult = await this.xpService.award(tx, userId, xpAwarded);
        await this.quizService.markPassed(tx, quizId, completion.id);

        return {
          prayerCompletionId: completion.id,
          prayerType: completion.prayerType,
          prayerDate: localDate.toISO(),
          completedAt: completion.completedAt.toISOString(),
          xpAwarded,
          xpAfter: xpResult.xp,
          level: xpResult.level,
          leveledUp: xpResult.leveledUp,
          streakAdvanced,
          currentStreak,
          longestStreak,
          isFirstOfDay,
        };
      });
    } catch (e) {
      if (e instanceof Prisma.PrismaClientKnownRequestError && e.code === 'P2002') {
        throw new BusinessException('PRAYER_ALREADY_COMPLETED', HttpStatus.CONFLICT);
      }
      throw e;
    }
  }

  private async updateStats(
    tx: Prisma.TransactionClient,
    userId: string,
    prayerType: PrayerType,
    now: DateTime,
  ): Promise<void> {
    const typeField = this.statsFieldFor(prayerType);

    await tx.userPrayerStats.upsert({
      where: { userId },
      create: {
        userId,
        totalCompleted: 1,
        totalFajr: prayerType === 'FAJR' ? 1 : 0,
        totalDhuhr: prayerType === 'DHUHR' ? 1 : 0,
        totalAsr: prayerType === 'ASR' ? 1 : 0,
        totalMaghrib: prayerType === 'MAGHRIB' ? 1 : 0,
        totalIsha: prayerType === 'ISHA' ? 1 : 0,
        totalJumuah: prayerType === 'JUMUAH' ? 1 : 0,
        totalTarawih: prayerType === 'TARAWIH' ? 1 : 0,
        totalEidFitr: prayerType === 'EID_FITR' ? 1 : 0,
        totalEidAdha: prayerType === 'EID_ADHA' ? 1 : 0,
        lastCompletedAt: now.toJSDate(),
      },
      update: {
        totalCompleted: { increment: 1 },
        [typeField]: { increment: 1 },
        lastCompletedAt: now.toJSDate(),
      },
    });
  }

  private statsFieldFor(type: PrayerType): string {
    switch (type) {
      case 'FAJR':
        return 'totalFajr';
      case 'DHUHR':
        return 'totalDhuhr';
      case 'ASR':
        return 'totalAsr';
      case 'MAGHRIB':
        return 'totalMaghrib';
      case 'ISHA':
        return 'totalIsha';
      case 'JUMUAH':
        return 'totalJumuah';
      case 'TARAWIH':
        return 'totalTarawih';
      case 'EID_FITR':
        return 'totalEidFitr';
      case 'EID_ADHA':
        return 'totalEidAdha';
      default:
        throw new BusinessException('UNKNOWN_PRAYER_TYPE', HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }
}
