import { HttpStatus, Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { PrismaService } from '../../prisma/prisma.service';
import { BusinessException } from '../../common/exceptions/business.exception';
import { LocalDate } from '../../common/utils/local-date';
import { StreakRiskAssessmentDto } from '../dto/streak-risk.dto';
import { StreakFreezeUsageResultDto } from '../dto/streak-freeze-result.dto';
import { STREAK_FREEZE_MAX_GAP_DAYS } from '../constants/streak.constants';
import { evaluateStreakStatus } from '../domain/streak-status';

export interface StreakActivityResult {
  currentStreak: number;
  longestStreak: number;
  streakAdvanced: boolean;
  streakReset: boolean;
}

@Injectable()
export class StreakService {
  constructor(private readonly prisma: PrismaService) {}

  async inspectStreakRisk(userId: string, today: LocalDate): Promise<StreakRiskAssessmentDto> {
    const [streak, lastFreeze] = await Promise.all([
      this.prisma.userStreak.findUnique({ where: { userId } }),
      this.prisma.streakFreezeUsage.findFirst({
        where: { userId },
        orderBy: { protectedDate: 'desc' },
        select: { protectedDate: true },
      }),
    ]);

    return {
      ...evaluateStreakStatus(streak, today),
      lastFreezeUsedAt: lastFreeze
        ? LocalDate.fromPersisted(lastFreeze.protectedDate).toISO()
        : null,
    };
  }

  async registerDailyActivity(
    tx: Prisma.TransactionClient,
    userId: string,
    today: LocalDate,
  ): Promise<StreakActivityResult> {
    const streak = await tx.userStreak.upsert({
      where: { userId },
      update: {},
      create: {
        userId,
        currentStreak: 0,
        longestStreak: 0,
        streakFreezeCount: 0,
        lastActiveDate: null,
      },
    });

    const lastActive = streak.lastActiveDate
      ? LocalDate.fromPersisted(streak.lastActiveDate)
      : null;

    let nextStreak: number;
    let streakAdvanced: boolean;
    let streakReset = false;

    if (!lastActive) {
      nextStreak = 1;
      streakAdvanced = true;
    } else {
      const gap = lastActive.daysUntil(today);
      if (gap <= 0) {
        return {
          currentStreak: streak.currentStreak,
          longestStreak: streak.longestStreak,
          streakAdvanced: false,
          streakReset: false,
        };
      } else if (gap === 1) {
        nextStreak = streak.currentStreak + 1;
        streakAdvanced = true;
      } else {
        nextStreak = 1;
        streakAdvanced = true;
        streakReset = streak.currentStreak > 0;
      }
    }

    const longestStreak = Math.max(streak.longestStreak, nextStreak);

    const updated = await tx.userStreak.update({
      where: { userId },
      data: {
        currentStreak: nextStreak,
        longestStreak,
        lastActiveDate: today.toUtcMidnight(),
      },
    });

    return {
      currentStreak: updated.currentStreak,
      longestStreak: updated.longestStreak,
      streakAdvanced,
      streakReset,
    };
  }

  async useStreakFreeze(userId: string, today: LocalDate): Promise<StreakFreezeUsageResultDto> {
    return this.prisma.$transaction(
      async (tx) => {
        await this.lockStreakRow(tx, userId);

        const streak = await tx.userStreak.findUnique({ where: { userId } });
        if (!streak) {
          throw new BusinessException('STREAK_NOT_FOUND', HttpStatus.NOT_FOUND);
        }

        if (!streak.lastActiveDate || streak.currentStreak === 0) {
          throw new BusinessException('STREAK_NOT_AT_RISK', HttpStatus.CONFLICT);
        }

        const lastActive = LocalDate.fromPersisted(streak.lastActiveDate);
        const gap = lastActive.daysUntil(today);

        if (gap <= 1) {
          throw new BusinessException('STREAK_NOT_AT_RISK', HttpStatus.CONFLICT);
        }
        if (gap > STREAK_FREEZE_MAX_GAP_DAYS) {
          throw new BusinessException('STREAK_FREEZE_WINDOW_EXPIRED', HttpStatus.CONFLICT);
        }

        const protectedDays: LocalDate[] = [];
        for (let i = 1; i < gap; i++) protectedDays.push(lastActive.plusDays(i));

        const alreadyProtected = await tx.streakFreezeUsage.findMany({
          where: {
            userId,
            protectedDate: { in: protectedDays.map((d) => d.toUtcMidnight()) },
          },
          select: { protectedDate: true },
        });
        const allAlreadyProtected = alreadyProtected.length === protectedDays.length;

        if (!allAlreadyProtected) {
          if (streak.streakFreezeCount < 1) {
            throw new BusinessException('NO_STREAK_FREEZE_AVAILABLE', HttpStatus.CONFLICT);
          }

          for (const day of protectedDays) {
            await tx.streakFreezeUsage.upsert({
              where: {
                userId_protectedDate: {
                  userId,
                  protectedDate: day.toUtcMidnight(),
                },
              },
              update: {},
              create: {
                userId,
                protectedDate: day.toUtcMidnight(),
                reason: 'USER_INITIATED',
              },
            });
          }

          await tx.userStreak.update({
            where: { userId },
            data: {
              streakFreezeCount: streak.streakFreezeCount - 1,
              lastActiveDate: today.minusDays(1).toUtcMidnight(),
            },
          });
        }

        const refreshed = await tx.userStreak.findUniqueOrThrow({ where: { userId } });

        return {
          currentStreak: refreshed.currentStreak,
          longestStreak: refreshed.longestStreak,
          freezesRemaining: refreshed.streakFreezeCount,
          protectedDates: protectedDays.map((d) => d.toISO()),
          alreadyApplied: allAlreadyProtected,
        };
      },
      { isolationLevel: Prisma.TransactionIsolationLevel.Serializable },
    );
  }

  async lockStreakRow(tx: Prisma.TransactionClient, userId: string): Promise<void> {
    await tx.userStreak.upsert({
      where: { userId },
      update: {},
      create: {
        userId,
        currentStreak: 0,
        longestStreak: 0,
        streakFreezeCount: 0,
      },
    });
    await tx.$executeRaw`SELECT id FROM "user_streaks" WHERE "userId" = ${userId} FOR UPDATE`;
  }
}
