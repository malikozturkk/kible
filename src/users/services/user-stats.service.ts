import { Injectable, NotFoundException } from '@nestjs/common';
import { DateTime } from 'luxon';
import { PrismaService } from '../../prisma/prisma.service';
import { LevelCalculator } from '../../gamification/domain/level-calculator';
import { evaluateStreakStatus } from '../../gamification/domain/streak-status';
import { LocalDate } from '../../common/utils/local-date';
import { DEFAULT_TIMEZONE, resolveTimezone } from '../../common/utils/timezone.util';
import { resolveAvatarCustomizationFromDb } from '../../auth/utils/avatar-config.util';
import {
  PrayerBreakdownDto,
  PublicStatsResponseDto,
  PunctualityStatsDto,
  SelfStatsResponseDto,
} from '../dto/user-stats.dto';

@Injectable()
export class UserStatsService {
  constructor(private readonly prisma: PrismaService) {}

  async getSelfStats(userId: string): Promise<SelfStatsResponseDto> {
    const [user, xpRow, streakRow, prayerStats, followerCount, followingCount, quizCounts] =
      await Promise.all([
        this.prisma.user.findUnique({
          where: { id: userId },
          select: {
            username: true,
            createdAt: true,
            latitude: true,
            longitude: true,
            avatarConfig: { select: { colors: true, accessories: true, gender: true } },
          },
        }),
        this.prisma.userXp.findUnique({ where: { userId } }),
        this.prisma.userStreak.findUnique({ where: { userId } }),
        this.prisma.userPrayerStats.findUnique({ where: { userId } }),
        this.prisma.follow.count({ where: { followingId: userId } }),
        this.prisma.follow.count({ where: { followerId: userId } }),
        this.prisma.prayerQuizSubmission.groupBy({
          by: ['status'],
          where: { userId },
          _count: { _all: true },
        }),
      ]);

    if (!user) {
      throw new NotFoundException('USER_NOT_FOUND');
    }

    const xpValue = xpRow?.xp ?? 0;
    const totalXp = xpRow?.totalXp ?? 0;
    const levelView = LevelCalculator.computeLevelFromXp(xpValue);
    const streakStatus = evaluateStreakStatus(streakRow, this.resolveToday(user));

    const passed = this.pickCount(quizCounts, 'PASSED');
    const failed = this.pickCount(quizCounts, 'FAILED');
    const totalAttempts = passed + failed;
    const accuracyPercent = totalAttempts === 0 ? 0 : Math.round((passed / totalAttempts) * 100);

    return {
      username: user.username,
      avatarCustomization: resolveAvatarCustomizationFromDb(user.avatarConfig),
      joinedAt: user.createdAt.toISOString(),
      level: {
        level: levelView.level,
        badgeKey: levelView.badgeKey,
        progressPercent: levelView.progressPercent,
        xp: levelView.xp,
        totalXp,
        currentLevelXp: levelView.currentLevelXp,
        xpToNextLevel: levelView.xpToNextLevel,
        totalXpForNextLevel: levelView.totalXpForNextLevel,
      },
      streak: {
        current: streakStatus.currentStreak,
        longest: streakStatus.longestStreak,
        freezeCount: streakStatus.freezesAvailable,
        lastActiveDate: streakStatus.lastActiveDate,
      },
      prayers: {
        totalCompleted: prayerStats?.totalCompleted ?? 0,
        breakdown: this.buildBreakdown(prayerStats),
        punctuality: this.buildPunctuality(prayerStats),
        lastCompletedAt: prayerStats?.lastCompletedAt?.toISOString() ?? null,
        quiz: {
          totalAttempts,
          passed,
          failed,
          accuracyPercent,
        },
      },
      social: { followerCount, followingCount },
    };
  }

  async getPublicStats(username: string, viewerId: string): Promise<PublicStatsResponseDto> {
    const target = await this.prisma.user.findUnique({
      where: { username },
      select: {
        id: true,
        username: true,
        createdAt: true,
        latitude: true,
        longitude: true,
        avatarConfig: { select: { colors: true, accessories: true, gender: true } },
      },
    });

    if (!target) {
      throw new NotFoundException('USER_NOT_FOUND');
    }

    const [xpRow, streakRow, prayerStats, followerCount, followingCount] = await Promise.all([
      this.prisma.userXp.findUnique({ where: { userId: target.id } }),
      this.prisma.userStreak.findUnique({ where: { userId: target.id } }),
      this.prisma.userPrayerStats.findUnique({ where: { userId: target.id } }),
      this.prisma.follow.count({ where: { followingId: target.id } }),
      this.prisma.follow.count({ where: { followerId: target.id } }),
    ]);

    const levelView = LevelCalculator.computeLevelFromXp(xpRow?.xp ?? 0);
    const streakStatus = evaluateStreakStatus(streakRow, this.resolveToday(target));

    return {
      username: target.username,
      avatarCustomization: resolveAvatarCustomizationFromDb(target.avatarConfig),
      joinedAt: target.createdAt.toISOString(),
      level: {
        level: levelView.level,
        badgeKey: levelView.badgeKey,
        progressPercent: levelView.progressPercent,
      },
      streak: {
        current: streakStatus.currentStreak,
        longest: streakStatus.longestStreak,
      },
      prayers: {
        totalCompleted: prayerStats?.totalCompleted ?? 0,
        breakdown: this.buildBreakdown(prayerStats),
        punctuality: this.buildPunctuality(prayerStats),
      },
      social: { followerCount, followingCount },
      isSelf: target.id === viewerId,
    };
  }

  private resolveToday(user: { latitude: number | null; longitude: number | null }): LocalDate {
    const timezone =
      user.latitude === null || user.longitude === null
        ? DEFAULT_TIMEZONE
        : resolveTimezone(user.latitude, user.longitude);
    return LocalDate.fromInstant(DateTime.now(), timezone);
  }

  private buildBreakdown(
    stats: {
      totalFajr: number;
      totalDhuhr: number;
      totalAsr: number;
      totalMaghrib: number;
      totalIsha: number;
      totalJumuah: number;
      totalTarawih: number;
      totalEidFitr: number;
      totalEidAdha: number;
    } | null,
  ): PrayerBreakdownDto {
    return {
      fajr: stats?.totalFajr ?? 0,
      dhuhr: stats?.totalDhuhr ?? 0,
      asr: stats?.totalAsr ?? 0,
      maghrib: stats?.totalMaghrib ?? 0,
      isha: stats?.totalIsha ?? 0,
      jumuah: stats?.totalJumuah ?? 0,
      tarawih: stats?.totalTarawih ?? 0,
      eidFitr: stats?.totalEidFitr ?? 0,
      eidAdha: stats?.totalEidAdha ?? 0,
    };
  }

  private buildPunctuality(
    stats: { totalOnTime: number; totalLate: number } | null,
  ): PunctualityStatsDto {
    const onTime = stats?.totalOnTime ?? 0;
    const late = stats?.totalLate ?? 0;
    const total = onTime + late;
    return {
      onTime,
      late,
      onTimePercent: total === 0 ? 0 : Math.round((onTime / total) * 100),
    };
  }

  private pickCount(
    rows: Array<{ status: string; _count: { _all: number } }>,
    status: 'PASSED' | 'FAILED' | 'EXPIRED' | 'PENDING',
  ): number {
    return rows.find((r) => r.status === status)?._count._all ?? 0;
  }
}
