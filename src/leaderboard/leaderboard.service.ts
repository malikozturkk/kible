import { Injectable, NotFoundException } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import { LocalDate } from '../common/utils/local-date';
import { DEFAULT_TIMEZONE, resolveTimezone } from '../common/utils/timezone.util';
import { evaluateStreakStatus } from '../gamification/domain/streak-status';
import { resolveAvatarCustomizationFromDb } from '../auth/utils/avatar-config.util';
import { AVATAR_CONFIG_SELECT } from '../users/types/users.types';
import { LeaderboardMetric, LeaderboardPeriod, LeaderboardScope } from './enums/leaderboard.enums';
import type { LeaderboardQueryDto } from './dto/leaderboard-query.dto';
import type { LeaderboardEntryDto, LeaderboardResponseDto } from './dto/leaderboard-response.dto';
import {
  LEADERBOARD_DEFAULT_LIMIT,
  LEADERBOARD_MIN_SCORE,
  LEADERBOARD_SELF_RANK_SCAN_LIMIT,
} from './constants/leaderboard.constants';

interface ScoredUser {
  id: string;
  username: string;
  city: string | null;
  avatar: string | null;
  avatarConfig: Prisma.UserAvatarConfigGetPayload<typeof AVATAR_CONFIG_SELECT> | null;
  score: number;
}

@Injectable()
export class LeaderboardService {
  constructor(private readonly prisma: PrismaService) {}

  async getLeaderboard(
    viewerId: string,
    query: LeaderboardQueryDto,
  ): Promise<LeaderboardResponseDto> {
    const metric = query.metric ?? LeaderboardMetric.STREAK;
    const scope = query.scope ?? LeaderboardScope.GLOBAL;
    const period = query.period ?? LeaderboardPeriod.ALL_TIME;
    const limit = query.limit ?? LEADERBOARD_DEFAULT_LIMIT;

    const viewer = await this.prisma.user.findUnique({
      where: { id: viewerId },
      select: { id: true, city: true },
    });
    if (!viewer) {
      throw new NotFoundException('USER_NOT_FOUND');
    }

    const audience = await this.resolveAudience(viewer, scope);
    const scored = await this.scoreUsers(metric, period, audience);

    scored.sort((a, b) => b.score - a.score || a.username.localeCompare(b.username, 'tr'));

    const ranked = scored.filter((u) => u.score >= LEADERBOARD_MIN_SCORE);
    const entries: LeaderboardEntryDto[] = ranked.slice(0, limit).map((user, index) => ({
      rank: index + 1,
      username: user.username,
      city: user.city,
      avatar: user.avatar,
      avatarCustomization: resolveAvatarCustomizationFromDb(user.avatarConfig),
      score: user.score,
      isCurrentUser: user.id === viewerId,
    }));

    const selfIndex = ranked.findIndex((u) => u.id === viewerId);
    const selfScore = scored.find((u) => u.id === viewerId)?.score ?? 0;

    return {
      metric,
      scope,
      period,
      city: scope === LeaderboardScope.CITY ? viewer.city : null,
      entries,
      currentUser: {
        rank: selfIndex >= 0 && selfIndex < LEADERBOARD_SELF_RANK_SCAN_LIMIT ? selfIndex + 1 : null,
        score: selfScore,
        inTopList: selfIndex >= 0 && selfIndex < limit,
      },
    };
  }

  private async resolveAudience(
    viewer: { id: string; city: string | null },
    scope: LeaderboardScope,
  ): Promise<string[] | undefined> {
    if (scope === LeaderboardScope.GLOBAL) return undefined;

    if (scope === LeaderboardScope.CITY) {
      if (!viewer.city) return [viewer.id];
      const peers = await this.prisma.user.findMany({
        where: { city: viewer.city },
        select: { id: true },
      });
      return peers.map((p) => p.id);
    }

    const following = await this.prisma.follow.findMany({
      where: { followerId: viewer.id },
      select: { followingId: true },
    });
    return [viewer.id, ...following.map((f) => f.followingId)];
  }

  private async scoreUsers(
    metric: LeaderboardMetric,
    period: LeaderboardPeriod,
    audience: string[] | undefined,
  ): Promise<ScoredUser[]> {
    switch (metric) {
      case LeaderboardMetric.XP:
        return this.scoreByXp(audience);
      case LeaderboardMetric.PRAYERS:
        return this.scoreByPrayers(period, audience);
      case LeaderboardMetric.STREAK:
      default:
        return this.scoreByStreak(audience);
    }
  }

  private userSelect() {
    return {
      id: true,
      username: true,
      city: true,
      avatar: true,
      avatarConfig: AVATAR_CONFIG_SELECT,
    } as const;
  }

  private async scoreByXp(audience: string[] | undefined): Promise<ScoredUser[]> {
    const rows = await this.prisma.userXp.findMany({
      where: {
        totalXp: { gte: LEADERBOARD_MIN_SCORE },
        ...(audience && { userId: { in: audience } }),
      },
      orderBy: { totalXp: 'desc' },
      take: LEADERBOARD_SELF_RANK_SCAN_LIMIT,
      select: { totalXp: true, user: { select: this.userSelect() } },
    });

    return rows.map((row) => ({ ...row.user, score: row.totalXp }));
  }

  private async scoreByPrayers(
    period: LeaderboardPeriod,
    audience: string[] | undefined,
  ): Promise<ScoredUser[]> {
    const today = LocalDate.todayIn(DEFAULT_TIMEZONE);
    const windowDays =
      period === LeaderboardPeriod.WEEKLY ? 7 : period === LeaderboardPeriod.MONTHLY ? 30 : null;

    const grouped = await this.prisma.prayerCompletion.groupBy({
      by: ['userId'],
      where: {
        ...(audience && { userId: { in: audience } }),
        ...(windowDays !== null && {
          prayerDate: { gte: today.plusDays(-(windowDays - 1)).toUtcMidnight() },
        }),
      },
      _count: { _all: true },
      orderBy: { _count: { userId: 'desc' } },
      take: LEADERBOARD_SELF_RANK_SCAN_LIMIT,
    });

    if (grouped.length === 0) return [];

    const users = await this.prisma.user.findMany({
      where: { id: { in: grouped.map((g) => g.userId) } },
      select: this.userSelect(),
    });
    const byId = new Map(users.map((u) => [u.id, u]));

    return grouped.flatMap((g) => {
      const user = byId.get(g.userId);
      return user ? [{ ...user, score: g._count._all }] : [];
    });
  }

  private async scoreByStreak(audience: string[] | undefined): Promise<ScoredUser[]> {
    const rows = await this.prisma.userStreak.findMany({
      where: {
        currentStreak: { gte: LEADERBOARD_MIN_SCORE },
        ...(audience && { userId: { in: audience } }),
      },
      orderBy: { currentStreak: 'desc' },
      take: LEADERBOARD_SELF_RANK_SCAN_LIMIT,
      select: {
        currentStreak: true,
        longestStreak: true,
        streakFreezeCount: true,
        lastActiveDate: true,
        user: {
          select: {
            ...this.userSelect(),
            latitude: true,
            longitude: true,
          },
        },
      },
    });

    return rows.map((row) => {
      const { latitude, longitude, ...publicUser } = row.user;
      const timezone =
        latitude !== null && longitude !== null
          ? resolveTimezone(latitude, longitude)
          : DEFAULT_TIMEZONE;

      const status = evaluateStreakStatus(
        {
          currentStreak: row.currentStreak,
          longestStreak: row.longestStreak,
          streakFreezeCount: row.streakFreezeCount,
          lastActiveDate: row.lastActiveDate,
        },
        LocalDate.todayIn(timezone),
      );

      return { ...publicUser, score: status.currentStreak };
    });
  }
}
