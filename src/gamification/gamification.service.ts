import { Injectable, UnauthorizedException } from '@nestjs/common';
import { LevelCalculator } from './domain/level-calculator';
import { UserXpResponseDto } from './dto/user-xp.dto';
import { PrismaService } from '../prisma/prisma.service';
import { UserStreakResponseDto } from './dto/user-streak.dto';

@Injectable()
export class GamificationService {
  constructor(private readonly prisma: PrismaService) {}

  async userXp(userId: string): Promise<UserXpResponseDto> {
    const xpRecord = await this.prisma.userXp.upsert({
      where: { userId },
      update: {},
      create: {
        userId,
        xp: 0,
        totalXp: 0,
      },
    });

    const { xp, totalXp } = xpRecord;
    return {
      ...LevelCalculator.computeLevelFromXp(xp),
      totalXp,
    };
  }

  async userStreak(userId: string): Promise<UserStreakResponseDto> {
    return this.prisma.userStreak.upsert({
      where: { userId },
      update: {},
      create: {
        userId,
        currentStreak: 0,
        longestStreak: 0,
        streakFreezeCount: 0,
      },
    });
  }
}
