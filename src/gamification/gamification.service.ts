import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { LevelCalculator } from './domain/level-calculator';
import { UserXpResponseDto } from './dto/user-xp.dto';
import { UserStreakResponseDto } from './dto/user-streak.dto';
import { DailyPrayersResponseDto } from './dto/daily-prayers.dto';
import { PrayerQuestionsResponseDto } from './dto/prayer-questions.dto';
import {
  GamificationActionRequestDto,
  GamificationActionResponseDto,
} from './dto/gamification-action.dto';
import { PrayerScheduleService } from './services/prayer-schedule.service';
import { PrayerQuizService } from './services/prayer-quiz.service';
import { GamificationActionService } from './services/gamification-action.service';
import { PrayerScheduleParams } from './types/gamification.types';
import { PrayerType } from '@prisma/client';

@Injectable()
export class GamificationService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly prayerScheduleService: PrayerScheduleService,
    private readonly prayerQuizService: PrayerQuizService,
    private readonly actionService: GamificationActionService,
  ) {}

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

  async dailyPrayers(params: PrayerScheduleParams): Promise<DailyPrayersResponseDto> {
    return this.prayerScheduleService.getDailyView(params);
  }

  async prayerQuestions(
    params: PrayerScheduleParams,
    prayerType: PrayerType,
  ): Promise<PrayerQuestionsResponseDto> {
    return this.prayerQuizService.issueQuiz(params, prayerType);
  }

  async action(
    userId: string,
    body: GamificationActionRequestDto,
  ): Promise<GamificationActionResponseDto> {
    return this.actionService.dispatch(userId, body);
  }
}
