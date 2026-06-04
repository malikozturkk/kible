import { Injectable } from '@nestjs/common';
import { DateTime } from 'luxon';
import { PrismaService } from '../prisma/prisma.service';
import { DailyPrayersResponseDto } from './dto/daily-prayers.dto';
import { PrayerQuestionsResponseDto } from './dto/prayer-questions.dto';
import {
  GamificationActionRequestDto,
  GamificationActionResponseDto,
} from './dto/gamification-action.dto';
import { PrayerScheduleService } from './services/prayer-schedule.service';
import { PrayerQuizService } from './services/prayer-quiz.service';
import { GamificationActionService } from './services/gamification-action.service';
import { PrayerScheduleParams, PrayerViewRequest } from './types/gamification.types';
import { PrayerType } from '@prisma/client';

@Injectable()
export class GamificationService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly prayerScheduleService: PrayerScheduleService,
    private readonly prayerQuizService: PrayerQuizService,
    private readonly actionService: GamificationActionService,
  ) {}

  async dailyPrayers(request: PrayerViewRequest): Promise<DailyPrayersResponseDto> {
    const params = await this.toScheduleParams(request.userId, request.date);
    return this.prayerScheduleService.getDailyView(params);
  }

  async prayerQuestions(
    userId: string,
    prayerType: PrayerType,
  ): Promise<PrayerQuestionsResponseDto> {
    const params = await this.toScheduleParams(userId);
    return this.prayerQuizService.issueQuiz(params, prayerType);
  }

  async action(
    userId: string,
    body: GamificationActionRequestDto,
  ): Promise<GamificationActionResponseDto> {
    return this.actionService.dispatch(userId, body);
  }

  private async toScheduleParams(userId: string, date?: string): Promise<PrayerScheduleParams> {
    const config = await this.prayerScheduleService.getUserPrayerConfig(userId);
    return {
      userId,
      date: date ?? DateTime.now().setZone(config.timezone).toISODate()!,
      timezone: config.timezone,
      latitude: config.latitude,
      longitude: config.longitude,
      madhab: config.madhab,
    };
  }
}
