import { Injectable } from '@nestjs/common';
import { DateTime } from 'luxon';
import { PrismaService } from '../prisma/prisma.service';
import { DailyPrayersResponseDto } from './dto/daily-prayers.dto';
import {
  AnswerPrayerQuestionResponseDto,
  PrayerQuestionsResponseDto,
  StartPrayerQuestionResponseDto,
} from './dto/prayer-questions.dto';
import {
  GamificationActionRequestDto,
  GamificationActionResponseDto,
} from './dto/gamification-action.dto';
import { PrayerScheduleService } from './services/prayer-schedule.service';
import { PrayerQuizService } from './services/prayer-quiz.service';
import { PrayerCompletionService } from './services/prayer-completion.service';
import { GamificationActionService } from './services/gamification-action.service';
import { PrayerScheduleParams, PrayerViewRequest } from './types/gamification.types';
import { PrayerType } from '@prisma/client';

@Injectable()
export class GamificationService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly prayerScheduleService: PrayerScheduleService,
    private readonly prayerQuizService: PrayerQuizService,
    private readonly prayerCompletionService: PrayerCompletionService,
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

  async startPrayerQuestion(
    userId: string,
    quizId: string,
    questionId: string,
  ): Promise<StartPrayerQuestionResponseDto> {
    return this.prayerQuizService.startQuestion(userId, quizId, questionId);
  }

  async answerPrayerQuestion(
    userId: string,
    quizId: string,
    questionId: string,
    optionId: string,
  ): Promise<AnswerPrayerQuestionResponseDto> {
    const { response, allCorrect } = await this.prayerQuizService.answerQuestion(
      userId,
      quizId,
      questionId,
      optionId,
    );

    if (allCorrect) {
      const completion = await this.prayerCompletionService.completeFromPassedQuiz(
        userId,
        allCorrect.submissionId,
        allCorrect.prayerType,
      );
      return { ...response, prayerCompletion: completion };
    }

    return response;
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
