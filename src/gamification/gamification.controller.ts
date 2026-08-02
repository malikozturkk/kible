import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  ParseEnumPipe,
  ParseUUIDPipe,
  Post,
  Query,
  Request,
  UseGuards,
} from '@nestjs/common';
import { PrayerType } from '@prisma/client';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import type { AuthenticatedRequest } from '../auth/strategies/jwt.strategy';
import { GamificationService } from './gamification.service';
import { DailyPrayersQueryDto, DailyPrayersResponseDto } from './dto/daily-prayers.dto';
import { PrayerHistoryQueryDto, PrayerHistoryResponseDto } from './dto/prayer-history.dto';
import { StreakRiskAssessmentDto } from './dto/streak-risk.dto';
import {
  AnswerPrayerQuestionBodyDto,
  AnswerPrayerQuestionResponseDto,
  PrayerQuestionsResponseDto,
  StartPrayerQuestionResponseDto,
} from './dto/prayer-questions.dto';
import {
  GamificationActionRequestDto,
  GamificationActionResponseDto,
} from './dto/gamification-action.dto';

@Controller('gamification')
@UseGuards(JwtAuthGuard)
export class GamificationController {
  constructor(private readonly gamificationService: GamificationService) {}

  @Get('daily-prayers')
  async dailyPrayers(
    @Request() req: AuthenticatedRequest,
    @Query() query: DailyPrayersQueryDto,
  ): Promise<DailyPrayersResponseDto> {
    return this.gamificationService.dailyPrayers({
      userId: req.user.id,
      date: query.date,
    });
  }

  @Get('prayer-history')
  async prayerHistory(
    @Request() req: AuthenticatedRequest,
    @Query() query: PrayerHistoryQueryDto,
  ): Promise<PrayerHistoryResponseDto> {
    return this.gamificationService.prayerHistory(req.user.id, query.from, query.to);
  }

  @Get('streak-risk')
  async streakRisk(@Request() req: AuthenticatedRequest): Promise<StreakRiskAssessmentDto> {
    return this.gamificationService.streakRisk(req.user.id);
  }

  @Get('prayer-questions/:prayerId')
  async prayerQuestions(
    @Request() req: AuthenticatedRequest,
    @Param('prayerId', new ParseEnumPipe(PrayerType)) prayerId: PrayerType,
  ): Promise<PrayerQuestionsResponseDto> {
    return this.gamificationService.prayerQuestions(req.user.id, prayerId);
  }

  @Post('prayer-questions/:quizId/questions/:questionId/start')
  @HttpCode(HttpStatus.OK)
  async startPrayerQuestion(
    @Request() req: AuthenticatedRequest,
    @Param('quizId', new ParseUUIDPipe()) quizId: string,
    @Param('questionId', new ParseUUIDPipe()) questionId: string,
  ): Promise<StartPrayerQuestionResponseDto> {
    return this.gamificationService.startPrayerQuestion(req.user.id, quizId, questionId);
  }

  @Post('prayer-questions/:quizId/questions/:questionId/answer')
  @HttpCode(HttpStatus.OK)
  async answerPrayerQuestion(
    @Request() req: AuthenticatedRequest,
    @Param('quizId', new ParseUUIDPipe()) quizId: string,
    @Param('questionId', new ParseUUIDPipe()) questionId: string,
    @Body() body: AnswerPrayerQuestionBodyDto,
  ): Promise<AnswerPrayerQuestionResponseDto> {
    return this.gamificationService.answerPrayerQuestion(
      req.user.id,
      quizId,
      questionId,
      body.optionId,
    );
  }

  @Post('action')
  @HttpCode(HttpStatus.OK)
  async action(
    @Request() req: AuthenticatedRequest,
    @Body() body: GamificationActionRequestDto,
  ): Promise<GamificationActionResponseDto> {
    return this.gamificationService.action(req.user.id, body);
  }
}
