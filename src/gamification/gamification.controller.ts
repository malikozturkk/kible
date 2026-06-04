import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  ParseEnumPipe,
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
import { PrayerQuestionsResponseDto } from './dto/prayer-questions.dto';
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

  @Get('prayer-questions/:prayerId')
  async prayerQuestions(
    @Request() req: AuthenticatedRequest,
    @Param('prayerId', new ParseEnumPipe(PrayerType)) prayerId: PrayerType,
  ): Promise<PrayerQuestionsResponseDto> {
    return this.gamificationService.prayerQuestions(req.user.id, prayerId);
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
