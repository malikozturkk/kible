import { HttpStatus, Injectable } from '@nestjs/common';
import { DateTime } from 'luxon';
import { BusinessException } from '../../common/exceptions/business.exception';
import { LocalDate } from '../../common/utils/local-date';
import { StreakService } from './streak.service';
import { PrayerScheduleService } from './prayer-schedule.service';
import { GamificationActionType } from '../enums/gamification-action.enum';
import {
  GamificationActionRequestDto,
  GamificationActionResponseDto,
} from '../dto/gamification-action.dto';

@Injectable()
export class GamificationActionService {
  constructor(
    private readonly streakService: StreakService,
    private readonly scheduleService: PrayerScheduleService,
  ) {}

  async dispatch(
    userId: string,
    request: GamificationActionRequestDto,
  ): Promise<GamificationActionResponseDto> {
    switch (request.actionType) {
      case GamificationActionType.STREAK_FREEZE: {
        const { timezone } = await this.scheduleService.getUserPrayerConfig(userId);
        const now = DateTime.now().setZone(timezone);
        const today = LocalDate.fromInstant(now, timezone);
        const result = await this.streakService.useStreakFreeze(userId, today);
        return {
          actionType: GamificationActionType.STREAK_FREEZE,
          streakFreezeUsage: result,
        };
      }
      default: {
        throw new BusinessException('UNKNOWN_GAMIFICATION_ACTION', HttpStatus.BAD_REQUEST);
      }
    }
  }
}
