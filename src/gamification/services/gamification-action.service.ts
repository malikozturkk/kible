import { HttpStatus, Injectable } from '@nestjs/common';
import { DateTime } from 'luxon';
import { BusinessException } from '../../common/exceptions/business.exception';
import { LocalDate } from '../../common/utils/local-date';
import { StreakService } from './streak.service';
import { PrayerCompletionService } from './prayer-completion.service';
import { GamificationActionType } from '../enums/gamification-action.enum';
import {
  GamificationActionRequestDto,
  GamificationActionResponseDto,
} from '../dto/gamification-action.dto';

@Injectable()
export class GamificationActionService {
  constructor(
    private readonly prayerCompletionService: PrayerCompletionService,
    private readonly streakService: StreakService,
  ) {}

  async dispatch(
    userId: string,
    request: GamificationActionRequestDto,
  ): Promise<GamificationActionResponseDto> {
    switch (request.actionType) {
      case GamificationActionType.PRAYER_COMPLETION: {
        const result = await this.prayerCompletionService.handle(userId, request);
        return {
          actionType: GamificationActionType.PRAYER_COMPLETION,
          prayerCompletion: result,
        };
      }
      case GamificationActionType.STREAK_FREEZE: {
        const now = DateTime.now().setZone(request.tz);
        if (!now.isValid) {
          throw new BusinessException('INVALID_TIMEZONE', HttpStatus.BAD_REQUEST);
        }
        const today = LocalDate.fromInstant(now, request.tz);
        const result = await this.streakService.useStreakFreeze(userId, today);
        return {
          actionType: GamificationActionType.STREAK_FREEZE,
          streakFreezeUsage: result,
        };
      }
      default: {
        const _exhaustive: never = request.actionType;
        throw new BusinessException('UNKNOWN_GAMIFICATION_ACTION', HttpStatus.BAD_REQUEST);
      }
    }
  }
}
