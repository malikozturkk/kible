import { Controller, Get, Query, UseGuards, Request } from '@nestjs/common';
import { Throttle } from '@nestjs/throttler';
import { WorshipService } from './worship.service';
import { PublicPrayerTimesService } from './services/public-prayer-times.service';
import { AdhanQueryDto } from './dto/worship.dto';
import { PublicPrayerTimesQueryDto } from './dto/public-prayer-times.dto';
import type { PublicPrayerTimesDTO } from './types/public-prayer-times.types';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { THROTTLE_PUBLIC_PRAYER_TIMES } from '../common/throttler/throttle.constants';
import type { AuthenticatedRequest } from '../auth/strategies/jwt.strategy';

@Controller('worship')
export class WorshipController {
  constructor(
    private readonly worshipService: WorshipService,
    private readonly publicPrayerTimesService: PublicPrayerTimesService,
  ) {}

  @Get('public/prayer-times')
  @Throttle({ default: THROTTLE_PUBLIC_PRAYER_TIMES })
  publicPrayerTimes(@Query() query: PublicPrayerTimesQueryDto): PublicPrayerTimesDTO {
    return this.publicPrayerTimesService.getPrayerTimes(query);
  }

  @Get()
  @UseGuards(JwtAuthGuard)
  async adhan(@Request() req: AuthenticatedRequest, @Query() query: AdhanQueryDto) {
    return this.worshipService.adhan({
      userId: req.user.id,
      date: query.date,
    });
  }
}
