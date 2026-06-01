import { Controller, Get, Query, UseGuards, Request } from '@nestjs/common';
import { WorshipService } from './worship.service';
import { AdhanQueryDto } from './dto/worship.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import type { AuthenticatedRequest } from '../auth/strategies/jwt.strategy';
import type { PrayerOptionsResponse } from './constants/prayer-options.constants';

@Controller('worship')
export class WorshipController {
  constructor(private readonly worshipService: WorshipService) {}

  @Get()
  @UseGuards(JwtAuthGuard)
  async adhan(@Request() req: AuthenticatedRequest, @Query() query: AdhanQueryDto) {
    return this.worshipService.adhan({
      userId: req.user.id,
      date: query.date,
      timezone: query.tz,
    });
  }

  @Get('options')
  getOptions(): PrayerOptionsResponse {
    return this.worshipService.getOptions();
  }
}
