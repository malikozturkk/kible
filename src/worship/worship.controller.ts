import { Controller, Get, Query } from '@nestjs/common';
import { WorshipService } from './worship.service';
import { AdhanQueryDto } from './dto/worship.dto';
import type { PrayerOptionsResponse } from './constants/prayer-options.constants';

@Controller('worship')
export class WorshipController {
  constructor(private readonly worshipService: WorshipService) {}

  @Get()
  async adhan(@Query() query: AdhanQueryDto) {
    return this.worshipService.adhan({
      latitude: Number(query.lat),
      longitude: Number(query.lng),
      date: query.date,
      timezone: query.tz,
      method: query.method,
      madhab: query.madhab,
    });
  }

  @Get('options')
  getOptions(): PrayerOptionsResponse {
    return this.worshipService.getOptions();
  }
}
