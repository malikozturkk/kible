import { Module } from '@nestjs/common';
import { WorshipService } from './worship.service';
import { WorshipController } from './worship.controller';
import { PrayerTimeFactory } from './factories/prayer-time.factory';
import { PrayerCountdownService } from './services/prayer-countdown.service';
import { FastingProgressService } from './services/fasting-progress.service';
import { DayProgressService } from './services/day-progress.service';
import { WorshipResponseMapper } from './mappers/worship-response.mapper';

@Module({
  controllers: [WorshipController],
  providers: [
    WorshipService,
    PrayerTimeFactory,
    PrayerCountdownService,
    FastingProgressService,
    DayProgressService,
    WorshipResponseMapper,
  ],
  exports: [WorshipService, PrayerTimeFactory],
})
export class WorshipModule {}
