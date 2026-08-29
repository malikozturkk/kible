import { Module } from '@nestjs/common';
import { PrismaModule } from '../prisma/prisma.module';
import { WorshipService } from './worship.service';
import { WorshipController } from './worship.controller';
import { PrayerTimesService } from './services/prayer-times.service';
import { PrayerCountdownService } from './services/prayer-countdown.service';
import { PublicPrayerTimesService } from './services/public-prayer-times.service';
import { FastingProgressService } from './services/fasting-progress.service';
import { DayProgressService } from './services/day-progress.service';
import { WorshipResponseMapper } from './mappers/worship-response.mapper';

@Module({
  imports: [PrismaModule],
  controllers: [WorshipController],
  providers: [
    WorshipService,
    PrayerTimesService,
    PrayerCountdownService,
    PublicPrayerTimesService,
    FastingProgressService,
    DayProgressService,
    WorshipResponseMapper,
  ],
  exports: [WorshipService, PrayerTimesService, PublicPrayerTimesService],
})
export class WorshipModule {}
