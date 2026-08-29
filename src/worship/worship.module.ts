import { Module } from '@nestjs/common';
import { PrismaModule } from '../prisma/prisma.module';
import { WorshipService } from './worship.service';
import { WorshipController } from './worship.controller';
import { PrayerTimeFactory } from './factories/prayer-time.factory';
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
    PrayerTimeFactory,
    PrayerCountdownService,
    PublicPrayerTimesService,
    FastingProgressService,
    DayProgressService,
    WorshipResponseMapper,
  ],
  exports: [WorshipService, PrayerTimeFactory, PublicPrayerTimesService],
})
export class WorshipModule {}
