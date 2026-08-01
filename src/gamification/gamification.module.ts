import { Module } from '@nestjs/common';
import { PrismaModule } from '../prisma/prisma.module';
import { WorshipModule } from '../worship/worship.module';
import { GamificationController } from './gamification.controller';
import { GamificationService } from './gamification.service';
import { StreakService } from './services/streak.service';
import { XpService } from './services/xp.service';
import { PrayerScheduleService } from './services/prayer-schedule.service';
import { PrayerQuizService } from './services/prayer-quiz.service';
import { PrayerCompletionService } from './services/prayer-completion.service';
import { PrayerHistoryService } from './services/prayer-history.service';
import { GamificationActionService } from './services/gamification-action.service';

@Module({
  imports: [PrismaModule, WorshipModule],
  controllers: [GamificationController],
  providers: [
    GamificationService,
    StreakService,
    XpService,
    PrayerScheduleService,
    PrayerQuizService,
    PrayerCompletionService,
    PrayerHistoryService,
    GamificationActionService,
  ],
  exports: [
    GamificationService,
    StreakService,
    XpService,
    PrayerScheduleService,
    PrayerQuizService,
    PrayerCompletionService,
    PrayerHistoryService,
  ],
})
export class GamificationModule {}
