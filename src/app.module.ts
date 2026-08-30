import { Module } from '@nestjs/common';
import { ScheduleModule } from '@nestjs/schedule';
import { ConfigModule } from '@nestjs/config';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { PrismaModule } from './prisma/prisma.module';
import { AuthModule } from './auth/auth.module';
import { GamificationModule } from './gamification/gamification.module';
import { GuidesModule } from './guides/guides.module';
import { WorshipModule } from './worship/worship.module';
import { UsersModule } from './users/users.module';
import { ConsentModule } from './consent/consent.module';
import { legalConfig } from './config/legal.config';
import { LegalModule } from './legal/legal.module';
import { LeaderboardModule } from './leaderboard/leaderboard.module';
import { AppThrottlerModule } from './common/throttler/throttler.module';
import { AppLoggingModule } from './common/logging/logging.module';
import { TelemetryModule } from './telemetry/telemetry.module';
import { NotificationsModule } from './notifications/notifications.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [legalConfig],
    }),
    AppLoggingModule,
    AppThrottlerModule,
    PrismaModule,
    AuthModule,
    GamificationModule,
    GuidesModule,
    WorshipModule,
    UsersModule,
    LegalModule,
    ConsentModule,
    LeaderboardModule,
    TelemetryModule,
    NotificationsModule,
    ScheduleModule.forRoot(),
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
