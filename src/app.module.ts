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
import { consentConfig } from './config/consent.config';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [consentConfig],
    }),
    PrismaModule,
    AuthModule,
    GamificationModule,
    GuidesModule,
    WorshipModule,
    UsersModule,
    ConsentModule,
    ScheduleModule.forRoot(),
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
