import { Module } from '@nestjs/common';
import { ScheduleModule } from '@nestjs/schedule';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { PrismaModule } from './prisma/prisma.module';
import { AuthModule } from './auth/auth.module';
import { GamificationModule } from './gamification/gamification.module';
import { GuidesModule } from './guides/guides.module';

@Module({
  imports: [PrismaModule, AuthModule, GamificationModule, GuidesModule, ScheduleModule.forRoot()],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
