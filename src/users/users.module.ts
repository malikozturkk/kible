import { Module } from '@nestjs/common';
import { UsersController } from './users.controller';
import { UsersService } from './users.service';
import { UserStatsService } from './services/user-stats.service';
import { DataExportService } from './services/data-export.service';
import { PrismaModule } from '../prisma/prisma.module';

@Module({
  imports: [PrismaModule],
  controllers: [UsersController],
  providers: [UsersService, UserStatsService, DataExportService],
  exports: [UsersService, UserStatsService, DataExportService],
})
export class UsersModule {}
