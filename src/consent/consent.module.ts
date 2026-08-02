import { Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { CacheModule } from '@nestjs/cache-manager';
import { ConsentService } from './consent.service';
import { ConsentController } from './consent.controller';
import { ConsentGuard } from './guards/consent.guard';

@Module({
  imports: [
    CacheModule.register({
      isGlobal: false,
    }),
  ],
  controllers: [ConsentController],
  providers: [
    ConsentService,
    {
      provide: APP_GUARD,
      useClass: ConsentGuard,
    },
  ],
  exports: [ConsentService],
})
export class ConsentModule {}
