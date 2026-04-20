import { Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { CacheModule } from '@nestjs/cache-manager';
import { ThrottlerModule } from '@nestjs/throttler';
import { ConsentService } from './consent.service';
import { ConsentController } from './consent.controller';
import { ConsentGuard } from './guards/consent.guard';

@Module({
  imports: [
    CacheModule.register({
      isGlobal: false,
    }),
    ThrottlerModule.forRoot([
      {
        name: 'default',
        ttl: 60_000,
        limit: 10,
      },
    ]),
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
