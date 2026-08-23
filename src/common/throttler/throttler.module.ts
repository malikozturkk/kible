import { Global, Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler';
import { THROTTLE_DEFAULT } from './throttle.constants';

@Global()
@Module({
  imports: [ThrottlerModule.forRoot([{ name: 'default', ...THROTTLE_DEFAULT }])],
  providers: [{ provide: APP_GUARD, useClass: ThrottlerGuard }],
  exports: [ThrottlerModule],
})
export class AppThrottlerModule {}
