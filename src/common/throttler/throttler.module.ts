import { Global, Module } from '@nestjs/common';
import { ThrottlerModule } from '@nestjs/throttler';
import { THROTTLE_DEFAULT } from './throttle.constants';

@Global()
@Module({
  imports: [ThrottlerModule.forRoot([{ name: 'default', ...THROTTLE_DEFAULT }])],
  exports: [ThrottlerModule],
})
export class AppThrottlerModule {}
