import { Global, Module } from '@nestjs/common';
import { CacheModule } from '@nestjs/cache-manager';
import { ConsentService } from './consent.service';
import { ConsentController } from './consent.controller';
import { ConsentGuard } from './guards/consent.guard';

@Global()
@Module({
  imports: [
    CacheModule.register({
      isGlobal: false,
    }),
  ],
  controllers: [ConsentController],
  providers: [ConsentService, ConsentGuard],
  exports: [ConsentService, ConsentGuard],
})
export class ConsentModule {}
