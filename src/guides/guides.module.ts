import { Module } from '@nestjs/common';
import { GuidesController } from './guides.controller';
import { GuidesService } from './guides.service';
import { WuduStrategy } from './strategies/wudu.strategy';
import { GhuslStrategy } from './strategies/ghusl.strategy';

@Module({
  imports: [],
  controllers: [GuidesController],
  providers: [GuidesService, WuduStrategy, GhuslStrategy],
  exports: [GuidesService],
})
export class GuidesModule {}

