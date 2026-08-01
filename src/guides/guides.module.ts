import { Module } from '@nestjs/common';
import { QuestionsModule } from '../questions/questions.module';
import { GuidesController } from './guides.controller';
import { GuidesService } from './guides.service';
import { WuduStrategy } from './strategies/wudu.strategy';
import { GhuslStrategy } from './strategies/ghusl.strategy';
import { FajrStrategy } from './strategies/fajr.strategy';
import { DhuhrStrategy } from './strategies/dhuhr.strategy';
import { AsrStrategy } from './strategies/asr.strategy';
import { MaghribStrategy } from './strategies/maghrib.strategy';
import { IshaStrategy } from './strategies/isha.strategy';
import { JumuahStrategy } from './strategies/jumuah.strategy';

@Module({
  imports: [QuestionsModule],
  controllers: [GuidesController],
  providers: [
    GuidesService,
    WuduStrategy,
    GhuslStrategy,
    FajrStrategy,
    DhuhrStrategy,
    AsrStrategy,
    MaghribStrategy,
    IshaStrategy,
    JumuahStrategy,
  ],
  exports: [GuidesService],
})
export class GuidesModule {}
