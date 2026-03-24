import { BadRequestException, Injectable } from '@nestjs/common';
import { QuestionsService } from '../questions/questions.service';
import { GuideResponseDto } from './dto/guide-response.dto';
import { GuideType } from './enums/guide-type.enum';
import { GuideStrategy } from './strategies/guide.strategy';
import { WuduStrategy } from './strategies/wudu.strategy';
import { GhuslStrategy } from './strategies/ghusl.strategy';
import { FajrStrategy } from './strategies/fajr.strategy';
import { DhuhrStrategy } from './strategies/dhuhr.strategy';
import { AsrStrategy } from './strategies/asr.strategy';
import { MaghribStrategy } from './strategies/maghrib.strategy';
import { IshaStrategy } from './strategies/isha.strategy';
import { JumuahStrategy } from './strategies/jumuah.strategy';

@Injectable()
export class GuidesService {
  private readonly strategies: GuideStrategy[];

  constructor(
    private readonly wuduStrategy: WuduStrategy,
    private readonly ghuslStrategy: GhuslStrategy,
    private readonly fajrStrategy: FajrStrategy,
    private readonly dhuhrStrategy: DhuhrStrategy,
    private readonly asrStrategy: AsrStrategy,
    private readonly maghribStrategy: MaghribStrategy,
    private readonly ishaStrategy: IshaStrategy,
    private readonly jumuahStrategy: JumuahStrategy,
    private readonly questionsService: QuestionsService,
  ) {
    this.strategies = [
      this.wuduStrategy,
      this.ghuslStrategy,
      this.fajrStrategy,
      this.dhuhrStrategy,
      this.asrStrategy,
      this.maghribStrategy,
      this.ishaStrategy,
      this.jumuahStrategy,
    ];
  }

  async getGuide(type: GuideType): Promise<GuideResponseDto> {
    const strategy = this.strategies.find((s) => s.supports(type));
    if (!strategy) {
      throw new BadRequestException('GUIDE_NOT_FOUND');
    }
    const guide = await strategy.getGuide();
    const randomQuestion = await this.questionsService.tryPickRandomQuestion(guide.id);
    if (randomQuestion && guide.steps.length > 0) {
      const stepNumber = Math.floor(Math.random() * guide.steps.length) + 1;
      const step =
        guide.steps.find((s) => s.step === stepNumber) ?? guide.steps[stepNumber - 1];
      if (step) {
        step.randomQuestion = randomQuestion;
      }
    }
    return guide;
  }
}
