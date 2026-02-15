import { BadRequestException, Injectable } from '@nestjs/common';
import { GuideResponseDto } from './dto/guide-response.dto';
import { GuideType } from './enums/guide-type.enum';
import { GuideStrategy } from './strategies/guide.strategy';
import { WuduStrategy } from './strategies/wudu.strategy';
import { GhuslStrategy } from './strategies/ghusl.strategy';

@Injectable()
export class GuidesService {
  private readonly strategies: GuideStrategy[];

  constructor(
    private readonly wuduStrategy: WuduStrategy,
    private readonly ghuslStrategy: GhuslStrategy,
  ) {
    this.strategies = [this.wuduStrategy, this.ghuslStrategy];
  }

  async getGuide(type: GuideType): Promise<GuideResponseDto> {
    const strategy = this.strategies.find((s) => s.supports(type));
    if (!strategy) {
      throw new BadRequestException('GUIDE_NOT_FOUND');
    }
    return strategy.getGuide();
  }
}
