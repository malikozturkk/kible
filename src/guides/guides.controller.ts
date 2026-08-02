import { Controller, Get, HttpStatus, Param, ParseEnumPipe } from '@nestjs/common';
import { GuidesService } from './guides.service';
import { GuideType } from './enums/guide-type.enum';
import { GuideResponseDto } from './dto/guide-response.dto';
import { BusinessException } from '../common/exceptions/business.exception';

@Controller('guides')
export class GuidesController {
  constructor(private readonly guidesService: GuidesService) {}

  @Get(':type')
  async getGuide(
    @Param(
      'type',
      new ParseEnumPipe(GuideType, {
        exceptionFactory: () => new BusinessException('GUIDE_NOT_FOUND', HttpStatus.NOT_FOUND),
      }),
    )
    type: GuideType,
  ): Promise<GuideResponseDto> {
    return this.guidesService.getGuide(type);
  }
}
