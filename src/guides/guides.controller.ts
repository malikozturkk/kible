import { Controller, Get, Param, ParseEnumPipe } from '@nestjs/common';
import { GuidesService } from './guides.service';
import { GuideType } from './enums/guide-type.enum';
import { GuideResponseDto } from './dto/guide-response.dto';

@Controller('guides')
export class GuidesController {
  constructor(private readonly guidesService: GuidesService) {}

  @Get(':type')
  async getGuide(
    @Param('type', new ParseEnumPipe(GuideType)) type: GuideType,
  ): Promise<GuideResponseDto> {
    return this.guidesService.getGuide(type);
  }
}

