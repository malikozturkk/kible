import { Controller, Get } from '@nestjs/common';
import { Throttle } from '@nestjs/throttler';
import { Public } from '../common/decorators/public.decorator';
import { THROTTLE_PUBLIC_LEGAL } from '../common/throttler/throttle.constants';
import { LegalService } from './legal.service';
import { LegalDocumentsResponseDto } from './dto/legal-document.dto';

@Controller('legal')
export class LegalController {
  constructor(private readonly legalService: LegalService) {}

  @Get('documents')
  @Public()
  @Throttle({ default: THROTTLE_PUBLIC_LEGAL })
  documents(): LegalDocumentsResponseDto {
    return this.legalService.listDocuments();
  }
}
