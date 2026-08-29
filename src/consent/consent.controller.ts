import { Body, Controller, Get, HttpCode, HttpStatus, Post, Req, UseGuards } from '@nestjs/common';
import { Throttle } from '@nestjs/throttler';
import type { Request as ExpressRequest } from 'express';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import type { AuthenticatedRequest } from '../auth/strategies/jwt.strategy';
import { ConsentService } from './consent.service';
import { AcceptConsentDto } from './dto/accept-consent.dto';
import { ConsentStatusResponseDto } from './dto/consent-status.dto';
import { ConsentBypass } from './decorators/consent-bypass.decorator';

@Controller('consent')
export class ConsentController {
  constructor(private readonly consentService: ConsentService) {}

  @Get('status')
  @UseGuards(JwtAuthGuard)
  @ConsentBypass()
  async getStatus(@Req() req: AuthenticatedRequest): Promise<ConsentStatusResponseDto> {
    return this.consentService.getStatus(req.user.id);
  }

  @Post('accept')
  @UseGuards(JwtAuthGuard)
  @Throttle({ default: { limit: 10, ttl: 60_000 } })
  @ConsentBypass()
  @HttpCode(HttpStatus.OK)
  async accept(
    @Req() req: AuthenticatedRequest & ExpressRequest,
    @Body() dto: AcceptConsentDto,
  ): Promise<null> {
    await this.consentService.accept(req.user.id, dto.type, dto.version);
    return null;
  }
}
