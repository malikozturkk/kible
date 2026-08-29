import { Body, Controller, HttpCode, HttpStatus, Post, Request } from '@nestjs/common';
import type { Request as ExpressRequest } from 'express';
import { Throttle } from '@nestjs/throttler';
import { TelemetryService } from './telemetry.service';
import { ReportClientErrorDto } from './dto/report-client-error.dto';
import { THROTTLE_CLIENT_ERRORS } from '../common/throttler/throttle.constants';

@Controller('telemetry')
export class TelemetryController {
  constructor(private readonly telemetryService: TelemetryService) {}

  @Throttle({ default: THROTTLE_CLIENT_ERRORS })
  @Post('client-errors')
  @HttpCode(HttpStatus.ACCEPTED)
  reportClientError(@Body() dto: ReportClientErrorDto, @Request() req: ExpressRequest): void {
    this.telemetryService.recordClientError(dto, req.headers['user-agent']);
  }
}
