import {
  Controller,
  Post,
  Body,
  UseGuards,
  Request,
  Res,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import type { Response as ExpressResponse } from 'express';
import { issueAuthResponse } from '../common/utils/auth-cookie.util';
import { Throttle } from '@nestjs/throttler';
import { OtpService } from './otp.service';
import { VerifyOtpDto } from './dto/verify-otp.dto';
import { OtpJwtGuard } from './guards/otp-jwt.guard';
import { AuthResponseDto } from '../auth/dto/auth-response.dto';
import { THROTTLE_EMAIL_SEND, THROTTLE_OTP_VERIFY } from '../common/throttler/throttle.constants';

@Controller('otp')
export class OtpController {
  constructor(private readonly otpService: OtpService) {}

  @Post('verify')
  @Throttle({ default: THROTTLE_OTP_VERIFY })
  @UseGuards(OtpJwtGuard)
  @HttpCode(HttpStatus.OK)
  async verify(
    @Request() req: { tempToken: string },
    @Body() verifyOtpDto: VerifyOtpDto,
    @Res({ passthrough: true }) res: ExpressResponse,
  ): Promise<Omit<AuthResponseDto, 'refreshToken'>> {
    return issueAuthResponse(res, await this.otpService.verify(req.tempToken, verifyOtpDto.code));
  }

  @Post('resend')
  @Throttle({ default: THROTTLE_EMAIL_SEND })
  @UseGuards(OtpJwtGuard)
  @HttpCode(HttpStatus.OK)
  async resend(@Request() req: { tempToken: string }): Promise<void> {
    return this.otpService.resend(req.tempToken);
  }
}
