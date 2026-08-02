import { Controller, Post, Body, UseGuards, Request, HttpCode, HttpStatus } from '@nestjs/common';
import { Throttle, ThrottlerGuard } from '@nestjs/throttler';
import { OtpService } from './otp.service';
import { VerifyOtpDto } from './dto/verify-otp.dto';
import { OtpJwtGuard } from './guards/otp-jwt.guard';
import { AuthResponseDto } from '../auth/dto/auth-response.dto';
import { THROTTLE_EMAIL_SEND, THROTTLE_OTP_VERIFY } from '../common/throttler/throttle.constants';

@UseGuards(ThrottlerGuard)
@Controller('otp')
export class OtpController {
  constructor(private readonly otpService: OtpService) {}

  @Post('verify')
  @Throttle({ default: THROTTLE_OTP_VERIFY }) 
  @UseGuards(OtpJwtGuard)
  @HttpCode(HttpStatus.OK)
  async verify(@Request() req: any, @Body() verifyOtpDto: VerifyOtpDto): Promise<AuthResponseDto> {
    return this.otpService.verify(req.tempToken, verifyOtpDto.code);
  }

  @Post('resend')
  @Throttle({ default: THROTTLE_EMAIL_SEND })
  @UseGuards(OtpJwtGuard)
  @HttpCode(HttpStatus.OK)
  async resend(@Request() req: any): Promise<void> {
    return this.otpService.resend(req.tempToken);
  }
}
