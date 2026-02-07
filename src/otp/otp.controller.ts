import { Controller, Post, Body, UseGuards, Request, HttpCode, HttpStatus } from '@nestjs/common';
import { OtpService } from './otp.service';
import { VerifyOtpDto } from './dto/verify-otp.dto';
import { OtpJwtGuard } from './guards/otp-jwt.guard';
import { AuthResponseDto } from '../auth/dto/auth-response.dto';

@Controller('otp')
export class OtpController {
  constructor(private readonly otpService: OtpService) {}

  @Post('verify')
  @UseGuards(OtpJwtGuard)
  @HttpCode(HttpStatus.OK)
  async verify(@Request() req: any, @Body() verifyOtpDto: VerifyOtpDto): Promise<AuthResponseDto> {
    return this.otpService.verify(req.tempToken, verifyOtpDto.code);
  }
}
