import {
  Controller,
  Post,
  Get,
  Patch,
  Delete,
  Body,
  UseGuards,
  Request,
  HttpCode,
  HttpStatus,
  Param,
} from '@nestjs/common';
import { Request as ExpressRequest } from 'express';
import { Throttle, ThrottlerGuard } from '@nestjs/throttler';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { AuthResponseDto } from './dto/auth-response.dto';
import { RegisterResponseDto } from './dto/register-response.dto';
import { UpdateProfileDto } from './dto/update-profile.dto';
import { PasswordResetService } from './password-reset.service';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ValidateResetTokenDto } from './dto/validate-reset-token.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import type { AuthenticatedRequest } from 'src/auth/strategies/jwt.strategy';
import { UpdateProfileResponseDto } from './dto/update-profile-response.dto';
import { ResumeRegistrationDto } from './dto/resume-registration.dto';
import {
  THROTTLE_EMAIL_SEND,
  THROTTLE_LOGIN,
  THROTTLE_REFRESH,
  THROTTLE_REGISTER,
  THROTTLE_RESET,
} from '../common/throttler/throttle.constants';

@UseGuards(ThrottlerGuard)
@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly passwordResetService: PasswordResetService,
  ) {}

  @Post('register')
  @Throttle({ default: THROTTLE_REGISTER })
  async register(@Body() registerDto: RegisterDto): Promise<RegisterResponseDto> {
    return this.authService.register(registerDto);
  }

  @Post('login')
  @Throttle({ default: THROTTLE_LOGIN })
  @HttpCode(HttpStatus.OK)
  async login(@Body() loginDto: LoginDto): Promise<AuthResponseDto> {
    return this.authService.login(loginDto);
  }

  @Post('refresh')
  @Throttle({ default: THROTTLE_REFRESH })
  @HttpCode(HttpStatus.OK)
  async refresh(@Body() refreshTokenDto: RefreshTokenDto): Promise<AuthResponseDto> {
    return this.authService.refresh(refreshTokenDto);
  }

  @Post('logout')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async logout(
    @Request() req: AuthenticatedRequest,
    @Body() refreshTokenDto: RefreshTokenDto,
  ): Promise<void> {
    await this.authService.logout(req.user.id, refreshTokenDto.refreshToken);
  }

  @Delete('me')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async deleteAccount(@Request() req: AuthenticatedRequest): Promise<void> {
    await this.authService.deleteAccount(req.user.id);
  }

  @Get(':username')
  @UseGuards(JwtAuthGuard)
  async getProfile(@Request() req: AuthenticatedRequest, @Param('username') username: string) {
    return this.authService.getProfileByUsername(username, req.user.id);
  }

  @Patch('profile')
  @UseGuards(JwtAuthGuard)
  async updateProfile(
    @Request() req: AuthenticatedRequest,
    @Body() updateProfileDto: UpdateProfileDto,
  ): Promise<UpdateProfileResponseDto> {
    return this.authService.updateProfile(req.user.id, updateProfileDto);
  }

  @Post('resume-registration')
  @Throttle({ default: THROTTLE_RESET })
  @HttpCode(HttpStatus.OK)
  async resumeRegistration(
    @Body() resumeRegistrationDto: ResumeRegistrationDto,
  ): Promise<RegisterResponseDto> {
    return this.authService.resumeRegistration(resumeRegistrationDto.email);
  }

  @Post('forgot-password')
  @Throttle({ default: THROTTLE_EMAIL_SEND })
  async forgotPassword(@Body() forgotPasswordDto: ForgotPasswordDto) {
    await this.passwordResetService.requestReset(forgotPasswordDto.email);
    return {
      message: 'FORGOT_PASSWORD_EMAIL_SENT',
    };
  }

  @Post('validate-reset-token')
  @Throttle({ default: THROTTLE_RESET })
  async validateResetToken(@Body() validateResetTokenDto: ValidateResetTokenDto) {
    return this.passwordResetService.validateToken(validateResetTokenDto);
  }

  @Post('reset-password')
  @Throttle({ default: THROTTLE_RESET })
  async resetPassword(@Body() resetPasswordDto: ResetPasswordDto) {
    return this.passwordResetService.resetPassword(resetPasswordDto);
  }

  @Post(':username/follow')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async toggleFollow(@Request() req: AuthenticatedRequest, @Param('username') username: string) {
    return this.authService.toggleFollow(req.user.id, username);
  }

  @Get(':username/followers')
  @UseGuards(JwtAuthGuard)
  async getFollowers(@Param('username') username: string) {
    return this.authService.getFollowers(username);
  }

  @Get(':username/following')
  @UseGuards(JwtAuthGuard)
  async getFollowing(@Param('username') username: string) {
    return this.authService.getFollowing(username);
  }
}
