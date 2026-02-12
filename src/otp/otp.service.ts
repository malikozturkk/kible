import { Injectable, BadRequestException, ConflictException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Cron, CronExpression } from '@nestjs/schedule';
import { StringValue } from 'ms';
import * as crypto from 'crypto';
import { PrismaService } from '../prisma/prisma.service';
import { AuthResponseDto } from '../auth/dto/auth-response.dto';
import { EmailService } from '../email/email.service';

export interface RegisterData {
  email: string;
  username: string;
  passwordHash: string;
}

@Injectable()
export class OtpService {
  private readonly OTP_EXPIRES_IN_MINUTES = 3;
  private readonly REGISTRATION_EXPIRES_IN_MINUTES = 10;
  private readonly JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN;
  private readonly REFRESH_TOKEN_EXPIRES_IN_DAYS = 1;

  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
    private readonly emailService: EmailService,
  ) {}

  async create(token: string, registrationData: RegisterData): Promise<void> {
    const tokenHash = this.hashToken(token);
    const otpCode = this.generateOtpCode();
    const otpExpiresAt = new Date(Date.now() + this.OTP_EXPIRES_IN_MINUTES * 60 * 1000);
    const expiresAt = new Date(Date.now() + this.REGISTRATION_EXPIRES_IN_MINUTES * 60 * 1000);

    await this.prisma.otpVerification.create({
      data: {
        tokenHash,
        otpCode,
        otpExpiresAt,
        email: registrationData.email,
        username: registrationData.username,
        passwordHash: registrationData.passwordHash,
        expiresAt,
      },
    });

    await this.sendOtpEmail(registrationData.email, registrationData.username, otpCode);
  }

  async resend(token: string): Promise<void> {
    const tokenHash = this.hashToken(token);
    const now = new Date();
    const otpCode = this.generateOtpCode();
    const otpExpiresAt = new Date(Date.now() + this.OTP_EXPIRES_IN_MINUTES * 60 * 1000);

    const minExpiresAt = new Date(Date.now() + this.OTP_EXPIRES_IN_MINUTES * 60 * 1000);
    const result = await this.prisma.otpVerification.updateMany({
      where: {
        tokenHash,
        otpExpiresAt: { lte: now },
        expiresAt: { gt: minExpiresAt },
      },
      data: { otpCode, otpExpiresAt },
    });

    const record = await this.prisma.otpVerification.findUnique({
      where: { tokenHash },
    });

    if (!record) {
      throw new BadRequestException('NO_PENDING_REGISTRATION');
    }

    if (record.expiresAt <= now) {
      await this.prisma.otpVerification.delete({ where: { id: record.id } });
      throw new BadRequestException('REGISTRATION_EXPIRED');
    }

    if (record.expiresAt <= minExpiresAt) {
      if (record.otpExpiresAt <= now) {
        await this.prisma.otpVerification.delete({ where: { id: record.id } });
        throw new BadRequestException('REGISTRATION_EXPIRED');
      }
      throw new BadRequestException('INSUFFICIENT_TIME_FOR_NEW_OTP');
    }

    if (result.count === 0) {
      throw new BadRequestException('ACTIVE_OTP_EXISTS');
    }
    await this.sendOtpEmail(record.email, record.username, otpCode);
  }

  async cleanupStaleRegistrations(email: string, username: string): Promise<void> {
    const now = new Date();
    const minExpiresAt = new Date(Date.now() + this.OTP_EXPIRES_IN_MINUTES * 60 * 1000);

    await this.prisma.otpVerification.deleteMany({
      where: {
        OR: [{ email }, { username }],
        otpExpiresAt: { lte: now },
        expiresAt: { gt: now, lte: minExpiresAt },
      },
    });
  }

  private async sendOtpEmail(email: string, name: string, code: string): Promise<void> {
    try {
      await this.emailService.sendOtpEmail(email, name, { code });
    } catch (error) {
      console.error(`OTP e-postası gönderilemedi: ${email}`, error);
    }
  }

  private generateOtpCode(): string {
    return crypto.randomInt(100000, 999999).toString();
  }

  private hashToken(token: string): string {
    return crypto.createHash('sha256').update(token).digest('hex');
  }

  async verify(token: string, code: string): Promise<AuthResponseDto> {
    const tokenHash = this.hashToken(token);

    const record = await this.prisma.otpVerification.findUnique({
      where: { tokenHash },
    });

    if (!record) {
      throw new BadRequestException('OTP_NOT_FOUND');
    }

    if (record.expiresAt < new Date()) {
      await this.prisma.otpVerification.delete({ where: { id: record.id } });
      throw new BadRequestException('REGISTRATION_EXPIRED');
    }

    if (record.otpExpiresAt < new Date()) {
      throw new BadRequestException('OTP_EXPIRED');
    }

    if (!crypto.timingSafeEqual(Buffer.from(record.otpCode), Buffer.from(code))) {
      throw new BadRequestException('INVALID_OTP_CODE');
    }

    let user;
    try {
      user = await this.prisma.user.create({
        data: {
          email: record.email,
          username: record.username,
          credentials: {
            create: {
              passwordHash: record.passwordHash,
            },
          },
        },
        select: {
          id: true,
          username: true,
          email: true,
          avatar: true,
        },
      });
    } catch (error: any) {
      if (error.code === 'P2002') {
        await this.prisma.otpVerification.delete({ where: { id: record.id } });
        throw new ConflictException('USER_ALREADY_EXISTS');
      }
      throw error;
    }

    await this.prisma.otpVerification.delete({ where: { id: record.id } });
    const tokens = await this.generateTokens(user.id, user.username);

    return {
      ...tokens,
      user,
    };
  }

  private async generateTokens(
    userId: string,
    username: string,
  ): Promise<{ accessToken: string; refreshToken: string }> {
    const payload = { sub: userId, username };

    const accessToken = this.jwtService.sign(payload, {
      expiresIn: this.JWT_EXPIRES_IN as StringValue,
    });

    const refreshToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');

    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + this.REFRESH_TOKEN_EXPIRES_IN_DAYS);

    await this.prisma.refreshToken.create({
      data: {
        userId,
        tokenHash,
        expiresAt,
      },
    });

    return {
      accessToken,
      refreshToken,
    };
  }

  @Cron(CronExpression.EVERY_MINUTE)
  async cleanupExpiredRecords(): Promise<void> {
    await this.prisma.otpVerification.deleteMany({
      where: {
        expiresAt: { lt: new Date() },
      },
    });
  }
}
