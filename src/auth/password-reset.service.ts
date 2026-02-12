import {
  Injectable,
  BadRequestException,
  ConflictException,
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import * as crypto from 'crypto';
import * as bcrypt from 'bcrypt';
import { PrismaService } from '../prisma/prisma.service';
import { EmailService } from '../email/email.service';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { ValidateResetTokenDto } from './dto/validate-reset-token.dto';

@Injectable()
export class PasswordResetService {
  private readonly TOKEN_EXPIRES_MINUTES = 30;
  private readonly PEPPER = process.env.PEPPER;
  private readonly FRONTEND_BASE_URL = process.env.FRONTEND_BASE_URL;

  constructor(
    private prisma: PrismaService,
    private emailService: EmailService,
  ) {}

  private generateRawToken(): string {
    return crypto.randomBytes(32).toString('hex');
  }

  private async hashToken(raw: string): Promise<string> {
    return await bcrypt.hash(raw, 12);
  }

  private async isTokenMatch(raw: string, hash: string): Promise<boolean> {
    return await bcrypt.compare(raw, hash);
  }

  async requestReset(email: string): Promise<void> {
    const user = await this.prisma.user.findUnique({ where: { email } });
    if (!user) {
      return;
    }

    const now = new Date();
    const active = await this.prisma.passwordReset.findFirst({
      where: {
        userId: user.id,
        isUsed: false,
        expiresAt: { gt: now },
      },
      orderBy: { createdAt: 'desc' },
    });

    if (active) {
      throw new ConflictException('ACTIVE_RESET_EXISTS');
    }

    const rawToken = this.generateRawToken();
    const tokenHash = await this.hashToken(rawToken);
    const expiresAt = new Date(Date.now() + this.TOKEN_EXPIRES_MINUTES * 60 * 1000);

    const record = await this.prisma.passwordReset.create({
      data: {
        userId: user.id,
        tokenHash,
        expiresAt,
      },
    });

    const resetLink = `${this.FRONTEND_BASE_URL}/reset-password?user_id=${user.id}&token=${rawToken}`;

    try {
      await this.emailService.sendForgotPasswordEmail(user.email, user.username, {
        reset_link: resetLink,
      });
    } catch (err) {
      await this.prisma.passwordReset.delete({ where: { id: record.id } });
      throw new InternalServerErrorException('EMAIL_SEND_FAILED');
    }
  }

  async validateToken(validateResetTokenDto: ValidateResetTokenDto): Promise<boolean> {
    const { userId, token } = validateResetTokenDto;
    const record = await this.prisma.passwordReset.findFirst({
      where: { userId, isUsed: false },
      orderBy: { createdAt: 'desc' },
    });

    if (!record) {
      throw new BadRequestException('INVALID_OR_EXPIRED_TOKEN');
    }

    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) {
      await this.prisma.passwordReset.delete({ where: { id: record.id } });
      throw new UnauthorizedException('USER_NOT_FOUND');
    }

    if (record.expiresAt < new Date()) {
      await this.prisma.passwordReset.delete({ where: { id: record.id } });
      throw new BadRequestException('INVALID_OR_EXPIRED_TOKEN');
    }

    const match = await this.isTokenMatch(token, record.tokenHash);
    if (!match) {
      throw new BadRequestException('INVALID_OR_EXPIRED_TOKEN');
    }

    return true;
  }

  async resetPassword(resetPasswordDto: ResetPasswordDto): Promise<void> {
    const { userId, token, newPassword, confirmPassword } = resetPasswordDto;
    if (newPassword !== confirmPassword) {
      throw new BadRequestException('PASSWORDS_DO_NOT_MATCH');
    }

    const record = await this.prisma.passwordReset.findFirst({
      where: { userId, isUsed: false },
      orderBy: { createdAt: 'desc' },
    });

    if (!record) {
      throw new BadRequestException('INVALID_OR_EXPIRED_TOKEN');
    }

    if (record.expiresAt < new Date()) {
      await this.prisma.passwordReset.delete({ where: { id: record.id } });
      throw new BadRequestException('INVALID_OR_EXPIRED_TOKEN');
    }

    const match = await this.isTokenMatch(token, record.tokenHash);
    if (!match) {
      throw new BadRequestException('INVALID_OR_EXPIRED_TOKEN');
    }

    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      include: { credentials: true },
    });
    if (!user || !user.credentials) {
      await this.prisma.passwordReset.delete({ where: { id: record.id } });
      throw new BadRequestException('USER_NOT_FOUND');
    }

    const secureNewPassword = newPassword + this.PEPPER;
    const newHash = await bcrypt.hash(secureNewPassword, 12);

    try {
      await this.prisma.$transaction([
        this.prisma.userCredential.update({
          where: { userId: user.id },
          data: { passwordHash: newHash, passwordUpdatedAt: new Date() },
        }),
        this.prisma.refreshToken.updateMany({
          where: { userId: user.id, isRevoked: false },
          data: { isRevoked: true },
        }),
        this.prisma.passwordReset.update({
          where: { id: record.id },
          data: { isUsed: true },
        }),
      ]);
    } catch (err) {
      throw new InternalServerErrorException('PASSWORD_UPDATE_FAILED');
    }
  }

  @Cron(CronExpression.EVERY_MINUTE)
  async cleanupExpired(): Promise<void> {
    await this.prisma.passwordReset.deleteMany({
      where: { expiresAt: { lt: new Date() } },
    });
  }
}
