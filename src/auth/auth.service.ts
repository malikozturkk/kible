import {
  Injectable,
  UnauthorizedException,
  ConflictException,
  BadRequestException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { StringValue } from 'ms';
import * as bcrypt from 'bcrypt';
import { PrismaService } from '../prisma/prisma.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { UpdateProfileDto } from './dto/update-profile.dto';
import { AuthResponseDto } from './dto/auth-response.dto';
import { RegisterResponseDto } from './dto/register-response.dto';
import { JwtPayload } from './strategies/jwt.strategy';
import { OtpService } from '../otp/otp.service';
import * as crypto from 'crypto';

@Injectable()
export class AuthService {
  private readonly PEPPER = process.env.PEPPER;
  private readonly JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN;
  private readonly REFRESH_TOKEN_EXPIRES_IN_DAYS = 1;

  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private otpService: OtpService,
  ) {}

  async register(registerDto: RegisterDto): Promise<RegisterResponseDto> {
    const { username, email, password } = registerDto;

    if (!email) {
      throw new BadRequestException('EMAIL_REQUIRED');
    }

    const existingUsername = await this.prisma.user.findUnique({
      where: { username },
    });

    if (existingUsername) {
      throw new ConflictException('USERNAME_ALREADY_EXISTS');
    }
    const existingEmail = await this.prisma.user.findUnique({
      where: { email },
    });

    if (existingEmail) {
      throw new ConflictException('USER_ALREADY_EXISTS');
    }

    const securePassword = password + this.PEPPER;
    const passwordHash = await bcrypt.hash(securePassword, 12);

    const activeOtp = await this.prisma.otpVerification.findFirst({
      where: {
        OR: [{ email }, { username }],
        otpExpiresAt: { gt: new Date() },
        expiresAt: { gt: new Date() },
      },
    });

    if (activeOtp) {
      throw new ConflictException('ACTIVE_OTP_EXISTS');
    }

    await this.prisma.otpVerification.deleteMany({
      where: {
        OR: [{ email }, { username }],
        otpExpiresAt: { lte: new Date() },
      },
    });

    const tempToken = this.jwtService.sign(
      { email, username, purpose: 'register' },
      { expiresIn: '10m' },
    );

    await this.otpService.create(tempToken, { email, username, passwordHash });

    return {
      tempToken,
      message: 'OTP_SENT_TO_EMAIL',
    };
  }

  async login(loginDto: LoginDto): Promise<AuthResponseDto> {
    const { email, password } = loginDto;

    if (!email) {
      throw new BadRequestException('EMAIL_REQUIRED');
    }

    const user = await this.prisma.user.findUnique({
      where: { email },
      include: {
        credentials: true,
      },
    });

    if (!user || !user.credentials) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const securePassword = password + this.PEPPER;
    const isValid = await bcrypt.compare(securePassword, user.credentials.passwordHash);

    if (!isValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const tokens = await this.generateTokens(user.id, user.username);
    return {
      ...tokens,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        avatar: user.avatar,
      },
    };
  }

  async refresh(refreshTokenDto: RefreshTokenDto): Promise<AuthResponseDto> {
    const { refreshToken } = refreshTokenDto;
    const tokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');
    const storedToken = await this.prisma.refreshToken.findUnique({
      where: { tokenHash },
      include: {
        user: {
          select: {
            id: true,
            username: true,
            email: true,
            avatar: true,
          },
        },
      },
    });

    if (!storedToken || storedToken.isRevoked || storedToken.expiresAt < new Date()) {
      throw new UnauthorizedException('Invalid or expired refresh token');
    }

    const tokens = await this.generateTokens(storedToken.user.id, storedToken.user.username);
    return {
      ...tokens,
      user: storedToken.user,
    };
  }

  async logout(userId: string, refreshToken: string): Promise<void> {
    const tokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');

    const storedToken = await this.prisma.refreshToken.findUnique({
      where: { tokenHash },
    });

    if (!storedToken) {
      throw new UnauthorizedException('INVALID_REFRESH_TOKEN');
    }

    if (storedToken.userId !== userId) {
      throw new UnauthorizedException('INVALID_REFRESH_TOKEN');
    }

    if (storedToken.isRevoked) {
      throw new UnauthorizedException('TOKEN_ALREADY_INVALIDATED');
    }

    if (storedToken.expiresAt < new Date()) {
      throw new UnauthorizedException('REFRESH_TOKEN_EXPIRED');
    }

    await this.prisma.refreshToken.update({
      where: { id: storedToken.id },
      data: { isRevoked: true },
    });
  }

  async me(userId: string) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        username: true,
        email: true,
        avatar: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    return user;
  }

  async updateProfile(
    userId: string,
    updateProfileDto: UpdateProfileDto,
  ): Promise<AuthResponseDto['user']> {
    const { username, avatar } = updateProfileDto;
    if (username) {
      const existingUser = await this.prisma.user.findFirst({
        where: {
          username,
          NOT: { id: userId },
        },
      });

      if (existingUser) {
        throw new ConflictException('Username already exists');
      }
    }

    const user = await this.prisma.user.update({
      where: { id: userId },
      data: {
        ...(username && { username }),
        ...(avatar !== undefined && { avatar }),
      },
      select: {
        id: true,
        username: true,
        email: true,
        avatar: true,
      },
    });

    return user;
  }

  private async generateTokens(
    userId: string,
    username: string,
  ): Promise<{ accessToken: string; refreshToken: string }> {
    const payload: JwtPayload = {
      sub: userId,
      username,
    };

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
}
