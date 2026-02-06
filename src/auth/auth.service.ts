import { Injectable, UnauthorizedException, ConflictException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { StringValue } from 'ms';
import * as bcrypt from 'bcrypt';
import { PrismaService } from '../prisma/prisma.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { UpdateProfileDto } from './dto/update-profile.dto';
import { AuthResponseDto } from './dto/auth-response.dto';
import { JwtPayload } from './strategies/jwt.strategy';
import * as crypto from 'crypto';

@Injectable()
export class AuthService {
  private readonly PEPPER = process.env.PEPPER;
  private readonly JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN;
  private readonly REFRESH_TOKEN_EXPIRES_IN_DAYS = 1;

  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
  ) {}

  async register(registerDto: RegisterDto): Promise<AuthResponseDto> {
    const { username, phone, password } = registerDto;
    const existingUser = await this.prisma.user.findFirst({
      where: {
        OR: [{ username }, { phone }],
      },
    });

    if (existingUser) {
      if (existingUser.username === username) {
        throw new ConflictException('Username already exists');
      }
      if (existingUser.phone === phone) {
        throw new ConflictException('Phone number already exists');
      }
    }

    const securePassword = password + this.PEPPER;
    const passwordHash = await bcrypt.hash(securePassword, 12);
    const user = await this.prisma.user.create({
      data: {
        username,
        phone,
        credentials: {
          create: {
            passwordHash,
          },
        },
      },
      select: {
        id: true,
        username: true,
        phone: true,
        avatar: true,
      },
    });

    const tokens = await this.generateTokens(user.id, user.username);
    return {
      ...tokens,
      user,
    };
  }

  async login(loginDto: LoginDto): Promise<AuthResponseDto> {
    const { username, password } = loginDto;
    const user = await this.prisma.user.findUnique({
      where: { username },
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
        phone: user.phone,
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
            phone: true,
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

  async logout(userId: string, refreshToken?: string): Promise<void> {
    if (refreshToken) {
      const tokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');

      await this.prisma.refreshToken.updateMany({
        where: {
          tokenHash,
          userId,
        },
        data: {
          isRevoked: true,
        },
      });
    } else {
      await this.prisma.refreshToken.updateMany({
        where: {
          userId,
          isRevoked: false,
        },
        data: {
          isRevoked: true,
        },
      });
    }
  }

  async me(userId: string) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        username: true,
        phone: true,
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
        phone: true,
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
