import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { Request as ExpressRequest } from 'express';
import { PrismaService } from '../../prisma/prisma.service';

export interface JwtPayload {
  sub: string;
  username: string;
  tv?: number;
  iat?: number;
}

export type AuthenticatedRequest = ExpressRequest & {
  user: {
    id: string;
  };
};

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private prisma: PrismaService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: process.env.JWT_SECRET as string,
    });
  }

  async validate(payload: JwtPayload) {
    const user = await this.prisma.user.findUnique({
      where: { id: payload.sub },
      select: {
        id: true,
        username: true,
        email: true,
        avatar: true,
        credentials: { select: { tokenVersion: true } },
      },
    });

    if (!user) {
      throw new UnauthorizedException('USER_NOT_FOUND');
    }

    const currentTokenVersion = user.credentials?.tokenVersion ?? 0;
    if ((payload.tv ?? 0) !== currentTokenVersion) {
      throw new UnauthorizedException('TOKEN_REVOKED_BY_PASSWORD_CHANGE');
    }

    const { credentials: _credentials, ...safeUser } = user;
    return safeUser;
  }
}
