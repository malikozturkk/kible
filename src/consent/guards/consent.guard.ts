import { CanActivate, ExecutionContext, ForbiddenException, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { Request as ExpressRequest } from 'express';
import { CONSENT_BYPASS_ROUTES, ConsentErrorCode } from '../consent.constants';
import { CONSENT_BYPASS_KEY } from '../decorators/consent-bypass.decorator';
import { IS_PUBLIC_KEY } from '../../common/decorators/public.decorator';
import { ConsentService } from '../consent.service';

@Injectable()
export class ConsentGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly consentService: ConsentService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    if (context.getType() !== 'http') return true;

    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (isPublic) return true;

    const hasBypass = this.reflector.getAllAndOverride<boolean>(CONSENT_BYPASS_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (hasBypass) return true;

    const req = context.switchToHttp().getRequest<
      ExpressRequest & {
        user?: { id: string };
      }
    >();

    if (this.matchesBypassRoute(req)) return true;

    const userId = req.user?.id;
    if (!userId) return true;

    const required = this.consentService.getRequiredVersions();
    const latest = await this.consentService.fetchLatestPerType(userId);
    const byType = new Map(latest.map((row) => [row.type, row.version]));

    for (const [type, expectedVersion] of Object.entries(required) as Array<
      [keyof typeof required, string]
    >) {
      if (byType.get(type) !== expectedVersion) {
        throw new ForbiddenException(ConsentErrorCode.CONSENT_REQUIRED);
      }
    }

    return true;
  }

  private matchesBypassRoute(req: ExpressRequest): boolean {
    const rawUrl = req.originalUrl ?? req.url ?? '';
    const path = rawUrl.split('?')[0] ?? '';
    const method = (req.method ?? '').toUpperCase();

    for (const rule of CONSENT_BYPASS_ROUTES) {
      if (rule.method === method && rule.path.test(path)) {
        return true;
      }
    }
    return false;
  }
}
