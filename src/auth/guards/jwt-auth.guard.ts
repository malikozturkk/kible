import { ExecutionContext, Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { ConsentGuard } from '../../consent/guards/consent.guard';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  constructor(private readonly consentGuard: ConsentGuard) {
    super();
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const authenticated = (await super.canActivate(context)) as boolean;
    if (!authenticated) return false;

    return this.consentGuard.canActivate(context);
  }
}
