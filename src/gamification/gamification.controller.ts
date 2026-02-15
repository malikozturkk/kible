import { Controller, Request, Get, UseGuards } from '@nestjs/common';
import { UserXpResponseDto } from './dto/user-xp.dto';
import { GamificationService } from './gamification.service';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import type { AuthenticatedRequest } from 'src/auth/strategies/jwt.strategy';
import { UserStreakResponseDto } from './dto/user-streak.dto';

@Controller('gamification')
export class GamificationController {
  constructor(private readonly gamificationService: GamificationService) {}

  @Get('user-xp')
  @UseGuards(JwtAuthGuard)
  async userXp(@Request() req: AuthenticatedRequest): Promise<UserXpResponseDto> {
    return this.gamificationService.userXp(req.user.id);
  }

  @Get('user-streak')
  @UseGuards(JwtAuthGuard)
  async userStreak(@Request() req: AuthenticatedRequest): Promise<UserStreakResponseDto> {
    return this.gamificationService.userStreak(req.user.id);
  }
}
