import { Controller, Get, Header, Param, Query, UseGuards, Request } from '@nestjs/common';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import type { AuthenticatedRequest } from '../auth/strategies/jwt.strategy';
import { UsersService } from './users.service';
import { UserStatsService } from './services/user-stats.service';
import { SearchUsersDto } from './dto/search-users.dto';
import { SearchUsersResponse } from './types/users.types';
import { PublicStatsResponseDto, SelfStatsResponseDto } from './dto/user-stats.dto';
import { DataExportService } from './services/data-export.service';
import { ConsentBypass } from '../consent/decorators/consent-bypass.decorator';
import { Throttle } from '@nestjs/throttler';

@Controller('users')
@UseGuards(JwtAuthGuard)
export class UsersController {
  constructor(
    private readonly usersService: UsersService,
    private readonly userStatsService: UserStatsService,
    private readonly dataExportService: DataExportService,
  ) {}

  @Get('search')
  async searchUsers(
    @Query() dto: SearchUsersDto,
    @Request() req: AuthenticatedRequest,
  ): Promise<SearchUsersResponse> {
    return this.usersService.searchUsers(dto, req.user.id);
  }

  @Get('me/stats')
  async selfStats(@Request() req: AuthenticatedRequest): Promise<SelfStatsResponseDto> {
    return this.userStatsService.getSelfStats(req.user.id);
  }

  @Get('me/export')
  @ConsentBypass()
  @Throttle({ default: { limit: 3, ttl: 3_600_000 } })
  @Header('Content-Disposition', 'attachment; filename="namazgo-verilerim.json"')
  async exportMyData(@Request() req: AuthenticatedRequest): Promise<Record<string, unknown>> {
    return this.dataExportService.exportUserData(req.user.id);
  }

  @Get(':username/stats')
  async publicStats(
    @Param('username') username: string,
    @Request() req: AuthenticatedRequest,
  ): Promise<PublicStatsResponseDto> {
    return this.userStatsService.getPublicStats(username, req.user.id);
  }
}
