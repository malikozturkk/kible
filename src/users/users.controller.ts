import { Controller, Get, Query, UseGuards, Request } from '@nestjs/common';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import type { AuthenticatedRequest } from '../auth/strategies/jwt.strategy';
import { UsersService } from './users.service';
import { SearchUsersDto } from './dto/search-users.dto';
import { SearchUsersResponse } from './types/users.types';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Get('search')
  @UseGuards(JwtAuthGuard)
  async searchUsers(
    @Query() dto: SearchUsersDto,
    @Request() req: AuthenticatedRequest,
  ): Promise<SearchUsersResponse> {
    return this.usersService.searchUsers(dto, req.user.id);
  }
}
